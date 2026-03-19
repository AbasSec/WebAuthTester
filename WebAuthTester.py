#!/usr/bin/env python3
"""
WebAuthTester Pro v2.2 - Enterprise Security Research Edition
An advanced asynchronous framework for authentication auditing.
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
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from difflib import SequenceMatcher

# --- UI & Styling ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.live import Live
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False

# --- Banner ---
BANNER = r"""[bold red]
 __      __      ___.       _____         __  .__     
/  \    /  \ ____\_ |__    /  _  \  __ ___/  |_|  |__  
\   \/\/   // __ \| __ \  /  /_\  \|  |  \   __\  |  \ 
 \        /\  ___/| \_\ \/    |    \  |  /|  | |   Y  \
  \__/\  /  \___  >___  /\____|__  /____/ |__| |___|  /
       \/       \/    \/         \/                 \/ 
                 [italic white]v2.2 - Advanced Auth Auditing Suite[/italic white]
[/bold red]"""

# --- Dependency Management ---
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# --- Constants ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

def get_random_ua():
    return random.choice(USER_AGENTS)

# --- Data Models ---

@dataclass
class AuthEndpoint:
    url: str
    auth_type: str
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

# --- Core Logic ---

class DiscoveryEngine:
    def __init__(self, session, target, max_pages=50, proxy=None):
        self.session = session
        self.target = target
        self.max_pages = max_pages
        self.proxy = proxy
        self.visited = set()
        self.endpoints = []
        self.queue = asyncio.Queue()

    async def run(self):
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
                    else: await self._extract_regex(body, url)
                    
                    if "text/html" in resp.headers.get("Content-Type", ""):
                        await self._find_links(body, url)
            except Exception: pass
            finally: self.queue.task_done()

    async def _find_links(self, html, source):
        links = []
        if HAS_BS4:
            links = [l.get('href') for l in BeautifulSoup(html, 'html.parser').find_all('a', href=True)]
        else:
            links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
        for l in links:
            n = urllib.parse.urljoin(source, l)
            if urllib.parse.urlparse(n).netloc == urllib.parse.urlparse(self.target).netloc:
                await self.queue.put(n)

    async def _extract_bs4(self, html, source):
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = urllib.parse.urljoin(source, form.get('action') or source)
            u, p = None, None
            inputs = {}
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if not name: continue
                itype = (inp.get('type') or 'text').lower()
                if itype == "password" or "pass" in name.lower(): p = name
                elif any(x in name.lower() for x in ["user", "email", "login"]): u = name
                inputs[name] = inp.get('value') or ''
            if u and p:
                self._add_ep(AuthEndpoint(action, 'form_urlencoded', form.get('method', 'POST').upper(), u, p, {k:v for k,v in inputs.items() if k not in [u, p]}, source))

    async def _extract_regex(self, html, source):
        # Fallback simplified regex
        pass

    def _add_ep(self, ep):
        if not any(e.url == ep.url for e in self.endpoints): self.endpoints.append(ep)

class BruteEngine:
    def __init__(self, session, concurrency=10, proxy=None):
        self.session = session
        self.sem = asyncio.Semaphore(concurrency)
        self.proxy = proxy
        self.baselines = {}
        self.results = []
        self.rate_limited = False

    async def capture_baseline(self, ep):
        try:
            async with self.session.post(ep.url, data={ep.username_field: 'fake', ep.password_field: 'fake'}, proxy=self.proxy, timeout=10) as resp:
                body = (await resp.text(errors='ignore')).lower()
                self.baselines[ep.url] = AuthBaseline(resp.status, len(body), body[:2000])
        except Exception: pass

    async def test(self, ep, u, p):
        if self.rate_limited: return
        async with self.sem:
            try:
                async with self.session.post(ep.url, data={ep.username_field: u, ep.password_field: p, **ep.extra_fields}, proxy=self.proxy, allow_redirects=False, timeout=10) as resp:
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

# --- UI Helper ---

def show_banner():
    if HAS_RICH:
        console.print(BANNER)
    else:
        print("WebAuthTester Pro v2.2")

# --- CLI Setup ---

class CustomFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def get_args():
    parser = argparse.ArgumentParser(
        description="Advanced Asynchronous Authentication Auditing Suite",
        formatter_class=CustomFormatter,
        epilog="Examples:\n  ./WebAuthTester.py https://example.com\n  ./WebAuthTester.py https://example.com -u users.txt -p pass.txt -c 20\n  ./WebAuthTester.py https://example.com --proxy http://127.0.0.1:8080"
    )
    
    target_group = parser.add_argument_group('🎯 TARGET CONFIGURATION')
    target_group.add_argument("target", help="Target URL (e.g., https://example.com)")
    
    wordlist_group = parser.add_argument_group('📂 WORDLISTS')
    wordlist_group.add_argument("-u", "--userlist", default="wordlists/usernames.txt", help="Path to username wordlist")
    wordlist_group.add_argument("-p", "--passlist", default="wordlists/passwords.txt", help="Path to password wordlist")
    
    perf_group = parser.add_argument_group('⚡ PERFORMANCE & STEALTH')
    perf_group.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent connections")
    perf_group.add_argument("-x", "--proxy", help="HTTP proxy to route traffic through")
    
    return parser.parse_args()

async def main():
    args = get_args()
    show_banner()
    
    if not os.path.exists(args.userlist) or not os.path.exists(args.passlist):
        if HAS_RICH: console.print("[red][!] Error: Wordlists missing. Please run setup.sh first.[/red]")
        else: print("Error: Wordlists missing.")
        return

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        discovery = DiscoveryEngine(session, args.target, proxy=args.proxy)
        
        if HAS_RICH:
            with console.status("[bold green]Crawling target for entry points...") as status:
                endpoints = await discovery.run()
        else:
            print("[*] Discovering endpoints...")
            endpoints = await discovery.run()

        if not endpoints:
            if HAS_RICH: console.print("[yellow][!] No authentication endpoints identified.[/yellow]")
            else: print("No endpoints found.")
            return

        if HAS_RICH: console.print(f"[green][+] Identified {len(endpoints)} authentication gateway(s).[/green]")

        brute = BruteEngine(session, args.concurrency, args.proxy)
        for ep in endpoints:
            if HAS_RICH: console.print(f"\n[bold cyan]Auditing:[/bold cyan] {ep.url}")
            await brute.capture_baseline(ep)

            users = [l.strip() for l in open(args.userlist).readlines() if l.strip()][:50]
            passwords = [l.strip() for l in open(args.passlist).readlines() if l.strip()][:50]

            if HAS_RICH:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
                    task = progress.add_task("[cyan]Testing credentials...", total=len(users)*len(passwords))
                    for u in users:
                        for p in passwords:
                            if brute.rate_limited: break
                            await brute.test(ep, u, p)
                            progress.update(task, advance=1)
            else:
                for u in users:
                    for p in passwords:
                        if brute.rate_limited: break
                        await brute.test(ep, u, p)

        if brute.results:
            if HAS_RICH:
                table = Table(title="[bold green]VALID CREDENTIALS FOUND[/bold green]", border_style="green")
                table.add_column("URL", style="cyan"); table.add_column("Username", style="white"); table.add_column("Password", style="bold red")
                for r in brute.results: table.add_row(r[0], r[1], r[2])
                console.print(table)
            else:
                for r in brute.results: print(f"SUCCESS: {r[1]}:{r[2]} at {r[0]}")
        else:
            if HAS_RICH: console.print("[yellow][*] Audit complete. No valid credentials found.[/yellow]")
            else: print("Audit complete. No valid credentials found.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

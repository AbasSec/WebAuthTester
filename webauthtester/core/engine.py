"""
WebAuth Core Engine - Refactored Plugin-Based Architecture.
"""

import asyncio
import aiohttp
import urllib.parse
import random
import logging
import time
from typing import List, Dict, Set, Tuple
from difflib import SequenceMatcher
from bs4 import BeautifulSoup

from .models import AuthEndpoint, AuthBaseline, SecurityFinding
from webauthtester.modules.form_auth import FormAuthModule
from webauthtester.modules.oauth_auth import OAuthDetectionModule
from webauthtester.modules.json_auth import JSONAuthModule
from webauthtester.modules.firebase_auth import FirebaseAuthModule

logger = logging.getLogger(__name__)

class DiscoveryEngine:
    """Enterprise-grade Discovery Engine with Plugin Architecture."""
    
    COMMON_PATHS = [
        '/login', '/admin', '/api/login', '/api/v1/auth', '/auth', 
        '/wp-login.php', '/signin', '/user/login', '/api/auth/token',
        '/oauth/token', '/api/session', '/.well-known/openid-configuration'
    ]

    def __init__(self, session: aiohttp.ClientSession, target: str, max_pages: int = 30, proxy: str = None):
        self.session = session
        self.target = target.rstrip("/")
        self.target_netloc = urllib.parse.urlparse(self.target).netloc
        self.max_pages = max_pages
        self.proxy = proxy
        self.visited: Set[str] = set()
        self.endpoints: List[AuthEndpoint] = []
        self.queue = asyncio.Queue()
        # Register modules
        self.modules = [
            FormAuthModule(session, proxy),
            OAuthDetectionModule(session, proxy),
            JSONAuthModule(session, proxy),
            FirebaseAuthModule(session, proxy)
        ]


    def _is_internal(self, url: str) -> bool:
        """Determines if a URL is internal to the target domain."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == self.target_netloc or not parsed.netloc

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
            logger.warning("Discovery timeout reached.")
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
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                    'Accept-Encoding': 'identity' # Explicitly prevent compression issues in some edge cases
                }
                
                async with self.session.get(url, headers=headers, proxy=self.proxy, timeout=10) as resp:
                    body = await resp.text(errors='ignore')
                    
                    # Run all modules
                    for module in self.modules:
                        found = await module.discover(body, str(resp.url))
                        for ep in found:
                            if not any(e.url == ep.url and e.auth_type == ep.auth_type for e in self.endpoints):
                                self.endpoints.append(ep)

                    # Extract links for crawling
                    await self._extract_links(body, str(resp.url))

            except Exception as e:
                logger.error(f"Discovery worker error on {url}: {type(e).__name__}: {e}")
            finally: 
                self.queue.task_done()

    async def _extract_links(self, html: str, source: str):
        """Extracts and filters internal links for further discovery."""
        soup = BeautifulSoup(html, 'html.parser')
        # Skip common static assets to save resources
        skip_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js', '.woff', '.ttf', '.ico', '.pdf')
        
        for tag in soup.find_all(['a', 'script', 'link']):
            val = tag.get('href') or tag.get('src')
            if not val:
                continue
            
            # Basic sanity check to avoid binary/asset noise
            if val.lower().split('?')[0].endswith(skip_extensions):
                continue

            joined_url = urllib.parse.urljoin(source, val)
            if self._is_internal(joined_url):
                await self.queue.put(joined_url)


class BruteEngine:
    """RAPTOR-grade Differential Authentication Engine with Module Support."""
    
    # Sensitivity threshold for differential body analysis
    SIMILARITY_THRESHOLD = 0.90

    def __init__(self, session: aiohttp.ClientSession, concurrency: int = 10, proxy: str = None, stealth: bool = False):
        self.session = session
        self.sem = asyncio.Semaphore(concurrency)
        self.proxy = proxy
        self.stealth = stealth
        self.baselines: Dict[str, AuthBaseline] = {}
        self.results: List[Tuple[str, str, str]] = []
        self.findings: List[SecurityFinding] = []
        self.rate_limited = False
        
        # Initialize modules
        self.modules = {
            'form_urlencoded': FormAuthModule(session, proxy),
            'oauth_detected': OAuthDetectionModule(session, proxy),
            'json': JSONAuthModule(session, proxy),
            'firebase': FirebaseAuthModule(session, proxy)
        }

    async def capture_baseline(self, ep: AuthEndpoint):
        """Captures a robust failure fingerprint."""
        if ep.is_oauth:
            # Report OAuth detection as a finding
            self.findings.append(SecurityFinding(
                type="Authentication Discovery",
                title="OAuth2/SSO Flow Detected",
                severity="Info",
                cwe="CWE-1000",
                cvss_score=0.0,
                description=f"Identified potential OAuth2/OpenID Connect flow at {ep.url}. Brute force is out of scope.",
                remediation="Ensure OAuth implementation follows security best practices (PKCE, redirect URI whitelisting).",
                endpoint=ep.url
            ))
            return False

        module = self.modules.get(ep.auth_type)
        if not module: return False

        samples = []
        for _ in range(2):
            success, resp_data = await module.test(ep, f"fake_{int(time.time())}", "FakePass123!", None)
            if success and resp_data:
                samples.append(resp_data)
        
        if not samples: return False
        
        self.baselines[ep.url] = AuthBaseline(
            failed_status=samples[0][0],
            failed_length=len(samples[0][1]),
            failed_body_sample=samples[0][1].lower()[:2000]
        )
        return True

    async def test(self, ep: AuthEndpoint, u: str, p: str):
        if self.rate_limited: return
        
        module = self.modules.get(ep.auth_type)
        if not module: return

        async with self.sem:
            if self.rate_limited: return
            
            if self.stealth:
                await asyncio.sleep(random.uniform(0.5, 2.0))

            success, resp_data = await module.test(ep, u, p, self.baselines.get(ep.url))
            if not success or not resp_data: return
            
            status, body, headers = resp_data
            body_l = body.lower()
            baseline = self.baselines.get(ep.url)
            
            if status in [429, 403] or 'too many requests' in body_l or 'cloudflare' in body_l:
                if baseline and status != baseline.failed_status:
                    self.rate_limited = True
                return

            is_success = False
            if baseline:
                # Differential analysis
                if status != baseline.failed_status:
                    is_success = True
                else:
                    # Same status code, check body similarity
                    ratio = SequenceMatcher(None, body_l[:2000], baseline.failed_body_sample).ratio()
                    # If the body is significantly different (ratio < SIMILARITY_THRESHOLD) OR 
                    # contains explicit success markers that the baseline DID NOT have.
                    if ratio < self.SIMILARITY_THRESHOLD: 
                        # Avoid common failure keywords
                        if not any(x in body_l for x in ["invalid", "incorrect", "fail", "wrong", "error"]):
                            is_success = True
                    
                    # Explicit Success Tokens (overrides structural check)
                    success_indicators = ['token', '"success":true', 'access_token', '"authenticated":true', 'jwt']
                    if any(x in body_l for x in success_indicators) and not any(x in baseline.failed_body_sample for x in success_indicators):
                        is_success = True
            
            # Additional check for redirects
            if not is_success and status in [301, 302, 303, 307, 308]:
                loc = headers.get('Location', '').lower()
                if loc and not any(x in loc for x in ['login', 'error', 'fail', 'signin', 'auth']):
                    is_success = True

            if is_success:
                self.results.append((ep.url, u, p))

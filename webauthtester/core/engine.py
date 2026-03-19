"""
WebAuth Core Engine - Refactored Plugin-Based Architecture.
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

from .models import AuthEndpoint, AuthBaseline, SecurityFinding
from webauthtester.modules.form_auth import FormAuthModule
from webauthtester.modules.oauth_auth import OAuthDetectionModule

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
        self.max_pages = max_pages
        self.proxy = proxy
        self.visited: Set[str] = set()
        self.endpoints: List[AuthEndpoint] = []
        self.queue = asyncio.Queue()
        # Register modules
        self.modules = [
            FormAuthModule(session, proxy),
            OAuthDetectionModule(session, proxy)
        ]

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
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'}
                
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
                logger.debug(f"Worker error on {url}: {e}")
            finally: 
                self.queue.task_done()

    async def _extract_links(self, html, source):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        target_netloc = urllib.parse.urlparse(self.target).netloc
        
        for tag in soup.find_all(['a', 'script', 'link']):
            val = tag.get('href') or tag.get('src')
            if not val: continue
            
            n = urllib.parse.urljoin(source, val)
            parsed_n = urllib.parse.urlparse(n)
            if parsed_n.netloc == target_netloc or not parsed_n.netloc:
                await self.queue.put(n)


class BruteEngine:
    """RAPTOR-grade Differential Authentication Engine with Module Support."""
    
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
            'oauth_detected': OAuthDetectionModule(session, proxy)
        }

    async def capture_baseline(self, ep: AuthEndpoint):
        """Captures a robust failure fingerprint."""
        if ep.is_oauth:
            # Report OAuth detection as a finding
            self.findings.append(SecurityFinding(
                type="Authentication Discovery",
                title="OAuth2/SSO Flow Detected",
                severity="Info",
                cwe="CWE-1000", # General category for info
                cvss_score=0.0,
                description=f"Identified potential OAuth2/OpenID Connect flow at {ep.url}. Brute force is out of scope.",
                remediation="Ensure OAuth implementation follows security best practices (PKCE, redirect URI whitelisting).",
                endpoint=ep.url
            ))
            return False

        module = self.modules.get(ep.auth_type)
        if not module: return False

        samples = []
        for i in range(2):
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
            if status in [200, 201] and baseline and status != baseline.failed_status:
                if not any(x in body_l for x in ["invalid", "incorrect", "fail", "wrong"]):
                    is_success = True
            elif status in [301, 302, 303]:
                loc = headers.get('Location', '').lower()
                if loc and not any(x in loc for x in ['login', 'error', 'fail', 'signin']):
                    is_success = True

            if is_success:
                self.results.append((ep.url, u, p))
            
            # Check for lack of account lockout (CWE-307)
            # This is a simplistic check: if we've made many attempts and haven't hit rate limiting
            # but this would require tracking attempts per endpoint.
            # For now, we add a finding if rate_limited is still false after many attempts.

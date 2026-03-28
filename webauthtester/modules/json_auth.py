import logging
from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
import urllib.parse
from .base import AuthModule
from webauthtester.core.models import AuthEndpoint, AuthBaseline

logger = logging.getLogger(__name__)

class JSONAuthModule(AuthModule):
    """Handler for JSON-based authentication endpoints."""

    async def discover(self, html: str, url: str) -> List[AuthEndpoint]:
        soup = BeautifulSoup(html, 'html.parser')
        endpoints = []
        
        # 1. Look for common JSON API patterns in scripts or meta
        # Often these are in script tags or JS files, but we only have the HTML here.
        # We can look for common API paths in the HTML or common JS login patterns.
        
        # 2. Look for forms that might be JSON-backed (e.g., have id="login-form" but no action)
        forms = soup.find_all('form')
        for form in forms:
            # If a form has fields but no standard action/method, or is explicitly marked as JSON
            u_field, p_field = None, None
            for inp in form.find_all(['input']):
                name = inp.get('name') or inp.get('id') or inp.get('placeholder') or inp.get('aria-label') or inp.get('title', '')
                nl = name.lower()
                itype = (inp.get('type') or 'text').lower()
                
                if itype == "password" or any(x in nl for x in ['pass', 'pwd', 'secret']):
                    p_field = name
                elif any(x in nl for x in ['user', 'email', 'login', 'id', 'account']):
                    u_field = name
            
            if u_field and p_field:
                # Stronger JSON detection: Avoid common non-auth patterns
                action = form.get('action') or ''
                # Only add as JSON if the action is explicitly API-like or if the form is in an API context
                # If there's NO action, it might be JS-driven, but FormAuth handles it as urlencoded by default.
                # We only want to duplicate it here as JSON if we have a strong reason.
                if any(x in action.lower() for x in ['api', 'json', 'auth', 'login', 'signin', 'token', 'session']) or '/api/' in url:
                    target_url = urllib.parse.urljoin(url, action or url)
                    # Deduplicate within this discovery run
                    if not any(e.url == target_url and e.auth_type == 'json' for e in endpoints):
                        endpoints.append(AuthEndpoint(
                            url=target_url,
                            auth_type='json',
                            method='POST',
                            username_field=u_field,
                            password_field=p_field,
                            extra_fields={},
                            source_page=url
                        ))

        # 3. Heuristic: If the URL itself looks like a JSON login endpoint
        if any(path in url.lower() for path in ['/api/login', '/api/v1/auth', '/api/auth/token', '/api/session']):
            if not any(e.url == url for e in endpoints):
                endpoints.append(AuthEndpoint(
                    url=url,
                    auth_type='json',
                    method='POST',
                    username_field='username',
                    password_field='password',
                    extra_fields={},
                    source_page=url
                ))

        return endpoints

    async def test(self, ep: AuthEndpoint, u: str, p: str, baseline: Optional[AuthBaseline]) -> Tuple[bool, Optional[Tuple[int, str, dict]]]:
        """Executes a single JSON authentication attempt."""
        payload = {
            ep.username_field: u,
            ep.password_field: p
        }
        if ep.extra_fields:
            payload.update(ep.extra_fields)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Accept-Encoding': 'identity',
            'Referer': ep.source_page or ep.url
        }

        try:
            async with self.session.post(
                ep.url, 
                json=payload, 
                headers=headers, 
                proxy=self.proxy, 
                allow_redirects=False, 
                timeout=15,
                cookies={}
            ) as resp:
                body = await resp.text(errors='ignore')
                body_l = body.lower()
                
                # Heuristic Success Check (overridden by engine's differential check)
                is_success = False
                if resp.status in [200, 201]:
                    success_indicators = ['token', '"success":true', 'access_token', 'jwt', '"authenticated":true']
                    if any(x in body_l for x in success_indicators):
                        is_success = True
                    elif baseline and resp.status != baseline.failed_status:
                        is_success = True
                
                return True, (resp.status, body, dict(resp.headers))
        except Exception as e:
            logger.debug(f"JSON test error at {ep.url}: {e}")
            return False, None

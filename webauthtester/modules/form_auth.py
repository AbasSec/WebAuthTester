import re
import logging
from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
import urllib.parse
from .base import AuthModule
from webauthtester.core.models import AuthEndpoint, AuthBaseline

logger = logging.getLogger(__name__)

class FormAuthModule(AuthModule):
    """Handler for standard HTML form-based authentication."""

    async def fetch_csrf_token(self, ep: AuthEndpoint) -> str:
        """Fetches a fresh CSRF token from the source page."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                'Accept-Encoding': 'identity'
            }
            async with self.session.get(ep.source_page, headers=headers, proxy=self.proxy, timeout=10) as resp:
                body = await resp.text()
                soup = BeautifulSoup(body, 'html.parser')
                # Look for common CSRF input names
                token_tag = soup.find('input', {'name': re.compile(r'csrf|_token|nonce|authenticity_token', re.I)})
                if token_tag:
                    return token_tag.get('value', '')
        except Exception as e:
            logger.debug(f"CSRF acquisition failure at {ep.source_page}: {e}")
        return ''

    async def discover(self, html: str, url: str) -> List[AuthEndpoint]:
        soup = BeautifulSoup(html, 'html.parser')
        endpoints = []
        
        forms = list(soup.find_all('form'))
        # Aggressively look for wrappers
        wrappers = soup.find_all(['div', 'section', 'main'])
        for wrap in wrappers:
            if wrap.find('input', {'type': 'password'}):
                if wrap not in forms:
                    forms.append(wrap)

        for form in forms:
            action = urllib.parse.urljoin(url, form.get('action') or url)
            method = (form.get('method') or 'POST').upper()
            
            u_field, p_field, csrf_field = None, None, None
            inputs = {}
            
            for inp in form.find_all(['input', 'textarea', 'select']):
                # Heuristic: Find the most descriptive identifier
                name = inp.get('name') or inp.get('id') or inp.get('placeholder') or inp.get('aria-label') or inp.get('title')
                if not name: continue
                
                itype = (inp.get('type') or 'text').lower()
                nl = name.lower()
                
                # Expanded keyword matching
                if itype == "password" or any(x in nl for x in ['pass', 'pwd', 'secret', 'mypass']):
                    p_field = name
                elif any(x in nl for x in ['user', 'email', 'login', 'id', 'account', 'member']):
                    u_field = name
                elif any(x in nl for x in ['csrf', 'token', 'nonce', 'authenticity', 'xsrf']):
                    csrf_field = name
                
                inputs[name] = inp.get('value') or ''

            if u_field and p_field:
                extra = {k: v for k, v in inputs.items() if k not in [u_field, p_field]}
                endpoints.append(AuthEndpoint(
                    url=action,
                    auth_type='form_urlencoded',
                    method=method,
                    username_field=u_field,
                    password_field=p_field,
                    extra_fields=extra,
                    source_page=url,
                    csrf_field=csrf_field
                ))
        return endpoints

    async def test(self, ep: AuthEndpoint, u: str, p: str, baseline: Optional[AuthBaseline]) -> Tuple[bool, Optional[Tuple[int, str, dict]]]:
        # Handle CSRF
        extra = ep.extra_fields.copy()
        if ep.csrf_field:
            token = await self.fetch_csrf_token(ep)
            if token:
                extra[ep.csrf_field] = token

        payload = {ep.username_field: u, ep.password_field: p, **extra}
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept-Encoding': 'identity'
        }
        try:
            # Use shared session for connection pooling. 
            # Passing cookies={} ensures we don't send existing session cookies,
            # maintaining isolation between attempts.
            async with self.session.post(
                ep.url, 
                data=payload, 
                headers=headers, 
                proxy=self.proxy, 
                allow_redirects=False, 
                timeout=15,
                cookies={}
            ) as resp:
                body = await resp.text(errors='ignore')
                return True, (resp.status, body, dict(resp.headers))
        except Exception as e:
            logger.debug(f"Error during test at {ep.url}: {e}")
            return False, None

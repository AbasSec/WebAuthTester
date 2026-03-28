import logging
import re
from typing import List, Optional, Tuple
from .base import AuthModule
from webauthtester.core.models import AuthEndpoint, AuthBaseline

logger = logging.getLogger(__name__)

class FirebaseAuthModule(AuthModule):
    """Handler for Firebase Authentication (Google Identity Toolkit API)."""

    async def discover(self, html: str, url: str) -> List[AuthEndpoint]:
        endpoints = []
        
        # Regex to find Firebase API Key in inline scripts or JS files
        # Matches: apiKey: "AIzaSy..." or apiKey:'AIzaSy...'
        match = re.search(r'apiKey\s*:\s*[\'"](AIza[a-zA-Z0-9_\-]+)[\'"]', html)
        if match:
            api_key = match.group(1)
            # The actual Google endpoint for Firebase Email/Password login
            target_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            
            endpoints.append(AuthEndpoint(
                url=target_url,
                auth_type='firebase',
                method='POST',
                username_field='email',
                password_field='password',
                extra_fields={"returnSecureToken": True},
                source_page=url
            ))
            
        return endpoints

    async def test(self, ep: AuthEndpoint, u: str, p: str, baseline: Optional[AuthBaseline]) -> Tuple[bool, Optional[Tuple[int, str, dict]]]:
        payload = {
            ep.username_field: u,
            ep.password_field: p
        }
        if ep.extra_fields:
            payload.update(ep.extra_fields)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Accept-Encoding': 'identity'
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
                
                # Firebase specific success detection
                is_success = False
                if resp.status == 200 and 'idToken' in body:
                    is_success = True
                
                # The BruteEngine handles the final success check, but for Firebase 
                # we can rely on standard baseline diffs too. However, returning 
                # the tuple is enough.
                return True, (resp.status, body, dict(resp.headers))
        except Exception as e:
            logger.debug(f"Firebase test error at {ep.url}: {e}")
            return False, None

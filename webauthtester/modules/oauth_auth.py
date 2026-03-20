from typing import List, Optional, Tuple
from .base import AuthModule
from webauthtester.core.models import AuthEndpoint, AuthBaseline

class OAuthDetectionModule(AuthModule):
    """Module for detecting OAuth2, OIDC, and SAML authentication flows."""

    OAUTH_INDICATORS = [
        '/oauth/authorize', '/connect/authorize', '/login/oauth',
        'response_type=code', 'client_id=', '.well-known/openid-configuration',
        'SAMLRequest', 'saml/login'
    ]

    async def discover(self, html: str, url: str) -> List[AuthEndpoint]:
        endpoints = []
        # Check URL and HTML for indicators
        if any(indicator in url for indicator in self.OAUTH_INDICATORS) or \
           any(indicator in html for indicator in self.OAUTH_INDICATORS):
            
            endpoints.append(AuthEndpoint(
                url=url,
                auth_type='oauth_detected',
                method='GET',
                username_field='N/A',
                password_field='N/A',
                extra_fields={},
                source_page=url,
                is_oauth=True
            ))
        return endpoints

    async def test(self, ep: AuthEndpoint, u: str, p: str, baseline: Optional[AuthBaseline]) -> Tuple[bool, Optional[Tuple[int, str, dict]]]:
        # OAuth brute force is out of scope for this tool's primary engine
        # We just report it as detected.
        return False, None

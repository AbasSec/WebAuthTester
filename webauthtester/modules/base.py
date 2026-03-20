import aiohttp
from typing import List, Optional, Tuple
from abc import ABC, abstractmethod
from webauthtester.core.models import AuthEndpoint, AuthBaseline

class AuthModule(ABC):
    """Abstract Base Class for all Authentication Handlers."""
    
    def __init__(self, session: aiohttp.ClientSession, proxy: str = None):
        self.session = session
        self.proxy = proxy

    @abstractmethod
    async def discover(self, html: str, url: str) -> List[AuthEndpoint]:
        """Identifies relevant endpoints within HTML content."""
        pass

    @abstractmethod
    async def test(self, ep: AuthEndpoint, u: str, p: str, baseline: Optional[AuthBaseline]) -> Tuple[bool, Optional[Tuple[int, str, dict]]]:
        """Executes a single authentication attempt."""
        pass

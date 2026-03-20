import pytest
import aiohttp
import sys
import os

# Add parent directory to sys.path for module discovery
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from webauthtester.core.engine import BruteEngine
from webauthtester.core.models import AuthEndpoint, AuthBaseline
from webauthtester.modules.form_auth import FormAuthModule

@pytest.mark.asyncio
async def test_brute_success_detection_200():
    """Verifies that 200 OK with differential content is detected as success."""
    async with aiohttp.ClientSession() as session:
        engine = BruteEngine(session)
        ep = AuthEndpoint("https://example.com/login", "form_urlencoded", "POST", "user", "pass", {}, "https://example.com")
        
        # Set baseline to something different (e.g., 401)
        engine.baselines[ep.url] = AuthBaseline(
            failed_status=401,
            failed_length=100,
            failed_body_sample="unauthorized"
        )
        
        # Create a mock module and replace it in the engine
        class MockModule:
            def __init__(self, *args, **kwargs): pass
            async def test(self, ep, u, p, baseline):
                return True, (200, "Welcome user! You are logged in. Access Token: 12345", {})
        
        engine.modules['form_urlencoded'] = MockModule()
        
        await engine.test(ep, "admin", "admin")
        
        assert len(engine.results) == 1
        assert engine.results[0][1] == "admin"

@pytest.mark.asyncio
async def test_brute_rate_limit_detection():
    """Verifies that 429 triggers the rate_limited flag."""
    async with aiohttp.ClientSession() as session:
        engine = BruteEngine(session)
        ep = AuthEndpoint("https://example.com/login", "form_urlencoded", "POST", "user", "pass", {}, "https://example.com")
        
        engine.baselines[ep.url] = AuthBaseline(200, 100, "fail")

        class MockModule:
            def __init__(self, *args, **kwargs): pass
            async def test(self, ep, u, p, baseline):
                return True, (429, "Too many requests", {})
        
        engine.modules['form_urlencoded'] = MockModule()
        
        await engine.test(ep, "user", "pass")
        
        assert engine.rate_limited is True

@pytest.mark.asyncio
async def test_discovery_form_extraction():
    """Verifies form extraction logic via FormAuthModule."""
    async with aiohttp.ClientSession() as session:
        module = FormAuthModule(session)
        html = """
        <html>
            <body>
                <form action="/auth" method="POST">
                    <input name="username" type="text">
                    <input name="pwd" type="password">
                    <input name="csrf_token" type="hidden" value="secret123">
                </form>
            </body>
        </html>
        """
        endpoints = await module.discover(html, "https://example.com")
        assert len(endpoints) == 1
        assert endpoints[0].csrf_field == "csrf_token"

@pytest.mark.asyncio
async def test_oauth_detection():
    """Verifies that OAuth endpoints are detected but not brute-forced."""
    async with aiohttp.ClientSession() as session:
        engine = BruteEngine(session)
        ep = AuthEndpoint("https://example.com/oauth/authorize", "oauth_detected", "GET", "N/A", "N/A", {}, "https://example.com", is_oauth=True)
        
        success = await engine.capture_baseline(ep)
        assert success is False
        assert len(engine.findings) == 1
        assert engine.findings[0].title == "OAuth2/SSO Flow Detected"

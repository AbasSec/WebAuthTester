import pytest
import asyncio
import aiohttp
from unittest.mock import AsyncMock, MagicMock
from webauthtester.core.engine import BruteEngine
from webauthtester.core.models import AuthEndpoint, AuthBaseline

@pytest.mark.asyncio
async def test_differential_logic_success():
    """Test that a significant structural difference triggers a success even with 200 OK."""
    session = MagicMock(spec=aiohttp.ClientSession)
    engine = BruteEngine(session)
    
    ep = AuthEndpoint(
        url="http://example.com/login",
        auth_type="form_urlencoded",
        method="POST",
        username_field="user",
        password_field="pass",
        extra_fields={},
        source_page="http://example.com/"
    )
    
    # Setup baseline: a typical failure page
    baseline_body = "<html><body><h1>Login</h1><p>Invalid credentials, please try again.</p></body></html>"
    engine.baselines[ep.url] = AuthBaseline(
        failed_status=200,
        failed_length=len(baseline_body),
        failed_body_sample=baseline_body.lower()
    )
    
    # Mock a response that is significantly different (a dashboard)
    success_body = "<html><body><h1>Dashboard</h1><p>Welcome back, admin! You have 5 new messages.</p><div>User Settings</div></body></html>"
    
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text.return_value = success_body
    mock_resp.headers = {}
    
    # Mock the session.post used by the module
    mock_post_context = AsyncMock()
    mock_post_context.__aenter__.return_value = mock_resp
    session.post.return_value = mock_post_context
    
    await engine.test(ep, "admin", "password123")
    
    assert len(engine.results) == 1
    assert engine.results[0] == (ep.url, "admin", "password123")

@pytest.mark.asyncio
async def test_differential_logic_failure_high_similarity():
    """Test that high similarity results in a failure."""
    session = MagicMock(spec=aiohttp.ClientSession)
    engine = BruteEngine(session)
    
    ep = AuthEndpoint(
        url="http://example.com/login",
        auth_type="form_urlencoded",
        method="POST",
        username_field="user",
        password_field="pass",
        extra_fields={},
        source_page="http://example.com/"
    )
    
    baseline_body = "<html><body><h1>Login</h1><p>Invalid credentials</p></body></html>"
    engine.baselines[ep.url] = AuthBaseline(
        failed_status=200,
        failed_length=len(baseline_body),
        failed_body_sample=baseline_body.lower()
    )
    
    # Very similar body (just a different error message)
    failure_body = "<html><body><h1>Login</h1><p>Wrong username or password</p></body></html>"
    
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text.return_value = failure_body
    mock_resp.headers = {}
    
    mock_post_context = AsyncMock()
    mock_post_context.__aenter__.return_value = mock_resp
    session.post.return_value = mock_post_context
    
    await engine.test(ep, "user", "wrongpass")
    
    assert len(engine.results) == 0

@pytest.mark.asyncio
async def test_differential_logic_failure_indicator():
    """Test that even with structural difference, a failure indicator prevents false positive."""
    session = MagicMock(spec=aiohttp.ClientSession)
    engine = BruteEngine(session)
    
    ep = AuthEndpoint(
        url="http://example.com/login",
        auth_type="form_urlencoded",
        method="POST",
        username_field="user",
        password_field="pass",
        extra_fields={},
        source_page="http://example.com/"
    )
    
    baseline_body = "<html><body><h1>Login</h1><p>Auth Failed</p></body></html>"
    engine.baselines[ep.url] = AuthBaseline(
        failed_status=200,
        failed_length=len(baseline_body),
        failed_body_sample=baseline_body.lower()
    )
    
    # Different structure but contains "incorrect"
    failure_body = "<div><section><h1>Error</h1><p>The password you entered is incorrect.</p></section></div>"
    
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text.return_value = failure_body
    mock_resp.headers = {}
    
    mock_post_context = AsyncMock()
    mock_post_context.__aenter__.return_value = mock_resp
    session.post.return_value = mock_post_context
    
    await engine.test(ep, "user", "wrongpass")
    
    assert len(engine.results) == 0

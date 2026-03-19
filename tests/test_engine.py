"""
Unit tests for the WebAuth core engine.
"""

import pytest
from webauthtester.core.engine import DiscoveryEngine

def test_internal_url_check():
    """Verifies that the crawler correctly identifies internal vs external URLs."""
    engine = DiscoveryEngine(None, "https://example.com")
    
    assert engine._is_internal("https://example.com/login") is True
    assert engine._is_internal("https://other.com/login") is False
    assert engine._is_internal("https://sub.example.com/login") is False  # Strict same-host

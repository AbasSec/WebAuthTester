"""
Unit tests for the WebAuth core engine.
"""

import pytest
import sys
import os

# Ensure the package is in the path for CI
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from webauthtester.core.engine import DiscoveryEngine

def test_internal_url_check():
    """Verifies that the crawler correctly identifies internal vs external URLs."""
    # Pass dummy session and target
    engine = DiscoveryEngine(None, "https://example.com")
    
    assert engine._is_internal("https://example.com/login") is True
    assert engine._is_internal("https://other.com/login") is False

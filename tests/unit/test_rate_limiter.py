"""
tests/unit/test_rate_limiter.py — AI Cyber Shield v6

Tests for the concurrent scan rate limiter (scan_rate_limiter.py).
Focused on the core token-bucket / lock semantics required by Brief 1.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from scan_rate_limiter import ScanRateLimiter, get_limiter


class TestRateLimiterCore:
    """Brief 1 — test_rate_limiter.py requirements (5 tests)."""

    def test_first_request_allowed(self):
        limiter = ScanRateLimiter()
        assert limiter.acquire("https://example.com") is True

    def test_burst_blocked_same_domain(self):
        """Same domain is blocked while a scan is active (per-domain lock)."""
        limiter = ScanRateLimiter()
        limiter.acquire("https://target.com")
        # Second acquire on the same domain must fail
        assert limiter.acquire("https://target.com") is False

    def test_over_limit_is_false(self):
        """Acquiring a locked domain returns False, not an exception."""
        limiter = ScanRateLimiter()
        limiter.acquire("https://a.com")
        result = limiter.acquire("https://a.com")
        assert result is False

    def test_release_allows_reacquire(self):
        """After release, the domain can be acquired again."""
        limiter = ScanRateLimiter()
        limiter.acquire("https://reacquire.com")
        limiter.release("https://reacquire.com")
        assert limiter.acquire("https://reacquire.com") is True

    def test_different_domains_are_independent(self):
        """IP/domain A being locked does not affect domain B."""
        limiter = ScanRateLimiter()
        limiter.acquire("https://a.com")
        # Domain B should be acquirable even though A is locked
        assert limiter.acquire("https://b.com") is True

    def test_singleton_pattern(self):
        """get_limiter() always returns the same instance."""
        get_limiter.cache_clear()
        a = get_limiter()
        b = get_limiter()
        get_limiter.cache_clear()
        assert a is b

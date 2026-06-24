"""
tests/test_scan_rate_limiter.py — AI Cyber Shield v6

Test suite for scan_rate_limiter.py.
"""

from __future__ import annotations

import threading

import pytest

from scan_rate_limiter import (
    ScanRateLimiter,
    _domain_key,
    get_limiter,
)


# ─────────────────────────────────────────────────────────────────────────────
# _domain_key helper
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainKey:
    def test_strips_scheme(self):
        assert _domain_key("https://example.com/path") == "example.com"

    def test_strips_port(self):
        # urlparse puts port in netloc but hostname excludes it
        key = _domain_key("https://example.com:8443/path")
        assert key == "example.com"

    def test_lowercased(self):
        assert _domain_key("HTTPS://EXAMPLE.COM/") == "example.com"

    def test_http_and_https_same_key(self):
        assert _domain_key("http://example.com") == _domain_key("https://example.com")

    def test_different_paths_same_key(self):
        assert _domain_key("https://example.com/page1") == \
               _domain_key("https://example.com/page2")

    def test_different_domains_different_keys(self):
        assert _domain_key("https://a.com") != _domain_key("https://b.com")

    def test_subdomain_different_from_apex(self):
        assert _domain_key("https://sub.example.com") != _domain_key("https://example.com")


# ─────────────────────────────────────────────────────────────────────────────
# ScanRateLimiter core behaviour
# ─────────────────────────────────────────────────────────────────────────────

class TestScanRateLimiter:
    @pytest.fixture
    def limiter(self) -> ScanRateLimiter:
        return ScanRateLimiter()

    # ── acquire ───────────────────────────────────────────────────────────────

    def test_acquire_returns_true_first_time(self, limiter):
        assert limiter.acquire("https://example.com") is True

    def test_acquire_returns_false_if_already_active(self, limiter):
        limiter.acquire("https://example.com")
        assert limiter.acquire("https://example.com") is False

    def test_acquire_different_domains_both_succeed(self, limiter):
        assert limiter.acquire("https://a.com") is True
        assert limiter.acquire("https://b.com") is True

    def test_acquire_http_and_https_same_domain_blocked(self, limiter):
        limiter.acquire("https://example.com")
        # http:// same domain → same key → should be blocked
        assert limiter.acquire("http://example.com") is False

    # ── release ───────────────────────────────────────────────────────────────

    def test_release_allows_reacquire(self, limiter):
        limiter.acquire("https://example.com")
        limiter.release("https://example.com")
        assert limiter.acquire("https://example.com") is True

    def test_release_non_existent_does_not_raise(self, limiter):
        limiter.release("https://notacquired.com")   # must not raise

    def test_double_release_does_not_raise(self, limiter):
        limiter.acquire("https://example.com")
        limiter.release("https://example.com")
        limiter.release("https://example.com")   # second release is a no-op

    # ── is_scanning ───────────────────────────────────────────────────────────

    def test_is_scanning_true_after_acquire(self, limiter):
        limiter.acquire("https://scan.com")
        assert limiter.is_scanning("https://scan.com") is True

    def test_is_scanning_false_before_acquire(self, limiter):
        assert limiter.is_scanning("https://scan.com") is False

    def test_is_scanning_false_after_release(self, limiter):
        limiter.acquire("https://scan.com")
        limiter.release("https://scan.com")
        assert limiter.is_scanning("https://scan.com") is False

    # ── active_count ──────────────────────────────────────────────────────────

    def test_active_count_zero_initially(self, limiter):
        assert limiter.active_count == 0

    def test_active_count_increments(self, limiter):
        limiter.acquire("https://a.com")
        assert limiter.active_count == 1
        limiter.acquire("https://b.com")
        assert limiter.active_count == 2

    def test_active_count_decrements_on_release(self, limiter):
        limiter.acquire("https://a.com")
        limiter.acquire("https://b.com")
        limiter.release("https://a.com")
        assert limiter.active_count == 1

    # ── active_domains ────────────────────────────────────────────────────────

    def test_active_domains_empty_initially(self, limiter):
        assert limiter.active_domains() == []

    def test_active_domains_contains_acquired(self, limiter):
        limiter.acquire("https://example.com")
        assert "example.com" in limiter.active_domains()

    def test_active_domains_excludes_released(self, limiter):
        limiter.acquire("https://example.com")
        limiter.release("https://example.com")
        assert "example.com" not in limiter.active_domains()

    def test_active_domains_is_snapshot(self, limiter):
        """Modifying the returned list must not affect internal state."""
        limiter.acquire("https://a.com")
        snap = limiter.active_domains()
        snap.append("evil.com")
        assert limiter.active_count == 1  # internal state unchanged

    # ── Thread safety ─────────────────────────────────────────────────────────

    def test_thread_safety_concurrent_acquires(self, limiter):
        """Only one thread should succeed in acquiring the same domain."""
        successes: list[bool] = []
        lock = threading.Lock()

        def _try_acquire():
            result = limiter.acquire("https://shared.com")
            with lock:
                successes.append(result)

        threads = [threading.Thread(target=_try_acquire) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert successes.count(True) == 1
        assert successes.count(False) == 19

    def test_thread_safety_acquire_release_cycle(self, limiter):
        """Sequential acquire-release cycles in threads should never corrupt state."""
        errors: list[Exception] = []

        def _cycle():
            try:
                for _ in range(10):
                    acquired = limiter.acquire("https://cycle.com")
                    if acquired:
                        limiter.release("https://cycle.com")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_cycle) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ─────────────────────────────────────────────────────────────────────────────
# get_limiter() singleton tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGetLimiter:
    def test_returns_scan_rate_limiter(self):
        get_limiter.cache_clear()
        limiter = get_limiter()
        get_limiter.cache_clear()
        assert isinstance(limiter, ScanRateLimiter)

    def test_returns_same_instance(self):
        get_limiter.cache_clear()
        a = get_limiter()
        b = get_limiter()
        get_limiter.cache_clear()
        assert a is b

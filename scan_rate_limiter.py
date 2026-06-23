"""
scan_rate_limiter.py — AI Cyber Shield v6

Thread-safe per-domain concurrent scan limiter.

Prevents two simultaneous scans of the same domain from running,
protecting the target from unintentional flooding and protecting
the local process from resource contention.

Usage::

    limiter = get_limiter()

    if not limiter.acquire("https://example.com"):
        raise RuntimeError("Scan already running for this domain")
    try:
        result = run_url_security_audit("https://example.com")
    finally:
        limiter.release("https://example.com")

Public API
──────────
  get_limiter() -> ScanRateLimiter   — module-level singleton
  limiter.acquire(url) -> bool       — True = slot acquired; False = busy
  limiter.release(url) -> None
  limiter.is_scanning(url) -> bool
  limiter.active_count -> int
  limiter.active_domains() -> list[str]
"""

from __future__ import annotations

import logging
import threading
from functools import lru_cache
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _domain_key(url: str) -> str:
    """Normalise URL to bare lowercase hostname for rate-limiting."""
    try:
        hostname = urlparse(url).hostname or url
        return hostname.lower().strip()
    except Exception:
        return url.lower().strip()


class ScanRateLimiter:
    """Thread-safe per-domain scan slot registry."""

    def __init__(self) -> None:
        self._lock            = threading.Lock()
        self._active: set[str] = set()

    # ── Core operations ───────────────────────────────────────────────────────

    def acquire(self, url: str) -> bool:
        """
        Try to acquire a scan slot for the domain of *url*.

        Returns True if the slot was acquired and the caller may proceed.
        Returns False if a scan for that domain is already in progress.
        """
        key = _domain_key(url)
        with self._lock:
            if key in self._active:
                logger.warning("rate_limiter: %r is already being scanned", key)
                return False
            self._active.add(key)
            logger.debug("rate_limiter: acquired slot for %r (%d active)", key, len(self._active))
            return True

    def release(self, url: str) -> None:
        """Release the scan slot for the domain of *url*. Safe to call even if not held."""
        key = _domain_key(url)
        with self._lock:
            self._active.discard(key)
            logger.debug("rate_limiter: released %r (%d remaining)", key, len(self._active))

    def is_scanning(self, url: str) -> bool:
        """Return True if a scan is currently active for the domain of *url*."""
        key = _domain_key(url)
        with self._lock:
            return key in self._active

    # ── Introspection ─────────────────────────────────────────────────────────

    @property
    def active_count(self) -> int:
        """Number of domains currently being scanned."""
        with self._lock:
            return len(self._active)

    def active_domains(self) -> list[str]:
        """Snapshot of all domains currently being scanned."""
        with self._lock:
            return list(self._active)


@lru_cache(maxsize=1)
def get_limiter() -> ScanRateLimiter:
    """Return the module-level singleton ScanRateLimiter."""
    return ScanRateLimiter()

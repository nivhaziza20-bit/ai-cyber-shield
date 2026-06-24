"""
IP-level rate limiting — blocks abuse at network layer before auth check.
Uses Streamlit session identity as proxy for IP (Streamlit Cloud doesn't
expose real IPs, but session_id changes on each browser session).
Limits: 30 requests/minute per session before any auth.
"""
from __future__ import annotations
import time
import logging
from collections import defaultdict, deque
import streamlit as st

_log = logging.getLogger(__name__)

_WINDOW_S = 60          # 1-minute sliding window
_MAX_REQUESTS = 30      # max unauthenticated requests per window
_MAX_SCAN_REQUESTS = 10 # max scan submissions per window per session

# In-memory counters — reset on app restart (acceptable for Streamlit Cloud)
_request_log: dict[str, deque] = defaultdict(deque)


def _session_key() -> str:
    """Use Streamlit's internal session ID as proxy for IP."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        ctx = get_script_run_ctx()
        if ctx:
            return ctx.session_id[:16]
    except Exception:
        pass
    return "unknown"


def _check_rate(bucket: str, max_requests: int, window_s: int) -> bool:
    """
    Returns True if the request is allowed, False if rate limited.
    Slides the window automatically.
    """
    key = f"{_session_key()}:{bucket}"
    now = time.monotonic()
    log = _request_log[key]

    # Remove entries outside the window
    while log and log[0] < now - window_s:
        log.popleft()

    if len(log) >= max_requests:
        return False

    log.append(now)
    return True


def check_page_rate() -> bool:
    """Called on every page load — protects against bot scraping."""
    return _check_rate("page", _MAX_REQUESTS, _WINDOW_S)


def check_scan_rate() -> bool:
    """Called before each scan submission — protects GROQ quota."""
    return _check_rate("scan", _MAX_SCAN_REQUESTS, _WINDOW_S)


def enforce_rate_limit() -> None:
    """Call at top of app. Shows error and stops if rate limited."""
    if not check_page_rate():
        st.error(
            "⚠️ Rate limit exceeded — too many requests from this session. "
            "Please wait a moment and try again."
        )
        st.stop()

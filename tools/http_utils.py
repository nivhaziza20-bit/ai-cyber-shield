"""
Shared HTTP utility for all scanning tools.

Provides:
  safe_get()         — SSRF-guarded GET with per-redirect IP check and 5 MB cap
  stealth_safe_get() — sync wrapper around StealthSession; used as WAF-bypass
                       fallback when safe_get() receives a 403/429/503 block
  _is_waf_response() — lightweight heuristic to detect WAF-blocked responses
"""

import asyncio
import ipaddress
import logging
import re
import socket
import threading
from urllib.parse import urljoin, urlparse

import requests

from config import get_settings

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_REDIRECTS      = 10


# ─────────────────────────────────────────────────────────────────────────────
# Per-thread scan auth context
#
# Allows the authenticated scanning pipeline to inject session cookies and
# headers into every safe_get() call in the current thread without modifying
# tool function signatures.
#
# Usage (in pipeline worker thread):
#   set_scan_auth({"Authorization": "Bearer ..."}, {"session": "abc123"})
#   try:
#       result = tool_func(url)   # safe_get() inside picks up the auth
#   finally:
#       clear_scan_auth()
# ─────────────────────────────────────────────────────────────────────────────

_SCAN_AUTH_LOCAL = threading.local()


def set_scan_auth(headers: dict[str, str], cookies: dict[str, str]) -> None:
    """Set authenticated session state for the calling thread."""
    _SCAN_AUTH_LOCAL.headers = dict(headers)
    _SCAN_AUTH_LOCAL.cookies = dict(cookies)
    _SCAN_AUTH_LOCAL.active  = True


def clear_scan_auth() -> None:
    """Remove auth context from the calling thread."""
    _SCAN_AUTH_LOCAL.active  = False
    _SCAN_AUTH_LOCAL.headers = {}
    _SCAN_AUTH_LOCAL.cookies = {}


def get_scan_auth() -> tuple[dict[str, str], dict[str, str]]:
    """
    Return (headers, cookies) for the current thread's auth context.
    Returns two empty dicts when no auth is active.
    Always returns copies — mutating the returned dicts is safe.
    """
    if not getattr(_SCAN_AUTH_LOCAL, "active", False):
        return {}, {}
    return (
        dict(getattr(_SCAN_AUTH_LOCAL, "headers", {})),
        dict(getattr(_SCAN_AUTH_LOCAL, "cookies", {})),
    )


# ─────────────────────────────────────────────────────────────────────────────
# SSRF guard (IPv4 + IPv6)
# ─────────────────────────────────────────────────────────────────────────────

def is_ssrf_blocked(hostname: str) -> bool:
    """
    Returns True if hostname resolves to a blocked (private/loopback) IP.
    Handles both IPv4 and IPv6.
    """
    import os
    # Allow loopback only inside the accuracy benchmark test suite.
    # AICS_BENCHMARK_MODE=1 is set by benchmark/runner.py — never in production.
    if os.environ.get("AICS_BENCHMARK_MODE") == "1" and hostname in ("127.0.0.1", "::1", "localhost"):
        return False

    settings = get_settings()
    blocked_networks = settings.get_blocked_networks()

    # Additional IPv6 blocked ranges
    _V6_BLOCKED = [
        ipaddress.IPv6Network("::1/128"),           # loopback
        ipaddress.IPv6Network("fc00::/7"),           # unique-local
        ipaddress.IPv6Network("fe80::/10"),          # link-local
        ipaddress.IPv6Network("::ffff:0:0/96"),      # IPv4-mapped
    ]

    try:
        # getaddrinfo returns duplicates per socket type (STREAM/DGRAM/RAW).
        # Deduplicate by IP string so we only check each address once.
        seen_ips: set[str] = set()
        for result in socket.getaddrinfo(hostname, None):
            family, _, _, _, sockaddr = result
            ip_str = sockaddr[0]
            if ip_str in seen_ips:
                continue
            seen_ips.add(ip_str)

            if family == socket.AF_INET:
                ip = ipaddress.IPv4Address(ip_str)
                if any(ip in net for net in blocked_networks):
                    return True

            elif family == socket.AF_INET6:
                ip6 = ipaddress.IPv6Address(ip_str)
                # Check _V6_BLOCKED (includes ::ffff:0:0/96 — IPv4-mapped)
                if any(ip6 in net for net in _V6_BLOCKED):
                    return True
                # Also unwrap IPv4-mapped addresses and check IPv4 blocklist
                if ip6.ipv4_mapped is not None:
                    if any(ip6.ipv4_mapped in net for net in blocked_networks):
                        return True

    except (socket.gaierror, ValueError):
        pass  # Unresolvable — will fail naturally at connect time

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Safe GET
# ─────────────────────────────────────────────────────────────────────────────

class SSRFError(ValueError):
    """Raised when a redirect would send the request to a blocked network."""


def safe_get(
    url: str,
    session: requests.Session | None = None,
    timeout: int = 15,
    max_bytes: int = MAX_RESPONSE_BYTES,
    extra_headers: dict | None = None,
) -> requests.Response:
    """
    Performs an HTTP GET with:
      - SSRF check on every redirect hop
      - Response body limited to max_bytes
      - IPv4 + IPv6 private-range blocking

    Args:
        url:          Target URL (must be http:// or https://)
        session:      Optional pre-configured requests.Session
        timeout:      Per-request timeout in seconds
        max_bytes:    Maximum bytes to read from the response body
        extra_headers: Additional request headers

    Returns:
        requests.Response with `.text` and `.content` populated (up to max_bytes)

    Raises:
        SSRFError:  If any redirect hop resolves to a blocked IP
        ValueError: If the URL scheme is not http/https
        requests.RequestException: Network errors
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http/https URLs are allowed. Got: {parsed.scheme!r}")

    if is_ssrf_blocked(parsed.hostname or ""):
        raise SSRFError(f"SSRF blocked: {parsed.hostname!r} resolves to a private/loopback IP")

    # Merge thread-local scan auth (set by authenticated scanning pipeline).
    # extra_headers takes final precedence so callers can always override.
    auth_headers, auth_cookies = get_scan_auth()

    sess = session or requests.Session()
    if auth_cookies:
        sess.cookies.update(auth_cookies)

    headers = {"User-Agent": "Mozilla/5.0 (SecurityAudit/1.0; Defensive Scanner)"}
    if auth_headers:
        headers.update(auth_headers)
    if extra_headers:
        headers.update(extra_headers)

    current_url = url
    redirects   = 0

    while True:
        resp = sess.get(
            current_url,
            timeout=timeout,
            allow_redirects=False,
            headers=headers,
            stream=True,
        )

        if resp.is_redirect:
            if redirects >= MAX_REDIRECTS:
                break  # Return the redirect response as-is

            location = resp.headers.get("Location", "")
            next_url  = urljoin(current_url, location)
            next_host = urlparse(next_url).hostname or ""

            if is_ssrf_blocked(next_host):
                raise SSRFError(
                    f"SSRF blocked: redirect from {current_url!r} "
                    f"to {next_url!r} points to a private IP"
                )

            current_url = next_url
            redirects  += 1
            continue

        # ── Read body with size cap ───────────────────────────────────────────
        chunks = []
        total  = 0
        for chunk in resp.iter_content(chunk_size=65536):
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break

        content = b"".join(chunks)

        # Patch response so callers can use .text and .content as normal
        resp._content         = content
        resp._content_consumed = True
        resp.encoding = resp.apparent_encoding or "utf-8"

        return resp


# ─────────────────────────────────────────────────────────────────────────────
# WAF detection heuristic
# ─────────────────────────────────────────────────────────────────────────────

# Status codes commonly returned by WAFs when blocking a request
_WAF_STATUS_CODES: frozenset[int] = frozenset({403, 429, 503})

# Header names that are vendor-specific WAF signatures
_WAF_HEADER_HINTS: frozenset[str] = frozenset({
    "cf-ray", "cf-cache-status", "cf-request-id",          # Cloudflare
    "x-akamai-transformed", "akamai-origin-hop",            # Akamai
    "x-iinfo",                                              # Imperva / Incapsula
    "x-amzn-requestid", "x-amzn-waf-action",               # AWS WAF
    "x-datadome", "datadome",                               # DataDome
    "x-sucuri-id",                                          # Sucuri
    "x-barracuda-connect",                                  # Barracuda
})

# Body keywords that indicate a WAF challenge / block page
_WAF_BODY_RE = re.compile(
    r"cloudflare|incapsula|datadome|barracuda|sucuri|"
    r"captcha|hcaptcha|recaptcha|turnstile|"
    r"access denied|request blocked|bot detection|"
    r"cf-chl|__cf_chl|cf_chl_opt",
    re.IGNORECASE,
)


def _is_waf_response(resp: requests.Response) -> bool:
    """
    Returns True when the response looks like a WAF block.

    Requires BOTH a blocking status code AND at least one WAF signal
    (vendor header or body keyword) to minimise false positives on
    legitimate 403/429 responses.
    """
    if resp.status_code not in _WAF_STATUS_CODES:
        return False

    # Check for vendor-specific response headers
    lower_headers = {k.lower() for k in resp.headers}
    if lower_headers & _WAF_HEADER_HINTS:
        return True

    # Inspect first 4 KB of body for WAF keywords
    try:
        body_sample = resp.content[:4096].decode("utf-8", errors="ignore")
    except Exception:
        return False

    return bool(_WAF_BODY_RE.search(body_sample))


# ─────────────────────────────────────────────────────────────────────────────
# Stealth GET — sync wrapper around async StealthSession
# ─────────────────────────────────────────────────────────────────────────────

def stealth_safe_get(
    url:           str,
    timeout:       int  = 15,
    extra_headers: dict | None = None,
    max_bytes:     int  = MAX_RESPONSE_BYTES,
) -> requests.Response | None:
    """
    Synchronous WAF-bypass GET using StealthSession (browser TLS fingerprint,
    random User-Agent profile, optional proxy rotation).

    Designed to be called from ThreadPoolExecutor worker threads when
    safe_get() receives a WAF-blocked response.  Creates its own asyncio
    event loop so it never interferes with the caller's loop.

    Returns a requests.Response-compatible object (same interface as safe_get)
    or None on any failure.  Never raises — failures are logged at DEBUG level.

    SSRF guard is applied before dispatch; raises SSRFError on blocked hosts.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        logger.debug("stealth_safe_get: blocked non-http/https scheme %s", parsed.scheme)
        return None

    hostname = parsed.hostname or ""
    if is_ssrf_blocked(hostname):
        raise SSRFError(
            f"SSRF protection: stealth_safe_get blocked {hostname!r} "
            "(resolves to a private/reserved address)"
        )

    async def _run() -> "StealthResponse":  # type: ignore[name-defined]
        # Lazy import avoids circular dependency:
        # http_utils ← stealth_http_client ← http_utils (module-level)
        from tools.stealth_http_client import StealthSession  # noqa: PLC0415
        async with StealthSession(timeout=float(timeout)) as sess:
            return await sess.get(url, extra_headers=extra_headers)

    try:
        # We may already be inside an event loop (e.g. Jupyter, async test).
        # asyncio.run() raises RuntimeError in that case — use a new thread loop.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # Spawn a fresh OS thread with its own event loop to avoid
            # "This event loop is already running" errors.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(asyncio.run, _run())
                stealth_resp = future.result(timeout=timeout + 5)
        else:
            stealth_resp = asyncio.run(_run())

    except SSRFError:
        raise  # Re-raise SSRF violations — callers must see them
    except Exception as exc:
        logger.debug("stealth_safe_get(%s) failed: %s", url, type(exc).__name__)
        return None

    # ── Convert StealthResponse → requests.Response ───────────────────────────
    # StealthResponse is a dataclass with .status_code, .headers, .text, .cookies
    mock = requests.Response()
    mock.status_code = stealth_resp.status_code
    mock.headers     = requests.structures.CaseInsensitiveDict(stealth_resp.headers)

    encoded = stealth_resp.text.encode("utf-8", errors="replace")
    mock._content          = encoded[:max_bytes]   # enforce OOM cap
    mock._content_consumed = True
    mock.encoding          = "utf-8"

    # Expose WAF detection result as a non-standard attribute for callers that
    # want to know whether stealth also got blocked.
    mock.waf_detection = stealth_resp.waf_detection  # type: ignore[attr-defined]

    logger.debug(
        "stealth_safe_get(%s) → %d (profile=%s waf=%s)",
        url,
        mock.status_code,
        stealth_resp.profile_name,
        stealth_resp.waf_detection is not None,
    )
    return mock

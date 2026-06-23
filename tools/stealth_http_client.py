"""
tools/stealth_http_client.py — AI Cyber Shield v5

Stealth HTTP client with 5-layer WAF evasion for authorised security audits.

AUTHORISATION REQUIREMENT
─────────────────────────
This module is for use exclusively in:
  • Penetration tests with written scope authorisation
  • Security audits of infrastructure you own or operate
  • Authorised red-team and bug-bounty engagements

Using this against systems without explicit written permission is
unlawful and violates Anthropic's usage policy.

Layer 1: Dynamic proxy pool — per-proxy blocklisting, random rotation, jitter
Layer 2: Browser header profiles — Chrome / Safari / Firefox with aligned headers
Layer 3: TLS/JA3/JA4 + HTTP/2 mimicry via curl_cffi; httpx fallback
Layer 4: Cookie jar persistence — WAF clearance cookies survive across requests
Layer 5: WAF / anti-bot detection — structured block payload, graceful degradation
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from tools.http_utils import is_ssrf_blocked

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Optional dependency: curl_cffi provides real browser TLS fingerprints.
# Falls back to httpx when not installed (no TLS mimicry in that mode).
# Install: pip install curl-cffi
# ─────────────────────────────────────────────────────────────────────────────

try:
    from curl_cffi.requests import AsyncSession as _CurlSession  # type: ignore
    _HAS_CURL_CFFI = True
    logger.debug("curl_cffi available — TLS/JA3/JA4 mimicry enabled.")
except ImportError:
    _HAS_CURL_CFFI = False
    logger.info("curl_cffi not installed. Using httpx fallback (no TLS mimicry).")

try:
    import httpx as _httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

if not _HAS_CURL_CFFI and not _HAS_HTTPX:
    raise ImportError(
        "stealth_http_client requires curl_cffi (preferred) or httpx. "
        "pip install curl-cffi"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — Browser profiles
# Each profile encodes a complete, realistic header set for one UA + OS combo.
# Header ORDER is intentionally preserved — HTTP/2 HPACK header tables differ
# between browsers and some fingerprinting systems check ordering.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BrowserProfile:
    name:               str
    user_agent:         str
    accept:             str
    accept_language:    str
    accept_encoding:    str
    sec_ch_ua:          str | None   # None for non-Chromium browsers
    sec_ch_ua_mobile:   str
    sec_ch_ua_platform: str
    sec_fetch_dest:     str
    sec_fetch_mode:     str
    sec_fetch_site:     str
    connection:         str
    upgrade_insecure:   str | None
    curl_impersonate:   str          # curl_cffi BrowserType name


_BROWSER_PROFILES: list[BrowserProfile] = [
    # ── Chrome 124 / Windows 11 ───────────────────────────────────────────────
    BrowserProfile(
        name="Chrome124_Win11",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        connection="keep-alive",
        upgrade_insecure="1",
        curl_impersonate="chrome124",
    ),
    # ── Chrome 120 / macOS ────────────────────────────────────────────────────
    BrowserProfile(
        name="Chrome120_macOS",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"macOS"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        connection="keep-alive",
        upgrade_insecure="1",
        curl_impersonate="chrome120",
    ),
    # ── Safari 17.0 / macOS Sonoma ────────────────────────────────────────────
    BrowserProfile(
        name="Safari17_macOS",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.0 Safari/605.1.15"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua=None,
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        connection="keep-alive",
        upgrade_insecure="1",
        curl_impersonate="safari17_0",
    ),
    # ── Safari 17.2 / iOS 17 (iPhone 15) ─────────────────────────────────────
    BrowserProfile(
        name="Safari17_iOS",
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.2 Mobile/15E148 Safari/604.1"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua=None,
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        connection="keep-alive",
        upgrade_insecure="1",
        curl_impersonate="safari17_2_ios",
    ),
    # ── Firefox 133 / Linux ───────────────────────────────────────────────────
    BrowserProfile(
        name="Firefox133_Linux",
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) "
            "Gecko/20100101 Firefox/133.0"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua=None,
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        connection="keep-alive",
        upgrade_insecure="1",
        curl_impersonate="firefox133",
    ),
    # ── Firefox 120 / Windows ─────────────────────────────────────────────────
    BrowserProfile(
        name="Firefox120_Win",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua=None,
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        connection="keep-alive",
        upgrade_insecure="1",
        curl_impersonate="firefox120",
    ),
]


def _build_headers(
    profile: BrowserProfile,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Assemble headers in the correct order for the given browser profile.
    Header order is significant for HTTP/2 HPACK and some WAF fingerprinters.
    """
    h: dict[str, str] = {}

    if profile.upgrade_insecure:
        h["Upgrade-Insecure-Requests"] = profile.upgrade_insecure

    h["User-Agent"]       = profile.user_agent
    h["Accept"]           = profile.accept

    if profile.sec_ch_ua:
        h["Sec-Ch-Ua"]          = profile.sec_ch_ua
        h["Sec-Ch-Ua-Mobile"]   = profile.sec_ch_ua_mobile
        h["Sec-Ch-Ua-Platform"] = profile.sec_ch_ua_platform

    h["Sec-Fetch-Site"]   = profile.sec_fetch_site
    h["Sec-Fetch-Mode"]   = profile.sec_fetch_mode
    h["Sec-Fetch-Dest"]   = profile.sec_fetch_dest
    h["Accept-Encoding"]  = profile.accept_encoding
    h["Accept-Language"]  = profile.accept_language
    h["Connection"]       = profile.connection

    if extra:
        h.update(extra)

    return h


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — Proxy pool
# ─────────────────────────────────────────────────────────────────────────────

class ProxyPool:
    """
    Asyncio-safe rotating proxy pool with per-proxy TTL blocklisting.

    Accepts any proxy URL form:
      http://user:pass@host:port
      socks5://host:port
      https://host:port

    When all proxies are blocklisted, next_proxy() returns None so the
    caller can attempt a direct (unproxied) connection or raise an error.
    """

    def __init__(self, proxies: list[str], blocklist_ttl: float = 300.0):
        self._proxies       = list(proxies)
        self._blocklist_ttl = blocklist_ttl
        self._blocked: dict[str, float] = {}   # proxy_url → monotonic unblock time
        self._lock = asyncio.Lock()

    @property
    def size(self) -> int:
        return len(self._proxies)

    async def next_proxy(self) -> str | None:
        """Return a random available proxy, or None if pool is empty / all blocked."""
        if not self._proxies:
            return None
        async with self._lock:
            now  = time.monotonic()
            free = [p for p in self._proxies if self._blocked.get(p, 0) <= now]
        if not free:
            logger.warning(
                "All %d proxies are currently blocklisted; falling back to direct.",
                len(self._proxies),
            )
            return None
        return random.choice(free)

    async def block(self, proxy: str, ttl: float | None = None) -> None:
        """Suspend a proxy for `ttl` seconds (default: blocklist_ttl)."""
        if not proxy:
            return
        async with self._lock:
            expire = time.monotonic() + (ttl if ttl is not None else self._blocklist_ttl)
            self._blocked[proxy] = expire
        logger.debug("Proxy %r blocked for %.0fs.", proxy, ttl or self._blocklist_ttl)

    async def available_count(self) -> int:
        """Number of proxies not currently blocklisted."""
        async with self._lock:
            now = time.monotonic()
            return sum(1 for p in self._proxies if self._blocked.get(p, 0) <= now)


# ─────────────────────────────────────────────────────────────────────────────
# Layer 5 — WAF / anti-bot fingerprints
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _WafSignature:
    name:        str
    header_keys: tuple[str, ...]           # any of these in response headers
    body_re:     re.Pattern[str]           # body pattern
    status_set:  frozenset[int]            # triggering HTTP status codes
    mitigation:  str


_WAF_SIGS: list[_WafSignature] = [
    _WafSignature(
        name="Cloudflare",
        header_keys=("cf-ray", "cf-cache-status", "cf-request-id"),
        body_re=re.compile(
            r"cloudflare|cf-error-code|__cf_chl|cf_chl_opt|Turnstile",
            re.IGNORECASE,
        ),
        status_set=frozenset({403, 429, 503}),
        mitigation=(
            "Switch to Headless Browser fallback (Playwright + stealth plugin). "
            "Alternatively use residential proxies with Cloudflare clearance cookie pre-fetch."
        ),
    ),
    _WafSignature(
        name="Akamai",
        header_keys=("x-akamai-transformed", "akamai-origin-hop", "x-check-cacheable"),
        body_re=re.compile(
            r"akamai|Reference\s*#[\d.]+|\bAccessDenied\b",
            re.IGNORECASE,
        ),
        status_set=frozenset({403, 429}),
        mitigation=(
            "Use residential proxy pool; replay Akamai sensor_data cookie "
            "captured from a real browser session."
        ),
    ),
    _WafSignature(
        name="Imperva",
        header_keys=("x-iinfo", "x-cdn"),
        body_re=re.compile(
            r"incapsula|_Incapsula_Resource|visid_incap|incap_ses",
            re.IGNORECASE,
        ),
        status_set=frozenset({403}),
        mitigation=(
            "Obtain Incapsula reese84/visid_incap cookies via headless browser "
            "pre-flight and inject into subsequent requests."
        ),
    ),
    _WafSignature(
        name="AWS_WAF",
        header_keys=("x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"),
        body_re=re.compile(
            r"aws-waf|AWSAccessDenied|Request blocked|x-amzn-waf",
            re.IGNORECASE,
        ),
        status_set=frozenset({403}),
        mitigation=(
            "Rotate IP/ASN via residential proxies. "
            "Check if target uses AWS Managed Rules or custom IP rate-based rules."
        ),
    ),
    _WafSignature(
        name="F5_BIG-IP",
        header_keys=("x-cnection", "ts"),
        body_re=re.compile(
            r"BIG-IP|F5 Networks|The requested URL was rejected",
            re.IGNORECASE,
        ),
        status_set=frozenset({403, 501}),
        mitigation=(
            "F5 uses behavioural fingerprinting; rotate User-Agent, "
            "introduce realistic timing, and switch source ASN."
        ),
    ),
    _WafSignature(
        name="DataDome",
        header_keys=("x-datadome", "datadome"),
        body_re=re.compile(r"datadome|dd_cookie", re.IGNORECASE),
        status_set=frozenset({403, 429}),
        mitigation=(
            "DataDome uses JS device fingerprinting; requires headless browser "
            "with full JS execution and canvas/WebGL spoofing."
        ),
    ),
]

_CHALLENGE_RE = re.compile(
    r"challenge[-_]?form|jschl|cf_chl_opt|Turnstile|recaptcha|hcaptcha|datadome",
    re.IGNORECASE,
)


def _detect_waf(
    status_code: int,
    response_headers: dict[str, str],
    response_body:    str,
) -> dict | None:
    """
    Inspect status, headers, and body for WAF fingerprints.

    Returns a structured block payload dict or None (clean response).
    """
    lower_hdrs = {k.lower(): v for k, v in response_headers.items()}
    body_sample = response_body[:8192]

    # Detect JS challenge type
    challenge_type: str | None = None
    if _CHALLENGE_RE.search(body_sample):
        challenge_type = "js_challenge"
    if re.search(r"Turnstile|turnstile", body_sample):
        challenge_type = "turnstile"
    if re.search(r"recaptcha|hcaptcha", body_sample, re.IGNORECASE):
        challenge_type = "captcha"

    for sig in _WAF_SIGS:
        header_hit = any(h in lower_hdrs for h in sig.header_keys)
        body_hit   = bool(sig.body_re.search(body_sample))
        status_hit = status_code in sig.status_set

        if (header_hit or body_hit) and status_hit:
            return {
                "status":               "blocked_by_waf",
                "waf_type":             sig.name,
                "http_status":          status_code,
                "challenge_type":       challenge_type,
                "mitigation_suggested": sig.mitigation,
            }

    # Generic anti-bot block (403/429 with challenge content or "block" text)
    if status_code in {403, 429} and (
        challenge_type
        or "block" in body_sample.lower()
        or "captcha" in body_sample.lower()
        or "robot" in body_sample.lower()
    ):
        return {
            "status":               "blocked_by_waf",
            "waf_type":             "Unknown",
            "http_status":          status_code,
            "challenge_type":       challenge_type,
            "mitigation_suggested": "Try residential proxy rotation or headless browser fallback.",
        }

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Response and configuration dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class StealthResponse:
    status_code:   int
    headers:       dict[str, str]
    text:          str
    cookies:       dict[str, str]
    proxy_used:    str | None
    profile_name:  str
    response_time: float          # wall-clock seconds
    waf_detection: dict | None    # None = clean; dict = WAF block payload


@dataclass
class JitterConfig:
    enabled:   bool  = True
    min_delay: float = 0.2   # seconds
    max_delay: float = 1.5   # seconds

    async def sleep(self) -> None:
        if self.enabled:
            delay = random.uniform(self.min_delay, self.max_delay)
            logger.debug("Jitter: sleeping %.2fs.", delay)
            await asyncio.sleep(delay)


# ─────────────────────────────────────────────────────────────────────────────
# Main stealth session
# ─────────────────────────────────────────────────────────────────────────────

class StealthSession:
    """
    Async context manager providing a 5-layer WAF-evasive HTTP session.

    Example::

        proxies = ["http://user:pass@p1.example.com:8080",
                   "socks5://p2.example.com:1080"]
        async with StealthSession(proxies=proxies) as sess:
            resp = await sess.get("https://target.example.com/api/v2/users")
            if resp.waf_detection:
                print(resp.waf_detection)  # {"status": "blocked_by_waf", ...}
            else:
                print(resp.status_code, resp.text[:200])

    Parameters
    ----------
    proxies:
        Proxy URL list.  Empty list → direct (no proxy).
    max_retries:
        Additional attempts after a WAF block or proxy error (default 3).
    jitter:
        JitterConfig for inter-request random delays.
    profiles:
        Override the default browser profile list.
    timeout:
        Per-request timeout in seconds (default 15.0).
    verify_ssl:
        Whether to verify TLS certificates (default False —
        WAF inspection nodes often use self-signed certs).
    """

    def __init__(
        self,
        proxies:     list[str] | None     = None,
        max_retries: int                  = 3,
        jitter:      JitterConfig | None  = None,
        profiles:    list[BrowserProfile] | None = None,
        timeout:     float                = 15.0,
        verify_ssl:  bool                 = False,
    ):
        self._pool        = ProxyPool(proxies or [])
        self._max_retries = max_retries
        self._jitter      = jitter or JitterConfig()
        self._profiles    = profiles or _BROWSER_PROFILES
        self._timeout     = timeout
        self._verify_ssl  = verify_ssl
        self._cookie_jar: dict[str, str] = {}   # Layer 4 — persistent cookies

        self._curl_session:  Any | None = None
        self._httpx_client:  Any | None = None

    async def __aenter__(self) -> StealthSession:
        if _HAS_CURL_CFFI:
            # curl_cffi manages its own TLS + H2 connection pool per session.
            # We don't pin an impersonate here — it's chosen per-request.
            self._curl_session = _CurlSession()
        elif _HAS_HTTPX:
            self._httpx_client = _httpx.AsyncClient(
                verify=self._verify_ssl,
                timeout=self._timeout,
                follow_redirects=True,
            )
        return self

    async def __aexit__(self, *_) -> None:
        if self._curl_session is not None:
            try:
                await self._curl_session.close()
            except Exception:
                pass
            self._curl_session = None
        if self._httpx_client is not None:
            try:
                await self._httpx_client.aclose()
            except Exception:
                pass
            self._httpx_client = None

    # ── Public API ─────────────────────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> StealthResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> StealthResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> StealthResponse:
        return await self.request("HEAD", url, **kwargs)

    async def request(
        self,
        method:        str,
        url:           str,
        extra_headers: dict[str, str] | None = None,
        **kwargs,
    ) -> StealthResponse:
        """
        Dispatch method/url through the full evasion stack.

        On each attempt:
          1. Pick a random available proxy from the pool.
          2. Pick a random browser profile.
          3. Apply jitter delay.
          4. Build aligned header graph.
          5. Inject persisted cookies (Layer 4).
          6. Dispatch via curl_cffi (TLS mimicry) or httpx (fallback).
          7. Merge returned cookies back into jar.
          8. Run WAF detection on response.
          9. On block: blocklist proxy, retry up to max_retries.
         10. If all retries exhausted by WAF blocks: return last waf_detection.
         11. If all retries exhausted by exceptions: raise RuntimeError.

        Never raises on WAF blocks — returns StealthResponse.waf_detection payload.
        Raises PermissionError immediately on SSRF-protected addresses.
        """
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""

        if is_ssrf_blocked(hostname):
            raise PermissionError(
                f"SSRF protection: {hostname!r} is a private or reserved address. "
                "Scanning internal infrastructure is not permitted."
            )

        last_exc:  Exception | None = None
        last_resp: StealthResponse | None = None

        for attempt in range(self._max_retries + 1):
            proxy   = await self._pool.next_proxy()
            profile = random.choice(self._profiles)
            headers = _build_headers(profile, extra_headers)

            # Layer 4: inject persisted session cookies
            if self._cookie_jar:
                headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in self._cookie_jar.items()
                )

            await self._jitter.sleep()
            t0 = time.monotonic()

            try:
                if _HAS_CURL_CFFI and self._curl_session is not None:
                    raw = await self._dispatch_curl(
                        method, url, headers, proxy, profile, **kwargs
                    )
                else:
                    raw = await self._dispatch_httpx(
                        method, url, headers, proxy, **kwargs
                    )
            except Exception as exc:
                logger.warning(
                    "Attempt %d/%d for %s failed (proxy=%r): %s",
                    attempt + 1, self._max_retries + 1, url, proxy, exc,
                )
                last_exc = exc
                if proxy:
                    await self._pool.block(proxy)
                continue

            elapsed = time.monotonic() - t0

            # Layer 4: merge returned cookies into jar for future requests
            self._cookie_jar.update(raw["cookies"])

            # Layer 5: WAF / anti-bot detection
            waf = _detect_waf(raw["status_code"], raw["headers"], raw["text"])

            resp = StealthResponse(
                status_code  = raw["status_code"],
                headers      = raw["headers"],
                text         = raw["text"],
                cookies      = raw["cookies"],
                proxy_used   = proxy,
                profile_name = profile.name,
                response_time= elapsed,
                waf_detection= waf,
            )
            last_resp = resp

            if waf:
                logger.warning(
                    "WAF block detected attempt %d/%d: waf=%s proxy=%r",
                    attempt + 1, self._max_retries + 1, waf["waf_type"], proxy,
                )
                if proxy:
                    # Shorter TTL for WAF blocks vs. network errors
                    await self._pool.block(proxy, ttl=60.0)
                if attempt < self._max_retries:
                    continue
                return resp  # all retries exhausted — return the WAF payload

            return resp  # clean success

        # All attempts exhausted
        if last_resp is not None:
            # Last response was a WAF block
            return last_resp
        raise RuntimeError(
            f"All {self._max_retries + 1} attempts to {url} failed. "
            f"Last error: {last_exc}"
        ) from last_exc

    # ── Layer 3: curl_cffi dispatch (TLS/JA3/JA4 + HTTP/2 mimicry) ────────────

    async def _dispatch_curl(
        self,
        method:  str,
        url:     str,
        headers: dict[str, str],
        proxy:   str | None,
        profile: BrowserProfile,
        **kwargs,
    ) -> dict:
        """
        curl_cffi impersonation provides a matching TLS Client Hello
        (cipher suites, extensions, elliptic curves) and HTTP/2 SETTINGS
        frame (HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE, MAX_CONCURRENT_STREAMS)
        for the chosen browser profile.  This defeats JA3/JA4 fingerprinting.
        """
        proxies: dict[str, str] = {}
        if proxy:
            proxies["https"] = proxy
            proxies["http"]  = proxy

        resp = await self._curl_session.request(
            method         = method,
            url            = url,
            headers        = headers,
            proxies        = proxies or None,
            impersonate    = profile.curl_impersonate,
            timeout        = self._timeout,
            verify         = self._verify_ssl,
            allow_redirects= True,
            **{k: v for k, v in kwargs.items()
               if k not in ("proxies", "impersonate", "verify", "allow_redirects")},
        )
        return {
            "status_code": resp.status_code,
            "headers":     dict(resp.headers),
            "text":        resp.text,
            "cookies":     {k: v for k, v in resp.cookies.items()},
        }

    # ── Layer 3 fallback: httpx (no TLS mimicry) ───────────────────────────────

    async def _dispatch_httpx(
        self,
        method:  str,
        url:     str,
        headers: dict[str, str],
        proxy:   str | None,
        **kwargs,
    ) -> dict:
        """
        httpx fallback — header spoofing and proxy rotation still apply,
        but the TLS fingerprint is standard OpenSSL, not a browser JA3/JA4.
        Sufficient against basic WAFs; advanced fingerprinters may catch it.
        """
        client_kwargs: dict = {
            "verify":           self._verify_ssl,
            "timeout":          self._timeout,
            "follow_redirects": True,
        }
        if proxy:
            # httpx proxy dict form — compatible with 0.24+ through 0.27+
            client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

        async with _httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.request(method, url, headers=headers, **kwargs)

        return {
            "status_code": resp.status_code,
            "headers":     dict(resp.headers),
            "text":        resp.text,
            "cookies":     {k: v for k, v in resp.cookies.items()},
        }


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

def build_stealth_session(
    proxies:     list[str] | None = None,
    max_retries: int               = 3,
    jitter_min:  float             = 0.2,
    jitter_max:  float             = 1.5,
    timeout:     float             = 15.0,
    verify_ssl:  bool              = False,
) -> StealthSession:
    """
    Convenience factory for the most common configuration.

    Usage::

        async with build_stealth_session(proxies=["http://p1:8080"]) as sess:
            resp = await sess.get("https://target.example.com")
    """
    return StealthSession(
        proxies     = proxies,
        max_retries = max_retries,
        jitter      = JitterConfig(
            enabled   = True,
            min_delay = jitter_min,
            max_delay = jitter_max,
        ),
        timeout    = timeout,
        verify_ssl = verify_ssl,
    )

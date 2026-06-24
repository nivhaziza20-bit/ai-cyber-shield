"""
Tests for tools/stealth_http_client.py

Structure
─────────
  TestProxyPool          — rotation, blocklisting, TTL, empty pool
  TestJitterConfig       — disabled/enabled sleep behaviour
  TestBrowserProfiles    — profile completeness, header alignment
  TestBuildHeaders       — Chrome Sec-CH-UA, Safari omissions, extra headers
  TestWafDetection       — per-WAF fingerprints, challenge types, clean pass
  TestStealthSession     — SSRF guard, success, cookie jar, retry, graceful
  TestBuildStealthSession— factory helper produces correct config

All network calls are mocked via patch.object on the internal dispatch
methods (_dispatch_curl / _dispatch_httpx) so no real HTTP is ever made.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.stealth_http_client import (
    BrowserProfile,
    JitterConfig,
    ProxyPool,
    StealthResponse,
    StealthSession,
    _BROWSER_PROFILES,
    _build_headers,
    _detect_waf,
    build_stealth_session,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _raw(status: int = 200, hdrs: dict | None = None,
         text: str = "<html>OK</html>", cookies: dict | None = None) -> dict:
    return {
        "status_code": status,
        "headers":     hdrs or {"content-type": "text/html; charset=utf-8"},
        "text":        text,
        "cookies":     cookies or {},
    }


_NO_JITTER = JitterConfig(enabled=False)


def _make_session(**kwargs) -> StealthSession:
    """Build a StealthSession with jitter disabled for fast tests."""
    return StealthSession(jitter=_NO_JITTER, **kwargs)


# Patch target when testing through httpx path (curl_cffi unavailable)
_PATCH_CURL = "tools.stealth_http_client._HAS_CURL_CFFI"
_PATCH_SSRF = "tools.stealth_http_client.is_ssrf_blocked"


# ─────────────────────────────────────────────────────────────────────────────
# ProxyPool
# ─────────────────────────────────────────────────────────────────────────────

class TestProxyPool:
    @pytest.mark.asyncio
    async def test_empty_pool_returns_none(self):
        pool = ProxyPool([])
        assert await pool.next_proxy() is None

    @pytest.mark.asyncio
    async def test_single_proxy_always_returned(self):
        pool = ProxyPool(["http://p1:8080"])
        for _ in range(5):
            assert await pool.next_proxy() == "http://p1:8080"

    @pytest.mark.asyncio
    async def test_blocked_proxy_not_returned(self):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080"])
        await pool.block("http://p1:8080", ttl=9999)
        for _ in range(20):
            assert await pool.next_proxy() == "http://p2:8080"

    @pytest.mark.asyncio
    async def test_all_blocked_returns_none(self):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080"])
        await pool.block("http://p1:8080", ttl=9999)
        await pool.block("http://p2:8080", ttl=9999)
        assert await pool.next_proxy() is None

    @pytest.mark.asyncio
    async def test_block_with_short_ttl_expires(self):
        pool = ProxyPool(["http://p1:8080"])
        await pool.block("http://p1:8080", ttl=0.0)   # expires immediately
        await asyncio.sleep(0.01)
        assert await pool.next_proxy() == "http://p1:8080"

    @pytest.mark.asyncio
    async def test_available_count_decrements_on_block(self):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080", "http://p3:8080"])
        assert await pool.available_count() == 3
        await pool.block("http://p1:8080", ttl=9999)
        assert await pool.available_count() == 2

    @pytest.mark.asyncio
    async def test_block_nonexistent_proxy_no_crash(self):
        pool = ProxyPool(["http://p1:8080"])
        await pool.block("http://ghost:9999")   # not in pool — should not raise

    @pytest.mark.asyncio
    async def test_size_property(self):
        pool = ProxyPool(["http://a:1", "http://b:2"])
        assert pool.size == 2

    @pytest.mark.asyncio
    async def test_block_empty_string_no_crash(self):
        pool = ProxyPool(["http://p1:8080"])
        await pool.block("")   # gracefully ignored


# ─────────────────────────────────────────────────────────────────────────────
# JitterConfig
# ─────────────────────────────────────────────────────────────────────────────

class TestJitterConfig:
    @pytest.mark.asyncio
    async def test_disabled_does_not_sleep(self):
        jitter = JitterConfig(enabled=False)
        t0 = time.monotonic()
        await jitter.sleep()
        assert time.monotonic() - t0 < 0.05   # no sleep

    @pytest.mark.asyncio
    async def test_enabled_sleeps_within_configured_range(self):
        with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
            jitter = JitterConfig(enabled=True, min_delay=0.3, max_delay=0.4)
            await jitter.sleep()
        mock_sleep.assert_called_once()
        delay = mock_sleep.call_args[0][0]
        assert 0.3 <= delay <= 0.4

    @pytest.mark.asyncio
    async def test_zero_range_sleeps_exactly_that_value(self):
        with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
            jitter = JitterConfig(enabled=True, min_delay=0.5, max_delay=0.5)
            await jitter.sleep()
        delay = mock_sleep.call_args[0][0]
        assert abs(delay - 0.5) < 1e-9


# ─────────────────────────────────────────────────────────────────────────────
# Browser profiles completeness
# ─────────────────────────────────────────────────────────────────────────────

class TestBrowserProfiles:
    def test_at_least_six_profiles_defined(self):
        assert len(_BROWSER_PROFILES) >= 6

    def test_all_profiles_have_name(self):
        for p in _BROWSER_PROFILES:
            assert p.name, f"Profile missing name: {p}"

    def test_all_profiles_have_user_agent(self):
        for p in _BROWSER_PROFILES:
            assert "Mozilla" in p.user_agent, f"Unexpected UA in {p.name}"

    def test_all_profiles_have_curl_impersonate_string(self):
        for p in _BROWSER_PROFILES:
            assert p.curl_impersonate, f"Missing curl_impersonate in {p.name}"

    def test_chrome_profiles_have_sec_ch_ua(self):
        chrome = [p for p in _BROWSER_PROFILES if "Chrome" in p.name]
        assert chrome, "No Chrome profiles found"
        for p in chrome:
            assert p.sec_ch_ua is not None, f"{p.name} is missing Sec-CH-UA"

    def test_safari_profiles_have_no_sec_ch_ua(self):
        safari = [p for p in _BROWSER_PROFILES if "Safari" in p.name]
        assert safari, "No Safari profiles found"
        for p in safari:
            assert p.sec_ch_ua is None, f"{p.name} should not have Sec-CH-UA"

    def test_firefox_profiles_have_no_sec_ch_ua(self):
        firefox = [p for p in _BROWSER_PROFILES if "Firefox" in p.name]
        assert firefox, "No Firefox profiles found"
        for p in firefox:
            assert p.sec_ch_ua is None, f"{p.name} should not have Sec-CH-UA"

    def test_all_profiles_have_accept_language(self):
        for p in _BROWSER_PROFILES:
            assert "en" in p.accept_language.lower()


# ─────────────────────────────────────────────────────────────────────────────
# _build_headers
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildHeaders:
    def _chrome_profile(self) -> BrowserProfile:
        return next(p for p in _BROWSER_PROFILES if "Chrome" in p.name)

    def _safari_profile(self) -> BrowserProfile:
        return next(p for p in _BROWSER_PROFILES if "Safari" in p.name)

    def test_user_agent_present(self):
        headers = _build_headers(self._chrome_profile())
        assert "User-Agent" in headers

    def test_chrome_headers_include_sec_ch_ua(self):
        headers = _build_headers(self._chrome_profile())
        assert "Sec-Ch-Ua" in headers
        assert "Sec-Ch-Ua-Mobile" in headers
        assert "Sec-Ch-Ua-Platform" in headers

    def test_safari_headers_omit_sec_ch_ua(self):
        headers = _build_headers(self._safari_profile())
        assert "Sec-Ch-Ua" not in headers
        assert "Sec-Ch-Ua-Mobile" not in headers

    def test_sec_fetch_headers_present_in_chrome(self):
        headers = _build_headers(self._chrome_profile())
        assert "Sec-Fetch-Site" in headers
        assert "Sec-Fetch-Mode" in headers
        assert "Sec-Fetch-Dest" in headers

    def test_extra_headers_merged(self):
        extra = {"X-Custom-Test": "hello"}
        headers = _build_headers(self._chrome_profile(), extra)
        assert headers["X-Custom-Test"] == "hello"

    def test_extra_headers_can_override(self):
        extra = {"User-Agent": "CustomBot/1.0"}
        headers = _build_headers(self._chrome_profile(), extra)
        assert headers["User-Agent"] == "CustomBot/1.0"

    def test_accept_encoding_present(self):
        headers = _build_headers(self._chrome_profile())
        assert "Accept-Encoding" in headers
        assert "gzip" in headers["Accept-Encoding"]

    def test_connection_header_present(self):
        headers = _build_headers(self._chrome_profile())
        assert "Connection" in headers


# ─────────────────────────────────────────────────────────────────────────────
# _detect_waf
# ─────────────────────────────────────────────────────────────────────────────

class TestWafDetection:
    def test_clean_200_returns_none(self):
        waf = _detect_waf(200, {"content-type": "text/html"}, "<html>OK</html>")
        assert waf is None

    def test_cloudflare_detected_via_header_403(self):
        waf = _detect_waf(403, {"cf-ray": "abc123def"}, "Error")
        assert waf is not None
        assert waf["waf_type"] == "Cloudflare"
        assert waf["status"] == "blocked_by_waf"

    def test_cloudflare_detected_via_header_429(self):
        waf = _detect_waf(429, {"cf-ray": "x"}, "rate limited")
        assert waf is not None
        assert waf["waf_type"] == "Cloudflare"

    def test_cloudflare_detected_via_body(self):
        waf = _detect_waf(503, {}, "This site is protected by cloudflare error code")
        assert waf is not None
        assert waf["waf_type"] == "Cloudflare"

    def test_akamai_detected_via_header(self):
        waf = _detect_waf(403, {"x-akamai-transformed": "1"}, "AccessDenied")
        assert waf is not None
        assert waf["waf_type"] == "Akamai"

    def test_imperva_detected_via_body(self):
        waf = _detect_waf(403, {}, "incapsula block page _Incapsula_Resource")
        assert waf is not None
        assert waf["waf_type"] == "Imperva"

    def test_aws_waf_detected_via_header_and_body(self):
        waf = _detect_waf(403, {"x-amzn-requestid": "abc"}, "AWSAccessDenied")
        assert waf is not None
        assert waf["waf_type"] == "AWS_WAF"

    def test_datadome_detected_via_header(self):
        waf = _detect_waf(403, {"x-datadome": "blocked"}, "")
        assert waf is not None
        assert waf["waf_type"] == "DataDome"

    def test_challenge_type_turnstile_detected(self):
        waf = _detect_waf(403, {"cf-ray": "x"}, "Cloudflare Turnstile challenge")
        assert waf is not None
        assert waf["challenge_type"] == "turnstile"

    def test_challenge_type_captcha_detected(self):
        waf = _detect_waf(403, {"cf-ray": "x"}, "Please solve this recaptcha")
        assert waf is not None
        assert waf["challenge_type"] == "captcha"

    def test_generic_403_with_block_keyword(self):
        waf = _detect_waf(403, {}, "Your request has been blocked by our security policy.")
        assert waf is not None
        assert waf["waf_type"] == "Unknown"

    def test_403_without_waf_signals_returns_none(self):
        waf = _detect_waf(403, {}, "Forbidden — authentication required.")
        assert waf is None

    def test_mitigation_field_always_present(self):
        waf = _detect_waf(403, {"cf-ray": "x"}, "")
        assert waf is not None
        assert "mitigation_suggested" in waf
        assert len(waf["mitigation_suggested"]) > 10

    def test_cloudflare_200_with_cf_ray_not_flagged(self):
        # A 200 response with cf-ray is normal CDN usage — not a block
        waf = _detect_waf(200, {"cf-ray": "abc123", "content-type": "text/html"}, "Hello World")
        assert waf is None


# ─────────────────────────────────────────────────────────────────────────────
# StealthSession
# ─────────────────────────────────────────────────────────────────────────────

class TestStealthSession:
    """
    All tests mock _dispatch_httpx (curl_cffi path patched to False).
    The mock replaces the unbound method on the class, so it is called
    with the same positional args the real method would receive.
    """

    async def _invoke(
        self,
        session:  StealthSession,
        dispatch_mock,
        url: str = "https://example.com",
    ) -> StealthResponse:
        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx", new=dispatch_mock):
            async with session as sess:
                return await sess.get(url)

    @pytest.mark.asyncio
    async def test_ssrf_blocked_raises_permission_error(self):
        async with _make_session() as sess:
            with patch(_PATCH_SSRF, return_value=True):
                with pytest.raises(PermissionError):
                    await sess.get("https://127.0.0.1/admin")

    @pytest.mark.asyncio
    async def test_successful_request_returns_200(self):
        mock = AsyncMock(return_value=_raw(200, text="Hello World"))
        resp = await self._invoke(_make_session(), mock)
        assert resp.status_code == 200
        assert resp.text == "Hello World"
        assert resp.waf_detection is None

    @pytest.mark.asyncio
    async def test_profile_name_in_response(self):
        mock = AsyncMock(return_value=_raw())
        resp = await self._invoke(_make_session(), mock)
        assert resp.profile_name in {p.name for p in _BROWSER_PROFILES}

    @pytest.mark.asyncio
    async def test_response_time_is_positive_float(self):
        mock = AsyncMock(return_value=_raw())
        resp = await self._invoke(_make_session(), mock)
        assert resp.response_time >= 0.0

    @pytest.mark.asyncio
    async def test_cookie_jar_populated_from_response(self):
        mock = AsyncMock(return_value=_raw(cookies={"sessionid": "abc123"}))
        session = _make_session()
        await self._invoke(session, mock)
        # After the request, the jar should hold the returned cookie
        assert session._cookie_jar.get("sessionid") == "abc123"

    @pytest.mark.asyncio
    async def test_cookies_injected_in_subsequent_request(self):
        received_headers: list[dict] = []

        async def capture_dispatch(method, url, headers, proxy, **kwargs):
            received_headers.append(dict(headers))
            call_n = len(received_headers)
            return _raw(cookies={"sess": "tok999"} if call_n == 1 else {})

        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=capture_dispatch)):
            async with _make_session() as sess:
                await sess.get("https://example.com")   # sets cookie
                await sess.get("https://example.com")   # should send cookie

        # Second request must contain Cookie header with "sess=tok999"
        assert len(received_headers) == 2
        cookie_hdr = received_headers[1].get("Cookie", "")
        assert "sess=tok999" in cookie_hdr

    @pytest.mark.asyncio
    async def test_cloudflare_block_returns_waf_payload(self):
        cf_response = _raw(
            status=403,
            hdrs={"cf-ray": "xyz", "content-type": "text/html"},
            text="Cloudflare block page.",
        )
        mock = AsyncMock(return_value=cf_response)
        resp = await self._invoke(_make_session(max_retries=0), mock)
        assert resp.waf_detection is not None
        assert resp.waf_detection["status"] == "blocked_by_waf"
        assert resp.waf_detection["waf_type"] == "Cloudflare"

    @pytest.mark.asyncio
    async def test_waf_block_retried_up_to_max_retries(self):
        """WAF block on each attempt → exactly max_retries+1 dispatch calls."""
        call_count = 0

        async def always_waf(method, url, headers, proxy, **kwargs):
            nonlocal call_count
            call_count += 1
            return _raw(403, {"cf-ray": "x"}, "Cloudflare error.")

        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=always_waf)):
            async with _make_session(max_retries=3) as sess:
                resp = await sess.get("https://example.com")

        assert call_count == 4   # initial + 3 retries
        assert resp.waf_detection is not None

    @pytest.mark.asyncio
    async def test_retry_succeeds_after_proxy_rotation(self):
        """First attempt returns 429 (CF block), second returns 200."""
        calls = 0

        async def rotating_response(method, url, headers, proxy, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return _raw(429, {"cf-ray": "x"}, "Too many requests")
            return _raw(200, text="Success after retry")

        proxies = ["http://proxy1:8080", "http://proxy2:8080"]
        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=rotating_response)):
            async with _make_session(proxies=proxies, max_retries=3) as sess:
                resp = await sess.get("https://example.com")

        assert resp.status_code == 200
        assert resp.waf_detection is None
        assert calls == 2

    @pytest.mark.asyncio
    async def test_proxy_blocked_after_exception(self):
        """Dispatch exception → proxy should be blocklisted after the attempt."""
        async def raise_error(method, url, headers, proxy, **kwargs):
            raise ConnectionError("Refused")

        proxies = ["http://proxy1:8080"]
        session = _make_session(proxies=proxies, max_retries=0)

        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=raise_error)):
            with pytest.raises(RuntimeError):
                async with session as sess:
                    await sess.get("https://example.com")

        # After the exception, the proxy should be blocklisted
        assert await session._pool.available_count() == 0

    @pytest.mark.asyncio
    async def test_all_exceptions_exhaust_retries_raises_runtime_error(self):
        async def fail(method, url, headers, proxy, **kwargs):
            raise OSError("Timeout")

        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=fail)):
            with pytest.raises(RuntimeError, match="attempts"):
                async with _make_session(max_retries=2) as sess:
                    await sess.get("https://example.com")

    @pytest.mark.asyncio
    async def test_no_proxy_mode_still_works(self):
        """Empty proxy list → proxy_used is None but request succeeds."""
        mock = AsyncMock(return_value=_raw(200, text="Direct connection"))
        resp = await self._invoke(_make_session(proxies=[]), mock)
        assert resp.status_code == 200
        assert resp.proxy_used is None

    @pytest.mark.asyncio
    async def test_head_method_dispatched(self):
        calls: list[str] = []

        async def capture(method, url, headers, proxy, **kwargs):
            calls.append(method)
            return _raw()

        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=capture)):
            async with _make_session() as sess:
                await sess.head("https://example.com")

        assert calls[0] == "HEAD"

    @pytest.mark.asyncio
    async def test_post_method_dispatched(self):
        calls: list[str] = []

        async def capture(method, url, headers, proxy, **kwargs):
            calls.append(method)
            return _raw()

        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=capture)):
            async with _make_session() as sess:
                await sess.post("https://example.com")

        assert calls[0] == "POST"

    @pytest.mark.asyncio
    async def test_extra_headers_passed_through(self):
        received: list[dict] = []

        async def capture(method, url, headers, proxy, **kwargs):
            received.append(dict(headers))
            return _raw()

        with patch(_PATCH_CURL, False), \
             patch(_PATCH_SSRF, return_value=False), \
             patch.object(StealthSession, "_dispatch_httpx",
                          new=AsyncMock(side_effect=capture)):
            async with _make_session() as sess:
                await sess.request(
                    "GET", "https://example.com",
                    extra_headers={"X-Scan-Token": "secret"},
                )

        assert received[0].get("X-Scan-Token") == "secret"

    @pytest.mark.asyncio
    async def test_context_manager_cleans_up_httpx_client(self):
        """Ensure __aexit__ closes httpx client without raising."""
        with patch(_PATCH_CURL, False), patch(_PATCH_SSRF, return_value=False):
            sess = _make_session()
            async with sess:
                pass   # don't even make a request
            assert sess._httpx_client is None


# ─────────────────────────────────────────────────────────────────────────────
# build_stealth_session factory
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildStealthSession:
    def test_returns_stealth_session_instance(self):
        s = build_stealth_session()
        assert isinstance(s, StealthSession)

    def test_proxy_list_forwarded(self):
        proxies = ["http://p1:8080", "http://p2:8080"]
        s = build_stealth_session(proxies=proxies)
        assert s._pool.size == 2

    def test_max_retries_forwarded(self):
        s = build_stealth_session(max_retries=5)
        assert s._max_retries == 5

    def test_jitter_min_max_forwarded(self):
        s = build_stealth_session(jitter_min=0.1, jitter_max=0.5)
        assert s._jitter.min_delay == 0.1
        assert s._jitter.max_delay == 0.5

    def test_timeout_forwarded(self):
        s = build_stealth_session(timeout=30.0)
        assert s._timeout == 30.0

    def test_default_jitter_enabled(self):
        s = build_stealth_session()
        assert s._jitter.enabled is True

    def test_empty_proxies_creates_empty_pool(self):
        s = build_stealth_session(proxies=[])
        assert s._pool.size == 0

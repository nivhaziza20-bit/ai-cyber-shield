"""
tests/test_stealth_integration.py

Unit and integration tests for the Stealth HTTP client pipeline integration:
  - _is_waf_response()   — WAF heuristic detection
  - stealth_safe_get()   — sync wrapper around async StealthSession
  - passive_recon._safe_get() stealth fallback
  - waf_detector.detect_waf() stealth upgrade path

All StealthSession and outbound network calls are mocked; no real HTTP.
"""
from __future__ import annotations

import asyncio
import json
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import requests
import requests.structures

# ─────────────────────────────────────────────────────────────────────────────
# Helpers — build fake responses
# ─────────────────────────────────────────────────────────────────────────────

def _make_response(
    status: int = 200,
    headers: dict | None = None,
    body: str = "OK",
    url: str = "https://example.com/",
) -> requests.Response:
    r = requests.Response()
    r.status_code = status
    r.headers = requests.structures.CaseInsensitiveDict(headers or {})
    r._content = body.encode("utf-8")
    r._content_consumed = True
    r.encoding = "utf-8"
    r.url = url
    return r


def _make_stealth_response(
    status: int = 200,
    headers: dict | None = None,
    text: str = "OK",
    profile_name: str = "Chrome124_Win11",
    waf_detection: dict | None = None,
) -> MagicMock:
    """Create a StealthResponse-like mock."""
    m = MagicMock()
    m.status_code  = status
    m.headers      = headers or {}
    m.text         = text
    m.cookies      = {}
    m.proxy_used   = None
    m.profile_name = profile_name
    m.response_time = 0.1
    m.waf_detection = waf_detection
    return m


# ─────────────────────────────────────────────────────────────────────────────
# 1. _is_waf_response unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIsWafResponse(unittest.TestCase):

    def _get(self, status, headers=None, body=""):
        from tools.http_utils import _is_waf_response
        return _is_waf_response(_make_response(status, headers, body))

    # ── Status code alone is NOT enough ──────────────────────────────────────

    def test_200_not_waf(self):
        self.assertFalse(self._get(200, {"cf-ray": "abc"}, "cloudflare"))

    def test_404_not_waf(self):
        self.assertFalse(self._get(404, {"cf-ray": "abc"}, "cloudflare"))

    def test_403_clean_no_waf(self):
        # 403 with no WAF header and no WAF body → legitimate 403
        self.assertFalse(self._get(403, {}, "Forbidden — you don't have permission"))

    # ── Status + WAF header ───────────────────────────────────────────────────

    def test_403_cloudflare_header(self):
        self.assertTrue(self._get(403, {"cf-ray": "7a1b2c3d4e5f6a7b-LHR"}))

    def test_429_cloudflare_header(self):
        self.assertTrue(self._get(429, {"cf-cache-status": "MISS"}))

    def test_503_akamai_header(self):
        self.assertTrue(self._get(503, {"x-akamai-transformed": "9 - 0"}))

    def test_403_imperva_header(self):
        self.assertTrue(self._get(403, {"x-iinfo": "14-123456-0"}))

    def test_403_aws_waf_header(self):
        self.assertTrue(self._get(403, {"x-amzn-waf-action": "BLOCK"}))

    def test_403_datadome_header(self):
        self.assertTrue(self._get(403, {"x-datadome": "blocked"}))

    # ── Status + WAF body keyword ─────────────────────────────────────────────

    def test_403_cloudflare_body(self):
        self.assertTrue(self._get(403, {}, "Error from Cloudflare — Ray ID: 7a1b"))

    def test_429_captcha_body(self):
        self.assertTrue(self._get(429, {}, "Please complete a CAPTCHA to continue"))

    def test_503_incapsula_body(self):
        self.assertTrue(self._get(503, {}, "Powered by Incapsula"))

    def test_403_datadome_body(self):
        self.assertTrue(self._get(403, {}, "Please enable JS and cookies — Powered by DataDome"))

    def test_503_turnstile_body(self):
        self.assertTrue(self._get(503, {}, "cf_chl_opt = {type: 'turnstile'}"))

    def test_429_recaptcha_body(self):
        self.assertTrue(self._get(429, {}, "www.google.com/recaptcha/api.js"))

    # ── Edge cases ────────────────────────────────────────────────────────────

    def test_body_case_insensitive(self):
        self.assertTrue(self._get(403, {}, "CLOUDFLARE IS BLOCKING THIS REQUEST"))

    def test_200_with_cf_ray(self):
        # Cloudflare header on a 200 is normal for CDN — should NOT flag
        self.assertFalse(self._get(200, {"cf-ray": "abc"}))


# ─────────────────────────────────────────────────────────────────────────────
# 2. stealth_safe_get() unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestStealthSafeGet(unittest.TestCase):

    def _call(self, url="https://example.com/", **kw):
        from tools.http_utils import stealth_safe_get
        return stealth_safe_get(url, **kw)

    # ── SSRF guard ────────────────────────────────────────────────────────────

    def test_ssrf_private_ip_raises(self):
        from tools.http_utils import SSRFError
        with self.assertRaises(SSRFError):
            self._call("http://192.168.1.1/secret")

    def test_ssrf_localhost_raises(self):
        from tools.http_utils import SSRFError
        with self.assertRaises(SSRFError):
            self._call("http://localhost/internal")

    def test_non_http_scheme_returns_none(self):
        result = self._call("ftp://example.com/file")
        self.assertIsNone(result)

    def test_file_scheme_returns_none(self):
        result = self._call("file:///etc/passwd")
        self.assertIsNone(result)

    # ── Happy path with mocked StealthSession ────────────────────────────────

    def test_successful_stealth_get(self):
        stealth_mock = _make_stealth_response(200, {"content-type": "text/html"}, "<h1>OK</h1>")

        async def _fake_get(url, **kw):
            return stealth_mock

        session_mock = AsyncMock()
        session_mock.get = _fake_get
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__  = AsyncMock(return_value=False)

        with patch("tools.stealth_http_client.StealthSession", return_value=session_mock):
            result = self._call("https://example.com/")

        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertIn(b"<h1>OK</h1>", result.content)

    def test_stealth_response_converts_headers(self):
        stealth_mock = _make_stealth_response(
            200,
            {"Content-Type": "application/json", "X-Custom": "value"},
            '{"ok": true}',
        )

        async def _fake_get(url, **kw):
            return stealth_mock

        session_mock = AsyncMock()
        session_mock.get = _fake_get
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__  = AsyncMock(return_value=False)

        with patch("tools.stealth_http_client.StealthSession", return_value=session_mock):
            result = self._call("https://example.com/api")

        self.assertIsNotNone(result)
        self.assertEqual(result.headers.get("Content-Type"), "application/json")

    def test_stealth_response_size_cap(self):
        large_body = "A" * (6 * 1024 * 1024)  # 6 MB > 5 MB cap
        stealth_mock = _make_stealth_response(200, {}, large_body)

        async def _fake_get(url, **kw):
            return stealth_mock

        session_mock = AsyncMock()
        session_mock.get = _fake_get
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__  = AsyncMock(return_value=False)

        with patch("tools.stealth_http_client.StealthSession", return_value=session_mock):
            result = self._call("https://example.com/huge", max_bytes=5 * 1024 * 1024)

        self.assertIsNotNone(result)
        self.assertLessEqual(len(result.content), 5 * 1024 * 1024)

    def test_stealth_exception_returns_none(self):
        """If StealthSession raises any error, stealth_safe_get returns None."""
        session_mock = AsyncMock()
        session_mock.__aenter__ = AsyncMock(side_effect=RuntimeError("network down"))
        session_mock.__aexit__  = AsyncMock(return_value=False)

        with patch("tools.stealth_http_client.StealthSession", return_value=session_mock):
            result = self._call("https://example.com/")

        self.assertIsNone(result)

    def test_waf_detection_attribute_exposed(self):
        """mock.waf_detection attribute is accessible on returned response."""
        waf_info = {"status": "blocked_by_waf", "waf_type": "Cloudflare"}
        stealth_mock = _make_stealth_response(403, {}, "blocked", waf_detection=waf_info)

        async def _fake_get(url, **kw):
            return stealth_mock

        session_mock = AsyncMock()
        session_mock.get = _fake_get
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__  = AsyncMock(return_value=False)

        with patch("tools.stealth_http_client.StealthSession", return_value=session_mock):
            result = self._call("https://example.com/")

        self.assertIsNotNone(result)
        self.assertEqual(result.waf_detection["waf_type"], "Cloudflare")


# ─────────────────────────────────────────────────────────────────────────────
# 3. passive_recon._safe_get() stealth fallback tests
# ─────────────────────────────────────────────────────────────────────────────

class TestPassiveReconSafeGetStealth(unittest.TestCase):

    def test_no_stealth_on_clean_200(self):
        """Clean 200 response should never trigger stealth."""
        clean = _make_response(200, {}, "Hello World")

        with patch("tools.passive_recon._http_safe_get", return_value=clean) as mock_http, \
             patch("tools.passive_recon._stealth_safe_get") as mock_stealth:
            from tools.passive_recon import _safe_get
            result = _safe_get("https://example.com/")

        mock_stealth.assert_not_called()
        self.assertEqual(result.status_code, 200)

    def test_stealth_triggered_on_waf_block(self):
        """WAF-blocked response (403 + cf-ray) should trigger stealth fallback."""
        blocked = _make_response(403, {"cf-ray": "abc123"}, "Cloudflare block")
        stealth_ok = _make_response(200, {"content-type": "text/html"}, "Real page")

        with patch("tools.passive_recon._http_safe_get", return_value=blocked), \
             patch("tools.passive_recon._stealth_safe_get", return_value=stealth_ok) as mock_stealth:
            from tools.passive_recon import _safe_get
            result = _safe_get("https://target.example.com/")

        mock_stealth.assert_called_once()
        self.assertEqual(result.status_code, 200)

    def test_stealth_fallback_when_stealth_also_blocked(self):
        """If stealth is also blocked (403), return original WAF response."""
        blocked   = _make_response(403, {"cf-ray": "abc123"}, "Cloudflare")
        still_403 = _make_response(403, {}, "Still blocked")

        with patch("tools.passive_recon._http_safe_get", return_value=blocked), \
             patch("tools.passive_recon._stealth_safe_get", return_value=still_403):
            from tools.passive_recon import _safe_get
            result = _safe_get("https://target.example.com/")

        # Should fall back to the original blocked response
        self.assertEqual(result.status_code, 403)

    def test_stealth_fallback_when_stealth_returns_none(self):
        """If stealth returns None (error), return original response."""
        blocked = _make_response(503, {"x-iinfo": "imperva"}, "Service Unavailable")

        with patch("tools.passive_recon._http_safe_get", return_value=blocked), \
             patch("tools.passive_recon._stealth_safe_get", return_value=None):
            from tools.passive_recon import _safe_get
            result = _safe_get("https://target.example.com/")

        self.assertEqual(result.status_code, 503)

    def test_ssrf_not_bypassed_via_stealth(self):
        """SSRF violations must propagate even through the stealth path."""
        from tools.http_utils import SSRFError
        from tools.passive_recon import _safe_get

        # _http_safe_get raises SSRFError → _safe_get must return None (not call stealth)
        with patch("tools.passive_recon._http_safe_get", side_effect=SSRFError("blocked")), \
             patch("tools.passive_recon._stealth_safe_get") as mock_stealth:
            result = _safe_get("http://10.0.0.1/secret")

        mock_stealth.assert_not_called()
        self.assertIsNone(result)

    def test_non_http_scheme_returns_none(self):
        from tools.passive_recon import _safe_get
        result = _safe_get("file:///etc/passwd")
        self.assertIsNone(result)


# ─────────────────────────────────────────────────────────────────────────────
# 4. waf_detector.detect_waf() stealth upgrade tests
# ─────────────────────────────────────────────────────────────────────────────

class TestWafDetectorStealth(unittest.TestCase):

    def _run(self, url="https://example.com/"):
        from tools.waf_detector import detect_waf
        return json.loads(detect_waf.invoke({"url": url}))

    def test_no_stealth_on_clean_response(self):
        """Clean 200 should not trigger stealth upgrade."""
        clean = _make_response(200, {"server": "nginx"}, "")

        with patch("tools.waf_detector.safe_get", return_value=clean), \
             patch("tools.waf_detector.stealth_safe_get") as mock_stealth:
            result = self._run()

        mock_stealth.assert_not_called()
        self.assertFalse(result.get("stealth_used"))

    def test_stealth_used_when_initial_is_waf_blocked(self):
        """If initial safe_get is WAF-blocked, stealth upgrade should run."""
        blocked = _make_response(403, {"cf-ray": "abc123-LHR"}, "Cloudflare")
        # Stealth gets through with Cloudflare headers visible in clean form
        stealth_ok = _make_response(200, {"cf-ray": "def456", "server": "cloudflare"}, "OK")

        with patch("tools.waf_detector.safe_get", return_value=blocked), \
             patch("tools.waf_detector.stealth_safe_get", return_value=stealth_ok), \
             patch("tools.waf_detector._is_waf_response", return_value=True):
            result = self._run()

        self.assertTrue(result.get("stealth_used"))

    def test_stealth_false_when_no_waf_block(self):
        """stealth_used must be False when WAF did not block initial request."""
        clean = _make_response(200, {"cf-ray": "abc"}, "CDN page")

        with patch("tools.waf_detector.safe_get", return_value=clean), \
             patch("tools.waf_detector._is_waf_response", return_value=False):
            result = self._run()

        self.assertFalse(result.get("stealth_used"))

    def test_ssrf_blocked_returns_ssrf_status(self):
        from tools.http_utils import SSRFError
        with patch("tools.waf_detector.safe_get", side_effect=SSRFError("blocked")):
            result = self._run("http://192.168.1.1/")
        self.assertEqual(result["status"], "ssrf_blocked")

    def test_stealth_used_key_present_in_output(self):
        """stealth_used key must always be present in completed results."""
        clean = _make_response(200, {}, "")
        with patch("tools.waf_detector.safe_get", return_value=clean), \
             patch("tools.waf_detector._is_waf_response", return_value=False):
            result = self._run()
        self.assertIn("stealth_used", result)

    def test_probe_stealth_when_probe_blocked_unknown_waf(self):
        """If probe is blocked but WAF is unidentified, try stealth probe for fingerprint."""
        clean_initial = _make_response(200, {"server": "nginx"}, "OK")
        probe_blocked = _make_response(403, {}, "Forbidden")
        # Stealth probe reveals WAF headers
        stealth_probe = _make_response(403, {"x-iinfo": "14-999"}, "Imperva")

        call_count = {"n": 0}

        def _fake_safe_get(url, **kw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return clean_initial
            return probe_blocked

        with patch("tools.waf_detector.safe_get", side_effect=_fake_safe_get), \
             patch("tools.waf_detector.stealth_safe_get", return_value=stealth_probe), \
             patch("tools.waf_detector._is_waf_response", return_value=False):
            result = self._run()

        self.assertTrue(result.get("probe_blocked"))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Concurrency / event-loop safety
# ─────────────────────────────────────────────────────────────────────────────

class TestStealthSafeGetEventLoopSafety(unittest.TestCase):

    def test_called_from_thread_pool(self):
        """stealth_safe_get must work when called from a ThreadPoolExecutor."""
        import concurrent.futures

        stealth_mock = _make_stealth_response(200, {}, "threaded")

        async def _fake_get(url, **kw):
            return stealth_mock

        session_mock = AsyncMock()
        session_mock.get = _fake_get
        session_mock.__aenter__ = AsyncMock(return_value=session_mock)
        session_mock.__aexit__  = AsyncMock(return_value=False)

        def _worker():
            from tools.http_utils import stealth_safe_get
            with patch("tools.stealth_http_client.StealthSession", return_value=session_mock):
                return stealth_safe_get("https://example.com/")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_worker) for _ in range(2)]
            results = [f.result() for f in futures]

        for r in results:
            self.assertIsNotNone(r)
            self.assertEqual(r.status_code, 200)

    def test_concurrent_calls_all_succeed(self):
        """Multiple concurrent stealth calls should not deadlock."""
        import concurrent.futures

        stealth_mock = _make_stealth_response(200, {}, "ok")

        async def _fake_get(url, **kw):
            await asyncio.sleep(0)  # yield
            return stealth_mock

        def _worker(n):
            from tools.http_utils import stealth_safe_get

            session_mock = AsyncMock()
            session_mock.get = _fake_get
            session_mock.__aenter__ = AsyncMock(return_value=session_mock)
            session_mock.__aexit__  = AsyncMock(return_value=False)

            with patch("tools.stealth_http_client.StealthSession", return_value=session_mock):
                return stealth_safe_get(f"https://example.com/path{n}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(_worker, i) for i in range(4)]
            results = [f.result(timeout=15) for f in futures]

        self.assertEqual(len(results), 4)
        self.assertTrue(all(r is not None for r in results))


if __name__ == "__main__":
    unittest.main()

"""
Accuracy benchmark test suite for AI Cyber Shield scanning tools.

Verifies that each tool correctly detects (or ignores) known configurations
served by local mock HTTP servers or mocked DNS responses.

Test structure:
  TestMockTarget         — 8  tests: mock server mechanics
  TestBenchmarkDataset   — 5  tests: dataset integrity checks
  TestSecurityHeaders    — 6  tests: check_security_headers accuracy
  TestCorsCSP            — 7  tests: check_cors_csp accuracy
  TestCookieSecurity     — 6  tests: scan_cookie_security accuracy
  TestExposureChecker    — 6  tests: check_exposure accuracy
  TestHSTSPreload        — 6  tests: check_hsts_preload accuracy
  TestWAFDetector        — 6  tests: detect_waf accuracy
  TestDNSScanner         — 7  tests: scan_dns_security accuracy (mocked DoH)
  TestScorer             — 6  tests: scorer mechanics
  ─────────────────────────────────────────────────────────
  Total:                  63 tests
"""
from __future__ import annotations

import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

from benchmark.dataset import (
    ALL_DNS_CASES,
    ALL_HTTP_CASES,
    TOTAL_CASES,
    DNS_CASES,
    CORS_CSP_CASES,
    COOKIE_CASES,
    EXPOSURE_CASES,
    HSTS_CASES,
    SECURITY_HEADERS_CASES,
    WAF_CASES,
)
from benchmark.mock_target import MockServerConfig, mock_target
from benchmark.runner import BenchmarkRun, CheckResult, _score, _make_doh_mock
from benchmark.scorer import MetricSet, score


# ─────────────────────────────────────────────────────────────────────────────
# Fixture: enable SSRF bypass for all tests in this module
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def benchmark_mode(monkeypatch):
    """Set AICS_BENCHMARK_MODE=1 for every test in this file."""
    monkeypatch.setenv("AICS_BENCHMARK_MODE", "1")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _call(tool_name: str, url_or_domain: str) -> dict:
    """Import and call a tool function directly, returning parsed JSON dict."""
    import importlib
    _tool_map = {
        "security_headers": ("tools.web_tools",      "check_security_headers"),
        "cors_csp":         ("tools.cors_csp_checker","check_cors_csp"),
        "cookie":           ("tools.cookie_security", "scan_cookie_security"),
        "exposure":         ("tools.exposure_checker","check_exposure"),
        "hsts":             ("tools.hsts_preload",    "check_hsts_preload"),
        "waf":              ("tools.waf_detector",    "detect_waf"),
        "dns":              ("tools.dns_scanner",     "scan_dns_security"),
    }
    mod_name, fn_name = _tool_map[tool_name]
    mod = importlib.import_module(mod_name)
    fn_obj = getattr(mod, fn_name)
    fn = getattr(fn_obj, "func", fn_obj)
    raw = fn(url_or_domain)
    return json.loads(raw) if isinstance(raw, str) else (raw or {})


# ─────────────────────────────────────────────────────────────────────────────
# TestMockTarget — 8 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMockTarget:
    def test_default_response_200(self):
        cfg = MockServerConfig(status=200, body="hello")
        with mock_target(cfg) as url:
            import requests
            r = requests.get(url)
            assert r.status_code == 200
            assert "hello" in r.text

    def test_custom_headers_returned(self):
        cfg = MockServerConfig(headers={"X-Test-Header": "benchmark"})
        with mock_target(cfg) as url:
            import requests
            r = requests.get(url)
            assert r.headers.get("X-Test-Header") == "benchmark"

    def test_path_override_returns_correct_status(self):
        cfg = MockServerConfig(
            status=404,
            body="Not Found",
            paths={"/.env": (200, "SECRET=abc")},
        )
        with mock_target(cfg) as url:
            import requests
            assert requests.get(url + "/.env").status_code == 200
            assert requests.get(url + "/.other").status_code == 404

    def test_probe_keyword_returns_probe_status(self):
        cfg = MockServerConfig(
            probe_keyword="waf_probe",
            probe_status=403,
            probe_body="Blocked",
        )
        with mock_target(cfg) as url:
            import requests
            assert requests.get(url + "/?waf_probe=xss").status_code == 403
            assert requests.get(url).status_code == 200

    def test_head_method_handled(self):
        cfg = MockServerConfig(headers={"CF-Ray": "abc123"})
        with mock_target(cfg) as url:
            import requests
            r = requests.head(url)
            assert r.status_code == 200

    def test_multiple_path_overrides(self):
        cfg = MockServerConfig(
            status=404,
            body="404",
            paths={
                "/":          (200, "<html/>"),
                "/.git/HEAD": (200, "ref: refs/heads/main"),
                "/.env":      (200, "SECRET=x"),
            },
        )
        with mock_target(cfg) as url:
            import requests
            assert requests.get(url + "/").status_code == 200
            assert requests.get(url + "/.git/HEAD").status_code == 200
            assert requests.get(url + "/.env").status_code == 200
            assert requests.get(url + "/phpinfo.php").status_code == 404

    def test_concurrent_requests_handled(self):
        import threading
        import requests
        cfg = MockServerConfig(status=200, body="concurrent")
        results = []
        with mock_target(cfg) as url:
            def fetch():
                results.append(requests.get(url).status_code)
            threads = [threading.Thread(target=fetch) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        assert all(s == 200 for s in results)

    def test_set_cookie_header_served(self):
        cfg = MockServerConfig(
            headers={"Set-Cookie": "session=abc; SameSite=None"},
        )
        with mock_target(cfg) as url:
            import requests
            r = requests.get(url)
            assert "session" in r.headers.get("Set-Cookie", "")


# ─────────────────────────────────────────────────────────────────────────────
# TestBenchmarkDataset — 5 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBenchmarkDataset:
    def test_total_case_count_matches_constant(self):
        assert TOTAL_CASES == len(ALL_HTTP_CASES) + len(ALL_DNS_CASES)

    def test_all_http_cases_have_ground_truths(self):
        for case in ALL_HTTP_CASES:
            assert len(case.ground_truths) >= 1, f"{case.name} has no ground truths"

    def test_all_dns_cases_have_ground_truths(self):
        for case in ALL_DNS_CASES:
            assert len(case.ground_truths) >= 1, f"{case.name} has no ground truths"

    def test_category_values_are_valid(self):
        valid = {"positive", "negative"}
        for case in ALL_HTTP_CASES:
            for gt in case.ground_truths:
                assert gt.category in valid, f"{case.name}/{gt.tool}: invalid category"
        for case in ALL_DNS_CASES:
            for gt in case.ground_truths:
                assert gt.category in valid, f"{case.name}/{gt.tool}: invalid category"

    def test_check_fns_are_callable(self):
        for case in ALL_HTTP_CASES:
            for gt in case.ground_truths:
                assert callable(gt.check_fn), f"{case.name}/{gt.tool}: check_fn not callable"
                # Verify it doesn't crash on empty dict
                result = gt.check_fn({})
                assert isinstance(result, bool), f"{case.name}/{gt.tool}: check_fn must return bool"


# ─────────────────────────────────────────────────────────────────────────────
# TestSecurityHeaders — 6 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_no_headers_reports_missing(self):
        cfg = MockServerConfig(headers={}, body="<html><body>No headers</body></html>")
        with mock_target(cfg) as url:
            result = _call("security_headers", url)
        assert result.get("status") == "completed"
        assert len(result.get("missing_headers", [])) >= 5

    def test_server_version_disclosure_detected(self):
        cfg = MockServerConfig(
            headers={"Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1"},
        )
        with mock_target(cfg) as url:
            result = _call("security_headers", url)
        assert result.get("information_disclosure"), "Server version header not detected"

    def test_all_headers_reduces_missing(self):
        from benchmark.dataset import _ALL_SECURITY_HEADERS
        cfg = MockServerConfig(headers=_ALL_SECURITY_HEADERS)
        with mock_target(cfg) as url:
            result = _call("security_headers", url)
        # With all 9 headers present, missing count must be well below the 5 threshold
        assert len(result.get("missing_headers", [])) < 5

    def test_partial_headers_still_missing(self):
        cfg = MockServerConfig(headers={"X-Frame-Options": "DENY"})
        with mock_target(cfg) as url:
            result = _call("security_headers", url)
        assert len(result.get("missing_headers", [])) >= 4

    def test_completed_status_on_valid_url(self):
        cfg = MockServerConfig()
        with mock_target(cfg) as url:
            result = _call("security_headers", url)
        assert result.get("status") == "completed"

    def test_ground_truth_positive_cases_pass(self):
        from benchmark.runner import _run_http_case, _get_tool_funcs
        tool_funcs = _get_tool_funcs()
        for case in SECURITY_HEADERS_CASES:
            results = _run_http_case(case, tool_funcs)
            for r in results:
                assert r.outcome not in ("ERROR", "SKIP"), \
                    f"{case.name}: {r.outcome} — {r.error_msg}"
                assert r.outcome in ("TP", "TN"), \
                    f"{case.name}: expected TP/TN, got {r.outcome}\nActual: {r.actual_output}"


# ─────────────────────────────────────────────────────────────────────────────
# TestCorsCSP — 7 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCorsCSP:
    def test_wildcard_cors_detected(self):
        cfg = MockServerConfig(headers={"Access-Control-Allow-Origin": "*"})
        with mock_target(cfg) as url:
            result = _call("cors_csp", url)
        assert len(result.get("cors_issues", [])) > 0, "Wildcard CORS not detected"

    def test_wildcard_with_credentials_high_risk(self):
        cfg = MockServerConfig(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        with mock_target(cfg) as url:
            result = _call("cors_csp", url)
        assert result.get("risk_score", 0) >= 50

    def test_no_csp_reported(self):
        cfg = MockServerConfig(headers={})
        with mock_target(cfg) as url:
            result = _call("cors_csp", url)
        assert result.get("csp_quality", "none") == "none"

    def test_good_csp_quality(self):
        cfg = MockServerConfig(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        })
        with mock_target(cfg) as url:
            result = _call("cors_csp", url)
        assert result.get("csp_quality", "none") != "none", "Good CSP not recognised"

    def test_specific_cors_origin_no_issue(self):
        cfg = MockServerConfig(headers={
            "Access-Control-Allow-Origin": "https://api.example.com",
            "Content-Security-Policy": "default-src 'self'",
        })
        with mock_target(cfg) as url:
            result = _call("cors_csp", url)
        assert len(result.get("cors_issues", [])) == 0, "False positive on specific CORS origin"

    def test_unsafe_inline_not_strong_quality(self):
        cfg = MockServerConfig(headers={
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
        })
        with mock_target(cfg) as url:
            result = _call("cors_csp", url)
        # Tool adds risk for unsafe-inline/unsafe-eval; quality must NOT be "strong"
        assert result.get("csp_quality") != "strong", "unsafe-inline CSP flagged as strong"
        assert result.get("risk_score", 0) > 0, "unsafe-inline CSP has no risk score"

    def test_ground_truth_cases_pass(self):
        from benchmark.runner import _run_http_case, _get_tool_funcs
        tool_funcs = _get_tool_funcs()
        for case in CORS_CSP_CASES:
            results = _run_http_case(case, tool_funcs)
            for r in results:
                assert r.outcome not in ("ERROR", "SKIP"), \
                    f"{case.name}: {r.outcome} — {r.error_msg}"
                assert r.outcome in ("TP", "TN"), \
                    f"{case.name}: expected TP/TN, got {r.outcome}\nActual: {r.actual_output}"


# ─────────────────────────────────────────────────────────────────────────────
# TestCookieSecurity — 6 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCookieSecurity:
    def test_samesite_none_without_secure_detected(self):
        cfg = MockServerConfig(headers={"Set-Cookie": "session=abc; SameSite=None"})
        with mock_target(cfg) as url:
            result = _call("cookie", url)
        assert result.get("risk_score", 0) >= 35, \
            "SameSite=None without Secure not detected"

    def test_auth_cookie_no_httponly_detected(self):
        cfg = MockServerConfig(headers={"Set-Cookie": "session=abc123"})
        with mock_target(cfg) as url:
            result = _call("cookie", url)
        assert result.get("risk_score", 0) >= 30, \
            "Auth cookie without HttpOnly not detected"

    def test_well_configured_cookie_low_risk(self):
        cfg = MockServerConfig(headers={"Set-Cookie": "session=abc; HttpOnly; SameSite=Lax; Path=/"})
        with mock_target(cfg) as url:
            result = _call("cookie", url)
        assert result.get("risk_score", 0) < 30, \
            f"False positive on well-configured cookie (risk={result.get('risk_score')})"

    def test_no_cookie_returns_zero_risk(self):
        cfg = MockServerConfig(headers={})
        with mock_target(cfg) as url:
            result = _call("cookie", url)
        assert result.get("cookies_found", 0) == 0
        assert result.get("risk_score", 0) == 0

    def test_issues_list_populated_on_bad_cookie(self):
        cfg = MockServerConfig(headers={"Set-Cookie": "session=abc; SameSite=None"})
        with mock_target(cfg) as url:
            result = _call("cookie", url)
        assert len(result.get("issues", [])) > 0

    def test_ground_truth_cases_pass(self):
        from benchmark.runner import _run_http_case, _get_tool_funcs
        tool_funcs = _get_tool_funcs()
        for case in COOKIE_CASES:
            results = _run_http_case(case, tool_funcs)
            for r in results:
                assert r.outcome not in ("ERROR", "SKIP"), \
                    f"{case.name}: {r.outcome} — {r.error_msg}"
                assert r.outcome in ("TP", "TN"), \
                    f"{case.name}: expected TP/TN, got {r.outcome}\nActual: {r.actual_output}"


# ─────────────────────────────────────────────────────────────────────────────
# TestExposureChecker — 6 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestExposureChecker:
    def test_env_file_exposed(self):
        cfg = MockServerConfig(
            status=404, body="Not Found",
            paths={
                "/":     (200, "<html/>"),
                "/.env": (200, "SECRET=abc\nDB_PASS=hunter2"),
            },
        )
        with mock_target(cfg) as url:
            result = _call("exposure", url)
        assert result.get("risk_score", 0) >= 50, ".env exposure not detected"

    def test_git_head_exposed(self):
        cfg = MockServerConfig(
            status=404, body="Not Found",
            paths={
                "/":          (200, "<html/>"),
                "/.git/HEAD": (200, "ref: refs/heads/main"),
            },
        )
        with mock_target(cfg) as url:
            result = _call("exposure", url)
        assert len(result.get("exposed_files", [])) > 0, ".git/HEAD exposure not detected"

    def test_clean_site_no_exposure(self):
        from benchmark.dataset import _ALL_SENSITIVE_PATHS_404
        cfg = MockServerConfig(status=404, body="Not Found", paths=_ALL_SENSITIVE_PATHS_404)
        with mock_target(cfg) as url:
            result = _call("exposure", url)
        assert len(result.get("exposed_files", [])) == 0, \
            f"False positive: {result.get('exposed_files')}"

    def test_dual_critical_files_high_risk(self):
        cfg = MockServerConfig(
            status=404, body="Not Found",
            paths={
                "/":          (200, "<html/>"),
                "/.env":      (200, "SECRET=x"),
                "/.git/HEAD": (200, "ref: refs/heads/main"),
            },
        )
        with mock_target(cfg) as url:
            result = _call("exposure", url)
        assert result.get("risk_score", 0) >= 100

    def test_phpinfo_detected(self):
        cfg = MockServerConfig(
            status=404, body="Not Found",
            paths={
                "/":           (200, "<html/>"),
                "/phpinfo.php": (200, "<title>phpinfo()</title><body>PHP Version 8.1.0 Configure Command</body>"),
            },
        )
        with mock_target(cfg) as url:
            result = _call("exposure", url)
        assert len(result.get("exposed_files", [])) > 0

    def test_ground_truth_cases_pass(self):
        from benchmark.runner import _run_http_case, _get_tool_funcs
        tool_funcs = _get_tool_funcs()
        for case in EXPOSURE_CASES:
            results = _run_http_case(case, tool_funcs)
            for r in results:
                assert r.outcome not in ("ERROR", "SKIP"), \
                    f"{case.name}: {r.outcome} — {r.error_msg}"
                assert r.outcome in ("TP", "TN"), \
                    f"{case.name}: expected TP/TN, got {r.outcome}\nActual: {r.actual_output}"


# ─────────────────────────────────────────────────────────────────────────────
# TestHSTSPreload — 6 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHSTSPreload:
    def test_missing_hsts_detected(self):
        cfg = MockServerConfig(headers={})
        with mock_target(cfg) as url:
            result = _call("hsts", url)
        assert result.get("hsts_present") is False, "Missing HSTS not detected"

    def test_weak_max_age_reported(self):
        cfg = MockServerConfig(headers={"Strict-Transport-Security": "max-age=3600"})
        with mock_target(cfg) as url:
            result = _call("hsts", url)
        assert result.get("hsts_quality") == "weak", \
            f"Expected 'weak', got {result.get('hsts_quality')}"

    def test_strong_hsts_present(self):
        cfg = MockServerConfig(headers={
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        })
        with mock_target(cfg) as url:
            result = _call("hsts", url)
        assert result.get("hsts_present") is True
        assert result.get("hsts_quality") in ("strong", "medium")

    def test_medium_hsts_present(self):
        cfg = MockServerConfig(headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        with mock_target(cfg) as url:
            result = _call("hsts", url)
        assert result.get("hsts_present") is True

    def test_hsts_fields_populated(self):
        cfg = MockServerConfig(headers={
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        })
        with mock_target(cfg) as url:
            result = _call("hsts", url)
        parsed = result.get("parsed_hsts", {})
        assert parsed.get("max_age", 0) >= 63072000

    def test_ground_truth_cases_pass(self):
        from benchmark.runner import _run_http_case, _get_tool_funcs
        tool_funcs = _get_tool_funcs()
        for case in HSTS_CASES:
            results = _run_http_case(case, tool_funcs)
            for r in results:
                assert r.outcome not in ("ERROR", "SKIP"), \
                    f"{case.name}: {r.outcome} — {r.error_msg}"
                assert r.outcome in ("TP", "TN"), \
                    f"{case.name}: expected TP/TN, got {r.outcome}\nActual: {r.actual_output}"


# ─────────────────────────────────────────────────────────────────────────────
# TestWAFDetector — 6 tests
# ─────────────────────────────────────────────────────────────────────────────

class TestWAFDetector:
    def test_cloudflare_headers_detected(self):
        cfg = MockServerConfig(headers={
            "cf-ray": "87c3456789ab-IAD",
            "server": "cloudflare",
        })
        with mock_target(cfg) as url:
            result = _call("waf", url)
        assert result.get("waf_detected") is True
        assert "cloudflare" in (result.get("waf_name") or "").lower()

    def test_imperva_headers_detected(self):
        cfg = MockServerConfig(headers={
            "X-Iinfo": "8-12345678-0 0NNN RT(0 0) q(0 0 0 -1) r(0 0)",
            "Set-Cookie": "incap_ses_1234_5678=abc; Path=/",
        })
        with mock_target(cfg) as url:
            result = _call("waf", url)
        assert result.get("waf_detected") is True

    def test_probe_blocked_detected(self):
        cfg = MockServerConfig(
            probe_keyword="waf_probe",
            probe_status=403,
            probe_body="<html>Access Denied</html>",
        )
        with mock_target(cfg) as url:
            result = _call("waf", url)
        assert result.get("probe_blocked") is True

    def test_no_waf_not_detected(self):
        cfg = MockServerConfig(headers={"server": "nginx/1.24.0"})
        with mock_target(cfg) as url:
            result = _call("waf", url)
        assert result.get("waf_detected") is False, \
            f"False positive: waf_name={result.get('waf_name')}"

    def test_confidence_nonzero_when_detected(self):
        cfg = MockServerConfig(headers={
            "cf-ray": "abc123",
            "server": "cloudflare",
        })
        with mock_target(cfg) as url:
            result = _call("waf", url)
        assert result.get("confidence", 0) >= 35

    def test_ground_truth_cases_pass(self):
        from benchmark.runner import _run_http_case, _get_tool_funcs
        tool_funcs = _get_tool_funcs()
        for case in WAF_CASES:
            results = _run_http_case(case, tool_funcs)
            for r in results:
                assert r.outcome not in ("ERROR", "SKIP"), \
                    f"{case.name}: {r.outcome} — {r.error_msg}"
                assert r.outcome in ("TP", "TN"), \
                    f"{case.name}: expected TP/TN, got {r.outcome}\nActual: {r.actual_output}"


# ─────────────────────────────────────────────────────────────────────────────
# TestDNSScanner — 7 tests
# ─────────────────────────────────────────────────────────────────────────────

def _mock_doh(records: dict) -> MagicMock:
    """Returns a mock requests.get that simulates Cloudflare DoH responses."""
    def _fake_get(url, **kwargs):
        params = kwargs.get("params", {})
        name  = params.get("name", "")
        rtype = params.get("type", "TXT")
        key   = (name, rtype)
        data_list = records.get(key, [])
        rtype_num = {"TXT": 16, "CAA": 257}.get(rtype, 16)
        answers = [{"type": rtype_num, "data": d} for d in data_list]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"Answer": answers}
        return mock_resp
    return _fake_get


class TestDNSScanner:
    # scan_dns_security takes a full URL and extracts hostname via urlparse.
    # All DNS tests pass "http://domain.test" (the scanner queries "domain.test").

    def test_no_spf_detected(self):
        records = {
            ("no-spf.test", "TXT"):          [],
            ("_dmarc.no-spf.test", "TXT"):   [],
            ("no-spf.test", "CAA"):           [],
        }
        with patch("tools.dns_scanner.requests.get", side_effect=_mock_doh(records)):
            result = _call("dns", "http://no-spf.test")
        assert result.get("spf", {}).get("risk", 0) >= 30, "Missing SPF not detected"

    def test_spf_plus_all_critical(self):
        records = {
            ("plus-all.test", "TXT"):         ["v=spf1 +all"],
            ("_dmarc.plus-all.test", "TXT"):  [],
            ("plus-all.test", "CAA"):          [],
        }
        with patch("tools.dns_scanner.requests.get", side_effect=_mock_doh(records)):
            result = _call("dns", "http://plus-all.test")
        assert result.get("spf", {}).get("risk", 0) >= 40, "SPF +all not flagged as critical"

    def test_no_dmarc_detected(self):
        records = {
            ("no-dmarc.test", "TXT"):          ["v=spf1 include:_spf.google.com ~all"],
            ("_dmarc.no-dmarc.test", "TXT"):   [],
            ("no-dmarc.test", "CAA"):           [],
        }
        with patch("tools.dns_scanner.requests.get", side_effect=_mock_doh(records)):
            result = _call("dns", "http://no-dmarc.test")
        assert result.get("dmarc", {}).get("risk", 0) >= 20, "Missing DMARC not detected"

    def test_full_protection_low_risk(self):
        records = {
            ("secure.test", "TXT"):          ["v=spf1 include:_spf.google.com -all"],
            ("_dmarc.secure.test", "TXT"):   ["v=DMARC1; p=reject; rua=mailto:dmarc@secure.test"],
            ("secure.test", "CAA"):           ["0 issue \"letsencrypt.org\""],
        }
        with patch("tools.dns_scanner.requests.get", side_effect=_mock_doh(records)):
            result = _call("dns", "http://secure.test")
        total_risk = result.get("risk_score", result.get("spf", {}).get("risk", 0) +
                                              result.get("dmarc", {}).get("risk", 0))
        assert total_risk < 30, f"Full-protection domain scored too high: {total_risk}"

    def test_dmarc_p_none_flagged(self):
        records = {
            ("p-none.test", "TXT"):         ["v=spf1 -all"],
            ("_dmarc.p-none.test", "TXT"):  ["v=DMARC1; p=none"],
            ("p-none.test", "CAA"):          [],
        }
        with patch("tools.dns_scanner.requests.get", side_effect=_mock_doh(records)):
            result = _call("dns", "http://p-none.test")
        assert result.get("dmarc", {}).get("risk", 0) >= 10, "DMARC p=none not flagged"

    def test_completed_status_returned(self):
        records = {
            ("example.test", "TXT"):         ["v=spf1 -all"],
            ("_dmarc.example.test", "TXT"):  ["v=DMARC1; p=reject"],
            ("example.test", "CAA"):          [],
        }
        with patch("tools.dns_scanner.requests.get", side_effect=_mock_doh(records)):
            result = _call("dns", "http://example.test")
        assert result.get("status") == "completed"

    def test_ground_truth_dns_cases_pass(self):
        from benchmark.runner import _run_dns_case, _get_tool_funcs
        tool_funcs = _get_tool_funcs()
        for case in DNS_CASES:
            results = _run_dns_case(case, tool_funcs)
            for r in results:
                assert r.outcome not in ("ERROR", "SKIP"), \
                    f"{case.name}: {r.outcome} — {r.error_msg}"
                assert r.outcome in ("TP", "TN"), \
                    f"{case.name}: expected TP/TN, got {r.outcome}\nActual: {r.actual_output}"


# ─────────────────────────────────────────────────────────────────────────────
# TestScorer — 6 tests
# ─────────────────────────────────────────────────────────────────────────────

def _make_run(*outcomes: str) -> BenchmarkRun:
    """Helper: build a BenchmarkRun with synthetic CheckResults."""
    results = [
        CheckResult(
            case_name=f"CASE_{i}", tool="test_tool", category="positive",
            description="", outcome=o, actual_output={},
            error_msg=None, duration_ms=1.0,
        )
        for i, o in enumerate(outcomes)
    ]
    return BenchmarkRun(timestamp="2026-01-01T00:00:00", results=results,
                        total_cases=len(outcomes))


class TestScorer:
    def test_perfect_precision_and_recall(self):
        run = _make_run("TP", "TP", "TN", "TN")
        # Set TN category correctly
        run.results[2].category = "negative"
        run.results[3].category = "negative"
        report = score(run)
        assert report.overall.precision == 1.0
        assert report.overall.recall    == 1.0

    def test_false_positive_reduces_precision(self):
        run = _make_run("TP", "FP")
        run.results[1].category = "negative"
        report = score(run)
        assert report.overall.precision == pytest.approx(0.5)

    def test_false_negative_reduces_recall(self):
        run = _make_run("TP", "FN")
        report = score(run)
        assert report.overall.recall == pytest.approx(0.5)

    def test_gate_passes_when_above_threshold(self):
        # 4 TP + 0 FP + 4 TN + 1 FN → precision=1.0 recall=0.8 → above gate
        results = [
            CheckResult("C", "test", "positive", "", "TP", {}, None, 1.0),
            CheckResult("C", "test", "positive", "", "TP", {}, None, 1.0),
            CheckResult("C", "test", "positive", "", "TP", {}, None, 1.0),
            CheckResult("C", "test", "positive", "", "TP", {}, None, 1.0),
            CheckResult("C", "test", "negative", "", "TN", {}, None, 1.0),
            CheckResult("C", "test", "negative", "", "TN", {}, None, 1.0),
            CheckResult("C", "test", "negative", "", "TN", {}, None, 1.0),
            CheckResult("C", "test", "negative", "", "TN", {}, None, 1.0),
            CheckResult("C", "test", "positive", "", "FN", {}, None, 1.0),
        ]
        run = BenchmarkRun(timestamp="t", results=results, total_cases=9)
        report = score(run)
        assert report.gate_passed is True

    def test_gate_fails_below_precision_threshold(self):
        # 1 TP + 4 FP → precision = 0.20 → gate fails
        results = [
            CheckResult("C", "test", "positive", "", "TP", {}, None, 1.0),
            *[CheckResult("C", "test", "negative", "", "FP", {}, None, 1.0) for _ in range(4)],
        ]
        run = BenchmarkRun(timestamp="t", results=results, total_cases=5)
        report = score(run)
        assert report.gate_passed is False

    def test_per_tool_metrics_populated(self):
        results = [
            CheckResult("C1", "headers", "positive", "", "TP", {}, None, 1.0),
            CheckResult("C2", "headers", "negative", "", "TN", {}, None, 1.0),
            CheckResult("C3", "waf",     "positive", "", "FN", {}, None, 1.0),
        ]
        run = BenchmarkRun(timestamp="t", results=results, total_cases=3)
        report = score(run)
        assert "headers" in report.by_tool
        assert "waf" in report.by_tool
        assert report.by_tool["headers"].tp == 1
        assert report.by_tool["waf"].fn == 1

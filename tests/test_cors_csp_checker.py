"""
Tests for CORS & CSP Quality Checker.
All HTTP calls are mocked.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.cors_csp_checker import (
    check_cors_csp,
    _parse_csp,
    _csp_risk,
    _cors_risk,
)


# ─────────────────────────────────────────────────────────────────────────────
# Unit — CSP parser
# ─────────────────────────────────────────────────────────────────────────────

class TestParseCsp:
    def test_parses_single_directive(self):
        d = _parse_csp("default-src 'self'")
        assert d == {"default-src": ["'self'"]}

    def test_parses_multiple_directives(self):
        d = _parse_csp("default-src 'self'; script-src 'nonce-abc' https:")
        assert "default-src" in d
        assert "script-src" in d
        assert "'nonce-abc'" in d["script-src"]

    def test_empty_string_returns_empty(self):
        assert _parse_csp("") == {}

    def test_lowercases_values(self):
        d = _parse_csp("Script-Src 'UNSAFE-INLINE'")
        assert "'unsafe-inline'" in list(d.values())[0]


# ─────────────────────────────────────────────────────────────────────────────
# Unit — CSP risk
# ─────────────────────────────────────────────────────────────────────────────

class TestCspRisk:
    def test_missing_csp_high_risk(self):
        risk, issues, _ = _csp_risk(None)
        assert risk >= 30
        assert any("missing" in i.lower() for i in issues)

    def test_unsafe_inline_penalised(self):
        risk, issues, _ = _csp_risk("default-src 'self'; script-src 'unsafe-inline'")
        assert risk > 0
        assert any("unsafe-inline" in i for i in issues)

    def test_unsafe_eval_penalised(self):
        risk, issues, _ = _csp_risk("script-src 'unsafe-eval'")
        assert risk > 0
        assert any("unsafe-eval" in i for i in issues)

    def test_wildcard_source_penalised(self):
        risk, issues, _ = _csp_risk("default-src *")
        assert risk > 0
        assert any("wildcard" in i.lower() or "*" in i for i in issues)

    def test_strict_csp_low_risk(self):
        risk, issues, _ = _csp_risk(
            "default-src 'none'; script-src 'nonce-abc123'; style-src 'self'; report-uri /csp"
        )
        assert risk == 0

    def test_missing_default_src_penalised(self):
        risk, issues, _ = _csp_risk("script-src 'self'")
        assert risk > 0
        assert any("default-src" in i for i in issues)


# ─────────────────────────────────────────────────────────────────────────────
# Unit — CORS risk
# ─────────────────────────────────────────────────────────────────────────────

class TestCorsRisk:
    def test_no_cors_headers_zero_risk(self):
        risk, issues, _ = _cors_risk({}, "https://example.com")
        assert risk == 0
        assert issues == []

    def test_wildcard_without_credentials_warning(self):
        risk, issues, _ = _cors_risk(
            {"Access-Control-Allow-Origin": "*"},
            "https://example.com",
        )
        assert risk >= 10
        assert issues

    def test_wildcard_with_credentials_critical(self):
        risk, issues, _ = _cors_risk(
            {"Access-Control-Allow-Origin": "*",
             "Access-Control-Allow-Credentials": "true"},
            "https://example.com",
        )
        assert risk >= 40
        assert any("credentials" in i.lower() for i in issues)

    def test_specific_origin_lower_risk(self):
        risk, issues, _ = _cors_risk(
            {"Access-Control-Allow-Origin": "https://trusted.com"},
            "https://example.com",
        )
        assert risk < 15


# ─────────────────────────────────────────────────────────────────────────────
# Integration — mocked HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _mock_resp(headers: dict, url: str = "https://example.com"):
    resp = MagicMock()
    resp.headers = headers
    resp.url     = url
    resp.text    = ""
    return resp


class TestCheckCorsCsp:
    def _run(self, headers: dict, url: str = "https://example.com") -> dict:
        with patch("tools.cors_csp_checker.safe_get", return_value=_mock_resp(headers, url)):
            return json.loads(check_cors_csp.invoke({"url": url}))

    def test_invalid_scheme_rejected(self):
        result = json.loads(check_cors_csp.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_returns_required_keys(self):
        result = self._run({"Content-Security-Policy": "default-src 'self'"})
        for key in ("risk_score", "csp_present", "cors_issues", "csp_issues"):
            assert key in result

    def test_no_csp_detected(self):
        result = self._run({})
        assert result["csp_present"] is False
        assert result["risk_score"] >= 30

    def test_strong_csp_low_risk(self):
        result = self._run({
            "Content-Security-Policy":
                "default-src 'self'; script-src 'nonce-abc'; report-uri /csp"
        })
        assert result["csp_present"] is True
        assert result["risk_score"] < 15

    def test_wildcard_cors_detected(self):
        result = self._run({"Access-Control-Allow-Origin": "*"})
        assert result["cors_issues"]
        assert result["risk_score"] >= 10

    def test_cors_with_credentials_critical(self):
        result = self._run({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        assert result["risk_score"] >= 40

    def test_clean_site_low_risk(self):
        result = self._run({
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        })
        assert result["risk_score"] < 30

    def test_ssrf_blocked(self):
        with patch("tools.cors_csp_checker.safe_get",
                   side_effect=__import__("tools.http_utils", fromlist=["SSRFError"]).SSRFError("blocked")):
            result = json.loads(check_cors_csp.invoke({"url": "https://192.168.1.1"}))
        assert result["status"] == "ssrf_blocked"

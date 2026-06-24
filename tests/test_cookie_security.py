"""
Tests for tools/cookie_security.py

Structure
─────────
  TestParseCookie       — pure Python, no network
  TestIsAuthCookie      — pure Python
  TestAuditCookie       — pure Python, tests all security checks
  TestAuditAllCookies   — pure Python, integration of parse+audit
  TestScanCookieTool    — sync @tool wrapper, mocks _fetch_set_cookie_headers
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.cookie_security import (
    _audit_all_cookies,
    _audit_cookie,
    _is_auth_cookie,
    _parse_set_cookie,
    scan_cookie_security,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _issue_checks(issues: list[dict]) -> list[str]:
    return [i["check"] for i in issues]


# ─────────────────────────────────────────────────────────────────────────────
# _parse_set_cookie
# ─────────────────────────────────────────────────────────────────────────────

class TestParseCookie:
    def test_basic_name_value(self):
        c = _parse_set_cookie("session=abc123")
        assert c["name"] == "session"
        assert c["value_len"] == 6

    def test_secure_flag_parsed(self):
        c = _parse_set_cookie("id=xyz; Secure")
        assert c["secure"] is True

    def test_httponly_flag_parsed(self):
        c = _parse_set_cookie("token=x; HttpOnly")
        assert c["httponly"] is True

    def test_samesite_strict_parsed(self):
        c = _parse_set_cookie("sid=x; SameSite=Strict")
        assert c["samesite"] == "Strict"

    def test_samesite_lax_parsed(self):
        c = _parse_set_cookie("sid=x; SameSite=Lax")
        assert c["samesite"] == "Lax"

    def test_samesite_none_parsed(self):
        c = _parse_set_cookie("sid=x; SameSite=None")
        assert c["samesite"] == "None"

    def test_samesite_missing_is_none(self):
        c = _parse_set_cookie("sid=x")
        assert c["samesite"] is None

    def test_domain_parsed(self):
        c = _parse_set_cookie("sid=x; Domain=.example.com")
        assert c["domain"] == ".example.com"

    def test_path_parsed(self):
        c = _parse_set_cookie("sid=x; Path=/api")
        assert c["path"] == "/api"

    def test_max_age_parsed_as_int(self):
        c = _parse_set_cookie("sid=x; Max-Age=3600")
        assert c["max_age"] == 3600

    def test_partitioned_flag_parsed(self):
        c = _parse_set_cookie("sid=x; Secure; Partitioned")
        assert c["partitioned"] is True

    def test_secure_prefix_detected(self):
        c = _parse_set_cookie("__Secure-token=abc; Secure")
        assert c["prefix"] == "__Secure-"
        assert c["name"] == "__Secure-token"

    def test_host_prefix_detected(self):
        c = _parse_set_cookie("__Host-session=abc; Secure; Path=/")
        assert c["prefix"] == "__Host-"

    def test_no_prefix_is_none(self):
        c = _parse_set_cookie("regular=x")
        assert c["prefix"] is None

    def test_all_flags_together(self):
        header = "sessionid=xyz; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com"
        c = _parse_set_cookie(header)
        assert c["secure"] is True
        assert c["httponly"] is True
        assert c["samesite"] == "Lax"
        assert c["path"] == "/"
        assert c["domain"] == "example.com"

    def test_value_not_stored(self):
        """Only length is recorded — raw value must not appear anywhere."""
        c = _parse_set_cookie("token=supersecretvalue123")
        assert "supersecretvalue123" not in str(c)


# ─────────────────────────────────────────────────────────────────────────────
# _is_auth_cookie
# ─────────────────────────────────────────────────────────────────────────────

class TestIsAuthCookie:
    def test_session_is_auth(self):
        assert _is_auth_cookie("session") is True

    def test_jwt_is_auth(self):
        assert _is_auth_cookie("jwt_token") is True

    def test_csrftoken_is_auth(self):
        assert _is_auth_cookie("csrftoken") is True

    def test_access_token_is_auth(self):
        assert _is_auth_cookie("access_token") is True

    def test_preference_cookie_not_auth(self):
        assert _is_auth_cookie("theme_preference") is False

    def test_analytics_not_auth(self):
        assert _is_auth_cookie("_ga") is False

    def test_case_insensitive(self):
        assert _is_auth_cookie("SESSION_ID") is True


# ─────────────────────────────────────────────────────────────────────────────
# _audit_cookie
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditCookie:
    def _cookie(self, **kwargs) -> dict:
        defaults = {
            "name": "session", "value_len": 32,
            "secure": True, "httponly": True, "samesite": "Lax",
            "domain": None, "path": "/", "expires": None,
            "max_age": None, "partitioned": False, "prefix": None,
        }
        defaults.update(kwargs)
        return defaults

    def test_fully_secure_cookie_has_no_issues(self):
        issues = _audit_cookie(self._cookie(), is_https=True)
        assert issues == []

    def test_missing_secure_on_https_generates_issue(self):
        issues = _audit_cookie(self._cookie(secure=False), is_https=True)
        checks = _issue_checks(issues)
        assert "Secure flag missing" in checks

    def test_missing_secure_on_http_no_issue(self):
        issues = _audit_cookie(self._cookie(secure=False), is_https=False)
        checks = _issue_checks(issues)
        assert "Secure flag missing" not in checks

    def test_missing_httponly_generates_issue(self):
        issues = _audit_cookie(self._cookie(httponly=False), is_https=True)
        checks = _issue_checks(issues)
        assert "HttpOnly flag missing" in checks

    def test_samesite_none_without_secure_generates_issue(self):
        issues = _audit_cookie(
            self._cookie(name="tracker", samesite="None", secure=False),
            is_https=True,
        )
        checks = _issue_checks(issues)
        assert "SameSite=None without Secure" in checks

    def test_samesite_none_with_secure_generates_info_issue(self):
        issues = _audit_cookie(
            self._cookie(name="embed", samesite="None", secure=True),
            is_https=True,
        )
        checks = _issue_checks(issues)
        assert "SameSite=None (cross-site allowed)" in checks

    def test_missing_samesite_on_auth_cookie_generates_issue(self):
        issues = _audit_cookie(
            self._cookie(name="session", samesite=None), is_https=True
        )
        checks = _issue_checks(issues)
        assert "SameSite attribute missing" in checks

    def test_missing_samesite_on_non_auth_cookie_no_issue(self):
        issues = _audit_cookie(
            self._cookie(name="theme", samesite=None), is_https=True
        )
        checks = _issue_checks(issues)
        assert "SameSite attribute missing" not in checks

    def test_secure_prefix_without_secure_flag_generates_issue(self):
        issues = _audit_cookie(
            self._cookie(name="__Secure-token", prefix="__Secure-", secure=False),
            is_https=True,
        )
        checks = _issue_checks(issues)
        assert "__Secure- prefix without Secure flag" in checks

    def test_host_prefix_with_domain_generates_issue(self):
        issues = _audit_cookie(
            self._cookie(
                name="__Host-session", prefix="__Host-",
                secure=True, domain=".example.com", path="/",
            ),
            is_https=True,
        )
        checks = _issue_checks(issues)
        assert "__Host- prefix violations" in checks

    def test_host_prefix_fully_compliant_no_issue(self):
        issues = _audit_cookie(
            self._cookie(
                name="__Host-session", prefix="__Host-",
                secure=True, domain=None, path="/",
            ),
            is_https=True,
        )
        checks = _issue_checks(issues)
        assert "__Host- prefix violations" not in checks

    def test_broad_domain_on_auth_cookie_generates_issue(self):
        issues = _audit_cookie(
            self._cookie(name="session", domain=".example.com"),
            is_https=True,
        )
        checks = _issue_checks(issues)
        assert "Broad domain scope on auth cookie" in checks

    def test_auth_missing_secure_has_higher_risk_than_non_auth(self):
        auth_issues = _audit_cookie(
            self._cookie(name="session", secure=False), is_https=True
        )
        non_auth_issues = _audit_cookie(
            self._cookie(name="theme", secure=False), is_https=True
        )
        auth_risk = next(i["risk"] for i in auth_issues if i["check"] == "Secure flag missing")
        non_auth_risk = next(i["risk"] for i in non_auth_issues if i["check"] == "Secure flag missing")
        assert auth_risk > non_auth_risk


# ─────────────────────────────────────────────────────────────────────────────
# _audit_all_cookies
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditAllCookies:
    def test_no_cookies_returns_empty(self):
        cookies, issues, risk = _audit_all_cookies([], is_https=True)
        assert cookies == []
        assert issues == []
        assert risk == 0

    def test_secure_cookies_no_issues(self):
        raw = ["sessionid=abc; Secure; HttpOnly; SameSite=Lax"]
        cookies, issues, risk = _audit_all_cookies(raw, is_https=True)
        assert len(cookies) == 1
        assert issues == []
        assert risk == 0

    def test_insecure_cookie_has_issues(self):
        raw = ["session=abc"]
        _, issues, risk = _audit_all_cookies(raw, is_https=True)
        assert len(issues) > 0
        assert risk > 0

    def test_risk_capped_at_80(self):
        # Maximally bad cookies
        raw = [
            "session=x; SameSite=None",        # missing Secure, HttpOnly, SameSite=None without Secure
            "token=y; Domain=.example.com",     # missing Secure, HttpOnly, broad domain
            "auth=z; SameSite=None",
        ]
        _, _, risk = _audit_all_cookies(raw, is_https=True)
        assert risk <= 80

    def test_multiple_cookies_all_parsed(self):
        raw = [
            "session=x; Secure; HttpOnly; SameSite=Strict",
            "pref=y; SameSite=Lax",
        ]
        cookies, _, _ = _audit_all_cookies(raw, is_https=True)
        assert len(cookies) == 2

    def test_issues_list_contains_check_key(self):
        raw = ["session=x"]
        _, issues, _ = _audit_all_cookies(raw, is_https=True)
        for issue in issues:
            assert "check" in issue
            assert "risk" in issue
            assert "description" in issue


# ─────────────────────────────────────────────────────────────────────────────
# @tool wrapper
# ─────────────────────────────────────────────────────────────────────────────

class TestScanCookieTool:
    def _run(self, url: str, raw_headers: list[str]) -> dict:
        with patch("tools.cookie_security._fetch_set_cookie_headers", return_value=raw_headers):
            with patch("tools.cookie_security.is_ssrf_blocked", return_value=False):
                raw = scan_cookie_security.invoke({"url": url})
        return json.loads(raw)

    def test_invalid_scheme(self):
        result = json.loads(scan_cookie_security.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_ssrf_blocked(self):
        with patch("tools.cookie_security.is_ssrf_blocked", return_value=True):
            result = json.loads(scan_cookie_security.invoke({"url": "https://127.0.0.1"}))
        assert result["status"] == "ssrf_blocked"

    def test_no_cookies_returns_zero_risk(self):
        result = self._run("https://example.com", [])
        assert result["cookies_found"] == 0
        assert result["risk_score"] == 0

    def test_secure_cookie_zero_risk(self):
        result = self._run(
            "https://example.com",
            ["sessionid=abc; Secure; HttpOnly; SameSite=Strict"],
        )
        assert result["risk_score"] == 0

    def test_insecure_auth_cookie_nonzero_risk(self):
        result = self._run("https://example.com", ["session=x"])
        assert result["risk_score"] > 0

    def test_cookie_value_not_in_output(self):
        result = self._run("https://example.com", ["session=TOPSECRET"])
        assert "TOPSECRET" not in json.dumps(result)

    def test_output_contains_required_keys(self):
        result = self._run("https://example.com", [])
        for key in ("tool", "status", "url", "is_https", "cookies_found",
                    "cookies", "issues", "issue_count", "risk_score", "recommendations"):
            assert key in result, f"Missing key: {key}"

    def test_is_https_flag_set_correctly(self):
        result = self._run("https://example.com", [])
        assert result["is_https"] is True

    def test_is_https_false_for_http(self):
        result = self._run("http://example.com", [])
        assert result["is_https"] is False

    def test_fetch_error_returns_error_status(self):
        with patch("tools.cookie_security._fetch_set_cookie_headers",
                   side_effect=Exception("connection refused")):
            with patch("tools.cookie_security.is_ssrf_blocked", return_value=False):
                result = json.loads(scan_cookie_security.invoke({"url": "https://example.com"}))
        assert result["status"] == "error"

    def test_multiple_cookies_counted(self):
        result = self._run(
            "https://example.com",
            [
                "session=x; Secure; HttpOnly; SameSite=Lax",
                "pref=y; SameSite=Lax",
            ],
        )
        assert result["cookies_found"] == 2

    def test_recommendations_always_present(self):
        result = self._run("https://example.com", [])
        assert len(result["recommendations"]) >= 1

    def test_no_secure_recommendation_on_insecure_https_cookie(self):
        result = self._run("https://example.com", ["session=x"])
        recs = " ".join(result["recommendations"])
        assert "Secure" in recs or "CRITICAL" in recs

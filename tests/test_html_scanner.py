"""
Tests for HTML & JS Scanner.
All tests use mocked HTTP responses — no real network calls.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.html_scanner import (
    scan_html,
    _scan_secrets,
    _check_forms,
    _check_mixed_content,
    _check_comments,
    _extract_js_endpoints,
)
from bs4 import BeautifulSoup


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — pure functions
# ─────────────────────────────────────────────────────────────────────────────

class TestScanSecrets:

    def test_google_api_key_detected(self):
        text = 'var key = "AIzaSyD-9tSrke72I6MH54IvvMOR4Ej6abcdefg";'
        found = _scan_secrets(text)
        assert any(f["type"] == "Google API Key" for f in found)

    def test_aws_access_key_detected(self):
        text = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
        found = _scan_secrets(text)
        assert any(f["type"] == "AWS Access Key" for f in found)

    def test_stripe_live_key_detected(self):
        text = 'stripe.setPublishableKey("sk_live_abcdefghijklmnopqrstuvwx");'
        found = _scan_secrets(text)
        assert any(f["type"] == "Stripe Live Key" for f in found)

    def test_private_key_header_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        found = _scan_secrets(text)
        assert any("Private Key" in f["type"] for f in found)

    def test_hardcoded_password_detected(self):
        text = 'password = "hunter2secret"'
        found = _scan_secrets(text)
        assert any("Password" in f["type"] for f in found)

    def test_clean_code_no_secrets(self):
        text = "const greeting = 'Hello World'; console.log(greeting);"
        found = _scan_secrets(text)
        assert found == []

    def test_secret_value_redacted(self):
        text = 'AIzaSyD-9tSrke72I6MH54IvvMOR4Ej6abcdefg'
        found = _scan_secrets(text)
        assert found
        assert "***" in found[0]["sample"]
        assert found[0]["sample"] != text  # must NOT expose full key


class TestCheckForms:

    def test_post_form_without_csrf_flagged(self):
        html = '<form method="POST" action="/login"><input name="user"><input name="pass"></form>'
        soup = BeautifulSoup(html, "html.parser")
        issues = _check_forms(soup)
        assert len(issues) == 1
        assert "CSRF" in issues[0]["issue"]

    def test_post_form_with_csrf_token_passes(self):
        html = '<form method="POST"><input name="csrf_token" value="abc"><input name="user"></form>'
        soup = BeautifulSoup(html, "html.parser")
        issues = _check_forms(soup)
        assert issues == []

    def test_get_form_not_flagged(self):
        html = '<form method="GET" action="/search"><input name="q"></form>'
        soup = BeautifulSoup(html, "html.parser")
        issues = _check_forms(soup)
        assert issues == []

    def test_multiple_csrf_less_forms_all_caught(self):
        html = (
            '<form method="POST" action="/a"><input name="x"></form>'
            '<form method="POST" action="/b"><input name="y"></form>'
        )
        soup = BeautifulSoup(html, "html.parser")
        issues = _check_forms(soup)
        assert len(issues) == 2


class TestCheckMixedContent:

    def test_http_script_on_https_page_flagged(self):
        html = '<script src="http://cdn.evil.com/evil.js"></script>'
        soup = BeautifulSoup(html, "html.parser")
        mixed = _check_mixed_content(soup, "https://example.com")
        assert len(mixed) == 1
        assert "evil.js" in mixed[0]

    def test_https_script_on_https_page_clean(self):
        html = '<script src="https://cdn.example.com/app.js"></script>'
        soup = BeautifulSoup(html, "html.parser")
        mixed = _check_mixed_content(soup, "https://example.com")
        assert mixed == []

    def test_http_page_not_checked_for_mixed(self):
        html = '<img src="http://example.com/img.png">'
        soup = BeautifulSoup(html, "html.parser")
        mixed = _check_mixed_content(soup, "http://example.com")
        assert mixed == []


class TestCheckComments:

    def test_password_in_comment_flagged(self):
        html = "<!-- admin password: s3cr3t -->"
        soup = BeautifulSoup(html, "html.parser")
        comments = _check_comments(soup)
        assert len(comments) == 1

    def test_ip_address_in_comment_flagged(self):
        html = "<!-- internal server: 192.168.1.100 -->"
        soup = BeautifulSoup(html, "html.parser")
        comments = _check_comments(soup)
        assert len(comments) == 1

    def test_benign_comment_not_flagged(self):
        html = "<!-- navigation bar -->"
        soup = BeautifulSoup(html, "html.parser")
        comments = _check_comments(soup)
        assert comments == []


class TestExtractJsEndpoints:

    def test_api_endpoint_extracted(self):
        js = 'fetch("/api/v1/users").then(r => r.json())'
        endpoints = _extract_js_endpoints(js)
        assert "/api/v1/users" in endpoints

    def test_non_api_path_not_extracted(self):
        js = 'window.location = "/home";'
        endpoints = _extract_js_endpoints(js)
        assert endpoints == []


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests — mocked HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _mock_response(html: str, url: str = "https://example.com", cookies=None):
    resp = MagicMock()
    resp.text    = html
    resp.url     = url
    resp.cookies = cookies or []
    return resp


class TestScanHtmlIntegration:

    def _run(self, html: str, url: str = "https://example.com") -> dict:
        with patch("tools.html_scanner.safe_get", return_value=_mock_response(html, url)):
            return json.loads(scan_html.invoke({"url": url}))

    def test_invalid_scheme_rejected(self):
        result = json.loads(scan_html.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_clean_page_zero_risk(self):
        html = "<html><head><title>Clean</title></head><body><p>Hello</p></body></html>"
        result = self._run(html)
        assert result["status"] == "completed"
        assert result["risk_score"] == 0
        assert result["exposed_secrets"] == []

    def test_exposed_api_key_raises_risk(self):
        html = '<script>var key="AIzaSyD-9tSrke72I6MH54IvvMOR4Ej6abcdefg";</script>'
        result = self._run(html)
        assert result["risk_score"] >= 30
        assert result["exposed_secrets"]

    def test_csrf_less_form_detected(self):
        html = '<form method="POST" action="/submit"><input name="email"></form>'
        result = self._run(html)
        assert result["form_issues"]
        assert result["risk_score"] >= 20

    def test_mixed_content_detected(self):
        html = '<img src="http://cdn.example.com/img.png">'
        result = self._run(html)
        assert result["mixed_content"]
        assert result["risk_score"] >= 15

    def test_sensitive_comment_detected(self):
        html = "<!-- TODO: remove hardcoded password admin123 -->"
        result = self._run(html)
        assert result["sensitive_comments"]
        assert result["risk_score"] >= 10

    def test_recommendations_generated(self):
        html = '<script>var key="AIzaSyD-9tSrke72I6MH54IvvMOR4Ej6abcdefg";</script>'
        result = self._run(html)
        assert len(result["recommendations"]) >= 1

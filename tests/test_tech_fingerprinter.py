"""
Tests for Technology Fingerprinter.
All HTTP calls are mocked.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.tech_fingerprinter import (
    fingerprint_technologies,
    _check_fallback_cves,
    _version_tuple,
)


class TestVersionTuple:
    def test_three_part(self):   assert _version_tuple("3.6.1") == (3, 6, 1)
    def test_two_part(self):     assert _version_tuple("3.6")   == (3, 6)
    def test_invalid(self):      assert _version_tuple("x.y")   == (0,)


class TestCheckKnownCves:

    def test_vulnerable_jquery_flagged(self):
        cves = _check_fallback_cves("jQuery", "1.11.0")
        assert any("CVE" in c["cve"] for c in cves)

    def test_safe_jquery_not_flagged(self):
        cves = _check_fallback_cves("jQuery", "3.7.0")
        assert cves == []

    def test_vulnerable_bootstrap_flagged(self):
        cves = _check_fallback_cves("Bootstrap", "3.3.7")
        assert cves

    def test_unknown_library_not_flagged(self):
        cves = _check_fallback_cves("Lodash", "4.17.20")
        assert cves == []


def _mock_resp(html: str, headers: dict = None, url: str = "https://example.com"):
    resp = MagicMock()
    resp.text    = html
    resp.url     = url
    resp.headers = headers or {}
    return resp


class TestFingerprintTechnologies:

    def _run(self, html: str, headers: dict = None, url: str = "https://example.com") -> dict:
        with patch("tools.tech_fingerprinter.safe_get",
                   return_value=_mock_resp(html, headers or {}, url)):
            return json.loads(fingerprint_technologies.invoke({"url": url}))

    def test_invalid_scheme_rejected(self):
        result = json.loads(fingerprint_technologies.invoke({"url": "ftp://x.com"}))
        assert result["status"] == "invalid_url"

    def test_wordpress_detected(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/hello/style.css">'
        result = self._run(html)
        assert "WordPress" in result["detected_technologies"]

    def test_nextjs_detected(self):
        # Wappalyzer detects Next.js via x-powered-by header (the most reliable passive signal)
        result = self._run("<html></html>", headers={"x-powered-by": "Next.js 13.4.0"})
        assert "Next.js" in result["detected_technologies"]

    def test_jquery_version_extracted(self):
        html = '<script src="/js/jquery-3.3.1.min.js"></script>'
        result = self._run(html)
        libs = {e["library"]: e["version"] for e in result["versioned_libraries"]}
        assert "jQuery" in libs
        assert libs["jQuery"] == "3.3.1"

    def test_vulnerable_jquery_cve_reported(self):
        html = '<script src="/js/jquery-1.11.0.min.js"></script>'
        result = self._run(html)
        assert result["cve_findings"]
        assert result["risk_score"] > 0

    def test_safe_jquery_no_cve(self):
        html = '<script src="/js/jquery-3.7.0.min.js"></script>'
        result = self._run(html)
        assert result["cve_findings"] == []

    def test_nginx_detected_from_header(self):
        result = self._run("<html></html>", headers={"Server": "nginx/1.24.0"})
        # Wappalyzer names it "Nginx" (capital N)
        assert "Nginx" in result["detected_technologies"]

    def test_php_version_disclosure_flagged(self):
        result = self._run("<html></html>", headers={"X-Powered-By": "PHP/7.2.0"})
        assert "PHP" in result["detected_technologies"]
        assert any("X-Powered-By" in r for r in result["recommendations"])

    def test_clean_page_zero_risk(self):
        result = self._run("<html><body>Hello</body></html>")
        assert result["risk_score"] == 0
        assert result["cve_findings"] == []

    def test_google_analytics_detected(self):
        # Wappalyzer detects Google Analytics from the gtag/js script src URL
        html = '<script src="https://www.googletagmanager.com/gtag/js?id=G-XXX" async></script>'
        result = self._run(html)
        assert "Google Analytics" in result["detected_technologies"]

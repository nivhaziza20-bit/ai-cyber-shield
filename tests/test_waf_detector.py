"""Tests for WAF Detector. All HTTP calls mocked."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.waf_detector import detect_waf, _score_headers


# ─────────────────────────────────────────────────────────────────────────────
# Unit — header scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreHeaders:

    def test_cloudflare_cf_ray_detected(self):
        waf, conf = _score_headers({"cf-ray": "abc123", "Server": "cloudflare"}, [])
        assert waf == "Cloudflare"
        assert conf >= 35

    def test_akamai_header_detected(self):
        waf, conf = _score_headers({"x-akamai-transformed": "1"}, [])
        assert waf == "Akamai"
        assert conf >= 35

    def test_sucuri_header_detected(self):
        waf, conf = _score_headers({"x-sucuri-id": "12345"}, [])
        assert waf == "Sucuri"

    def test_incapsula_cookie_detected(self):
        waf, conf = _score_headers({}, ["incap_ses_abc=xyz"])
        assert waf == "Imperva / Incapsula"

    def test_no_waf_returns_none(self):
        waf, conf = _score_headers({"Server": "nginx", "Content-Type": "text/html"}, [])
        assert waf is None
        assert conf == 0

    def test_fastly_request_id(self):
        waf, conf = _score_headers({"x-fastly-request-id": "abc"}, [])
        assert waf == "Fastly"


# ─────────────────────────────────────────────────────────────────────────────
# Integration — mocked HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _mock_resp(status=200, headers=None, url="https://example.com"):
    r = MagicMock()
    r.status_code = status
    r.headers     = headers or {}
    r.url         = url
    r.text        = ""
    r.content     = b""
    return r


class TestDetectWaf:

    def _run(self, initial_headers=None, probe_status=200):
        init_resp  = _mock_resp(headers=initial_headers or {})
        probe_resp = _mock_resp(status=probe_status)
        with patch("tools.waf_detector.safe_get", side_effect=[init_resp, probe_resp]):
            return json.loads(detect_waf.invoke({"url": "https://example.com"}))

    def test_invalid_url_rejected(self):
        result = json.loads(detect_waf.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_ssrf_blocked(self):
        from tools.http_utils import SSRFError
        with patch("tools.waf_detector.safe_get", side_effect=SSRFError("blocked")):
            result = json.loads(detect_waf.invoke({"url": "https://192.168.1.1"}))
        assert result["status"] == "ssrf_blocked"

    def test_cloudflare_detected_via_header(self):
        result = self._run(initial_headers={"cf-ray": "abc123", "Server": "cloudflare"})
        assert result["status"] == "completed"
        assert result["waf_detected"] is True
        assert "Cloudflare" in result["waf_name"]
        assert result["protection_score"] > 50

    def test_no_waf_probe_allowed(self):
        result = self._run(initial_headers={"Server": "nginx"}, probe_status=200)
        assert result["waf_detected"] is False
        assert result["protection_score"] <= 40

    def test_probe_blocked_raises_confidence(self):
        result = self._run(initial_headers={"Server": "nginx"}, probe_status=403)
        assert result["probe_blocked"] is True
        assert result["waf_detected"] is True  # unknown WAF inferred from blocking

    def test_no_waf_recommendation_present(self):
        result = self._run(initial_headers={}, probe_status=200)
        assert any("WAF" in r for r in result["recommendations"])

    def test_protection_score_high_when_cloudflare(self):
        result = self._run(
            initial_headers={"cf-ray": "xyz", "Server": "cloudflare"},
            probe_status=403,
        )
        assert result["protection_score"] >= 70

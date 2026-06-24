"""Tests for HSTS Preload Checker. All HTTP calls mocked."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.hsts_preload import check_hsts_preload, _parse_hsts, _query_preload_list


# ─────────────────────────────────────────────────────────────────────────────
# Unit — header parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestParseHsts:

    def test_full_strong_header(self):
        h = _parse_hsts("max-age=31536000; includeSubDomains; preload")
        assert h["max_age"] == 31536000
        assert h["include_sub"] is True
        assert h["preload_directive"] is True

    def test_minimal_header(self):
        h = _parse_hsts("max-age=300")
        assert h["max_age"] == 300
        assert h["include_sub"] is False
        assert h["preload_directive"] is False

    def test_case_insensitive(self):
        h = _parse_hsts("max-age=31536000; IncludeSubDomains; PRELOAD")
        assert h["include_sub"] is True
        assert h["preload_directive"] is True

    def test_spaces_handled(self):
        h = _parse_hsts("  max-age = 31536000 ;  includeSubDomains  ")
        assert h["max_age"] == 31536000
        assert h["include_sub"] is True

    def test_empty_string(self):
        h = _parse_hsts("")
        assert h["max_age"] == 0
        assert h["include_sub"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Integration — mocked HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _mock_resp(hsts_header="", url="https://example.com"):
    r = MagicMock()
    r.status_code = 200
    r.url         = url
    r.headers     = {"Strict-Transport-Security": hsts_header} if hsts_header else {}
    return r


class TestCheckHstsPreload:

    def _run(self, hsts="", preload_status="preloaded", url="https://example.com"):
        resp = _mock_resp(hsts_header=hsts, url=url)
        with patch("tools.hsts_preload.safe_get", return_value=resp):
            with patch("tools.hsts_preload._query_preload_list", return_value=preload_status):
                return json.loads(check_hsts_preload.invoke({"url": url}))

    def test_invalid_url_rejected(self):
        result = json.loads(check_hsts_preload.invoke({"url": "ftp://x.com"}))
        assert result["status"] == "invalid_url"

    def test_ssrf_blocked(self):
        from tools.http_utils import SSRFError
        with patch("tools.hsts_preload.safe_get", side_effect=SSRFError("blocked")):
            result = json.loads(check_hsts_preload.invoke({"url": "https://192.168.1.1"}))
        assert result["status"] == "ssrf_blocked"

    def test_missing_hsts_high_risk(self):
        result = self._run(hsts="", preload_status="unknown")
        assert result["hsts_present"] is False
        assert result["risk_score"] >= 20
        assert result["hsts_quality"] == "none"

    def test_weak_max_age_penalised(self):
        result = self._run(hsts="max-age=300", preload_status="unknown")
        assert result["risk_score"] > 0
        assert result["hsts_quality"] == "weak"

    def test_missing_include_subdomains_penalised(self):
        result = self._run(hsts="max-age=31536000", preload_status="unknown")
        issues = result["issues"]
        assert any("includeSubDomains" in i for i in issues)

    def test_strong_hsts_low_risk(self):
        result = self._run(
            hsts="max-age=31536000; includeSubDomains; preload",
            preload_status="preloaded",
        )
        assert result["hsts_quality"] == "strong"
        assert result["preloaded"] is True
        assert result["risk_score"] == 0

    def test_preloaded_reduces_risk(self):
        result_not_preloaded = self._run(hsts="max-age=31536000", preload_status="unknown")
        result_preloaded     = self._run(hsts="max-age=31536000", preload_status="preloaded")
        assert result_preloaded["risk_score"] <= result_not_preloaded["risk_score"]

    def test_not_preloaded_recommendation(self):
        result = self._run(
            hsts="max-age=31536000; includeSubDomains; preload",
            preload_status="eligible",
        )
        recs = " ".join(result["recommendations"])
        assert "hstspreload" in recs.lower() or "preload" in recs.lower()

    def test_www_stripped_from_domain(self):
        result = self._run(url="https://www.example.com", hsts="max-age=31536000")
        assert result["domain"] == "example.com"

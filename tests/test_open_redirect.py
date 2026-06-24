"""Tests for Open Redirect Scanner. All HTTP calls mocked."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.open_redirect import scan_open_redirects, _extract_candidates


# ─────────────────────────────────────────────────────────────────────────────
# Unit — candidate extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractCandidates:

    def test_next_param_in_anchor(self):
        html = '<a href="/login?next=/dashboard">Login</a>'
        cands = _extract_candidates(html, "https://example.com", "example.com")
        assert any(c["param"] == "next" for c in cands)

    def test_url_param_in_anchor(self):
        html = '<a href="/go?url=https://example.com/home">Go</a>'
        cands = _extract_candidates(html, "https://example.com", "example.com")
        assert any(c["param"] == "url" for c in cands)

    def test_redirect_param_in_form_input(self):
        html = ('<form action="/auth">'
                '<input name="redirect" value="/">'
                '</form>')
        cands = _extract_candidates(html, "https://example.com", "example.com")
        assert any(c["param"] == "redirect" for c in cands)

    def test_no_redirect_params_empty(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        cands = _extract_candidates(html, "https://example.com", "example.com")
        assert cands == []

    def test_cross_origin_link_excluded(self):
        html = '<a href="https://evil.com/login?next=/x">External</a>'
        cands = _extract_candidates(html, "https://example.com", "example.com")
        assert cands == []

    def test_cap_at_15_candidates(self):
        hrefs = "".join(
            f'<a href="/page{i}?next=x">L</a>' for i in range(30)
        )
        html  = f"<html>{hrefs}</html>"
        cands = _extract_candidates(html, "https://example.com", "example.com")
        assert len(cands) <= 15


# ─────────────────────────────────────────────────────────────────────────────
# Integration — mocked HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _make_resp(status=200, body="<html></html>", headers=None, url="https://example.com"):
    r = MagicMock()
    r.status_code = status
    r.text        = body
    r.content     = body.encode()
    r.headers     = headers or {}
    r.url         = url
    return r


class TestScanOpenRedirects:

    def _run(self, html="<html></html>", probe_location=None, url="https://example.com"):
        """
        probe_location: if set, probe response will have a Location header
                        with this value (simulates confirmed redirect).
        """
        home_resp  = _make_resp(body=html, url=url)
        probe_resp = _make_resp(
            status=302 if probe_location else 200,
            headers={"Location": probe_location} if probe_location else {},
        )

        with patch("tools.open_redirect.safe_get", return_value=home_resp):
            with patch("tools.open_redirect.requests.Session") as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = probe_resp
                MockSession.return_value = mock_session
                return json.loads(scan_open_redirects.invoke({"url": url}))

    def test_invalid_url_rejected(self):
        result = json.loads(scan_open_redirects.invoke({"url": "ftp://x.com"}))
        assert result["status"] == "invalid_url"

    def test_ssrf_blocked(self):
        from tools.http_utils import SSRFError
        with patch("tools.open_redirect.safe_get", side_effect=SSRFError("blocked")):
            result = json.loads(scan_open_redirects.invoke({"url": "https://192.168.1.1"}))
        assert result["status"] == "ssrf_blocked"

    def test_no_redirect_params_zero_risk(self):
        result = self._run(html="<html><a href='/about'>About</a></html>")
        assert result["candidates_found"] == 0
        assert result["risk_score"] == 0
        assert result["confirmed_redirects"] == []

    def test_candidate_detected(self):
        html = '<html><a href="https://example.com/login?next=/x">Login</a></html>'
        result = self._run(html=html)
        assert result["candidates_found"] >= 1

    def test_confirmed_redirect_high_risk(self):
        html = '<html><a href="https://example.com/go?next=/x">Go</a></html>'
        result = self._run(
            html=html,
            probe_location="https://example.com/redirect-test-AICYBERSHIELD",
        )
        assert len(result["confirmed_redirects"]) >= 1
        assert result["risk_score"] >= 25

    def test_unconfirmed_candidates_low_risk(self):
        html = '<html><a href="https://example.com/login?return=/x">Login</a></html>'
        result = self._run(html=html, probe_location=None)
        assert result["candidates_found"] >= 1
        assert result["confirmed_redirects"] == []
        assert result["risk_score"] < 25

    def test_recommendation_present(self):
        result = self._run()
        assert len(result["recommendations"]) >= 1

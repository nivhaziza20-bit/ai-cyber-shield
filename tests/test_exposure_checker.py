"""
Tests for Exposure Checker.
All HTTP calls are mocked — no real network.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from bs4 import BeautifulSoup
from tools.exposure_checker import (
    check_exposure,
    _find_source_map_urls,
    _check_sri,
    _check_http_methods,
)


# ─────────────────────────────────────────────────────────────────────────────
# Unit — source map detection
# ─────────────────────────────────────────────────────────────────────────────

class TestFindSourceMapUrls:
    def test_script_tag_generates_map_url(self):
        html = '<script src="/js/app.js"></script>'
        maps = _find_source_map_urls(html, "https://example.com")
        assert any("app.js.map" in m for m in maps)

    def test_inline_sourcemappingurl_detected(self):
        html = "<script>//# sourceMappingURL=bundle.js.map\n</script>"
        maps = _find_source_map_urls(html, "https://example.com")
        assert any("bundle.js.map" in m for m in maps)

    def test_no_scripts_returns_empty(self):
        html = "<p>No scripts here</p>"
        maps = _find_source_map_urls(html, "https://example.com")
        assert maps == []

    def test_max_10_returned(self):
        # Create many script tags
        html = "".join(f'<script src="/js/lib{i}.js"></script>' for i in range(20))
        maps = _find_source_map_urls(html, "https://example.com")
        assert len(maps) <= 10


# ─────────────────────────────────────────────────────────────────────────────
# Unit — SRI checker
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckSri:
    def _soup(self, html):
        return BeautifulSoup(html, "html.parser")

    def test_external_script_without_integrity_flagged(self):
        soup = self._soup('<script src="https://cdn.example.com/lib.js"></script>')
        missing = _check_sri(soup, "mysite.com")
        assert missing

    def test_external_script_with_integrity_ok(self):
        soup = self._soup(
            '<script src="https://cdn.example.com/lib.js" '
            'integrity="sha384-abc" crossorigin="anonymous"></script>'
        )
        missing = _check_sri(soup, "mysite.com")
        assert missing == []

    def test_same_origin_script_not_flagged(self):
        soup = self._soup('<script src="https://mysite.com/app.js"></script>')
        missing = _check_sri(soup, "mysite.com")
        assert missing == []

    def test_relative_script_not_flagged(self):
        soup = self._soup('<script src="/js/app.js"></script>')
        missing = _check_sri(soup, "mysite.com")
        assert missing == []


# ─────────────────────────────────────────────────────────────────────────────
# Unit — HTTP methods
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckHttpMethods:
    def _session_with_options(self, allow_header: str):
        session = MagicMock()
        resp = MagicMock()
        resp.headers = {"Allow": allow_header}
        session.options.return_value = resp
        return session

    def test_trace_method_flagged(self):
        session = self._session_with_options("GET, POST, TRACE")
        dangerous, issues = _check_http_methods("https://example.com", session)
        assert "TRACE" in dangerous
        assert issues

    def test_put_method_flagged(self):
        session = self._session_with_options("GET, POST, PUT")
        dangerous, issues = _check_http_methods("https://example.com", session)
        assert "PUT" in dangerous

    def test_delete_method_flagged(self):
        session = self._session_with_options("GET, POST, DELETE")
        dangerous, issues = _check_http_methods("https://example.com", session)
        assert "DELETE" in dangerous

    def test_only_get_post_safe(self):
        session = self._session_with_options("GET, POST, HEAD, OPTIONS")
        dangerous, issues = _check_http_methods("https://example.com", session)
        assert dangerous == []
        assert issues == []

    def test_no_allow_header_returns_empty(self):
        session = MagicMock()
        resp = MagicMock()
        resp.headers = {}
        session.options.return_value = resp
        dangerous, issues = _check_http_methods("https://example.com", session)
        assert dangerous == []


# ─────────────────────────────────────────────────────────────────────────────
# Integration — mocked HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _make_resp(status: int, body: str, headers: dict = None):
    resp = MagicMock()
    resp.status_code = status
    resp.text        = body
    resp.content     = body.encode()
    resp.headers     = headers or {}
    resp.url         = "https://example.com"
    return resp


class TestCheckExposure:

    def _run(self, homepage_html: str = "<html></html>",
             exposed_paths: dict = None,
             url: str = "https://example.com") -> dict:
        """
        exposed_paths: {"/path": (status, body)} — paths that return non-404
        """
        exposed_paths = exposed_paths or {}

        home_resp = _make_resp(200, homepage_html)

        def mock_session_get(probe_url, **kwargs):
            for path, (status, body) in exposed_paths.items():
                if probe_url.endswith(path):
                    return _make_resp(status, body)
            return _make_resp(404, "Not Found")

        def mock_session_options(probe_url, **kwargs):
            return _make_resp(200, "", {"Allow": "GET, POST"})

        mock_session = MagicMock()
        mock_session.get.side_effect  = mock_session_get
        mock_session.options.side_effect = mock_session_options

        with patch("tools.exposure_checker.is_ssrf_blocked", return_value=False):
            with patch("tools.exposure_checker.safe_get", return_value=home_resp):
                with patch("tools.exposure_checker.requests.Session",
                           return_value=mock_session):
                    return json.loads(check_exposure.invoke({"url": url}))

    def test_invalid_scheme_rejected(self):
        result = json.loads(check_exposure.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_clean_site_zero_risk(self):
        result = self._run()
        assert result["status"] == "completed"
        assert result["risk_score"] == 0
        assert result["exposed_files"] == []

    def test_git_head_exposure_detected(self):
        result = self._run(
            exposed_paths={"/.git/HEAD": (200, "ref: refs/heads/main\n")}
        )
        assert any("git" in f["description"].lower() for f in result["exposed_files"])
        assert result["risk_score"] >= 50

    def test_env_file_exposure_detected(self):
        result = self._run(
            exposed_paths={"/.env": (200, "DB_PASSWORD=secret\nAPI_KEY=abc123\n")}
        )
        assert any(".env" in f["path"] for f in result["exposed_files"])
        assert result["risk_score"] >= 50

    def test_fake_200_on_nonexistent_path_not_flagged(self):
        # Many sites return custom 200 pages for 404 — should NOT flag
        result = self._run(
            # .env returns 200 but body doesn't look like env file
            exposed_paths={"/.env": (200, "<html><body>Not Found</body></html>")}
        )
        env_files = [f for f in result["exposed_files"] if ".env" in f["path"]]
        assert env_files == []

    def test_trace_method_flagged(self):
        home_resp = _make_resp(200, "<html></html>")
        options_resp = _make_resp(200, "", {"Allow": "GET, POST, TRACE"})
        mock_session = MagicMock()
        mock_session.get.return_value  = _make_resp(404, "")
        mock_session.options.return_value = options_resp

        with patch("tools.exposure_checker.is_ssrf_blocked", return_value=False):
            with patch("tools.exposure_checker.safe_get", return_value=home_resp):
                with patch("tools.exposure_checker.requests.Session",
                           return_value=mock_session):
                    result = json.loads(check_exposure.invoke({"url": "https://example.com"}))

        assert "TRACE" in result["dangerous_methods"]
        assert result["risk_score"] >= 20

    def test_sri_missing_detected(self):
        html = '<script src="https://cdn.jquery.com/jquery.min.js"></script>'
        result = self._run(homepage_html=html)
        assert len(result["sri_missing"]) >= 1

    def test_directory_listing_detected(self):
        html = "<html><head><title>Index of /</title></head></html>"
        result = self._run(homepage_html=html)
        assert result["directory_listing"] is True
        assert result["risk_score"] >= 15

    def test_ssrf_blocked(self):
        with patch("tools.exposure_checker.is_ssrf_blocked", return_value=True):
            result = json.loads(check_exposure.invoke({"url": "https://192.168.1.1"}))
        assert result["status"] == "ssrf_blocked"

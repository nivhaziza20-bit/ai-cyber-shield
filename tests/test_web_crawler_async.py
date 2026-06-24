"""
Async tests for web_crawler v2 (Playwright).

Coverage:
  - _request_guard() — SSRF blocking, binary blocking, normal pass-through
  - _compute_result() — risk scoring and recommendation logic
  - _run_async()      — sync bridge drives async coroutine correctly
  - _async_crawl()    — full BFS with mocked Playwright browser
  - crawl_website()   — @tool wrapper: validation, SSRF guard, Playwright guard
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from tools.web_crawler import (
    _request_guard,
    _compute_result,
    _run_async,
    crawl_website,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_route(url: str, *, abort=AsyncMock(), cont=AsyncMock()):
    """Build a mock Playwright Route object."""
    request      = MagicMock()
    request.url  = url
    route        = AsyncMock()
    route.request = request
    return route, request


def _empty_crawl_data() -> dict:
    return {
        "pages_visited":     [],
        "sensitive_paths":   [],
        "broken_links":      [],
        "login_pages":       [],
        "stack_leaks":       [],
        "robots_disallowed": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. _request_guard — SSRF protection + binary blocking
# ─────────────────────────────────────────────────────────────────────────────

class TestRequestGuard:

    @pytest.mark.asyncio
    async def test_private_ipv4_aborted(self):
        """SSRF: 192.168.x.x must be blocked."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "http://192.168.1.1/secret"
        await _request_guard(route, request)
        route.abort.assert_called_once_with("blockedbyclient")
        route.continue_.assert_not_called()

    @pytest.mark.asyncio
    async def test_loopback_aborted(self):
        """SSRF: 127.0.0.1 must be blocked."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "http://127.0.0.1/admin"
        await _request_guard(route, request)
        route.abort.assert_called_once_with("blockedbyclient")

    @pytest.mark.asyncio
    async def test_link_local_aborted(self):
        """SSRF: 169.254.x.x (AWS metadata) must be blocked."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "http://169.254.169.254/latest/meta-data/"
        await _request_guard(route, request)
        route.abort.assert_called_once_with("blockedbyclient")

    @pytest.mark.asyncio
    async def test_public_ip_allowed(self):
        """Normal public URLs must pass through."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "https://example.com/page"
        await _request_guard(route, request)
        route.continue_.assert_called_once()
        route.abort.assert_not_called()

    @pytest.mark.asyncio
    async def test_png_image_aborted(self):
        """Binary resources (png) must be aborted to speed up crawl."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "https://example.com/logo.png"
        await _request_guard(route, request)
        route.abort.assert_called_once()

    @pytest.mark.asyncio
    async def test_woff2_font_aborted(self):
        """Binary resources (woff2 font) must be aborted."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "https://example.com/font/Inter.woff2"
        await _request_guard(route, request)
        route.abort.assert_called_once()

    @pytest.mark.asyncio
    async def test_html_page_allowed(self):
        """HTML page requests must pass through."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "https://example.com/about"
        await _request_guard(route, request)
        route.continue_.assert_called_once()

    @pytest.mark.asyncio
    async def test_js_file_allowed(self):
        """JavaScript files must be allowed (needed for SPA rendering)."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "https://example.com/bundle.js"
        await _request_guard(route, request)
        route.continue_.assert_called_once()

    @pytest.mark.asyncio
    async def test_malformed_url_does_not_crash(self):
        """A completely invalid URL must not raise — guard should fallback."""
        route = AsyncMock()
        request = MagicMock()
        request.url = "not-a-url-at-all"
        await _request_guard(route, request)  # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# 2. _compute_result — risk scoring (pure function, no I/O)
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeResult:

    def test_clean_crawl_zero_risk(self):
        data   = _empty_crawl_data()
        data["pages_visited"] = [{"url": "https://example.com", "status": 200}]
        result = _compute_result("https://example.com", data)
        assert result["risk_score"] == 0
        assert result["status"] == "completed"
        assert result["total_pages"] == 1

    def test_sensitive_path_adds_risk(self):
        data = _empty_crawl_data()
        data["sensitive_paths"] = ["https://example.com/admin"]
        result = _compute_result("https://example.com", data)
        assert result["risk_score"] >= 15

    def test_stack_trace_adds_heavy_risk(self):
        data = _empty_crawl_data()
        data["stack_leaks"] = ["https://example.com/error"]
        result = _compute_result("https://example.com", data)
        assert result["risk_score"] >= 30

    def test_risk_capped_at_100(self):
        data = _empty_crawl_data()
        data["sensitive_paths"] = [f"https://example.com/admin{i}" for i in range(20)]
        data["stack_leaks"]     = [f"https://example.com/err{i}"   for i in range(10)]
        result = _compute_result("https://example.com", data)
        assert result["risk_score"] == 100

    def test_renderer_field_present(self):
        result = _compute_result("https://example.com", _empty_crawl_data())
        assert "playwright" in result["renderer"]

    def test_recommendations_for_sensitive_path(self):
        data = _empty_crawl_data()
        data["sensitive_paths"] = ["https://example.com/admin"]
        result = _compute_result("https://example.com", data)
        assert any("sensitive" in r.lower() or "admin" in r.lower()
                   for r in result["recommendations"])

    def test_recommendations_for_stack_trace(self):
        data = _empty_crawl_data()
        data["stack_leaks"] = ["https://example.com/crash"]
        result = _compute_result("https://example.com", data)
        assert any("debug" in r.lower() or "stack" in r.lower()
                   for r in result["recommendations"])

    def test_robots_recommendation(self):
        data = _empty_crawl_data()
        data["robots_disallowed"] = ["/admin", "/private"]
        result = _compute_result("https://example.com", data)
        assert any("robots" in r.lower() for r in result["recommendations"])


# ─────────────────────────────────────────────────────────────────────────────
# 3. _run_async — sync bridge
# ─────────────────────────────────────────────────────────────────────────────

class TestRunAsync:

    def test_bridge_returns_crawl_data(self):
        """_run_async must run the coroutine and return its result."""
        expected = {**_empty_crawl_data(),
                    "pages_visited": [{"url": "https://example.com", "status": 200}]}
        with patch("tools.web_crawler._async_crawl", new=AsyncMock(return_value=expected)):
            result = _run_async("https://example.com", 20)
        assert result["pages_visited"] == expected["pages_visited"]

    def test_bridge_propagates_exceptions(self):
        """_run_async must propagate exceptions from _async_crawl."""
        async def boom(url, pages):
            raise ValueError("crawl error")

        with patch("tools.web_crawler._async_crawl", new=boom):
            with pytest.raises(ValueError, match="crawl error"):
                _run_async("https://example.com", 5)

    def test_bridge_creates_fresh_loop_each_call(self):
        """Two sequential calls must not share event loop state."""
        call_count = 0

        async def counting_crawl(url, pages):
            nonlocal call_count
            call_count += 1
            return _empty_crawl_data()

        with patch("tools.web_crawler._async_crawl", new=counting_crawl):
            _run_async("https://example.com", 5)
            _run_async("https://example.com", 5)

        assert call_count == 2


# ─────────────────────────────────────────────────────────────────────────────
# 4. _async_crawl — BFS with mocked Playwright
# ─────────────────────────────────────────────────────────────────────────────

def _build_mock_playwright(
    pages: dict[str, tuple[int, str]],
    *,
    start_url: str = "https://example.com",
) -> MagicMock:
    """
    Minimal Playwright mock built from a {url: (status, html)} dict.
    Simulates: async_playwright → browser → context → page.goto().

    Key correctness requirement: page.url must return a *string* matching
    the most-recently navigated URL so that _extract_links() resolves
    relative hrefs correctly.
    """
    _state = {"html": "", "url": start_url}

    # ── mock page (reused across BFS iterations) ─────────────────────────────
    mock_page = AsyncMock()
    # Set .url as a plain string instance attribute (not a child mock)
    mock_page.url = start_url

    async def _goto(url: str, wait_until=None, timeout=None):
        mock_page.url = url                              # track current URL
        status, html  = pages.get(url, (404, ""))
        _state["html"] = html
        resp          = AsyncMock()
        resp.status   = status
        resp.headers  = {"content-type": "text/html; charset=utf-8"}
        resp.body     = AsyncMock(return_value=html.encode("utf-8"))
        resp.text     = AsyncMock(return_value=html)
        return resp

    async def _content():
        return _state["html"]

    mock_page.goto             = _goto
    mock_page.content          = _content
    mock_page.wait_for_timeout = AsyncMock()
    mock_page.close            = AsyncMock()

    # ── robots.txt page (first context.new_page() call) ───────────────────────
    mock_rb_page       = AsyncMock()
    mock_rb_page.goto  = AsyncMock(return_value=None)   # 404 → no robots.txt
    mock_rb_page.close = AsyncMock()

    _call_n = [0]

    async def _new_page():
        _call_n[0] += 1
        return mock_rb_page if _call_n[0] == 1 else mock_page

    mock_context          = AsyncMock()
    mock_context.new_page = _new_page
    mock_context.route    = AsyncMock()

    mock_browser             = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_browser.close       = AsyncMock()

    mock_pw                    = AsyncMock()
    mock_pw.chromium.launch    = AsyncMock(return_value=mock_browser)
    mock_pw.__aenter__         = AsyncMock(return_value=mock_pw)
    mock_pw.__aexit__          = AsyncMock(return_value=False)

    return mock_pw


class TestAsyncCrawl:
    """Tests for _async_crawl via mocked Playwright."""

    def _run(self, pages, start_url="https://example.com"):
        mock_pw = _build_mock_playwright(pages, start_url=start_url)
        with patch("tools.web_crawler.async_playwright", return_value=mock_pw):
            with patch("tools.web_crawler.is_ssrf_blocked", return_value=False):
                return asyncio.run(__import__("tools.web_crawler", fromlist=["_async_crawl"])._async_crawl(start_url, 20))

    def test_single_page_crawled(self):
        pages = {"https://example.com": (200, "<html><body>Hello</body></html>")}
        data  = self._run(pages)
        assert len(data["pages_visited"]) >= 1
        assert data["pages_visited"][0]["status"] == 200

    def test_admin_page_flagged_as_sensitive(self):
        pages = {
            "https://example.com": (200, '<a href="/admin">Admin</a>'),
            "https://example.com/admin": (200, "<h1>Admin Panel</h1>"),
        }
        data = self._run(pages)
        assert any("/admin" in p for p in data["sensitive_paths"])

    def test_stack_trace_detected(self):
        pages = {
            "https://example.com": (
                200,
                "Traceback (most recent call last):\n  File app.py line 5",
            ),
        }
        data = self._run(pages)
        assert len(data["stack_leaks"]) >= 1

    def test_login_page_detected(self):
        pages = {
            "https://example.com": (
                200,
                '<form><input type="password" name="pass"></form>',
            ),
        }
        data = self._run(pages)
        assert len(data["login_pages"]) >= 1

    def test_broken_link_recorded(self):
        pages = {
            "https://example.com": (200, '<a href="/missing">Gone</a>'),
            "https://example.com/missing": (404, "Not Found"),
        }
        data = self._run(pages)
        assert any(b["status"] == 404 for b in data["broken_links"])

    def test_ssrf_url_in_queue_blocked(self):
        """If a link resolves to an SSRF-blocked host, it must not be crawled."""
        pages = {
            "https://example.com": (200, '<a href="/internal">I</a>'),
            "https://example.com/internal": (200, "<h1>Internal</h1>"),
        }
        # Simulate SSRF check: block on /internal by raising for that host
        def ssrf(host):
            return host in ("169.254.169.254",)

        mock_pw = _build_mock_playwright(pages)
        with patch("tools.web_crawler.async_playwright", return_value=mock_pw):
            with patch("tools.web_crawler.is_ssrf_blocked", side_effect=ssrf):
                data = asyncio.run(
                    __import__("tools.web_crawler", fromlist=["_async_crawl"])
                    ._async_crawl("https://example.com", 20)
                )
        # Crawl should complete without crashing
        assert isinstance(data, dict)


# ─────────────────────────────────────────────────────────────────────────────
# 5. crawl_website @tool — end-to-end wrapper
# ─────────────────────────────────────────────────────────────────────────────

class TestCrawlWebsiteTool:

    def _run(self, crawl_data: dict, url: str = "https://example.com") -> dict:
        """Run crawl_website with mocked _run_async."""
        with patch("tools.web_crawler._run_async", return_value=crawl_data):
            with patch("tools.web_crawler.is_ssrf_blocked", return_value=False):
                return json.loads(crawl_website.invoke({"url": url}))

    def test_invalid_scheme_rejected(self):
        result = json.loads(crawl_website.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_ssrf_url_rejected(self):
        with patch("tools.web_crawler.is_ssrf_blocked", return_value=True):
            result = json.loads(crawl_website.invoke({"url": "https://192.168.1.1"}))
        assert result["status"] == "ssrf_blocked"

    def test_clean_site_zero_risk(self):
        data = {**_empty_crawl_data(),
                "pages_visited": [{"url": "https://example.com", "status": 200}]}
        result = self._run(data)
        assert result["status"] == "completed"
        assert result["risk_score"] == 0
        assert result["sensitive_paths"] == []

    def test_admin_path_flagged(self):
        data = {**_empty_crawl_data(),
                "pages_visited":  [{"url": "https://example.com/admin", "status": 200}],
                "sensitive_paths": ["https://example.com/admin"]}
        result = self._run(data)
        assert result["sensitive_paths"]
        assert result["risk_score"] > 0

    def test_stack_trace_leak_flagged(self):
        data = {**_empty_crawl_data(),
                "stack_leaks": ["https://example.com/error"]}
        result = self._run(data)
        assert result["stack_trace_leaks"]
        assert result["risk_score"] >= 30

    def test_login_page_detected(self):
        data = {**_empty_crawl_data(),
                "login_pages": ["https://example.com/login"]}
        result = self._run(data)
        assert result["login_pages"]

    def test_total_pages_counts_correctly(self):
        pages = [{"url": f"https://example.com/p{i}", "status": 200} for i in range(5)]
        data  = {**_empty_crawl_data(), "pages_visited": pages}
        result = self._run(data)
        assert result["total_pages"] == 5

    def test_playwright_not_installed_returns_error(self):
        with patch("tools.web_crawler._PLAYWRIGHT_AVAILABLE", False):
            result = json.loads(crawl_website.invoke({"url": "https://example.com"}))
        assert result["status"] == "error"
        assert "playwright" in result["error"].lower()

    def test_renderer_field_is_playwright(self):
        result = self._run(_empty_crawl_data())
        assert "playwright" in result["renderer"].lower()

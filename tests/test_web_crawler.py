"""
Tests for Web Crawler.
All HTTP calls are mocked — no real network.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.web_crawler import (
    crawl_website,
    _same_origin,
    _normalise,
    _extract_links,
    _check_sensitive_path,
    _compute_result,
)


class TestSameOrigin:
    def test_relative_link_is_same_origin(self):
        assert _same_origin("https://example.com", "/about") is True

    def test_same_domain_is_same_origin(self):
        assert _same_origin("https://example.com", "https://example.com/page") is True

    def test_different_domain_not_same_origin(self):
        assert _same_origin("https://example.com", "https://evil.com/steal") is False


class TestNormalise:
    def test_relative_path_resolved(self):
        result = _normalise("https://example.com/page", "/about")
        assert result == "https://example.com/about"

    def test_absolute_url_kept(self):
        result = _normalise("https://example.com", "https://example.com/news")
        assert result == "https://example.com/news"

    def test_fragment_stripped(self):
        result = _normalise("https://example.com", "/page#section")
        assert "#" not in result

    def test_mailto_ignored(self):
        assert _normalise("https://example.com", "mailto:a@b.com") is None

    def test_javascript_ignored(self):
        assert _normalise("https://example.com", "javascript:void(0)") is None


class TestExtractLinks:
    def test_internal_links_extracted(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        links = _extract_links(html, "https://example.com")
        assert "https://example.com/about"   in links
        assert "https://example.com/contact" in links

    def test_external_links_excluded(self):
        html = '<a href="https://evil.com/steal">Click</a>'
        links = _extract_links(html, "https://example.com")
        assert links == []

    def test_no_links_returns_empty(self):
        assert _extract_links("<p>No links</p>", "https://example.com") == []


class TestCheckSensitivePath:
    def test_admin_path_flagged(self):
        assert _check_sensitive_path("https://example.com/admin") is not None

    def test_git_path_flagged(self):
        assert _check_sensitive_path("https://example.com/.git/config") is not None

    def test_api_path_flagged(self):
        assert _check_sensitive_path("https://example.com/api/v1/users") is not None

    def test_normal_path_not_flagged(self):
        assert _check_sensitive_path("https://example.com/about-us") is None

    def test_blog_path_not_flagged(self):
        assert _check_sensitive_path("https://example.com/blog/2024") is None


def _empty_crawl() -> dict:
    return {
        "pages_visited": [], "sensitive_paths": [], "broken_links": [],
        "login_pages": [], "stack_leaks": [], "robots_disallowed": [],
    }


class TestCrawlWebsite:
    """
    Integration tests for the crawl_website @tool.
    Mocks _run_async to avoid launching a real browser.
    """

    def _run(self, crawl_data: dict, start_url: str = "https://example.com") -> dict:
        with patch("tools.web_crawler._run_async", return_value=crawl_data):
            with patch("tools.web_crawler.is_ssrf_blocked", return_value=False):
                return json.loads(crawl_website.invoke({"url": start_url}))

    def test_invalid_scheme_rejected(self):
        result = json.loads(crawl_website.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_single_clean_page_visited(self):
        data = {**_empty_crawl(),
                "pages_visited": [{"url": "https://example.com", "status": 200}]}
        result = self._run(data)
        assert result["status"] == "completed"
        assert result["total_pages"] == 1
        assert result["sensitive_paths"] == []
        assert result["risk_score"] == 0

    def test_admin_path_flagged(self):
        data = {**_empty_crawl(),
                "pages_visited":  [{"url": "https://example.com/admin", "status": 200}],
                "sensitive_paths": ["https://example.com/admin"]}
        result = self._run(data)
        assert any("/admin" in p for p in result["sensitive_paths"])
        assert result["risk_score"] > 0

    def test_broken_link_detected(self):
        data = {**_empty_crawl(),
                "broken_links": [{"url": "https://example.com/missing", "status": 404}]}
        result = self._run(data)
        assert result["broken_links"]
        assert result["broken_links"][0]["status"] == 404

    def test_stack_trace_leak_detected(self):
        data = {**_empty_crawl(),
                "stack_leaks": ["https://example.com/error"]}
        result = self._run(data)
        assert result["stack_trace_leaks"]
        assert result["risk_score"] >= 30

    def test_login_page_detected(self):
        data = {**_empty_crawl(),
                "login_pages": ["https://example.com/login"]}
        result = self._run(data)
        assert result["login_pages"]

    def test_max_pages_reflected(self):
        pages = [{"url": f"https://example.com/p{i}", "status": 200} for i in range(20)]
        data  = {**_empty_crawl(), "pages_visited": pages}
        result = self._run(data)
        assert result["total_pages"] == 20

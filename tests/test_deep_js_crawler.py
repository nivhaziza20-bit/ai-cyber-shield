"""
tests/test_deep_js_crawler.py — AI Cyber Shield v5

Comprehensive async test suite for tools/deep_js_crawler.py.

Coverage strategy:
  - Pure helper functions (secret scanner, form/link parser, risk score)
    are tested without any browser dependency.
  - Route / response handlers are tested by passing mock route/response objects
    directly to the handler methods.
  - Full crawl integration is tested via a fully mocked playwright hierarchy so
    no real browser or network is required.
  - The @tool wrapper is tested by patching DeepJsCrawler.crawl.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.deep_js_crawler import (
    CrawlConfig,
    CrawlResult,
    DeepJsCrawler,
    DiscoveredForm,
    DiscoveredLink,
    FormField,
    NetworkRequest,
    NetworkResponse,
    SecretLeak,
    SsrfAttempt,
    _calculate_risk_score,
    _extract_auth_info,
    _parse_form,
    _parse_link,
    _scan_text_for_secrets,
    _should_scan_response_body,
    crawl_spa,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_result(**kwargs) -> CrawlResult:
    defaults = dict(
        url="https://example.com",
        status="completed",
        pages_visited=["https://example.com"],
        network_requests=[],
        network_responses=[],
        discovered_forms=[],
        discovered_links=[],
        secret_leaks=[],
        ssrf_attempts=[],
        script_urls=[],
        crawl_duration=1.0,
        risk_score=0,
        summary={},
    )
    defaults.update(kwargs)
    return CrawlResult(**defaults)


def _mock_route(
    url="https://example.com/api",
    method="GET",
    headers=None,
    resource_type="fetch",
    post_data=None,
):
    """Build a minimal Playwright Route mock."""
    req = MagicMock()
    req.url           = url
    req.method        = method
    req.headers       = headers or {}
    req.resource_type = resource_type
    req.post_data     = post_data

    route = MagicMock()
    route.request   = req
    route.abort     = AsyncMock()
    route.continue_ = AsyncMock()
    return route


def _mock_response(
    url="https://example.com/app.js",
    status=200,
    content_type="application/javascript",
    body="",
):
    """Build a minimal Playwright Response mock."""
    resp = MagicMock()
    resp.url     = url
    resp.status  = status
    resp.headers = {"content-type": content_type}
    resp.text    = AsyncMock(return_value=body)
    return resp


def _make_playwright_mock(evaluate_side_effect=None):
    """
    Build the full async_playwright() mock hierarchy.

    Returns (mock_pw_cm, mock_page) so tests can configure mock_page further.
    """
    mock_page = MagicMock()
    mock_page.url             = "https://example.com"
    mock_page.goto            = AsyncMock()
    mock_page.wait_for_load_state = AsyncMock()
    mock_page.add_init_script = AsyncMock()
    mock_page.route           = AsyncMock()
    mock_page.on              = MagicMock()   # sync in playwright-python

    if evaluate_side_effect is not None:
        mock_page.evaluate = AsyncMock(side_effect=evaluate_side_effect)
    else:
        mock_page.evaluate = AsyncMock(return_value=[])

    mock_ctx = AsyncMock()
    mock_ctx.new_page = AsyncMock(return_value=mock_page)

    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_ctx)
    mock_browser.close        = AsyncMock()

    mock_chromium = AsyncMock()
    mock_chromium.launch = AsyncMock(return_value=mock_browser)

    mock_pw = MagicMock()
    mock_pw.chromium = mock_chromium

    mock_pw_cm = MagicMock()
    mock_pw_cm.__aenter__ = AsyncMock(return_value=mock_pw)
    mock_pw_cm.__aexit__  = AsyncMock(return_value=False)

    return mock_pw_cm, mock_page


# ─────────────────────────────────────────────────────────────────────────────
# 1. Secret scanner
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretScanner:

    def test_detects_aws_access_key(self):
        text = "var creds = { key: 'AKIAIOSFODNN7EXAMPLE' };"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/app.js")
        assert any(l.kind == "AWS_ACCESS_KEY_ID" for l in leaks)

    def test_detects_jwt_token(self):
        jwt  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"const token = '{jwt}';"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/app.js")
        assert any(l.kind == "JWT_TOKEN" for l in leaks)

    def test_detects_firebase_api_key(self):
        text = "const config = { apiKey: 'AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567' };"
        leaks = _scan_text_for_secrets(text, "response_body", "https://e.com")
        kinds = {l.kind for l in leaks}
        assert "FIREBASE_API_KEY" in kinds

    def test_detects_firebase_db_url(self):
        text = "const db = firebase.initializeApp({ databaseURL: 'https://myapp-default-rtdb.firebaseio.com' });"
        leaks = _scan_text_for_secrets(text, "response_body", "https://e.com")
        assert any(l.kind == "FIREBASE_DB_URL" for l in leaks)

    def test_detects_stripe_secret_key(self):
        text = "stripe.init('sk_live_ABCDEFGHIJKLMNOPQRSTUVWX');"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/pay.js")
        assert any(l.kind == "STRIPE_SECRET_KEY" for l in leaks)

    def test_detects_stripe_pub_key(self):
        text = "var pk = 'pk_live_ABCDEFGHIJKLMNOPQRSTUVWX';"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/pay.js")
        assert any(l.kind == "STRIPE_PUB_KEY" for l in leaks)

    def test_detects_github_token(self):
        text = "const GH_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/ci.js")
        assert any(l.kind == "GITHUB_TOKEN" for l in leaks)

    def test_detects_private_key_material(self):
        text = "const pem = '-----BEGIN RSA PRIVATE KEY-----\\n...';"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/auth.js")
        assert any(l.kind == "PRIVATE_KEY_MATERIAL" for l in leaks)

    def test_detects_sourcemap_reference(self):
        text = "function app(){};\n//# sourceMappingURL=app.js.map"
        leaks = _scan_text_for_secrets(text, "response_body", "https://e.com/app.js")
        assert any(l.kind == "SOURCEMAP_REF" for l in leaks)

    def test_detects_hardcoded_password(self):
        text = "const opts = { password: 'SuperSecret123!' };"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/db.js")
        assert any(l.kind == "HARDCODED_PASSWORD" for l in leaks)

    def test_sample_is_redacted(self):
        text = "var k = 'AKIAIOSFODNN7EXAMPLE';"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/app.js")
        aws = next(l for l in leaks if l.kind == "AWS_ACCESS_KEY_ID")
        assert aws.sample.endswith("...")
        assert len(aws.sample) <= 12   # 8 chars + "..."

    def test_clean_text_returns_no_leaks(self):
        text = "function hello() { return 'world'; }"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/app.js")
        assert leaks == []

    def test_deduplication_same_pattern_same_url(self):
        # Two occurrences of the same pattern in one text → only ONE SecretLeak
        text = "var a = 'AKIAIOSFODNN7EXAMPLE'; var b = 'AKIAIOSFODNN7EXAMPLE';"
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/app.js")
        aws_leaks = [l for l in leaks if l.kind == "AWS_ACCESS_KEY_ID"]
        assert len(aws_leaks) == 1

    def test_multiple_different_patterns_detected(self):
        text = (
            "const key = 'AKIAIOSFODNN7EXAMPLE';\n"
            "const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature';\n"
        )
        leaks = _scan_text_for_secrets(text, "inline_script", "https://e.com/app.js")
        kinds = {l.kind for l in leaks}
        assert "AWS_ACCESS_KEY_ID" in kinds
        assert "JWT_TOKEN" in kinds

    def test_source_and_url_are_recorded(self):
        text = "const k = 'AKIAIOSFODNN7EXAMPLE';"
        leaks = _scan_text_for_secrets(text, "response_body", "https://cdn.example.com/bundle.js")
        assert leaks[0].source     == "response_body"
        assert leaks[0].source_url == "https://cdn.example.com/bundle.js"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Auth header extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractAuthInfo:

    def test_bearer_token_detected(self):
        has_auth, scheme = _extract_auth_info({"authorization": "Bearer abc123xyz"})
        assert has_auth  is True
        assert scheme    == "Bearer"

    def test_basic_auth_detected(self):
        has_auth, scheme = _extract_auth_info({"Authorization": "Basic dXNlcjpwYXNz"})
        assert has_auth  is True
        assert scheme    == "Basic"

    def test_x_api_key_detected(self):
        has_auth, scheme = _extract_auth_info({"x-api-key": "my-secret-key"})
        assert has_auth  is True
        assert scheme    == "ApiKey"

    def test_x_auth_token_detected(self):
        has_auth, scheme = _extract_auth_info({"x-auth-token": "tok_abc"})
        assert has_auth  is True
        assert scheme    == "ApiKey"

    def test_no_auth_headers(self):
        has_auth, scheme = _extract_auth_info({"content-type": "application/json", "accept": "*/*"})
        assert has_auth is False
        assert scheme   is None

    def test_empty_headers_dict(self):
        has_auth, scheme = _extract_auth_info({})
        assert has_auth is False
        assert scheme   is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Form parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestParseForm:

    def test_basic_login_form_parsed(self):
        raw = {
            "action": "/login",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text",     "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
        }
        form = _parse_form(raw, "https://example.com/login")
        assert form.action == "/login"
        assert form.method == "POST"
        assert len(form.fields) == 2

    def test_csrf_token_detected(self):
        raw = {
            "action": "/submit",
            "method": "POST",
            "inputs": [
                {"name": "email",      "type": "email",  "value": ""},
                {"name": "csrf_token", "type": "hidden", "value": "abc"},
            ],
        }
        form = _parse_form(raw, "https://example.com/submit")
        assert form.has_csrf_token is True

    def test_no_csrf_token_detected(self):
        raw = {
            "action": "/search",
            "method": "GET",
            "inputs": [{"name": "q", "type": "text", "value": ""}],
        }
        form = _parse_form(raw, "https://example.com/search")
        assert form.has_csrf_token is False

    def test_action_defaults_to_page_url(self):
        raw = {"action": None, "method": "GET", "inputs": []}
        form = _parse_form(raw, "https://example.com/page")
        assert form.action == "https://example.com/page"

    def test_method_uppercased(self):
        raw = {"action": "/go", "method": "post", "inputs": []}
        form = _parse_form(raw, "https://example.com/")
        assert form.method == "POST"

    def test_inputs_without_name_ignored(self):
        raw = {
            "action": "/go",
            "method": "POST",
            "inputs": [
                {"name": "",    "type": "button", "value": "Submit"},
                {"name": "uid", "type": "text",   "value": ""},
            ],
        }
        form = _parse_form(raw, "https://example.com/")
        assert len(form.fields) == 1
        assert form.fields[0].name == "uid"

    def test_authenticity_token_name_detected_as_csrf(self):
        raw = {
            "action": "/", "method": "POST",
            "inputs": [{"name": "authenticity_token", "type": "hidden", "value": "xyz"}],
        }
        form = _parse_form(raw, "https://example.com/")
        assert form.has_csrf_token is True

    def test_form_page_url_stored(self):
        raw = {"action": "/", "method": "GET", "inputs": []}
        form = _parse_form(raw, "https://example.com/page")
        assert form.page_url == "https://example.com/page"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Link parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestParseLink:

    def test_same_origin_link(self):
        link = _parse_link({"href": "https://example.com/about", "text": "About"}, "https://example.com")
        assert link is not None
        assert link.is_same_origin is True
        assert link.href == "https://example.com/about"

    def test_external_link(self):
        link = _parse_link({"href": "https://other.com/page", "text": "Other"}, "https://example.com")
        assert link is not None
        assert link.is_same_origin is False

    def test_javascript_href_ignored(self):
        link = _parse_link({"href": "javascript:void(0)", "text": "Click"}, "https://example.com")
        assert link is None

    def test_mailto_href_ignored(self):
        link = _parse_link({"href": "mailto:user@example.com", "text": "Email"}, "https://example.com")
        assert link is None

    def test_empty_href_ignored(self):
        link = _parse_link({"href": "", "text": ""}, "https://example.com")
        assert link is None

    def test_link_text_truncated_at_100_chars(self):
        text = "A" * 200
        link = _parse_link({"href": "https://example.com/page", "text": text}, "https://example.com")
        assert link is not None
        assert len(link.text) <= 100


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk score calculation
# ─────────────────────────────────────────────────────────────────────────────

class TestCalculateRiskScore:

    def _leak(self):
        return SecretLeak("AWS_ACCESS_KEY_ID", "AWS Key", "AKIAXXXX...", "inline_script", "https://e.com")

    def _ssrf(self):
        return SsrfAttempt("http://169.254.169.254/", "169.254.169.254", "fetch")

    def _form_no_csrf(self):
        return DiscoveredForm("/login", "POST", "https://e.com/login", [], has_csrf_token=False)

    def _form_with_csrf(self):
        return DiscoveredForm("/login", "POST", "https://e.com/login", [], has_csrf_token=True)

    def test_no_issues_score_zero(self):
        assert _calculate_risk_score([], [], []) == 0

    def test_single_secret_leak_score_20(self):
        assert _calculate_risk_score([self._leak()], [], []) == 20

    def test_three_secrets_cap_at_60(self):
        leaks = [self._leak() for _ in range(5)]
        score = _calculate_risk_score(leaks, [], [])
        assert score == 60   # capped at 60 for secrets

    def test_ssrf_attempt_adds_25(self):
        score = _calculate_risk_score([], [self._ssrf()], [])
        assert score == 25

    def test_form_without_csrf_adds_10(self):
        score = _calculate_risk_score([], [], [self._form_no_csrf()])
        assert score == 10

    def test_form_with_csrf_adds_nothing(self):
        score = _calculate_risk_score([], [], [self._form_with_csrf()])
        assert score == 0

    def test_combined_caps_at_100(self):
        leaks = [self._leak() for _ in range(10)]
        ssrfs = [self._ssrf()  for _ in range(10)]
        forms = [self._form_no_csrf() for _ in range(10)]
        score = _calculate_risk_score(leaks, ssrfs, forms)
        assert score == 100


# ─────────────────────────────────────────────────────────────────────────────
# 6. Response body content-type filter
# ─────────────────────────────────────────────────────────────────────────────

class TestShouldScanResponseBody:

    def test_javascript_scannable(self):
        assert _should_scan_response_body("application/javascript") is True

    def test_json_scannable(self):
        assert _should_scan_response_body("application/json; charset=utf-8") is True

    def test_html_scannable(self):
        assert _should_scan_response_body("text/html; charset=utf-8") is True

    def test_image_not_scannable(self):
        assert _should_scan_response_body("image/png") is False

    def test_font_not_scannable(self):
        assert _should_scan_response_body("font/woff2") is False


# ─────────────────────────────────────────────────────────────────────────────
# 7. Route handler (SSRF guard + request logging)
# ─────────────────────────────────────────────────────────────────────────────

class TestRouteHandler:

    @pytest.mark.asyncio
    async def test_ssrf_request_aborted(self):
        crawler = DeepJsCrawler(CrawlConfig())
        route   = _mock_route(url="http://169.254.169.254/latest/meta-data/")

        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=True):
            await crawler._handle_route(route)

        route.abort.assert_called_once_with("blockedbyclient")
        route.continue_.assert_not_called()
        assert len(crawler._ssrf_attempts) == 1

    @pytest.mark.asyncio
    async def test_ssrf_attempt_records_hostname(self):
        crawler = DeepJsCrawler(CrawlConfig())
        route   = _mock_route(url="http://169.254.169.254/secret")

        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=True):
            await crawler._handle_route(route)

        assert crawler._ssrf_attempts[0].blocked_hostname == "169.254.169.254"

    @pytest.mark.asyncio
    async def test_clean_request_passed_through(self):
        crawler = DeepJsCrawler(CrawlConfig())
        route   = _mock_route(url="https://example.com/api/users")

        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            await crawler._handle_route(route)

        route.continue_.assert_called_once()
        route.abort.assert_not_called()

    @pytest.mark.asyncio
    async def test_clean_request_logged(self):
        crawler = DeepJsCrawler(CrawlConfig())
        route   = _mock_route(url="https://example.com/api/data", method="POST")

        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            await crawler._handle_route(route)

        assert len(crawler._network_requests) == 1
        assert crawler._network_requests[0].method == "POST"

    @pytest.mark.asyncio
    async def test_auth_header_recorded(self):
        crawler = DeepJsCrawler(CrawlConfig())
        route   = _mock_route(
            url="https://example.com/api",
            headers={"authorization": "Bearer tok_xyz"},
        )

        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            await crawler._handle_route(route)

        req = crawler._network_requests[0]
        assert req.has_auth_header is True
        assert req.auth_scheme     == "Bearer"

    @pytest.mark.asyncio
    async def test_query_params_extracted(self):
        crawler = DeepJsCrawler(CrawlConfig())
        route   = _mock_route(url="https://example.com/search?q=xss&page=1")

        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            await crawler._handle_route(route)

        req = crawler._network_requests[0]
        assert "q"    in req.query_params
        assert "page" in req.query_params

    @pytest.mark.asyncio
    async def test_resource_type_recorded(self):
        crawler = DeepJsCrawler(CrawlConfig())
        route   = _mock_route(url="https://example.com/api", resource_type="xhr")

        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            await crawler._handle_route(route)

        assert crawler._network_requests[0].resource_type == "xhr"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Response handler (logging + secret scanning)
# ─────────────────────────────────────────────────────────────────────────────

class TestResponseHandler:

    @pytest.mark.asyncio
    async def test_response_logged(self):
        crawler  = DeepJsCrawler(CrawlConfig())
        response = _mock_response(url="https://example.com/api", status=200,
                                  content_type="application/json", body="{}")
        await crawler._handle_response(response)
        assert len(crawler._network_responses) == 1
        assert crawler._network_responses[0].url    == "https://example.com/api"
        assert crawler._network_responses[0].status == 200

    @pytest.mark.asyncio
    async def test_js_body_scanned_for_secrets(self):
        body = "const config = { key: 'AKIAIOSFODNN7EXAMPLE' };"
        crawler  = DeepJsCrawler(CrawlConfig())
        response = _mock_response(
            url="https://example.com/app.js",
            content_type="application/javascript",
            body=body,
        )
        await crawler._handle_response(response)
        assert any(l.kind == "AWS_ACCESS_KEY_ID" for l in crawler._secret_leaks)

    @pytest.mark.asyncio
    async def test_json_body_scanned_for_secrets(self):
        body = '{"firebase": {"apiKey": "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"}}'
        crawler  = DeepJsCrawler(CrawlConfig())
        response = _mock_response(
            url="https://example.com/config.json",
            content_type="application/json",
            body=body,
        )
        await crawler._handle_response(response)
        assert any(l.kind == "FIREBASE_API_KEY" for l in crawler._secret_leaks)

    @pytest.mark.asyncio
    async def test_image_body_not_scanned(self):
        crawler  = DeepJsCrawler(CrawlConfig())
        response = _mock_response(
            url="https://example.com/logo.png",
            content_type="image/png",
            body="AKIAIOSFODNN7EXAMPLE",   # would match if scanned
        )
        await crawler._handle_response(response)
        # response should still be logged
        assert len(crawler._network_responses) == 1
        # but no secret scan should have run
        assert len(crawler._secret_leaks) == 0

    @pytest.mark.asyncio
    async def test_body_fetch_failure_handled_gracefully(self):
        crawler  = DeepJsCrawler(CrawlConfig())
        response = _mock_response(content_type="application/javascript")
        response.text = AsyncMock(side_effect=Exception("buffer consumed"))
        # Should NOT raise
        await crawler._handle_response(response)
        assert len(crawler._network_responses) == 1  # metadata still logged

    @pytest.mark.asyncio
    async def test_secret_source_recorded_as_response_body(self):
        body = "var k = 'AKIAIOSFODNN7EXAMPLE';"
        crawler  = DeepJsCrawler(CrawlConfig())
        response = _mock_response(
            url="https://cdn.example.com/bundle.js",
            content_type="text/javascript",
            body=body,
        )
        await crawler._handle_response(response)
        leak = next(l for l in crawler._secret_leaks if l.kind == "AWS_ACCESS_KEY_ID")
        assert leak.source     == "response_body"
        assert leak.source_url == "https://cdn.example.com/bundle.js"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Integration: full crawl with mocked Playwright
# ─────────────────────────────────────────────────────────────────────────────

class TestCrawlIntegration:
    """
    Full crawl flow with mocked playwright — no real browser required.
    The mock page.evaluate is dispatched by content of the JS snippet.
    """

    def _evaluate_dispatch(self, js_code: str):
        """Dispatch evaluate calls based on the JS snippet contents."""
        if "querySelectorAll('form')" in js_code:
            return [{"action": "/login", "method": "POST", "inputs": [
                {"name": "user",         "type": "text",     "value": ""},
                {"name": "pass",         "type": "password", "value": ""},
                {"name": "csrf_token",   "type": "hidden",   "value": "abc"},
            ]}]
        if "querySelectorAll('a[href]')" in js_code:
            return [
                {"href": "https://example.com/about", "text": "About"},
                {"href": "https://other.com/page",    "text": "External"},
            ]
        if "querySelectorAll('script')" in js_code:
            return [{"src": None, "content": "const k = 'AKIAIOSFODNN7EXAMPLE';"}]
        return []

    @pytest.mark.asyncio
    async def test_successful_crawl_returns_completed_status(self):
        mock_pw_cm, _ = _make_playwright_mock(self._evaluate_dispatch)

        with patch("tools.deep_js_crawler.async_playwright", return_value=mock_pw_cm), \
             patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", True), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            result = await DeepJsCrawler(CrawlConfig()).crawl("https://example.com")

        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_crawl_discovers_form(self):
        mock_pw_cm, _ = _make_playwright_mock(self._evaluate_dispatch)

        with patch("tools.deep_js_crawler.async_playwright", return_value=mock_pw_cm), \
             patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", True), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            result = await DeepJsCrawler(CrawlConfig()).crawl("https://example.com")

        assert len(result.discovered_forms) >= 1
        assert result.discovered_forms[0].has_csrf_token is True

    @pytest.mark.asyncio
    async def test_crawl_discovers_same_origin_link(self):
        mock_pw_cm, _ = _make_playwright_mock(self._evaluate_dispatch)

        with patch("tools.deep_js_crawler.async_playwright", return_value=mock_pw_cm), \
             patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", True), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            result = await DeepJsCrawler(CrawlConfig()).crawl("https://example.com")

        same_origin = [l for l in result.discovered_links if l.is_same_origin]
        assert any(l.href == "https://example.com/about" for l in same_origin)

    @pytest.mark.asyncio
    async def test_crawl_detects_inline_script_secret(self):
        mock_pw_cm, _ = _make_playwright_mock(self._evaluate_dispatch)

        with patch("tools.deep_js_crawler.async_playwright", return_value=mock_pw_cm), \
             patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", True), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            result = await DeepJsCrawler(CrawlConfig()).crawl("https://example.com")

        assert any(l.kind == "AWS_ACCESS_KEY_ID" for l in result.secret_leaks)

    @pytest.mark.asyncio
    async def test_crawl_risk_score_nonzero_on_secrets(self):
        mock_pw_cm, _ = _make_playwright_mock(self._evaluate_dispatch)

        with patch("tools.deep_js_crawler.async_playwright", return_value=mock_pw_cm), \
             patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", True), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            result = await DeepJsCrawler(CrawlConfig()).crawl("https://example.com")

        assert result.risk_score > 0

    @pytest.mark.asyncio
    async def test_crawl_summary_contains_key_fields(self):
        mock_pw_cm, _ = _make_playwright_mock(self._evaluate_dispatch)

        with patch("tools.deep_js_crawler.async_playwright", return_value=mock_pw_cm), \
             patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", True), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            result = await DeepJsCrawler(CrawlConfig()).crawl("https://example.com")

        for key in ("pages_visited", "requests_captured", "forms_found",
                    "links_found", "secrets_detected", "ssrf_blocked"):
            assert key in result.summary

    @pytest.mark.asyncio
    async def test_crawl_timeout_returns_timeout_status(self):
        async def _hang(*args, **kwargs):
            # Yields control back to the event loop so wait_for can cancel
            await asyncio.sleep(999)

        mock_pw_cm, mock_page = _make_playwright_mock()
        mock_page.goto = AsyncMock(side_effect=_hang)

        with patch("tools.deep_js_crawler.async_playwright", return_value=mock_pw_cm), \
             patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", True), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            # Very short timeout so the test doesn't actually take 20s
            result = await DeepJsCrawler(CrawlConfig(max_total_seconds=0.05)).crawl(
                "https://example.com"
            )

        assert result.status == "timeout"

    @pytest.mark.asyncio
    async def test_playwright_not_installed_returns_error_status(self):
        with patch("tools.deep_js_crawler._HAS_PLAYWRIGHT", False), \
             patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=False):
            result = await DeepJsCrawler(CrawlConfig()).crawl("https://example.com")

        assert "error" in result.status


# ─────────────────────────────────────────────────────────────────────────────
# 10. @tool wrapper
# ─────────────────────────────────────────────────────────────────────────────

class TestCrawlSpaTool:

    def _minimal_result(self, status="completed") -> CrawlResult:
        return _make_result(status=status, tool="deep_js_crawler")  # type: ignore[call-arg]

    def test_tool_returns_valid_json(self):
        mock_result = _make_result()
        with patch.object(DeepJsCrawler, "crawl", new=AsyncMock(return_value=mock_result)):
            output = crawl_spa.invoke({"url": "https://example.com"})
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_tool_injects_tool_key(self):
        mock_result = _make_result()
        with patch.object(DeepJsCrawler, "crawl", new=AsyncMock(return_value=mock_result)):
            output = crawl_spa.invoke({"url": "https://example.com"})
        assert json.loads(output)["tool"] == "deep_js_crawler"

    def test_tool_rejects_non_http_scheme(self):
        output = crawl_spa.invoke({"url": "ftp://example.com"})
        data   = json.loads(output)
        assert data["status"] == "invalid_url"

    def test_tool_blocks_ssrf_target(self):
        with patch("tools.deep_js_crawler.is_ssrf_blocked", return_value=True):
            output = crawl_spa.invoke({"url": "https://169.254.169.254/secret"})
        data = json.loads(output)
        assert data["status"] == "ssrf_blocked"

    def test_tool_serializes_secret_leaks(self):
        leak   = SecretLeak("AWS_ACCESS_KEY_ID", "AWS Key", "AKIAXXXX...",
                            "inline_script", "https://example.com/app.js")
        result = _make_result(secret_leaks=[leak], risk_score=20)
        with patch.object(DeepJsCrawler, "crawl", new=AsyncMock(return_value=result)):
            output = crawl_spa.invoke({"url": "https://example.com"})
        data = json.loads(output)
        assert data["risk_score"] == 20
        assert len(data["secret_leaks"]) == 1
        assert data["secret_leaks"][0]["kind"] == "AWS_ACCESS_KEY_ID"

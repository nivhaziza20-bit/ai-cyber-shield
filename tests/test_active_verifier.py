"""
tests/test_active_verifier.py — AI Cyber Shield v6

Test suite for active_verifier.py.

Covers:
  • VulnType / VerificationStatus enums
  • _assert_payload_safe (ethical gate)
  • _detect_waf_block
  • SafePayloadFactory (all payload builders)
  • ProbeRequest.to_curl
  • ResponseOracle (all 7 analysis methods)
  • ActiveProber.probe (SSRF guard, WAF abort, timeout, happy path)
  • ActiveVerifier.verify_vulnerability (all 7 vuln types + error paths)
  • _build_reproduction_steps
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Module under test
from active_verifier import (
    _CANARY_DOMAIN,
    _CRLF_CANARY_HEADER,
    _SSTI_EXPRESSION,
    ActiveProber,
    ActiveVerifier,
    EthicalViolationError,
    ProbeRequest,
    ResponseOracle,
    ResponseSummary,
    SafePayloadFactory,
    SsrfBlockError,
    VerificationResult,
    VerificationStatus,
    VulnType,
    WafBlockError,
    _assert_payload_safe,
    _build_reproduction_steps,
    _detect_waf_block,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_httpx_response(
    status_code:  int    = 200,
    headers:      dict   = None,
    text:         str    = "",
) -> MagicMock:
    """Return a mock that looks like an httpx.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers     = headers or {}
    mock_resp.text        = text
    return mock_resp


async def _mock_probe(
    request: ProbeRequest,
    status:  int   = 200,
    headers: dict  = None,
    body:    str   = "",
    elapsed: float = 0.1,
) -> tuple[int, dict, str, float]:
    return status, headers or {}, body, elapsed


# ─────────────────────────────────────────────────────────────────────────────
# 1. Enum smoke tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVulnType:
    def test_all_types_present(self):
        names = {v.value for v in VulnType}
        assert "OPEN_REDIRECT"         in names
        assert "REFLECTED_XSS"         in names
        assert "CORS_MISCONFIGURATION" in names
        assert "PATH_TRAVERSAL"        in names
        assert "HOST_HEADER_INJECTION" in names
        assert "SSTI"                  in names
        assert "CRLF_INJECTION"        in names

    def test_string_coercible(self):
        assert VulnType("OPEN_REDIRECT") is VulnType.OPEN_REDIRECT

    def test_is_str(self):
        assert isinstance(VulnType.SSTI, str)


class TestVerificationStatus:
    def test_all_statuses_present(self):
        values = {s.value for s in VerificationStatus}
        assert "CONFIRMED"                 in values
        assert "NOT_CONFIRMED"             in values
        assert "BLOCKED_BY_ACTIVE_DEFENSE" in values
        assert "SSRF_BLOCKED"              in values
        assert "TIMEOUT"                   in values
        assert "ERROR"                     in values
        assert "ETHICAL_VIOLATION"         in values


# ─────────────────────────────────────────────────────────────────────────────
# 2. Ethical gate — _assert_payload_safe
# ─────────────────────────────────────────────────────────────────────────────

class TestAssertPayloadSafe:
    SAFE_PAYLOADS = [
        "https://aics-probe.example.com/verify?token=AICS-CANARY-ABC123",
        "<!--AICS-CANARY-DEADBEEF001-->",
        "../../robots.txt",
        "{{7*1111}}",
        "%0d%0aX-AICS-Probe: canary",
        "https://attacker-aics.example.com",
    ]

    FORBIDDEN_PAYLOADS = [
        ("rm -rf /",                "rm -rf"),
        ("sudo rm /etc/passwd",     "sudo"),
        ("; id",                    "id"),
        ("; whoami",                "whoami"),
        ("wget http://evil.com",    "wget"),
        ("curl http://evil.com",    "curl"),
        ("nc 1.2.3.4 4444",         "nc"),
        ("bash -c 'id'",            "bash"),
        ("python -c 'import os'",   "python"),
        ("DROP TABLE users",        "DROP TABLE"),
        ("DROP DATABASE prod",      "DROP DATABASE"),
        ("DELETE FROM users",       "DELETE FROM"),
        ("/etc/passwd",             "/etc/passwd"),
        ("/etc/shadow",             "/etc/shadow"),
        ("169.254.169.254",         "IMDS"),
        ("metadata.google.internal","google metadata"),
    ]

    @pytest.mark.parametrize("payload", SAFE_PAYLOADS)
    def test_safe_payloads_pass(self, payload):
        _assert_payload_safe(payload)  # must not raise

    @pytest.mark.parametrize("payload,label", FORBIDDEN_PAYLOADS)
    def test_forbidden_payloads_raise(self, payload, label):
        with pytest.raises(EthicalViolationError):
            _assert_payload_safe(payload, label)

    def test_context_appears_in_error_message(self):
        with pytest.raises(EthicalViolationError, match="my-context"):
            _assert_payload_safe("rm -rf /", "my-context")


# ─────────────────────────────────────────────────────────────────────────────
# 3. WAF block detector
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectWafBlock:
    def test_no_block_on_200(self):
        assert _detect_waf_block(200, {}, "hello world") is None

    def test_no_block_on_404(self):
        assert _detect_waf_block(404, {}, "not found") is None

    def test_cloudflare_header_403(self):
        sig = _detect_waf_block(403, {"cf-ray": "abc123"}, "")
        assert sig is not None
        assert "cf-ray" in sig.lower()

    def test_cloudflare_body_403(self):
        sig = _detect_waf_block(403, {}, "Please wait... cloudflare is checking")
        assert sig is not None

    def test_incapsula_header(self):
        sig = _detect_waf_block(403, {"x-iinfo": "123"}, "")
        assert sig is not None

    def test_aws_waf_header_403(self):
        sig = _detect_waf_block(403, {"x-amzn-waf": "yes"}, "")
        assert sig is not None

    def test_datadome_header(self):
        sig = _detect_waf_block(403, {"x-datadome": "blocked"}, "")
        assert sig is not None

    def test_generic_block_body_429(self):
        sig = _detect_waf_block(429, {}, "Your request has been blocked by our security system")
        assert sig is not None

    def test_no_false_positive_clean_403(self):
        # 403 with no WAF indicators → None
        assert _detect_waf_block(403, {"content-type": "text/html"}, "Forbidden") is None

    def test_no_false_positive_200_with_waf_word_in_body(self):
        # Word 'cloudflare' in body but 200 status → None
        assert _detect_waf_block(200, {}, "Powered by Cloudflare CDN") is None


# ─────────────────────────────────────────────────────────────────────────────
# 4. SafePayloadFactory
# ─────────────────────────────────────────────────────────────────────────────

class TestSafePayloadFactory:
    # ── canary_token ─────────────────────────────────────────────────────────

    def test_canary_token_format(self):
        token = SafePayloadFactory.canary_token()
        assert token.startswith("AICS-CANARY-")
        assert len(token) > len("AICS-CANARY-")

    def test_canary_tokens_are_unique(self):
        tokens = {SafePayloadFactory.canary_token() for _ in range(20)}
        assert len(tokens) == 20  # all unique

    # ── open_redirect ────────────────────────────────────────────────────────

    def test_open_redirect_method(self):
        req = SafePayloadFactory.open_redirect("https://target.example.com/redir", "next", "CANARY")
        assert req.method == "GET"

    def test_open_redirect_no_follow(self):
        req = SafePayloadFactory.open_redirect("https://t.example.com/r", "url", "CANARY")
        assert req.allow_redirects is False

    def test_open_redirect_canary_in_params(self):
        req = SafePayloadFactory.open_redirect("https://t.example.com/r", "url", "CANARY-123")
        param_value = req.params["url"]
        assert _CANARY_DOMAIN in param_value
        assert "CANARY-123" in param_value

    def test_open_redirect_payload_passes_ethical_gate(self):
        req = SafePayloadFactory.open_redirect("https://t.example.com/r", "url", "CANARY")
        _assert_payload_safe(req.params["url"])  # must not raise

    # ── reflected_xss ─────────────────────────────────────────────────────────

    def test_xss_is_html_comment(self):
        req = SafePayloadFactory.reflected_xss("https://t.example.com/", "q", "MY-CANARY")
        val = req.params["q"]
        assert val.startswith("<!--")
        assert val.endswith("-->")
        assert "MY-CANARY" in val

    def test_xss_follows_redirects(self):
        req = SafePayloadFactory.reflected_xss("https://t.example.com/", "q", "X")
        assert req.allow_redirects is True

    def test_xss_payload_passes_ethical_gate(self):
        req = SafePayloadFactory.reflected_xss("https://t.example.com/", "q", "CANARY")
        _assert_payload_safe(req.params["q"])  # must not raise

    # ── cors_probe ────────────────────────────────────────────────────────────

    def test_cors_has_origin_header(self):
        req = SafePayloadFactory.cors_probe("https://t.example.com/api", "CANARY")
        assert "Origin" in req.headers
        assert "example.com" in req.headers["Origin"]

    def test_cors_origin_contains_canary(self):
        req = SafePayloadFactory.cors_probe("https://t.example.com/api", "MY-CAN")
        assert "my-can" in req.headers["Origin"].lower()

    # ── path_traversal ────────────────────────────────────────────────────────

    def test_path_traversal_returns_list(self):
        probes = SafePayloadFactory.path_traversal("https://t.example.com/file", "f")
        assert isinstance(probes, list)
        assert len(probes) >= 1

    def test_path_traversal_targets_robots(self):
        probes = SafePayloadFactory.path_traversal("https://t.example.com/file", "f")
        for p in probes:
            assert "robots.txt" in p.params["f"]

    def test_path_traversal_never_targets_passwd(self):
        probes = SafePayloadFactory.path_traversal("https://t.example.com/file", "f")
        for p in probes:
            assert "passwd" not in p.params["f"]
            assert "shadow" not in p.params["f"]

    def test_path_traversal_payloads_pass_ethical_gate(self):
        probes = SafePayloadFactory.path_traversal("https://t.example.com/file", "f")
        for p in probes:
            _assert_payload_safe(p.params["f"])  # must not raise

    # ── host_header_injection ─────────────────────────────────────────────────

    def test_host_header_injection_sets_host(self):
        req = SafePayloadFactory.host_header_injection("https://t.example.com/", "CANARY-X")
        assert "Host" in req.headers
        assert _CANARY_DOMAIN in req.headers["Host"]

    def test_host_header_injection_no_follow(self):
        req = SafePayloadFactory.host_header_injection("https://t.example.com/", "X")
        assert req.allow_redirects is False

    # ── ssti ──────────────────────────────────────────────────────────────────

    def test_ssti_returns_list(self):
        probes = SafePayloadFactory.ssti("https://t.example.com/", "msg")
        assert isinstance(probes, list)
        assert len(probes) >= 1

    def test_ssti_payloads_are_math_only(self):
        probes = SafePayloadFactory.ssti("https://t.example.com/", "msg")
        for p in probes:
            payload = p.params["msg"]
            assert "1111" in payload  # arithmetic operand
            _assert_payload_safe(payload)  # must not raise

    # ── crlf_injection ────────────────────────────────────────────────────────

    def test_crlf_returns_list(self):
        probes = SafePayloadFactory.crlf_injection("https://t.example.com/", "p")
        assert isinstance(probes, list)
        assert len(probes) >= 1

    def test_crlf_payloads_contain_header_name(self):
        probes = SafePayloadFactory.crlf_injection("https://t.example.com/", "p")
        for p in probes:
            payload = p.params["p"]
            assert _CRLF_CANARY_HEADER in payload or "AICS" in payload.upper()


# ─────────────────────────────────────────────────────────────────────────────
# 5. ProbeRequest.to_curl
# ─────────────────────────────────────────────────────────────────────────────

class TestProbeRequestToCurl:
    def test_basic_get(self):
        req = ProbeRequest(method="GET", url="https://example.com/path")
        curl = req.to_curl()
        assert "curl" in curl
        assert "https://example.com/path" in curl

    def test_params_appended_to_url(self):
        req = ProbeRequest(
            method="GET",
            url="https://example.com/redir",
            params={"next": "https://aics-probe.example.com/verify"},
        )
        curl = req.to_curl()
        assert "next=" in curl
        assert "example.com" in curl

    def test_custom_header_included(self):
        req = ProbeRequest(
            method="GET",
            url="https://example.com/",
            headers={"X-Test": "probe"},
        )
        curl = req.to_curl()
        assert "X-Test" in curl
        assert "probe" in curl

    def test_auth_header_redacted(self):
        req = ProbeRequest(
            method="GET",
            url="https://example.com/",
            headers={"Authorization": "Bearer secret-token"},
        )
        curl = req.to_curl()
        assert "secret-token" not in curl
        assert "REDACTED" in curl

    def test_cookie_header_redacted(self):
        req = ProbeRequest(
            method="GET",
            url="https://example.com/",
            headers={"Cookie": "session=abc123"},
        )
        curl = req.to_curl()
        assert "abc123" not in curl
        assert "REDACTED" in curl

    def test_no_follow_flag(self):
        req = ProbeRequest(method="GET", url="https://example.com/", allow_redirects=False)
        curl = req.to_curl()
        assert "--no-location" in curl

    def test_follow_redirects_flag(self):
        req = ProbeRequest(method="GET", url="https://example.com/", allow_redirects=True)
        curl = req.to_curl()
        assert "-L" in curl

    def test_max_time_present(self):
        req = ProbeRequest(method="GET", url="https://example.com/")
        assert "--max-time" in req.to_curl()


# ─────────────────────────────────────────────────────────────────────────────
# 6. ResponseOracle
# ─────────────────────────────────────────────────────────────────────────────

class TestResponseOracleOpenRedirect:
    def test_confirmed_full_match(self):
        headers = {"location": f"https://{_CANARY_DOMAIN}/verify?token=CANARY-XYZ"}
        ok, conf = ResponseOracle.open_redirect(302, headers, "CANARY-XYZ")
        assert ok is True
        assert conf == 1.0

    def test_confirmed_domain_only(self):
        headers = {"location": f"https://{_CANARY_DOMAIN}/path"}
        ok, conf = ResponseOracle.open_redirect(301, headers, "OTHER")
        assert ok is True
        assert conf >= 0.85

    def test_example_com_partial_confidence(self):
        headers = {"location": "https://other.example.com/somewhere"}
        ok, conf = ResponseOracle.open_redirect(302, headers, "CANARY")
        # example.com match but no canary domain
        assert ok is True
        assert conf < 1.0

    def test_not_confirmed_no_location(self):
        ok, conf = ResponseOracle.open_redirect(302, {}, "CANARY")
        assert ok is False

    def test_not_confirmed_non_redirect(self):
        headers = {"location": f"https://{_CANARY_DOMAIN}/"}
        ok, conf = ResponseOracle.open_redirect(200, headers, "CANARY")
        assert ok is False
        assert conf == 0.0


class TestResponseOracleReflectedXss:
    def test_confirmed_comment_reflected(self):
        canary = "AICS-CANARY-ABC123"
        body   = f"<html><body><!--{canary}--></body></html>"
        ok, conf = ResponseOracle.reflected_xss(body, canary)
        assert ok is True
        assert conf >= 0.9

    def test_not_confirmed_not_in_body(self):
        ok, conf = ResponseOracle.reflected_xss("<html>clean</html>", "AICS-CANARY-MISSING")
        assert ok is False
        assert conf == 0.0

    def test_partial_match_core_token(self):
        canary = "AICS-CANARY-CORE"
        body   = "<html><body>AICS-CANARY-CORE</body></html>"
        # canary is literally in body (not inside <!-- -->)
        ok, conf = ResponseOracle.reflected_xss(body, canary)
        assert ok is True


class TestResponseOracleCors:
    def test_confirmed_full_credential(self):
        headers = {
            "access-control-allow-origin":      "https://attacker.example.com",
            "access-control-allow-credentials": "true",
        }
        ok, conf = ResponseOracle.cors_misconfiguration(headers, "https://attacker.example.com")
        assert ok is True
        assert conf == 1.0

    def test_confirmed_wildcard(self):
        headers = {"access-control-allow-origin": "*"}
        ok, conf = ResponseOracle.cors_misconfiguration(headers, "https://attacker.example.com")
        assert ok is True
        assert conf < 1.0  # wildcard is weaker finding

    def test_confirmed_origin_echo_no_acac(self):
        headers = {"access-control-allow-origin": "https://attacker.example.com"}
        ok, conf = ResponseOracle.cors_misconfiguration(headers, "https://attacker.example.com")
        assert ok is True
        assert conf < 1.0

    def test_not_confirmed_different_origin(self):
        headers = {"access-control-allow-origin": "https://legitimate.example.com"}
        ok, conf = ResponseOracle.cors_misconfiguration(headers, "https://attacker.example.com")
        assert ok is False

    def test_not_confirmed_no_cors_headers(self):
        ok, conf = ResponseOracle.cors_misconfiguration({}, "https://attacker.example.com")
        assert ok is False


class TestResponseOraclePathTraversal:
    def test_confirmed_strong_robots_match(self):
        body = "User-agent: *\nDisallow: /admin\nAllow: /\nSitemap: https://example.com/sitemap.xml"
        ok, conf = ResponseOracle.path_traversal(body, 200)
        assert ok is True
        assert conf >= 0.9

    def test_confirmed_partial_match(self):
        ok, conf = ResponseOracle.path_traversal("User-agent: Googlebot\nDisallow: /", 200)
        assert ok is True
        assert conf >= 0.8

    def test_not_confirmed_wrong_status(self):
        body = "User-agent: *\nDisallow: /admin"
        ok, conf = ResponseOracle.path_traversal(body, 403)
        assert ok is False

    def test_not_confirmed_empty_body(self):
        ok, conf = ResponseOracle.path_traversal("", 200)
        assert ok is False

    def test_not_confirmed_unrelated_body(self):
        ok, conf = ResponseOracle.path_traversal("<html>Not a robots file</html>", 200)
        assert ok is False


class TestResponseOracleHostHeader:
    def test_confirmed_in_location(self):
        injected = f"CANARY-XYZ.{_CANARY_DOMAIN}"
        headers  = {"Location": f"https://{injected}/reset?token=abc"}
        ok, conf = ResponseOracle.host_header_injection(302, headers, "", injected)
        assert ok is True
        assert conf >= 0.9

    def test_confirmed_in_body(self):
        injected = f"CANARY-XYZ.{_CANARY_DOMAIN}"
        body     = f"Password reset link sent to https://{injected}/reset"
        ok, conf = ResponseOracle.host_header_injection(200, {}, body, injected)
        assert ok is True

    def test_confirmed_canary_domain_in_location(self):
        headers = {"Location": f"https://{_CANARY_DOMAIN}/reset"}
        ok, conf = ResponseOracle.host_header_injection(302, headers, "", "other.host")
        assert ok is True

    def test_not_confirmed_clean_response(self):
        ok, conf = ResponseOracle.host_header_injection(200, {}, "Normal page content", "injected.host.example.com")
        assert ok is False


class TestResponseOracleSsti:
    def test_confirmed_result_in_body(self):
        ok, conf = ResponseOracle.ssti(f"Result: {_SSTI_EXPRESSION}", 200)
        assert ok is True
        assert conf >= 0.9

    def test_not_confirmed_result_absent(self):
        ok, conf = ResponseOracle.ssti("No template evaluation here", 200)
        assert ok is False

    def test_not_confirmed_wrong_status(self):
        ok, conf = ResponseOracle.ssti(f"{_SSTI_EXPRESSION}", 500)
        assert ok is False


class TestResponseOracleCrlf:
    def test_confirmed_canary_header_present(self):
        headers = {_CRLF_CANARY_HEADER: "canary1"}
        ok, conf = ResponseOracle.crlf_injection(headers)
        assert ok is True
        assert conf == 1.0

    def test_confirmed_case_insensitive(self):
        headers = {_CRLF_CANARY_HEADER.lower(): "canary2"}
        ok, conf = ResponseOracle.crlf_injection(headers)
        assert ok is True

    def test_not_confirmed_no_injected_header(self):
        ok, conf = ResponseOracle.crlf_injection({"content-type": "text/html"})
        assert ok is False


# ─────────────────────────────────────────────────────────────────────────────
# 7. ActiveProber
# ─────────────────────────────────────────────────────────────────────────────

class TestActiveProber:
    """Tests for ActiveProber.probe — patch httpx.AsyncClient."""

    def _make_mock_client_response(
        self, status=200, headers=None, text=""
    ):
        resp = MagicMock()
        resp.status_code = status
        resp.headers     = headers or {}
        resp.text        = text
        return resp

    @pytest.mark.asyncio
    async def test_ssrf_blocked_raises(self):
        prober  = ActiveProber()
        request = ProbeRequest(method="GET", url="http://192.168.1.1/admin")
        with patch("active_verifier.is_ssrf_blocked", return_value=True):
            with pytest.raises(SsrfBlockError):
                await prober.probe(request)

    @pytest.mark.asyncio
    async def test_waf_block_raises_waf_error(self):
        prober  = ActiveProber()
        request = ProbeRequest(method="GET", url="https://example.com/")

        mock_resp = self._make_mock_client_response(
            status=403,
            headers={"cf-ray": "abc123"},
            text="",
        )
        with patch("active_verifier.is_ssrf_blocked", return_value=False), \
             patch("active_verifier.httpx.AsyncClient") as MockClient:
            ctx_mgr                    = MockClient.return_value.__aenter__ = AsyncMock()
            ctx_mgr.return_value       = AsyncMock()
            ctx_mgr.return_value.request = AsyncMock(return_value=mock_resp)
            with pytest.raises(WafBlockError):
                await prober.probe(request)

    @pytest.mark.asyncio
    async def test_happy_path_returns_tuple(self):
        prober  = ActiveProber()
        request = ProbeRequest(method="GET", url="https://example.com/", allow_redirects=False)

        mock_resp = self._make_mock_client_response(200, {"content-type": "text/html"}, "<html>hi</html>")

        with patch("active_verifier.is_ssrf_blocked", return_value=False), \
             patch("active_verifier.httpx.AsyncClient") as MockClient:
            ctx_mgr                    = MockClient.return_value.__aenter__ = AsyncMock()
            ctx_mgr.return_value       = AsyncMock()
            ctx_mgr.return_value.request = AsyncMock(return_value=mock_resp)
            status, headers, body, elapsed = await prober.probe(request)

        assert status  == 200
        assert "content-type" in {k.lower() for k in headers}
        assert "hi" in body
        assert isinstance(elapsed, float)

    @pytest.mark.asyncio
    async def test_params_appended_to_url(self):
        """params are URL-encoded and appended; the correct URL is passed to httpx."""
        prober  = ActiveProber()
        request = ProbeRequest(
            method="GET",
            url="https://target.example.com/redirect",
            params={"next": "https://aics-probe.example.com/verify?token=TOKEN"},
        )

        mock_resp = self._make_mock_client_response(200, {}, "")

        call_args_captured: list = []

        async def fake_request(method, url, **kw):
            call_args_captured.append(url)
            return mock_resp

        with patch("active_verifier.is_ssrf_blocked", return_value=False), \
             patch("active_verifier.httpx.AsyncClient") as MockClient:
            ctx_mgr                    = MockClient.return_value.__aenter__ = AsyncMock()
            ctx_mgr.return_value       = AsyncMock()
            ctx_mgr.return_value.request = AsyncMock(side_effect=fake_request)
            await prober.probe(request)

        assert len(call_args_captured) == 1
        called_url = call_args_captured[0]
        assert "next=" in called_url
        assert "target.example.com" in called_url

    def test_make_response_summary_structure(self):
        prober = ActiveProber()
        summary = prober._make_response_summary(
            302,
            {"Location": "https://example.com", "Content-Type": "text/html",
             "Access-Control-Allow-Origin": "*",
             "Access-Control-Allow-Credentials": "true"},
            "body text" * 100,
            0.42,
        )
        assert isinstance(summary, ResponseSummary)
        assert summary.status_code   == 302
        assert summary.location      == "https://example.com"
        assert summary.acao_header   == "*"
        assert summary.acac_header   == "true"
        assert len(summary.body_snippet) <= 500
        assert summary.response_time == 0.42


# ─────────────────────────────────────────────────────────────────────────────
# 8. ActiveVerifier — end-to-end with mocked prober
# ─────────────────────────────────────────────────────────────────────────────

def _patch_prober(
    verifier: ActiveVerifier,
    status: int = 200,
    headers: dict | None = None,
    body: str = "",
    elapsed: float = 0.05,
    side_effect: Exception | None = None,
):
    """
    Monkey-patch verifier._prober.probe so it returns canned data
    without making real HTTP calls.
    """
    async def _fake_probe(request):
        if side_effect:
            raise side_effect
        return status, headers or {}, body, elapsed

    verifier._prober.probe = _fake_probe


class TestActiveVerifierOpenRedirect:
    @pytest.mark.asyncio
    async def test_confirmed(self):
        verifier = ActiveVerifier()
        location = f"https://{_CANARY_DOMAIN}/active-verify?token=AICS"
        _patch_prober(verifier, status=302, headers={"location": location})

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/redir", "next", {}
        )
        assert result.is_confirmed
        assert result.status          == VerificationStatus.CONFIRMED
        assert result.confidence_score > 0.8
        assert result.vuln_type       == VulnType.OPEN_REDIRECT
        assert result.probes_sent     == 1
        assert result.raw_poc_request is not None

    @pytest.mark.asyncio
    async def test_not_confirmed(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={})

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/redir", "next", {}
        )
        assert not result.is_confirmed
        assert result.status == VerificationStatus.NOT_CONFIRMED

    @pytest.mark.asyncio
    async def test_waf_block(self):
        verifier = ActiveVerifier()
        _patch_prober(
            verifier,
            side_effect=WafBlockError("WAF-header:cf-ray", 403),
        )

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/redir", "next", {}
        )
        assert result.status      == VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
        assert not result.is_confirmed
        assert result.waf_signature is not None

    @pytest.mark.asyncio
    async def test_timeout(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, side_effect=asyncio.TimeoutError())

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/redir", "next", {}
        )
        assert result.status == VerificationStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_ssrf_blocked(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, side_effect=SsrfBlockError("private IP"))

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "http://192.168.0.1/redir", "next", {}
        )
        assert result.status == VerificationStatus.SSRF_BLOCKED

    @pytest.mark.asyncio
    async def test_reproduction_steps_populated(self):
        verifier = ActiveVerifier()
        location = f"https://{_CANARY_DOMAIN}/active-verify?token=AICS"
        _patch_prober(verifier, status=302, headers={"location": location})

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/redir", "next", {}
        )
        assert len(result.reproduction_steps) > 0
        steps_text = "\n".join(result.reproduction_steps)
        assert "curl" in steps_text


class TestActiveVerifierReflectedXss:
    @pytest.mark.asyncio
    async def test_confirmed(self):
        verifier = ActiveVerifier()

        async def fake_probe(request):
            # Echo the injected param value back in the response body unescaped
            val = ""
            if request.params:
                val = next(iter(request.params.values()), "")
            return 200, {}, val, 0.05

        verifier._prober.probe = fake_probe

        result = await verifier.verify_vulnerability(
            VulnType.REFLECTED_XSS, "https://target.example.com/search", "q", {}
        )
        assert result.is_confirmed
        assert result.status == VerificationStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_not_confirmed_canary_absent(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, body="<html>Sanitized output</html>")

        result = await verifier.verify_vulnerability(
            VulnType.REFLECTED_XSS, "https://target.example.com/search", "q", {}
        )
        assert not result.is_confirmed

    @pytest.mark.asyncio
    async def test_waf_block(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, side_effect=WafBlockError("WAF-body:cloudflare", 403))

        result = await verifier.verify_vulnerability(
            VulnType.REFLECTED_XSS, "https://target.example.com/search", "q", {}
        )
        assert result.status == VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE


class TestActiveVerifierCors:
    @pytest.mark.asyncio
    async def test_confirmed_credential_cors(self):
        verifier = ActiveVerifier()
        captured_origin: list[str] = []

        async def fake_probe(request):
            origin = request.headers.get("Origin", "")
            captured_origin.append(origin)
            headers = {
                "access-control-allow-origin":      origin,
                "access-control-allow-credentials": "true",
            }
            return 200, headers, "", 0.05

        verifier._prober.probe = fake_probe

        result = await verifier.verify_vulnerability(
            VulnType.CORS_MISCONFIGURATION, "https://api.target.example.com/data", "unused", {}
        )
        assert result.is_confirmed
        assert result.confidence_score == 1.0

    @pytest.mark.asyncio
    async def test_not_confirmed_no_acao(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={"content-type": "application/json"})

        result = await verifier.verify_vulnerability(
            VulnType.CORS_MISCONFIGURATION, "https://api.target.example.com/data", "unused", {}
        )
        assert not result.is_confirmed

    @pytest.mark.asyncio
    async def test_wildcard_cors_confirmed_lower_confidence(self):
        verifier = ActiveVerifier()
        _patch_prober(
            verifier, status=200,
            headers={"access-control-allow-origin": "*"},
        )

        result = await verifier.verify_vulnerability(
            VulnType.CORS_MISCONFIGURATION, "https://api.target.example.com/data", "unused", {}
        )
        assert result.is_confirmed
        assert result.confidence_score < 1.0


class TestActiveVerifierPathTraversal:
    @pytest.mark.asyncio
    async def test_confirmed_on_first_probe(self):
        verifier = ActiveVerifier()
        robots_body = "User-agent: *\nDisallow: /private\nAllow: /\nSitemap: https://target.example.com/sitemap.xml"
        _patch_prober(verifier, status=200, body=robots_body)

        result = await verifier.verify_vulnerability(
            VulnType.PATH_TRAVERSAL, "https://target.example.com/download", "file", {}
        )
        assert result.is_confirmed
        assert result.status == VerificationStatus.CONFIRMED
        assert result.probes_sent >= 1

    @pytest.mark.asyncio
    async def test_not_confirmed_all_probes_fail(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, body="<html>error: file not found</html>")

        result = await verifier.verify_vulnerability(
            VulnType.PATH_TRAVERSAL, "https://target.example.com/download", "file", {}
        )
        assert not result.is_confirmed

    @pytest.mark.asyncio
    async def test_waf_block_aborts_on_first_probe(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, side_effect=WafBlockError("WAF-generic", 403))

        result = await verifier.verify_vulnerability(
            VulnType.PATH_TRAVERSAL, "https://target.example.com/download", "file", {}
        )
        assert result.status == VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE

    @pytest.mark.asyncio
    async def test_timeout_continues_to_next_probe(self):
        verifier = ActiveVerifier()
        call_count = 0

        async def sometimes_timeout(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.TimeoutError()
            return 200, {}, "boring response with nothing useful", 0.05

        verifier._prober.probe = sometimes_timeout

        result = await verifier.verify_vulnerability(
            VulnType.PATH_TRAVERSAL, "https://target.example.com/download", "file", {}
        )
        # Should have tried multiple probes
        assert result.probes_sent >= 2


class TestActiveVerifierHostHeader:
    @pytest.mark.asyncio
    async def test_confirmed_in_location(self):
        verifier = ActiveVerifier()
        captured_host: list[str] = []

        async def fake_probe(request):
            host = request.headers.get("Host", "")
            captured_host.append(host)
            headers = {"Location": f"https://{host}/password-reset?token=abc"}
            return 302, headers, "", 0.05

        verifier._prober.probe = fake_probe

        result = await verifier.verify_vulnerability(
            VulnType.HOST_HEADER_INJECTION, "https://target.example.com/reset", "unused", {}
        )
        assert result.is_confirmed
        assert result.confidence_score >= 0.9

    @pytest.mark.asyncio
    async def test_not_confirmed(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={}, body="Normal password reset page")

        result = await verifier.verify_vulnerability(
            VulnType.HOST_HEADER_INJECTION, "https://target.example.com/reset", "unused", {}
        )
        assert not result.is_confirmed


class TestActiveVerifierSsti:
    @pytest.mark.asyncio
    async def test_confirmed(self):
        verifier = ActiveVerifier()
        # Call 1 = baseline (clean), call 2+ = SSTI-triggered response.
        # The baseline must NOT contain the expression, otherwise the verifier
        # correctly flags the result as inconclusive and returns early.
        call_count = 0

        async def baseline_then_ssti(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return 200, {}, "Normal template output", 0.05  # baseline: clean
            return 200, {}, f"Result: {_SSTI_EXPRESSION}", 0.05  # SSTI evaluated

        verifier._prober.probe = baseline_then_ssti

        result = await verifier.verify_vulnerability(
            VulnType.SSTI, "https://target.example.com/template", "msg", {}
        )
        assert result.is_confirmed
        assert result.status == VerificationStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_not_confirmed(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, body="Hello {{7*1111}} there")  # unevaluated

        result = await verifier.verify_vulnerability(
            VulnType.SSTI, "https://target.example.com/template", "msg", {}
        )
        assert not result.is_confirmed

    @pytest.mark.asyncio
    async def test_inconclusive_when_expression_in_baseline(self):
        """Expression already present in baseline → verifier must not confirm."""
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, body=f"page with {_SSTI_EXPRESSION} in it")

        result = await verifier.verify_vulnerability(
            VulnType.SSTI, "https://target.example.com/template", "msg", {}
        )
        assert not result.is_confirmed
        assert _SSTI_EXPRESSION in result.error

    @pytest.mark.asyncio
    async def test_confirmed_on_second_probe(self):
        verifier = ActiveVerifier()
        call_count = 0

        async def probe_responses(request):
            nonlocal call_count
            call_count += 1
            # call 1 = baseline, call 2 = first SSTI probe (no eval),
            # call 3 = second SSTI probe (confirmed)
            if call_count <= 2:
                return 200, {}, "no eval here", 0.05
            return 200, {}, f"evaluated: {_SSTI_EXPRESSION}", 0.05

        verifier._prober.probe = probe_responses

        result = await verifier.verify_vulnerability(
            VulnType.SSTI, "https://target.example.com/template", "msg", {}
        )
        assert result.is_confirmed
        assert result.probes_sent >= 2


class TestActiveVerifierCrlf:
    @pytest.mark.asyncio
    async def test_confirmed(self):
        verifier = ActiveVerifier()
        _patch_prober(
            verifier,
            status=200,
            headers={_CRLF_CANARY_HEADER: "canary1"},
        )

        result = await verifier.verify_vulnerability(
            VulnType.CRLF_INJECTION, "https://target.example.com/redirect", "url", {}
        )
        assert result.is_confirmed
        assert result.confidence_score == 1.0

    @pytest.mark.asyncio
    async def test_not_confirmed(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={"content-type": "text/html"})

        result = await verifier.verify_vulnerability(
            VulnType.CRLF_INJECTION, "https://target.example.com/redirect", "url", {}
        )
        assert not result.is_confirmed


# ─────────────────────────────────────────────────────────────────────────────
# 9. ActiveVerifier — cross-cutting concerns
# ─────────────────────────────────────────────────────────────────────────────

class TestActiveVerifierCrossCutting:
    @pytest.mark.asyncio
    async def test_unsupported_vuln_type_returns_error(self):
        verifier = ActiveVerifier()
        # Bypass enum validation with a raw string cast
        result = await verifier.verify_vulnerability(
            "UNSUPPORTED_TYPE",  # type: ignore[arg-type]
            "https://target.example.com/",
            "param",
            {},
        )
        assert result.status == VerificationStatus.ERROR
        assert not result.is_confirmed

    @pytest.mark.asyncio
    async def test_duration_is_populated(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={})

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/r", "next", {}
        )
        assert result.duration_seconds >= 0.0

    @pytest.mark.asyncio
    async def test_contextual_data_accepted_without_error(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={})

        ctx = {"tool_hints": ["open_redirect"], "prior_score": 55, "waf_detected": False}
        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/r", "next", ctx
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_none_contextual_data_accepted(self):
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={})

        result = await verifier.verify_vulnerability(
            VulnType.OPEN_REDIRECT, "https://target.example.com/r", "next", None
        )
        assert result is not None

    def test_timeout_capped_at_max(self):
        verifier = ActiveVerifier(timeout=999.0)
        assert verifier._timeout <= ActiveVerifier._MAX_ALLOWED_TIMEOUT

    def test_default_timeout(self):
        verifier = ActiveVerifier()
        from active_verifier import _PROBE_TIMEOUT_SECONDS
        assert verifier._timeout == _PROBE_TIMEOUT_SECONDS

    @pytest.mark.asyncio
    async def test_all_vuln_types_return_verification_result(self):
        """Smoke-test that every VulnType returns a VerificationResult."""
        verifier = ActiveVerifier()
        _patch_prober(verifier, status=200, headers={}, body="")

        for vuln in VulnType:
            result = await verifier.verify_vulnerability(
                vuln, "https://target.example.com/", "p", {}
            )
            assert isinstance(result, VerificationResult)
            assert result.vuln_type == vuln


# ─────────────────────────────────────────────────────────────────────────────
# 10. _build_reproduction_steps
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildReproductionSteps:
    def _make_req(self) -> ProbeRequest:
        return ProbeRequest(
            method="GET",
            url="https://target.example.com/redir",
            params={"next": f"https://{_CANARY_DOMAIN}/verify?token=XYZ"},
            allow_redirects=False,
        )

    def test_returns_list(self):
        steps = _build_reproduction_steps(
            VulnType.OPEN_REDIRECT, self._make_req(), (True, 1.0)
        )
        assert isinstance(steps, list)
        assert len(steps) > 0

    def test_curl_present(self):
        steps = _build_reproduction_steps(
            VulnType.OPEN_REDIRECT, self._make_req(), (True, 1.0)
        )
        full_text = "\n".join(steps)
        assert "curl" in full_text

    @pytest.mark.parametrize("vuln", list(VulnType))
    def test_all_vuln_types_produce_steps(self, vuln):
        req = ProbeRequest(
            method="GET",
            url="https://target.example.com/ep",
            params={"p": "payload"},
        )
        steps = _build_reproduction_steps(vuln, req, (False, 0.0))
        assert len(steps) > 0

    def test_confirmed_label(self):
        steps = _build_reproduction_steps(
            VulnType.OPEN_REDIRECT, self._make_req(), (True, 1.0)
        )
        full_text = "\n".join(steps)
        assert "CONFIRMED" in full_text

    def test_not_confirmed_label(self):
        steps = _build_reproduction_steps(
            VulnType.OPEN_REDIRECT, self._make_req(), (False, 0.2)
        )
        full_text = "\n".join(steps)
        assert "not confirmed" in full_text.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 11. WafBlockError / EthicalViolationError / SsrfBlockError
# ─────────────────────────────────────────────────────────────────────────────

class TestExceptions:
    def test_waf_block_error_attributes(self):
        exc = WafBlockError("WAF-header:cf-ray", 403)
        assert exc.waf_signature == "WAF-header:cf-ray"
        assert exc.status_code   == 403
        assert "WAF" in str(exc)

    def test_ethical_violation_error_message(self):
        exc = EthicalViolationError("payload rejected")
        assert "payload rejected" in str(exc)

    def test_ssrf_block_error_message(self):
        exc = SsrfBlockError("192.168.0.1 is private")
        assert "192.168.0.1" in str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# 12. VerificationResult dataclass
# ─────────────────────────────────────────────────────────────────────────────

class TestVerificationResult:
    def test_defaults(self):
        r = VerificationResult(
            vuln_type=VulnType.OPEN_REDIRECT,
            endpoint="https://example.com",
            parameter="next",
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False,
            confidence_score=0.0,
            canary_token="ABC",
        )
        assert r.raw_poc_request   is None
        assert r.response_summary  is None
        assert r.reproduction_steps == []
        assert r.waf_signature      is None
        assert r.error              == ""
        assert r.probes_sent        == 0
        assert r.duration_seconds   == 0.0

    def test_is_confirmed_true(self):
        r = VerificationResult(
            vuln_type=VulnType.REFLECTED_XSS,
            endpoint="https://example.com/search",
            parameter="q",
            status=VerificationStatus.CONFIRMED,
            is_confirmed=True,
            confidence_score=0.95,
            canary_token="XYZ",
        )
        assert r.is_confirmed
        assert r.confidence_score == 0.95

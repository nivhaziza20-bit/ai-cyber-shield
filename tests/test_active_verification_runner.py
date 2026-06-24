"""
tests/test_active_verification_runner.py — AI Cyber Shield v6

Test suite for active_verification_runner.py.
All HTTP calls are mocked — no real network traffic.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from active_verification_runner import (
    _MAX_VERIFICATIONS_PER_SCAN,
    _VerifiableVuln,
    _extract_verifiable_vulns,
    run_active_verification,
)
from active_verifier import VerificationResult, VerificationStatus, VulnType


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_BASE_URL = "https://target.example.com"


def _make_result(
    vuln_type: VulnType = VulnType.OPEN_REDIRECT,
    confirmed: bool = True,
    status: VerificationStatus = VerificationStatus.CONFIRMED,
) -> VerificationResult:
    return VerificationResult(
        vuln_type        = vuln_type,
        endpoint         = _BASE_URL,
        parameter        = "next",
        status           = status,
        is_confirmed     = confirmed,
        confidence_score = 1.0 if confirmed else 0.0,
        canary_token     = "AICS-CANARY-TEST",
    )


# ─────────────────────────────────────────────────────────────────────────────
# _extract_verifiable_vulns tests
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractVerifiableVulns:
    def test_empty_tool_results_returns_empty(self):
        assert _extract_verifiable_vulns(_BASE_URL, {}) == []

    def test_open_redirect_confirmed(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/redir"}]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.OPEN_REDIRECT in types

    def test_open_redirect_strips_query_string(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{
                    "param": "redirect",
                    "url": f"{_BASE_URL}/redir?token=abc&next=other",
                }]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        assert all("?" not in v.endpoint for v in vulns)

    def test_cors_wildcard_detected(self):
        tool_results = {
            "cors_csp": {
                "cors_issues": ["CORS wildcard Access-Control-Allow-Origin: * on /api"]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.CORS_MISCONFIGURATION in types

    def test_cors_allow_origin_detected(self):
        tool_results = {
            "cors_csp": {
                "cors_issues": ["Reflected allow-origin header found on /api/data"]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.CORS_MISCONFIGURATION in types

    def test_no_cors_issue_no_cors_vuln(self):
        tool_results = {"cors_csp": {"cors_issues": []}}
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        assert not any(v.vuln_type == VulnType.CORS_MISCONFIGURATION for v in vulns)

    def test_open_redirect_candidate_fallback(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [],
                "candidates": [{"param": "goto", "url": f"{_BASE_URL}/go"}],
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.OPEN_REDIRECT in types

    def test_confirmed_redirect_takes_priority_over_candidate(self):
        """If a confirmed redirect is present, candidates should not add duplicates."""
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/redir"}],
                "candidates": [{"param": "goto", "url": f"{_BASE_URL}/go"}],
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        open_redir = [v for v in vulns if v.vuln_type == VulnType.OPEN_REDIRECT]
        # Candidate should be skipped since confirmed already added
        for v in open_redir:
            assert v.source_tool == "open_redirect"

    def test_xss_from_spa_api_calls(self):
        tool_results = {
            "deep_js_crawler": {
                "api_calls": [{"url": f"{_BASE_URL}/api/search?q=test"}]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.REFLECTED_XSS in types

    def test_xss_skips_chrome_extension_urls(self):
        tool_results = {
            "deep_js_crawler": {
                "api_calls": [{"url": "chrome-extension://abcdef/api/call"}]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        assert not any(v.vuln_type == VulnType.REFLECTED_XSS for v in vulns)

    def test_ssti_from_html_template_issues(self):
        tool_results = {
            "html": {
                "template_issues": ["SSTI risk: user input rendered in template"]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.SSTI in types

    def test_path_traversal_from_crawler(self):
        tool_results = {
            "crawler": {
                "sensitive_paths": ["/download?file=../../etc/robots.txt"]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.PATH_TRAVERSAL in types

    def test_crlf_from_exposure(self):
        tool_results = {
            "exposure": {
                "http_issues": ["CRLF injection possible via Location header"]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.CRLF_INJECTION in types

    def test_host_header_from_missing_headers(self):
        tool_results = {
            "headers": {
                "missing_headers": ["X-Forwarded-Host validation missing (host header injection risk)"]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        types = [v.vuln_type for v in vulns]
        assert VulnType.HOST_HEADER_INJECTION in types

    def test_cap_at_max_verifications(self):
        """Never return more than _MAX_VERIFICATIONS_PER_SCAN items."""
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [
                    {"param": f"p{i}", "url": f"{_BASE_URL}/r{i}"} for i in range(10)
                ]
            },
            "cors_csp": {"cors_issues": ["CORS wildcard"]},
            "deep_js_crawler": {
                "api_calls": [{"url": f"{_BASE_URL}/api/x"}]
            },
            "html": {"template_issues": ["SSTI risk"]},
            "crawler": {"sensitive_paths": ["../../robots.txt"]},
            "exposure": {"http_issues": ["CRLF injection"]},
            "headers": {"missing_headers": ["host header"]},
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        assert len(vulns) <= _MAX_VERIFICATIONS_PER_SCAN

    def test_source_tool_recorded(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/r"}]
            }
        }
        vulns = _extract_verifiable_vulns(_BASE_URL, tool_results)
        assert vulns[0].source_tool == "open_redirect"


# ─────────────────────────────────────────────────────────────────────────────
# run_active_verification tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRunActiveVerification:
    def _patch_verifier(self, results: list[VerificationResult]):
        """Patch ActiveVerifier.verify_vulnerability to return given results in order."""
        results_iter = iter(results)

        async def fake_verify(self_v, vuln_type, endpoint, parameter, contextual_data=None):
            try:
                return next(results_iter)
            except StopIteration:
                return _make_result(vuln_type=vuln_type, confirmed=False,
                                    status=VerificationStatus.NOT_CONFIRMED)

        return patch(
            "active_verification_runner.ActiveVerifier.verify_vulnerability",
            new=fake_verify,
        )

    def test_empty_tool_results_returns_empty(self):
        results = run_active_verification(_BASE_URL, {})
        assert results == []

    def test_no_findings_returns_empty(self):
        tool_results = {"ssl": {"ssl_score": 100}, "headers": {"security_score": 90}}
        results = run_active_verification(_BASE_URL, tool_results)
        assert results == []

    def test_confirmed_redirect_in_results(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/redir"}]
            }
        }
        expected = _make_result(VulnType.OPEN_REDIRECT, confirmed=True)
        with self._patch_verifier([expected]):
            results = run_active_verification(_BASE_URL, tool_results)

        assert len(results) == 1
        assert results[0].is_confirmed is True

    def test_waf_block_in_results(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/redir"}]
            }
        }
        expected = _make_result(
            VulnType.OPEN_REDIRECT, confirmed=False,
            status=VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE,
        )
        with self._patch_verifier([expected]):
            results = run_active_verification(_BASE_URL, tool_results)

        assert results[0].status == VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
        assert results[0].is_confirmed is False

    def test_multiple_vulns_all_returned(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/redir"}]
            },
            "cors_csp": {"cors_issues": ["CORS wildcard"]},
        }
        expected_1 = _make_result(VulnType.OPEN_REDIRECT, confirmed=True)
        expected_2 = _make_result(VulnType.CORS_MISCONFIGURATION, confirmed=False,
                                  status=VerificationStatus.NOT_CONFIRMED)
        with self._patch_verifier([expected_1, expected_2]):
            results = run_active_verification(_BASE_URL, tool_results)

        assert len(results) == 2

    def test_exception_from_verifier_returns_empty(self):
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/redir"}]
            }
        }
        with patch(
            "active_verification_runner._run_async_safe",
            side_effect=RuntimeError("boom"),
        ):
            results = run_active_verification(_BASE_URL, tool_results)
        assert results == []

    def test_timeout_parameter_passed_to_verifier(self):
        """Ensure the timeout kwarg reaches the ActiveVerifier constructor."""
        tool_results = {
            "open_redirect": {
                "confirmed_redirects": [{"param": "next", "url": f"{_BASE_URL}/redir"}]
            }
        }
        captured_timeout: list[float] = []

        original_init = __import__("active_verifier").ActiveVerifier.__init__

        def patched_init(self_v, timeout=5.0, **kw):
            captured_timeout.append(timeout)
            original_init(self_v, timeout=timeout, **kw)

        with patch("active_verification_runner.ActiveVerifier.__init__", new=patched_init), \
             patch("active_verification_runner._run_async_safe", return_value=[]):
            run_active_verification(_BASE_URL, tool_results, timeout=3.0)

        assert captured_timeout and captured_timeout[0] == 3.0

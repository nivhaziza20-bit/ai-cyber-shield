"""
Tests for URL Scanner Pipeline (Step 5).
All tool calls and LLM calls are mocked — no network, no API cost.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from url_scanner_pipeline import (
    run_url_security_audit,
    _aggregate_scores,
    _extract_critical_findings,
    _grade,
)


# ─────────────────────────────────────────────────────────────────────────────
# Unit — grade + score helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestGrade:
    def test_90_plus_is_A(self):  assert _grade(95) == "A"
    def test_75_is_B(self):       assert _grade(75) == "B"
    def test_60_is_C(self):       assert _grade(60) == "C"
    def test_40_is_D(self):       assert _grade(40) == "D"
    def test_below_40_is_F(self): assert _grade(20) == "F"
    def test_zero_is_F(self):     assert _grade(0)  == "F"


class TestAggregateScores:

    def _make_results(self, ssl=100, headers=100, html_risk=0,
                      tech_risk=0, crawler_risk=0,
                      cors_csp_risk=0, dns_risk=0, exposure_risk=0,
                      waf_protection=100, ct_risk=0, hsts_risk=0, redir_risk=0,
                      api_spec_risk=0, takeover_risk=0,
                      port_risk=0, cookie_risk=0, js_risk=0):
        return {
            "ssl":                {"ssl_score": ssl},
            "headers":            {"security_score": headers},
            "html":               {"risk_score": html_risk},
            "tech":               {"risk_score": tech_risk},
            "crawler":            {"risk_score": crawler_risk},
            "cors_csp":           {"risk_score": cors_csp_risk},
            "dns":                {"risk_score": dns_risk},
            "exposure":           {"risk_score": exposure_risk},
            "waf":                {"protection_score": waf_protection},
            "cert_transparency":  {"risk_score": ct_risk},
            "hsts_preload":       {"risk_score": hsts_risk},
            "open_redirect":      {"risk_score": redir_risk},
            "api_spec":           {"risk_score": api_spec_risk},
            "subdomain_takeover": {"risk_score": takeover_risk},
            "port_scanner":       {"risk_score": port_risk},
            "cookie_security":    {"risk_score": cookie_risk},
            "deep_js_crawler":    {"risk_score": js_risk},
        }

    def test_perfect_scores_give_100(self):
        overall, cats = _aggregate_scores(self._make_results())
        assert overall == 100
        assert cats["ssl"] == 100

    def test_zero_ssl_drags_score_down(self):
        overall, _ = _aggregate_scores(self._make_results(ssl=0))
        assert overall <= 87  # ssl weight=13 → perfect others = 87

    def test_high_html_risk_lowers_score(self):
        overall, cats = _aggregate_scores(self._make_results(html_risk=100))
        assert cats["html"] == 0
        assert overall <= 91  # html weight=9 → perfect others = 91

    def test_missing_tool_defaults_to_zero(self):
        results = {}  # all tools missing
        overall, cats = _aggregate_scores(results)
        assert overall == 0


class TestExtractCriticalFindings:

    def test_exposed_secret_extracted(self):
        tool_results = {
            "html": {"exposed_secrets": [{"type": "AWS Access Key", "sample": "AKIA***"}]},
            "ssl": {"grade": "B", "findings": []},
            "tech": {"cve_findings": []},
            "crawler": {"sensitive_paths": [], "stack_trace_leaks": []},
        }
        findings = _extract_critical_findings(tool_results)
        assert any("AWS Access Key" in f for f in findings)

    def test_ssl_grade_f_findings_included(self):
        tool_results = {
            "ssl": {"grade": "F", "findings": ["CRITICAL: TLSv1 deprecated"]},
            "html": {"exposed_secrets": []},
            "tech": {"cve_findings": []},
            "crawler": {"sensitive_paths": [], "stack_trace_leaks": []},
        }
        findings = _extract_critical_findings(tool_results)
        assert any("TLSv1" in f for f in findings)

    def test_cve_finding_extracted(self):
        tool_results = {
            "ssl": {"grade": "A", "findings": []},
            "html": {"exposed_secrets": []},
            "tech": {"cve_findings": [{"cve": "CVE-2019-11358",
                                        "description": "Prototype pollution",
                                        "affected": "jQuery < 3.5.0"}]},
            "crawler": {"sensitive_paths": [], "stack_trace_leaks": []},
        }
        findings = _extract_critical_findings(tool_results)
        assert any("CVE-2019-11358" in f for f in findings)

    def test_max_12_findings_returned(self):
        tool_results = {
            "ssl": {"grade": "F",
                    "findings": [f"Finding {i}" for i in range(20)]},
            "html": {"exposed_secrets": [{"type": f"Key{i}", "sample": "***"}
                                          for i in range(10)]},
            "tech": {"cve_findings": []},
            "crawler": {"sensitive_paths": [], "stack_trace_leaks": []},
        }
        findings = _extract_critical_findings(tool_results)
        assert len(findings) <= 12


# ─────────────────────────────────────────────────────────────────────────────
# Integration — full pipeline with mocked tools + LLM
# ─────────────────────────────────────────────────────────────────────────────

_GOOD_TOOL_RESULTS = {
    "ssl":      {"status": "completed", "ssl_score": 100, "grade": "A",
                 "tls_version": "TLSv1.3", "findings": [], "cipher_suite": "AES256"},
    "headers":  {"status": "completed", "security_score": 90,
                 "missing_headers": [], "present_headers": {}},
    "html":     {"status": "completed", "risk_score": 0,
                 "exposed_secrets": [], "form_issues": [], "mixed_content": [],
                 "cookie_issues": [], "recommendations": []},
    "tech":     {"status": "completed", "risk_score": 0,
                 "detected_technologies": ["nginx"], "cve_findings": [],
                 "versioned_libraries": []},
    "crawler":  {"status": "completed", "risk_score": 0, "total_pages": 3,
                 "sensitive_paths": [], "broken_links": [],
                 "stack_trace_leaks": [], "login_pages": []},
    "cors_csp": {"status": "completed", "risk_score": 0,
                 "csp_present": True, "csp_quality": "strong",
                 "cors_issues": [], "csp_issues": []},
    "dns":      {"status": "completed", "risk_score": 0,
                 "spf": {"record": "v=spf1 -all", "risk": 0, "issues": []},
                 "dmarc": {"record": "v=DMARC1; p=reject", "risk": 0, "issues": []},
                 "caa": {"records": ["letsencrypt.org"], "risk": 0, "issues": []}},
    "exposure": {"status": "completed", "risk_score": 0,
                 "exposed_files": [], "exposed_source_maps": [],
                 "sri_missing": [], "dangerous_methods": []},
    "waf":               {"status": "completed", "waf_detected": True,
                          "waf_name": "Cloudflare", "confidence": 90,
                          "probe_blocked": True, "protection_score": 90},
    "cert_transparency": {"status": "completed", "risk_score": 0,
                          "subdomain_count": 2, "interesting_subdomains": [],
                          "all_subdomains": ["mail.example.com"]},
    "hsts_preload":      {"status": "completed", "risk_score": 0,
                          "hsts_present": True, "hsts_quality": "strong",
                          "preloaded": True, "preload_status": "preloaded"},
    "open_redirect":     {"status": "completed", "risk_score": 0,
                          "candidates_found": 0, "confirmed_redirects": []},
    "api_spec":          {"status": "completed", "risk_score": 0,
                          "exposed_specs": [], "graphql_introspection": [],
                          "total_operations": 0, "auth_schemes_disclosed": []},
    "subdomain_takeover": {"status": "completed", "risk_score": 0,
                           "checked_count": 1, "confirmed_takeovers": [],
                           "potential_takeovers": []},
    "port_scanner":      {"status": "completed", "risk_score": 0,
                          "open_ports": [], "open_count": 0},
    "cookie_security":   {"status": "completed", "risk_score": 0,
                          "cookies_found": 2, "issues": [], "issue_count": 0},
    "deep_js_crawler":   {"status": "completed", "risk_score": 0,
                          "pages_visited": ["https://example.com"],
                          "secret_leaks": [], "ssrf_attempts": [],
                          "discovered_forms": [], "discovered_links": [],
                          "summary": {"secrets_detected": 0, "ssrf_blocked": 0}},
}

_BAD_TOOL_RESULTS = {
    "ssl":      {"status": "completed", "ssl_score": 0, "grade": "F",
                 "tls_version": "TLSv1", "findings": ["CRITICAL: TLSv1 deprecated"],
                 "cipher_suite": "RC4"},
    "headers":  {"status": "completed", "security_score": 10,
                 "missing_headers": ["HSTS", "CSP"], "present_headers": {}},
    "html":     {"status": "completed", "risk_score": 80,
                 "exposed_secrets": [{"type": "AWS Access Key", "sample": "AKIA***"}],
                 "form_issues": [{"form_action": "/login", "issue": "No CSRF"}],
                 "mixed_content": [], "cookie_issues": [], "recommendations": []},
    "tech":     {"status": "completed", "risk_score": 50,
                 "detected_technologies": ["WordPress", "jQuery"],
                 "cve_findings": [{"cve": "CVE-2019-11358",
                                    "description": "Prototype pollution",
                                    "affected": "jQuery < 3.5.0",
                                    "detected": "1.11.0", "severity": "HIGH"}],
                 "versioned_libraries": [{"library": "jQuery", "version": "1.11.0"}]},
    "crawler":  {"status": "completed", "risk_score": 45, "total_pages": 5,
                 "sensitive_paths": ["https://example.com/admin"],
                 "broken_links": [], "stack_trace_leaks": [], "login_pages": []},
    "cors_csp": {"status": "completed", "risk_score": 60,
                 "csp_present": False, "csp_quality": "none",
                 "cors_issues": ["CRITICAL: wildcard + credentials"],
                 "csp_issues": ["No CSP header"]},
    "dns":      {"status": "completed", "risk_score": 50,
                 "spf": {"record": None, "risk": 30, "issues": ["No SPF"]},
                 "dmarc": {"record": None, "risk": 20, "issues": ["No DMARC"]},
                 "caa": {"records": [], "risk": 5, "issues": []}},
    "exposure": {"status": "completed", "risk_score": 50,
                 "exposed_files": [{"path": "/.git/HEAD", "description": "Git exposed",
                                     "url": "https://example.com/.git/HEAD", "risk": 50}],
                 "exposed_source_maps": [], "sri_missing": [], "dangerous_methods": ["TRACE"]},
    "waf":               {"status": "completed", "waf_detected": False, "waf_name": None,
                          "confidence": 0, "probe_blocked": False, "protection_score": 30},
    "cert_transparency": {"status": "completed", "risk_score": 30,
                          "subdomain_count": 18,
                          "interesting_subdomains": ["staging.example.com", "admin.example.com"],
                          "all_subdomains": ["staging.example.com", "admin.example.com"]},
    "hsts_preload":      {"status": "completed", "risk_score": 30,
                          "hsts_present": False, "hsts_quality": "none",
                          "preloaded": False, "preload_status": "unknown"},
    "open_redirect":     {"status": "completed", "risk_score": 50,
                          "candidates_found": 2,
                          "confirmed_redirects": [
                              {"url": "https://example.com/go?next=...",
                               "param": "next", "confirmed": True, "severity": "HIGH"}
                          ]},
    "api_spec":          {"status": "completed", "risk_score": 45,
                          "exposed_specs": [
                              {"path": "/swagger-ui.html", "description": "Swagger UI",
                               "category": "swagger_ui", "risk": 45}
                          ],
                          "graphql_introspection": [],
                          "total_operations": 32, "auth_schemes_disclosed": []},
    "subdomain_takeover": {"status": "completed", "risk_score": 50,
                           "checked_count": 2,
                           "confirmed_takeovers": [
                               {"subdomain": "staging.example.com",
                                "service": "Heroku", "confidence": "HIGH",
                                "severity": "HIGH",
                                "attack": "Attacker can claim Heroku app."}
                           ],
                           "potential_takeovers": []},
    "port_scanner":      {"status": "completed", "risk_score": 70,
                          "open_ports": [
                              {"port": 3306, "service": "MySQL",
                               "description": "Database exposed", "risk": 70}
                          ],
                          "open_count": 1},
    "cookie_security":   {"status": "completed", "risk_score": 55,
                          "cookies_found": 2,
                          "issues": [
                              {"check": "Secure flag missing", "severity": "HIGH",
                               "description": "Session cookie missing Secure", "risk": 40},
                              {"check": "HttpOnly flag missing", "severity": "HIGH",
                               "description": "Session cookie missing HttpOnly", "risk": 30},
                          ],
                          "issue_count": 2},
    "deep_js_crawler":   {"status": "completed", "risk_score": 60,
                          "pages_visited": ["https://example.com"],
                          "secret_leaks": [
                              {"kind": "AWS_ACCESS_KEY_ID", "description": "AWS Access Key ID",
                               "sample": "AKIAXXX...", "source": "inline_script",
                               "source_url": "https://example.com/app.js"}
                          ],
                          "ssrf_attempts": [],
                          "discovered_forms": [], "discovered_links": [],
                          "summary": {"secrets_detected": 1, "ssrf_blocked": 0}},
}


def _make_pipeline_mock(tool_results: dict, llm_text: str = "## Report\nAll good."):
    """Returns a context manager stack that mocks all tools + LLM."""
    def mock_run_tools(url, scan_auth=None):
        return tool_results

    mock_llm_resp = MagicMock()
    mock_llm_resp.content = llm_text

    return mock_run_tools, mock_llm_resp


class TestRunUrlSecurityAudit:

    def _run(self, url: str, tool_results: dict, llm_text: str = "## Report") -> dict:
        mock_tools, mock_llm_resp = _make_pipeline_mock(tool_results, llm_text)
        with patch("url_scanner_pipeline._run_tools_parallel", side_effect=mock_tools):
            with patch("url_scanner_pipeline._get_llm") as mock_get_llm:
                mock_llm = MagicMock()
                mock_llm.invoke.return_value = mock_llm_resp
                mock_get_llm.return_value = mock_llm
                return run_url_security_audit(url)

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="Invalid URL scheme"):
            run_url_security_audit("ftp://example.com")

    def test_returns_required_keys(self):
        result = self._run("https://example.com", _GOOD_TOOL_RESULTS)
        for key in ("raw_output", "overall_grade", "overall_score",
                    "category_scores", "critical_findings", "tool_results"):
            assert key in result, f"Missing key: {key}"

    def test_good_site_grades_well(self):
        result = self._run("https://example.com", _GOOD_TOOL_RESULTS)
        assert result["overall_grade"] in ("A", "B")
        assert result["overall_score"] >= 75

    def test_bad_site_grades_poorly(self):
        result = self._run("https://example.com", _BAD_TOOL_RESULTS)
        assert result["overall_grade"] in ("D", "F")
        assert result["overall_score"] < 50

    def test_critical_findings_extracted_for_bad_site(self):
        result = self._run("https://example.com", _BAD_TOOL_RESULTS)
        assert len(result["critical_findings"]) > 0

    def test_llm_output_in_raw_output(self):
        result = self._run("https://example.com", _GOOD_TOOL_RESULTS,
                           llm_text="## Security Report\nAll clear.")
        assert "Security Report" in result["raw_output"]

    def test_category_scores_all_present(self):
        result = self._run("https://example.com", _GOOD_TOOL_RESULTS)
        cats = result["category_scores"]
        for key in ("ssl", "headers", "html", "tech", "crawler",
                    "cors_csp", "dns", "exposure",
                    "waf", "cert_transparency", "hsts_preload", "open_redirect",
                    "api_spec", "subdomain_takeover",
                    "port_scanner", "cookie_security", "deep_js_crawler"):
            assert key in cats

    def test_tool_results_passed_through(self):
        result = self._run("https://example.com", _GOOD_TOOL_RESULTS)
        assert result["tool_results"] == _GOOD_TOOL_RESULTS

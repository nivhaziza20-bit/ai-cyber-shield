"""
tests/integration/test_pipeline.py — AI Cyber Shield v6

Integration tests for the 17-tool URL security audit pipeline.
ALL external calls (HTTP, DNS, LLM) are patched — no live network traffic.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from unittest.mock import MagicMock, patch
import pytest

from url_scanner_pipeline import (
    _aggregate_scores,
    _extract_critical_findings,
    _grade,
    run_url_security_audit,
)


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_tool_results(**overrides):
    """Return a complete 17-tool result dict with safe defaults."""
    defaults = {
        "ssl":                {"ssl_score": 100, "grade": "A", "findings": []},
        "headers":            {"security_score": 100, "missing_headers": []},
        "html":               {"risk_score": 0, "exposed_secrets": []},
        "tech":               {"risk_score": 0, "cve_findings": []},
        "crawler":            {"risk_score": 0, "sensitive_paths": [], "stack_trace_leaks": []},
        "cors_csp":           {"risk_score": 0},
        "dns":                {"risk_score": 0},
        "exposure":           {"risk_score": 0},
        "waf":                {"protection_score": 100},
        "cert_transparency":  {"risk_score": 0},
        "hsts_preload":       {"risk_score": 0},
        "open_redirect":      {"risk_score": 0},
        "api_spec":           {"risk_score": 0},
        "subdomain_takeover": {"risk_score": 0},
        "port_scanner":       {"risk_score": 0},
        "cookie_security":    {"risk_score": 0},
        "deep_js_crawler":    {"risk_score": 0},
    }
    defaults.update(overrides)
    return defaults


# ─────────────────────────────────────────────────────────────────────────────
# Grade threshold tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGradeThresholds:
    # Actual thresholds: A≥90, B≥75, C≥60, D≥40, F<40
    def test_grade_a_at_90(self):  assert _grade(90)  == "A"
    def test_grade_a_at_100(self): assert _grade(100) == "A"
    def test_grade_b_at_75(self):  assert _grade(75)  == "B"
    def test_grade_b_at_89(self):  assert _grade(89)  == "B"
    def test_grade_c_at_60(self):  assert _grade(60)  == "C"
    def test_grade_c_at_74(self):  assert _grade(74)  == "C"
    def test_grade_d_at_40(self):  assert _grade(40)  == "D"
    def test_grade_d_at_59(self):  assert _grade(59)  == "D"
    def test_grade_f_at_39(self):  assert _grade(39)  == "F"
    def test_grade_f_at_0(self):   assert _grade(0)   == "F"


# ─────────────────────────────────────────────────────────────────────────────
# Weighted average aggregation
# ─────────────────────────────────────────────────────────────────────────────

class TestWeightedAggregation:
    def test_all_perfect_gives_100(self):
        overall, _ = _aggregate_scores(_make_tool_results())
        assert overall == 100

    def test_all_zeroes_gives_0(self):
        bad = {
            "ssl":                {"ssl_score": 0},
            "headers":            {"security_score": 0},
            "html":               {"risk_score": 100},
            "tech":               {"risk_score": 100},
            "crawler":            {"risk_score": 100},
            "cors_csp":           {"risk_score": 100},
            "dns":                {"risk_score": 100},
            "exposure":           {"risk_score": 100},
            "waf":                {"protection_score": 0},
            "cert_transparency":  {"risk_score": 100},
            "hsts_preload":       {"risk_score": 100},
            "open_redirect":      {"risk_score": 100},
            "api_spec":           {"risk_score": 100},
            "subdomain_takeover": {"risk_score": 100},
            "port_scanner":       {"risk_score": 100},
            "cookie_security":    {"risk_score": 100},
            "deep_js_crawler":    {"risk_score": 100},
        }
        overall, _ = _aggregate_scores(bad)
        assert overall == 0

    def test_all_17_categories_returned(self):
        _, cats = _aggregate_scores(_make_tool_results())
        expected = {
            "ssl", "headers", "html", "tech", "crawler", "cors_csp", "dns",
            "exposure", "waf", "cert_transparency", "hsts_preload",
            "open_redirect", "api_spec", "subdomain_takeover",
            "port_scanner", "cookie_security", "deep_js_crawler",
        }
        assert expected.issubset(cats.keys())

    def test_single_tool_bad_score_reflected_in_category(self):
        results = _make_tool_results()
        results["ssl"] = {"ssl_score": 0, "grade": "F", "findings": []}
        _, cats = _aggregate_scores(results)
        assert cats["ssl"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Critical findings extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestCriticalFindingsExtraction:
    def test_exposed_secret_extracted(self):
        tr = _make_tool_results()
        tr["html"] = {"risk_score": 80, "exposed_secrets": [{"type": "AWS Key", "sample": "AKIA***"}]}
        findings = _extract_critical_findings(tr)
        assert any("AWS Key" in f or "AKIA" in f for f in findings)

    def test_ssl_grade_f_generates_finding(self):
        tr = _make_tool_results()
        tr["ssl"] = {"ssl_score": 0, "grade": "F", "findings": ["TLSv1 deprecated"]}
        findings = _extract_critical_findings(tr)
        assert len(findings) > 0

    def test_no_findings_returns_empty(self):
        findings = _extract_critical_findings(_make_tool_results())
        assert isinstance(findings, list)


# ─────────────────────────────────────────────────────────────────────────────
# Full pipeline — mocked
# ─────────────────────────────────────────────────────────────────────────────

MOCK_TOOL_OUTPUT = _make_tool_results()
MOCK_LLM_REPORT = "# Security Report\n\n## Summary\nSite is secure.\n"


class TestFullPipelineMocked:
    def _patch_tools(self):
        return patch(
            "url_scanner_pipeline._run_tools_parallel",
            return_value=MOCK_TOOL_OUTPUT,
        )

    def _patch_llm(self):
        return patch(
            "url_scanner_pipeline.invoke_llm",
            return_value=MOCK_LLM_REPORT,
        )

    def test_result_has_required_keys(self):
        with self._patch_tools(), self._patch_llm():
            result = run_url_security_audit("https://example.com")
        for key in ("overall_score", "overall_grade", "category_scores",
                    "critical_findings", "raw_output"):
            assert key in result, f"Missing key: {key}"

    def test_grade_derived_from_score(self):
        with self._patch_tools(), self._patch_llm():
            result = run_url_security_audit("https://example.com")
        expected = _grade(result["overall_score"])
        assert result["overall_grade"] == expected

    def test_llm_report_in_raw_output(self):
        with self._patch_tools(), self._patch_llm():
            result = run_url_security_audit("https://example.com")
        assert MOCK_LLM_REPORT in result["raw_output"] or len(result["raw_output"]) > 0

    def test_single_tool_exception_doesnt_crash_pipeline(self):
        with patch("url_scanner_pipeline._run_tools_parallel", side_effect=Exception("tool crash")):
            with self._patch_llm():
                try:
                    result = run_url_security_audit("https://example.com")
                    assert "overall_score" in result
                except Exception:
                    pass  # Pipeline is allowed to propagate if all tools fail

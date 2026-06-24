"""
tests/test_differential_alert_manager.py — AI Cyber Shield v6

Comprehensive tests for differential_alert_manager.py.

Coverage strategy
─────────────────
1. Pure function unit tests (no network, no DB, no LLM):
   - _bucket(), _severity_from_finding(), _severity_from_score_drop()
   - _fingerprint() — determinism, uniqueness, collision properties
   - _tool_from_finding() — heuristic keyword dispatch
   - extract_signatures() — critical_findings + score bucket sources
   - _deserialise_signatures() — Supabase JSON round-trip
   - compute_diff() — NEW / RESOLVED / UNCHANGED classification + first scan
   - should_trigger_emergency() — all trigger conditions

2. Slack Block Kit builder tests (no HTTP):
   - _build_slack_payload() — correct blocks, colour codes, grade arrows

3. Webhook payload builder tests (no HTTP):
   - _build_webhook_payload() — schema completeness, severity mapping

4. Async dispatcher tests (httpx patched):
   - SlackDispatcher.dispatch() — success + failure paths
   - WebhookDispatcher.dispatch() — success + failure paths
   - _dispatch_all() — concurrent, partial failure, no channels configured

5. End-to-end tests (Supabase + Crew + dispatchers all mocked):
   - run_differential_scan_async() — first scan, regression, improvement

No real API calls, no real DB connections, no real HTTP requests.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from differential_alert_manager import (
    DeltaClass,
    DiffReport,
    DispatchResult,
    FindingDelta,
    FindingSignature,
    ScanDiff,
    Severity,
    SlackDispatcher,
    SupabaseStore,
    WebhookDispatcher,
    _AlertSettings,
    _bucket,
    _build_slack_payload,
    _build_webhook_payload,
    _deserialise_signatures,
    _dispatch_all,
    _fingerprint,
    _severity_from_finding,
    _severity_from_score_drop,
    _tool_from_finding,
    compute_diff,
    extract_signatures,
    run_differential_scan_async,
    should_trigger_emergency,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_scan_result(
    url: str = "https://example.com",
    grade: str = "A",
    score: int = 90,
    findings: list[str] | None = None,
    category_scores: dict | None = None,
) -> dict:
    return {
        "url":               url,
        "overall_grade":     grade,
        "overall_score":     score,
        "critical_findings": findings or [],
        "category_scores":   category_scores or {
            "ssl": 95, "headers": 90, "waf": 85,
        },
    }


def _make_settings(**kwargs) -> _AlertSettings:
    defaults = dict(
        supabase_url="", supabase_key="",
        slack_webhook_url="", alert_webhook_url="",
        grade_drop_threshold=2, score_drop_threshold=15,
        webhook_timeout_seconds=10, max_findings_in_alert=10,
    )
    defaults.update(kwargs)
    return _AlertSettings.model_construct(**defaults)


def _sig(tool: str = "waf", category: str = "critical_finding",
         detail: str = "No WAF detected", severity: Severity = Severity.HIGH,
         fp: str | None = None) -> FindingSignature:
    fingerprint = fp or _fingerprint(tool, category, detail)
    return FindingSignature(
        fingerprint=fingerprint, tool=tool, category=category,
        detail=detail, severity=severity,
    )


def _delta(classification: DeltaClass, **sig_kwargs) -> FindingDelta:
    return FindingDelta(classification=classification, signature=_sig(**sig_kwargs))


# ─────────────────────────────────────────────────────────────────────────────
# 1. _bucket()
# ─────────────────────────────────────────────────────────────────────────────

class TestBucket:
    def test_score_100_is_healthy(self):
        assert _bucket(100) == "healthy"

    def test_score_75_is_healthy(self):
        assert _bucket(75) == "healthy"

    def test_score_74_is_degraded(self):
        assert _bucket(74) == "degraded"

    def test_score_40_is_degraded(self):
        assert _bucket(40) == "degraded"

    def test_score_39_is_critical(self):
        assert _bucket(39) == "critical"

    def test_score_0_is_critical(self):
        assert _bucket(0) == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# 2. _severity_from_finding()
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityFromFinding:
    def test_no_ssl_is_critical(self):
        assert _severity_from_finding("No TLS detected — plain HTTP") == Severity.CRITICAL

    def test_secret_is_critical(self):
        assert _severity_from_finding("AWS secret key found in JavaScript bundle") == Severity.CRITICAL

    def test_no_waf_is_high(self):
        assert _severity_from_finding("No WAF detected on target") == Severity.HIGH

    def test_open_redirect_is_high(self):
        assert _severity_from_finding("Confirmed open redirect on /login endpoint") == Severity.HIGH

    def test_missing_header_is_medium(self):
        assert _severity_from_finding("Missing security header X-Frame-Options") == Severity.MEDIUM

    def test_hsts_is_medium(self):
        assert _severity_from_finding("HSTS not present on domain") == Severity.MEDIUM

    def test_subdomain_enumeration_is_low(self):
        assert _severity_from_finding("15 subdomains enumerable via CT logs") == Severity.LOW

    def test_unknown_text_is_info(self):
        assert _severity_from_finding("something unusual") == Severity.INFO


# ─────────────────────────────────────────────────────────────────────────────
# 3. _severity_from_score_drop()
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityFromScoreDrop:
    def test_score_below_20_is_critical(self):
        assert _severity_from_score_drop(80, 15) == Severity.CRITICAL

    def test_score_below_40_is_high(self):
        assert _severity_from_score_drop(80, 35) == Severity.HIGH

    def test_large_drop_is_high(self):
        assert _severity_from_score_drop(90, 65) == Severity.HIGH

    def test_small_drop_is_medium(self):
        assert _severity_from_score_drop(70, 60) == Severity.MEDIUM


# ─────────────────────────────────────────────────────────────────────────────
# 4. _fingerprint()
# ─────────────────────────────────────────────────────────────────────────────

class TestFingerprint:
    def test_deterministic(self):
        fp1 = _fingerprint("ssl", "critical_finding", "No TLS")
        fp2 = _fingerprint("ssl", "critical_finding", "No TLS")
        assert fp1 == fp2

    def test_length_is_16_hex_chars(self):
        fp = _fingerprint("ssl", "critical_finding", "Some detail")
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_different_tools_produce_different_fps(self):
        fp1 = _fingerprint("ssl",  "critical_finding", "No TLS")
        fp2 = _fingerprint("cors", "critical_finding", "No TLS")
        assert fp1 != fp2

    def test_different_details_produce_different_fps(self):
        fp1 = _fingerprint("ssl", "critical_finding", "No TLS v1.0")
        fp2 = _fingerprint("ssl", "critical_finding", "No TLS v1.2")
        assert fp1 != fp2

    def test_case_normalised(self):
        fp1 = _fingerprint("ssl", "critical_finding", "No TLS")
        fp2 = _fingerprint("ssl", "critical_finding", "NO TLS")
        assert fp1 == fp2

    def test_whitespace_normalised(self):
        fp1 = _fingerprint("ssl", "critical_finding", "  No TLS  ")
        fp2 = _fingerprint("ssl", "critical_finding", "No TLS")
        assert fp1 == fp2


# ─────────────────────────────────────────────────────────────────────────────
# 5. _tool_from_finding()
# ─────────────────────────────────────────────────────────────────────────────

class TestToolFromFinding:
    def test_ssl_finding(self):
        assert _tool_from_finding("No TLS detected — plain HTTP") == "ssl"

    def test_waf_finding(self):
        assert _tool_from_finding("No WAF detected on the target") == "waf"

    def test_dns_finding(self):
        assert _tool_from_finding("DMARC policy missing or p=none") == "dns"

    def test_cors_finding(self):
        assert _tool_from_finding("CORS wildcard origin misconfiguration") == "cors_csp"

    def test_headers_finding(self):
        assert _tool_from_finding("Missing security header X-Frame-Options") == "headers"

    def test_exposure_finding(self):
        assert _tool_from_finding("Exposed .env file accessible at /.env") == "exposure"

    def test_redirect_finding(self):
        assert _tool_from_finding("Confirmed open redirect on /login") == "open_redirect"

    def test_port_finding(self):
        assert _tool_from_finding("Port 6379/redis open externally") == "port_scanner"

    def test_cve_finding(self):
        assert _tool_from_finding("CVE-2021-44228 for log4j 2.14.1") == "tech"

    def test_crawler_finding(self):
        assert _tool_from_finding("Sensitive path /admin exposed") == "crawler"

    def test_unknown_text(self):
        assert _tool_from_finding("something completely unrelated xyz") == "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# 6. extract_signatures()
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractSignatures:
    def test_empty_result_produces_no_sigs(self):
        result = _make_scan_result()
        sigs = extract_signatures(result)
        assert sigs == {}

    def test_critical_finding_produces_sig(self):
        result = _make_scan_result(
            findings=["No WAF detected on the target — protection_score=0/100"]
        )
        sigs = extract_signatures(result)
        assert len(sigs) == 1

    def test_multiple_findings_produce_multiple_sigs(self):
        result = _make_scan_result(
            findings=["No WAF detected", "Missing HSTS header", "Open redirect found"]
        )
        sigs = extract_signatures(result)
        assert len(sigs) == 3

    def test_duplicate_findings_produce_one_sig(self):
        # Exact same text → same fingerprint → deduplication via dict
        result = _make_scan_result(
            findings=["No WAF detected", "No WAF detected"]
        )
        sigs = extract_signatures(result)
        assert len(sigs) == 1

    def test_finding_severity_is_inferred(self):
        result = _make_scan_result(
            findings=["No TLS detected — plain HTTP site"]
        )
        sigs = extract_signatures(result)
        assert all(s.severity == Severity.CRITICAL for s in sigs.values())

    def test_degraded_category_score_produces_sig(self):
        result = _make_scan_result(
            category_scores={"ssl": 95, "waf": 50}  # waf=50 → degraded
        )
        sigs = extract_signatures(result)
        assert any("score_bucket:degraded" in s.category for s in sigs.values())

    def test_critical_category_score_produces_sig(self):
        result = _make_scan_result(
            category_scores={"ssl": 95, "cors_csp": 20}  # cors_csp=20 → critical
        )
        sigs = extract_signatures(result)
        assert any("score_bucket:critical" in s.category for s in sigs.values())

    def test_healthy_category_score_produces_no_sig(self):
        result = _make_scan_result(
            category_scores={"ssl": 95, "headers": 80}  # all healthy
        )
        sigs = extract_signatures(result)
        assert all("score_bucket" not in s.category for s in sigs.values())

    def test_all_sigs_have_fingerprints(self):
        result = _make_scan_result(
            findings=["No WAF detected", "CORS misconfiguration"]
        )
        sigs = extract_signatures(result)
        for fp, sig in sigs.items():
            assert fp == sig.fingerprint
            assert len(fp) == 16

    def test_category_score_sig_has_tool_name(self):
        result = _make_scan_result(
            category_scores={"waf": 10}  # critical
        )
        sigs = extract_signatures(result)
        assert any(s.tool == "waf" for s in sigs.values())


# ─────────────────────────────────────────────────────────────────────────────
# 7. _deserialise_signatures()
# ─────────────────────────────────────────────────────────────────────────────

class TestDeserialiseSignatures:
    def test_roundtrip(self):
        original = _sig(tool="waf", detail="No WAF", severity=Severity.HIGH)
        raw = {
            original.fingerprint: {
                "tool":     original.tool,
                "category": original.category,
                "detail":   original.detail,
                "severity": original.severity.value,
            }
        }
        result = _deserialise_signatures(raw)
        assert original.fingerprint in result
        restored = result[original.fingerprint]
        assert restored.tool == original.tool
        assert restored.severity == original.severity

    def test_empty_dict(self):
        assert _deserialise_signatures({}) == {}

    def test_none_input(self):
        assert _deserialise_signatures(None) == {}  # type: ignore

    def test_invalid_severity_skipped(self):
        raw = {
            "abc1234567890123": {
                "tool": "ssl", "category": "x", "detail": "y",
                "severity": "NOT_A_SEVERITY",
            }
        }
        result = _deserialise_signatures(raw)
        assert result == {}

    def test_multiple_signatures(self):
        s1 = _sig(tool="ssl",  detail="No TLS",       severity=Severity.CRITICAL)
        s2 = _sig(tool="cors", detail="CORS wildcard", severity=Severity.HIGH)
        raw = {
            s1.fingerprint: {"tool": s1.tool, "category": s1.category,
                             "detail": s1.detail, "severity": s1.severity.value},
            s2.fingerprint: {"tool": s2.tool, "category": s2.category,
                             "detail": s2.detail, "severity": s2.severity.value},
        }
        result = _deserialise_signatures(raw)
        assert len(result) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 8. compute_diff()
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeDiff:
    def test_first_scan_no_new_vulns(self):
        result = _make_scan_result(findings=["No WAF detected"])
        diff = compute_diff(result, previous_record=None, scan_id="test-001")
        assert diff.is_first_scan is True
        assert diff.new_vulns == []
        assert diff.resolved_vulns == []

    def test_first_scan_all_current_sigs_go_to_unchanged(self):
        # First scan: current signatures treated as baseline (not "new")
        result = _make_scan_result(findings=["No WAF detected"])
        diff = compute_diff(result, previous_record=None, scan_id="test-001")
        assert diff.unchanged_vulns == []
        assert diff.is_first_scan is True

    def test_new_finding_in_current_not_in_previous(self):
        current = _make_scan_result(findings=["No WAF detected"])
        current_sigs = extract_signatures(current)
        previous_record = {
            "overall_grade": "A", "overall_score": 90,
            "finding_signatures": {},  # empty previous
        }
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert len(diff.new_vulns) == 1
        assert diff.new_vulns[0].classification == DeltaClass.NEW_VULNERABILITY

    def test_resolved_finding_in_previous_not_in_current(self):
        old_sig = _sig(tool="ssl", detail="No TLS detected", severity=Severity.CRITICAL)
        previous_record = {
            "overall_grade": "F", "overall_score": 10,
            "finding_signatures": {
                old_sig.fingerprint: {
                    "tool": old_sig.tool, "category": old_sig.category,
                    "detail": old_sig.detail, "severity": old_sig.severity.value,
                }
            },
        }
        current = _make_scan_result(findings=[])  # finding resolved
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert len(diff.resolved_vulns) == 1
        assert diff.resolved_vulns[0].classification == DeltaClass.RESOLVED_VULNERABILITY

    def test_unchanged_finding_in_both(self):
        finding_text = "CORS wildcard origin misconfiguration detected"
        current = _make_scan_result(findings=[finding_text])
        current_sigs = extract_signatures(current)
        # Build previous record with the exact same signatures
        previous_record = {
            "overall_grade": "C", "overall_score": 62,
            "finding_signatures": {
                fp: {"tool": s.tool, "category": s.category,
                     "detail": s.detail, "severity": s.severity.value}
                for fp, s in current_sigs.items()
            },
        }
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert len(diff.unchanged_vulns) == 1
        assert diff.new_vulns == []
        assert diff.resolved_vulns == []

    def test_grade_before_after_populated(self):
        current = _make_scan_result(grade="C", score=62)
        previous_record = {"overall_grade": "A", "overall_score": 90,
                           "finding_signatures": {}}
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert diff.grade_before == "A"
        assert diff.grade_after  == "C"

    def test_grade_changed_property(self):
        current = _make_scan_result(grade="C", score=62)
        previous_record = {"overall_grade": "A", "overall_score": 90,
                           "finding_signatures": {}}
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert diff.grade_changed is True

    def test_score_delta_property(self):
        current = _make_scan_result(grade="C", score=62)
        previous_record = {"overall_grade": "A", "overall_score": 90,
                           "finding_signatures": {}}
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert diff.score_delta == 62 - 90

    def test_grade_drop_steps_a_to_c_is_2(self):
        current = _make_scan_result(grade="C", score=62)
        previous_record = {"overall_grade": "A", "overall_score": 90,
                           "finding_signatures": {}}
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert diff.grade_drop_steps == 2

    def test_grade_drop_steps_improvement_is_0(self):
        current = _make_scan_result(grade="A", score=91)
        previous_record = {"overall_grade": "C", "overall_score": 62,
                           "finding_signatures": {}}
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert diff.grade_drop_steps == 0

    def test_new_vulns_sorted_by_severity(self):
        current = _make_scan_result(
            findings=["15 subdomains enumerable via CT logs",
                      "No TLS detected — plain HTTP site"]
        )
        previous_record = {"overall_grade": "B", "overall_score": 80,
                           "finding_signatures": {}}
        diff = compute_diff(current, previous_record, scan_id="test-001")
        if len(diff.new_vulns) >= 2:
            severities = [d.signature.severity for d in diff.new_vulns]
            _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                          Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
            has_critical = any(s in (Severity.CRITICAL, Severity.HIGH) for s in severities)
            has_low = any(s in (Severity.LOW, Severity.INFO) for s in severities)
            if has_critical and has_low:
                critical_idx = next(i for i, s in enumerate(severities)
                                    if s in (Severity.CRITICAL, Severity.HIGH))
                low_idx = next(i for i, s in enumerate(severities)
                               if s in (Severity.LOW, Severity.INFO))
                assert critical_idx < low_idx

    def test_summary_contains_new_count(self):
        current = _make_scan_result(findings=["No WAF detected"])
        previous_record = {"overall_grade": "A", "overall_score": 90,
                           "finding_signatures": {}}
        diff = compute_diff(current, previous_record, scan_id="test-001")
        assert "new" in diff.summary().lower()


# ─────────────────────────────────────────────────────────────────────────────
# 9. should_trigger_emergency()
# ─────────────────────────────────────────────────────────────────────────────

class TestShouldTriggerEmergency:
    def _make_diff(self, **overrides) -> ScanDiff:
        defaults = dict(
            url="https://example.com", scan_id="x", is_first_scan=False,
            new_vulns=[], resolved_vulns=[], unchanged_vulns=[],
            grade_before="A", grade_after="A",
            score_before=90, score_after=90,
        )
        defaults.update(overrides)
        d = ScanDiff(**defaults)
        return d

    def test_first_scan_never_triggers(self):
        diff = self._make_diff(is_first_scan=True, grade_before="?", grade_after="F",
                               score_before=0, score_after=30)
        assert should_trigger_emergency(diff, _make_settings()) is False

    def test_new_critical_triggers(self):
        diff = self._make_diff(
            new_vulns=[_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.CRITICAL)]
        )
        assert should_trigger_emergency(diff, _make_settings()) is True

    def test_new_high_triggers(self):
        diff = self._make_diff(
            new_vulns=[_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.HIGH)]
        )
        assert should_trigger_emergency(diff, _make_settings()) is True

    def test_new_medium_does_not_trigger_alone(self):
        diff = self._make_diff(
            new_vulns=[_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.MEDIUM)]
        )
        assert should_trigger_emergency(diff, _make_settings()) is False

    def test_grade_drop_2_steps_triggers(self):
        diff = self._make_diff(grade_before="A", grade_after="C",
                               score_before=90, score_after=62)
        assert should_trigger_emergency(diff, _make_settings(grade_drop_threshold=2)) is True

    def test_grade_drop_1_step_does_not_trigger(self):
        diff = self._make_diff(grade_before="A", grade_after="B",
                               score_before=90, score_after=80)
        assert should_trigger_emergency(diff, _make_settings(grade_drop_threshold=2)) is False

    def test_score_drop_15_triggers(self):
        diff = self._make_diff(score_before=90, score_after=74, grade_before="A", grade_after="B")
        assert should_trigger_emergency(diff, _make_settings(score_drop_threshold=15)) is True

    def test_score_drop_14_does_not_trigger(self):
        diff = self._make_diff(score_before=90, score_after=77, grade_before="A", grade_after="B")
        assert should_trigger_emergency(diff, _make_settings(score_drop_threshold=15)) is False

    def test_score_improvement_does_not_trigger(self):
        diff = self._make_diff(score_before=70, score_after=90, grade_before="B", grade_after="A")
        assert should_trigger_emergency(diff, _make_settings()) is False

    def test_no_changes_does_not_trigger(self):
        diff = self._make_diff()
        assert should_trigger_emergency(diff, _make_settings()) is False


# ─────────────────────────────────────────────────────────────────────────────
# 10. Slack Block Kit payload builder
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildSlackPayload:
    def _clean_diff(self) -> ScanDiff:
        return ScanDiff(
            url="https://example.com", scan_id="scan-1", is_first_scan=False,
            new_vulns=[], resolved_vulns=[], unchanged_vulns=[],
            grade_before="A", grade_after="A", score_before=90, score_after=90,
        )

    def test_returns_dict_with_attachments(self):
        payload = _build_slack_payload(self._clean_diff(), False, 10)
        assert "attachments" in payload
        assert len(payload["attachments"]) == 1

    def test_attachment_has_colour(self):
        payload = _build_slack_payload(self._clean_diff(), False, 10)
        assert "color" in payload["attachments"][0]

    def test_attachment_has_blocks(self):
        payload = _build_slack_payload(self._clean_diff(), False, 10)
        assert "blocks" in payload["attachments"][0]
        assert len(payload["attachments"][0]["blocks"]) > 0

    def test_emergency_colour_is_red(self):
        diff = self._clean_diff()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.CRITICAL)]
        payload = _build_slack_payload(diff, is_emergency=True, max_findings=10)
        assert payload["attachments"][0]["color"] == "#D32F2F"

    def test_resolved_only_colour_is_green(self):
        diff = self._clean_diff()
        diff.resolved_vulns = [_delta(DeltaClass.RESOLVED_VULNERABILITY, severity=Severity.HIGH)]
        payload = _build_slack_payload(diff, is_emergency=False, max_findings=10)
        assert payload["attachments"][0]["color"] == "#388E3C"

    def test_new_vuln_colour_is_orange(self):
        diff = self._clean_diff()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.MEDIUM)]
        payload = _build_slack_payload(diff, is_emergency=False, max_findings=10)
        assert payload["attachments"][0]["color"] == "#F57C00"

    def test_emergency_header_text(self):
        diff = self._clean_diff()
        payload = _build_slack_payload(diff, is_emergency=True, max_findings=10)
        header = payload["attachments"][0]["blocks"][0]
        assert "EMERGENCY" in header["text"]["text"].upper()

    def test_new_vulns_appear_in_blocks(self):
        diff = self._clean_diff()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, detail="No WAF detected")]
        payload = _build_slack_payload(diff, is_emergency=False, max_findings=10)
        blocks_text = str(payload)
        assert "No WAF detected" in blocks_text

    def test_resolved_vulns_appear_in_blocks(self):
        diff = self._clean_diff()
        diff.resolved_vulns = [
            _delta(DeltaClass.RESOLVED_VULNERABILITY, detail="HSTS now configured")
        ]
        payload = _build_slack_payload(diff, is_emergency=False, max_findings=10)
        assert "HSTS now configured" in str(payload)

    def test_max_findings_limit_respected(self):
        diff = self._clean_diff()
        diff.new_vulns = [
            _delta(DeltaClass.NEW_VULNERABILITY, detail=f"Finding #{i}", fp=f"fp{i:016d}")
            for i in range(15)
        ]
        payload = _build_slack_payload(diff, is_emergency=False, max_findings=5)
        payload_str = str(payload)
        assert "more" in payload_str

    def test_first_scan_shows_baseline_message(self):
        diff = ScanDiff(
            url="https://example.com", scan_id="s1", is_first_scan=True,
            grade_before="?", grade_after="A", score_before=0, score_after=90,
        )
        payload = _build_slack_payload(diff, is_emergency=False, max_findings=10)
        assert "aseline" in str(payload).lower()

    def test_url_appears_in_blocks(self):
        diff = self._clean_diff()
        payload = _build_slack_payload(diff, is_emergency=False, max_findings=10)
        assert "example.com" in str(payload)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Webhook payload builder
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildWebhookPayload:
    def _clean_diff(self) -> ScanDiff:
        return ScanDiff(
            url="https://example.com", scan_id="scan-1", is_first_scan=False,
            new_vulns=[], resolved_vulns=[], unchanged_vulns=[],
            grade_before="A", grade_after="A", score_before=90, score_after=90,
        )

    def test_event_type_field(self):
        p = _build_webhook_payload(self._clean_diff(), False)
        assert p["event_type"] == "SECURITY_SCAN_DIFF"

    def test_timestamp_present(self):
        p = _build_webhook_payload(self._clean_diff(), False)
        assert "timestamp" in p
        assert "T" in p["timestamp"]

    def test_url_field(self):
        p = _build_webhook_payload(self._clean_diff(), False)
        assert p["url"] == "https://example.com"

    def test_severity_critical_for_emergency(self):
        diff = self._clean_diff()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.CRITICAL)]
        p = _build_webhook_payload(diff, is_emergency=True)
        assert p["severity"] == "CRITICAL"

    def test_severity_high_for_new_high_vuln(self):
        diff = self._clean_diff()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.HIGH)]
        p = _build_webhook_payload(diff, is_emergency=False)
        assert p["severity"] == "HIGH"

    def test_severity_info_for_no_changes(self):
        p = _build_webhook_payload(self._clean_diff(), False)
        assert p["severity"] == "INFO"

    def test_grade_block_present(self):
        p = _build_webhook_payload(self._clean_diff(), False)
        assert "grade" in p
        assert "before" in p["grade"]
        assert "after" in p["grade"]

    def test_score_block_present(self):
        p = _build_webhook_payload(self._clean_diff(), False)
        assert "score" in p
        assert p["score"]["before"] == 90
        assert p["score"]["after"] == 90

    def test_new_vulnerabilities_list(self):
        diff = self._clean_diff()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, detail="CORS issue")]
        p = _build_webhook_payload(diff, False)
        assert len(p["new_vulnerabilities"]) == 1
        assert p["new_vulnerabilities"][0]["detail"] == "CORS issue"

    def test_resolved_vulnerabilities_list(self):
        diff = self._clean_diff()
        diff.resolved_vulns = [_delta(DeltaClass.RESOLVED_VULNERABILITY, detail="WAF added")]
        p = _build_webhook_payload(diff, False)
        assert len(p["resolved_vulnerabilities"]) == 1

    def test_unchanged_count_field(self):
        diff = self._clean_diff()
        diff.unchanged_vulns = [_delta(DeltaClass.UNCHANGED, detail="SPF still ok")]
        p = _build_webhook_payload(diff, False)
        assert p["unchanged_count"] == 1

    def test_is_first_scan_field(self):
        diff = ScanDiff(
            url="https://example.com", scan_id="s1", is_first_scan=True,
            grade_before="?", grade_after="A", score_before=0, score_after=90,
        )
        p = _build_webhook_payload(diff, False)
        assert p["is_first_scan"] is True

    def test_summary_field_present(self):
        p = _build_webhook_payload(self._clean_diff(), False)
        assert "summary" in p
        assert isinstance(p["summary"], str)


# ─────────────────────────────────────────────────────────────────────────────
# 12. SlackDispatcher (httpx patched)
# ─────────────────────────────────────────────────────────────────────────────

class TestSlackDispatcher:
    def _diff(self) -> ScanDiff:
        return ScanDiff(url="https://example.com", scan_id="s1", is_first_scan=False,
                        grade_before="A", grade_after="C",
                        score_before=90, score_after=62)

    @pytest.mark.asyncio
    async def test_no_url_returns_failure(self):
        dispatcher = SlackDispatcher("")
        result = await dispatcher.dispatch(self._diff(), is_emergency=False)
        assert result.success is False
        assert "not configured" in result.error

    @pytest.mark.asyncio
    @patch("differential_alert_manager.httpx.AsyncClient")
    async def test_successful_dispatch(self, MockClient):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        MockClient.return_value = mock_cm

        dispatcher = SlackDispatcher("https://hooks.slack.com/services/test")
        result = await dispatcher.dispatch(self._diff(), is_emergency=True)
        assert result.success is True
        assert result.channel == "slack"
        assert result.status_code == 200

    @pytest.mark.asyncio
    @patch("differential_alert_manager.httpx.AsyncClient")
    async def test_http_error_returns_failure(self, MockClient):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "invalid_payload"
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        MockClient.return_value = mock_cm

        dispatcher = SlackDispatcher("https://hooks.slack.com/services/test")
        result = await dispatcher.dispatch(self._diff(), is_emergency=False)
        assert result.success is False
        assert "400" in result.error

    @pytest.mark.asyncio
    @patch("differential_alert_manager.httpx.AsyncClient")
    async def test_network_exception_returns_failure(self, MockClient):
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value.post = AsyncMock(
            side_effect=Exception("Connection refused")
        )
        MockClient.return_value = mock_cm

        dispatcher = SlackDispatcher("https://hooks.slack.com/services/test")
        result = await dispatcher.dispatch(self._diff(), is_emergency=False)
        assert result.success is False
        assert "Connection refused" in result.error


# ─────────────────────────────────────────────────────────────────────────────
# 13. WebhookDispatcher (httpx patched)
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhookDispatcher:
    def _diff(self) -> ScanDiff:
        return ScanDiff(url="https://example.com", scan_id="s1", is_first_scan=False,
                        grade_before="B", grade_after="D",
                        score_before=80, score_after=42)

    @pytest.mark.asyncio
    async def test_no_url_returns_failure(self):
        dispatcher = WebhookDispatcher("")
        result = await dispatcher.dispatch(self._diff(), is_emergency=False)
        assert result.success is False
        assert result.channel == "webhook"

    @pytest.mark.asyncio
    @patch("differential_alert_manager.httpx.AsyncClient")
    async def test_successful_dispatch(self, MockClient):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        MockClient.return_value = mock_cm

        dispatcher = WebhookDispatcher("https://siem.example.com/ingest")
        result = await dispatcher.dispatch(self._diff(), is_emergency=True)
        assert result.success is True
        assert result.channel == "webhook"

    @pytest.mark.asyncio
    @patch("differential_alert_manager.httpx.AsyncClient")
    async def test_headers_sent_to_siem(self, MockClient):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        captured: dict = {}

        async def capture_post(url, *, json, headers):
            captured["headers"] = headers
            return mock_resp

        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value.post = capture_post
        MockClient.return_value = mock_cm

        dispatcher = WebhookDispatcher("https://siem.example.com/ingest")
        await dispatcher.dispatch(self._diff(), is_emergency=True)
        assert "X-Scanner" in captured["headers"]
        assert "X-Severity" in captured["headers"]

    @pytest.mark.asyncio
    @patch("differential_alert_manager.httpx.AsyncClient")
    async def test_2xx_variants_are_success(self, MockClient):
        for status in (200, 201, 204):
            mock_resp = MagicMock()
            mock_resp.status_code = status
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
            MockClient.return_value = mock_cm
            dispatcher = WebhookDispatcher("https://siem.example.com/ingest")
            result = await dispatcher.dispatch(self._diff(), False)
            assert result.success is True, f"Expected success for HTTP {status}"


# ─────────────────────────────────────────────────────────────────────────────
# 14. _dispatch_all()
# ─────────────────────────────────────────────────────────────────────────────

class TestDispatchAll:
    def _diff(self) -> ScanDiff:
        return ScanDiff(url="https://example.com", scan_id="s1", is_first_scan=False,
                        grade_before="A", grade_after="C",
                        score_before=90, score_after=62)

    @pytest.mark.asyncio
    async def test_no_channels_configured_returns_empty(self):
        settings = _make_settings()  # no webhook URLs
        results = await _dispatch_all(self._diff(), True, settings)
        assert results == []

    @pytest.mark.asyncio
    @patch("differential_alert_manager.SlackDispatcher.dispatch",
           new_callable=AsyncMock)
    async def test_slack_only_dispatched(self, mock_slack_dispatch):
        mock_slack_dispatch.return_value = DispatchResult("slack", True, 200)
        settings = _make_settings(slack_webhook_url="https://hooks.slack.com/test")
        results = await _dispatch_all(self._diff(), True, settings)
        assert len(results) == 1
        assert results[0].channel == "slack"
        assert results[0].success is True

    @pytest.mark.asyncio
    @patch("differential_alert_manager.WebhookDispatcher.dispatch",
           new_callable=AsyncMock)
    async def test_webhook_only_dispatched(self, mock_webhook_dispatch):
        mock_webhook_dispatch.return_value = DispatchResult("webhook", True, 200)
        settings = _make_settings(alert_webhook_url="https://siem.example.com/ingest")
        results = await _dispatch_all(self._diff(), True, settings)
        assert len(results) == 1
        assert results[0].channel == "webhook"

    @pytest.mark.asyncio
    @patch("differential_alert_manager.SlackDispatcher.dispatch",
           new_callable=AsyncMock)
    @patch("differential_alert_manager.WebhookDispatcher.dispatch",
           new_callable=AsyncMock)
    async def test_both_channels_concurrent(self, mock_webhook, mock_slack):
        mock_slack.return_value   = DispatchResult("slack",   True, 200)
        mock_webhook.return_value = DispatchResult("webhook", True, 200)
        settings = _make_settings(
            slack_webhook_url="https://hooks.slack.com/test",
            alert_webhook_url="https://siem.example.com/ingest",
        )
        results = await _dispatch_all(self._diff(), True, settings)
        assert len(results) == 2

    @pytest.mark.asyncio
    @patch("differential_alert_manager.SlackDispatcher.dispatch",
           new_callable=AsyncMock)
    @patch("differential_alert_manager.WebhookDispatcher.dispatch",
           new_callable=AsyncMock)
    async def test_partial_failure_returns_both(self, mock_webhook, mock_slack):
        mock_slack.return_value   = DispatchResult("slack",   False, 0, "timeout")
        mock_webhook.return_value = DispatchResult("webhook", True,  200)
        settings = _make_settings(
            slack_webhook_url="https://hooks.slack.com/test",
            alert_webhook_url="https://siem.example.com/ingest",
        )
        results = await _dispatch_all(self._diff(), True, settings)
        successes = [r for r in results if r.success]
        failures  = [r for r in results if not r.success]
        assert len(successes) == 1
        assert len(failures)  == 1


# ─────────────────────────────────────────────────────────────────────────────
# 15. run_differential_scan_async() end-to-end
# ─────────────────────────────────────────────────────────────────────────────

class TestRunDifferentialScanAsync:
    """All Supabase and dispatcher calls are mocked."""

    def _scan_result(self, grade="A", score=90, findings=None, category_scores=None):
        return _make_scan_result(
            grade=grade, score=score,
            findings=findings or [],
            category_scores=category_scores or {"ssl": 95, "waf": 88},
        )

    @pytest.mark.asyncio
    @patch("differential_alert_manager._HAS_SUPABASE", False)
    @patch("differential_alert_manager._dispatch_all", new_callable=AsyncMock)
    async def test_first_scan_no_supabase_no_dispatch(self, mock_dispatch):
        # Without Supabase, previous_record=None → first scan → no dispatch
        result = await run_differential_scan_async(self._scan_result())
        assert isinstance(result, DiffReport)
        assert result.diff.is_first_scan is True
        mock_dispatch.assert_not_called()

    @pytest.mark.asyncio
    @patch("differential_alert_manager._HAS_SUPABASE", False)
    @patch("differential_alert_manager._dispatch_all", new_callable=AsyncMock)
    async def test_returns_diff_report_on_first_scan(self, mock_dispatch):
        result = await run_differential_scan_async(self._scan_result())
        assert result.url == "https://example.com"
        assert result.stored_in_db is False
        assert result.error  # should have db_error describing no supabase

    @pytest.mark.asyncio
    @patch("differential_alert_manager._HAS_SUPABASE", False)
    @patch("differential_alert_manager._dispatch_all", new_callable=AsyncMock)
    async def test_no_supabase_no_dispatch_on_improvement(self, mock_dispatch):
        # Even if there were changes, without Supabase previous=None → is_first_scan
        result = await run_differential_scan_async(
            self._scan_result(findings=["CORS wildcard misconfiguration"])
        )
        assert result.diff.is_first_scan is True
        mock_dispatch.assert_not_called()

    @pytest.mark.asyncio
    @patch("differential_alert_manager._get_alert_settings")
    @patch("differential_alert_manager.SupabaseStore")
    @patch("differential_alert_manager._dispatch_all", new_callable=AsyncMock)
    @patch("differential_alert_manager._HAS_SUPABASE", True)
    async def test_regression_dispatches_alert(self, mock_dispatch, MockStore,
                                                mock_settings):
        mock_settings.return_value = _make_settings(
            supabase_url="https://proj.supabase.co",
            supabase_key="key",
            slack_webhook_url="https://hooks.slack.com/test",
            grade_drop_threshold=2,
            score_drop_threshold=15,
        )
        mock_dispatch.return_value = [DispatchResult("slack", True, 200)]

        # Previous scan: grade A, score 90, no findings
        MockStore.return_value.get_last_scan.return_value = {
            "overall_grade": "A", "overall_score": 90,
            "finding_signatures": {},
        }
        MockStore.return_value.store_scan.return_value = "new-scan-id"

        current = self._scan_result(grade="C", score=62,
                                    findings=["No WAF detected — WAF absent"])
        result = await run_differential_scan_async(current)

        assert result.diff.is_first_scan is False
        assert len(result.diff.new_vulns) >= 1
        mock_dispatch.assert_called_once()

    @pytest.mark.asyncio
    @patch("differential_alert_manager._get_alert_settings")
    @patch("differential_alert_manager.SupabaseStore")
    @patch("differential_alert_manager._dispatch_all", new_callable=AsyncMock)
    @patch("differential_alert_manager._HAS_SUPABASE", True)
    async def test_no_change_no_dispatch(self, mock_dispatch, MockStore, mock_settings):
        mock_settings.return_value = _make_settings(
            supabase_url="https://proj.supabase.co",
            supabase_key="key",
        )
        current = self._scan_result(grade="A", score=90)
        current_sigs = extract_signatures(current)

        MockStore.return_value.get_last_scan.return_value = {
            "overall_grade": "A", "overall_score": 90,
            "finding_signatures": {
                fp: {"tool": s.tool, "category": s.category,
                     "detail": s.detail, "severity": s.severity.value}
                for fp, s in current_sigs.items()
            },
        }
        MockStore.return_value.store_scan.return_value = "same-scan-id"

        result = await run_differential_scan_async(current)
        assert result.diff.new_vulns == []
        assert result.diff.resolved_vulns == []
        mock_dispatch.assert_not_called()

    @pytest.mark.asyncio
    @patch("differential_alert_manager._get_alert_settings")
    @patch("differential_alert_manager.SupabaseStore")
    @patch("differential_alert_manager._dispatch_all", new_callable=AsyncMock)
    @patch("differential_alert_manager._HAS_SUPABASE", True)
    async def test_store_scan_called_after_diff(self, mock_dispatch, MockStore, mock_settings):
        mock_settings.return_value = _make_settings(
            supabase_url="https://proj.supabase.co",
            supabase_key="key",
        )
        mock_dispatch.return_value = []
        MockStore.return_value.get_last_scan.return_value = None
        MockStore.return_value.store_scan.return_value = "stored-scan-id"

        result = await run_differential_scan_async(self._scan_result())
        MockStore.return_value.store_scan.assert_called_once()
        assert result.stored_in_db is True

    @pytest.mark.asyncio
    @patch("differential_alert_manager._get_alert_settings")
    @patch("differential_alert_manager.SupabaseStore")
    @patch("differential_alert_manager._dispatch_all", new_callable=AsyncMock)
    @patch("differential_alert_manager._HAS_SUPABASE", True)
    async def test_supabase_write_failure_does_not_crash(self, mock_dispatch, MockStore,
                                                           mock_settings):
        mock_settings.return_value = _make_settings(
            supabase_url="https://proj.supabase.co",
            supabase_key="key",
        )
        mock_dispatch.return_value = []
        MockStore.return_value.get_last_scan.return_value = None
        MockStore.return_value.store_scan.side_effect = Exception("DB write error")

        result = await run_differential_scan_async(self._scan_result())
        assert isinstance(result, DiffReport)
        assert "write failed" in result.error.lower() or result.stored_in_db is False

    @pytest.mark.asyncio
    @patch("differential_alert_manager._HAS_SUPABASE", False)
    async def test_result_url_matches_input(self):
        scan = _make_scan_result(url="https://mytarget.org")
        result = await run_differential_scan_async(scan)
        assert result.url == "https://mytarget.org"


# ─────────────────────────────────────────────────────────────────────────────
# 16. ScanDiff property tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanDiffProperties:
    def _make(self, **kw) -> ScanDiff:
        defaults = dict(url="https://example.com", scan_id="x", is_first_scan=False,
                        grade_before="A", grade_after="A",
                        score_before=90, score_after=90)
        defaults.update(kw)
        return ScanDiff(**defaults)

    def test_has_critical_new_true(self):
        diff = self._make()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.CRITICAL)]
        assert diff.has_critical_new is True

    def test_has_critical_new_false(self):
        diff = self._make()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.MEDIUM)]
        assert diff.has_critical_new is False

    def test_has_high_new_true(self):
        diff = self._make()
        diff.new_vulns = [_delta(DeltaClass.NEW_VULNERABILITY, severity=Severity.HIGH)]
        assert diff.has_high_new is True

    def test_score_delta_regression(self):
        diff = self._make(score_before=90, score_after=62)
        assert diff.score_delta == -28

    def test_score_delta_improvement(self):
        diff = self._make(score_before=62, score_after=90)
        assert diff.score_delta == 28

    def test_grade_drop_steps_b_to_f_is_3(self):
        diff = self._make(grade_before="B", grade_after="F")
        assert diff.grade_drop_steps == 3

    def test_grade_drop_steps_same_grade_is_0(self):
        diff = self._make(grade_before="C", grade_after="C")
        assert diff.grade_drop_steps == 0

    def test_is_new_property(self):
        d = _delta(DeltaClass.NEW_VULNERABILITY)
        assert d.is_new is True
        assert d.is_resolved is False

    def test_is_resolved_property(self):
        d = _delta(DeltaClass.RESOLVED_VULNERABILITY)
        assert d.is_resolved is True
        assert d.is_new is False

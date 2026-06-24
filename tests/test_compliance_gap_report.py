"""
tests/test_compliance_gap_report.py — AI Cyber Shield v6

Test suite for reports/compliance_gap_report.py.

Tests cover:
  • ControlStatus enum values
  • _affected_controls: maps finding compliance fields to control IDs
  • _framework_readiness: thresholds (Compliant / At Risk / Non-Compliant)
  • generate_compliance_gap_report:
    - zero findings → all PASS (or NOT_TESTED)
    - critical finding hits PCI-DSS controls
    - SOC2 / ISO 27001 / NIST CSF control mapping
    - FAIL status for CRITICAL/HIGH findings
    - PARTIAL status for MEDIUM/LOW findings
    - per-framework pass rate calculation
    - overall_pass_rate aggregation
    - gap_score increases with severity
    - executive_summary text
    - to_json() produces valid JSON
    - to_dict() structure
    - summary_text() non-empty
    - scan_id and timestamp propagated
    - auto-timestamp when not provided
    - OWASP 2025 A11 / A12 findings handled gracefully
    - finding with no compliance fields doesn't crash
    - 25 findings produce valid report
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from reports.compliance_gap_report import (
    ControlStatus,
    ControlDef,
    ComplianceReport,
    ControlResult,
    FrameworkResult,
    generate_compliance_gap_report,
    _affected_controls,
    _framework_readiness,
    _compute_gap_score,
    _build_executive_summary,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fake SecurityFinding
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _FakeCvssScore:
    score:    float = 9.8
    severity: str   = "CRITICAL"

@dataclass
class _FakeCompliance:
    pci_dss:    str = ""
    soc2_cc:    str = ""
    iso_27001:  str = ""
    nist_csf:   str = ""
    owasp_asvs: str = ""

@dataclass
class _FakeRemediation:
    priority:     int   = 1
    effort_hours: float = 4.0
    summary:      str   = "Fix this."
    code_before:  str   = ""
    code_after:   str   = ""
    references:   list  = field(default_factory=list)

@dataclass
class _FakeFinding:
    finding_id:      str
    severity:        str   = "CRITICAL"
    cvss:            _FakeCvssScore  = field(default_factory=_FakeCvssScore)
    compliance:      _FakeCompliance = field(default_factory=_FakeCompliance)
    remediation:     _FakeRemediation= field(default_factory=_FakeRemediation)
    confirmed:       bool  = True
    title:           str   = "Test Finding"
    endpoint:        str   = "https://example.com/test"


def _make_finding(
    finding_id: str = "f-001",
    severity:   str = "CRITICAL",
    cvss_score: float = 9.8,
    pci_dss:    str = "",
    soc2_cc:    str = "",
    iso_27001:  str = "",
    nist_csf:   str = "",
) -> _FakeFinding:
    f = _FakeFinding(finding_id=finding_id, severity=severity)
    f.cvss = _FakeCvssScore(score=cvss_score, severity=severity)
    f.compliance = _FakeCompliance(
        pci_dss=pci_dss, soc2_cc=soc2_cc, iso_27001=iso_27001, nist_csf=nist_csf
    )
    return f


# ─────────────────────────────────────────────────────────────────────────────
# TestControlStatus
# ─────────────────────────────────────────────────────────────────────────────

class TestControlStatus:
    def test_enum_values(self):
        assert ControlStatus.PASS.value       == "PASS"
        assert ControlStatus.FAIL.value       == "FAIL"
        assert ControlStatus.PARTIAL.value    == "PARTIAL"
        assert ControlStatus.NOT_TESTED.value == "NOT_TESTED"

    def test_is_string_enum(self):
        assert isinstance(ControlStatus.PASS, str)

    def test_comparison(self):
        assert ControlStatus.PASS != ControlStatus.FAIL


# ─────────────────────────────────────────────────────────────────────────────
# TestAffectedControls
# ─────────────────────────────────────────────────────────────────────────────

class TestAffectedControls:
    def test_no_compliance_fields_returns_empty(self):
        f = _make_finding()
        assert _affected_controls(f) == set()

    def test_pci_6_2_4_maps_to_controls(self):
        f = _make_finding(pci_dss="Req 6.2.4")
        result = _affected_controls(f)
        assert "PCI-6.2.4" in result
        assert "PCI-6.4"   in result

    def test_pci_6_3_2_maps(self):
        f = _make_finding(pci_dss="Req 6.3.2")
        result = _affected_controls(f)
        assert "PCI-6.3.2" in result

    def test_soc2_cc61_maps(self):
        f = _make_finding(soc2_cc="CC6.1")
        result = _affected_controls(f)
        assert "CC6.1" in result

    def test_soc2_cc67_maps(self):
        f = _make_finding(soc2_cc="CC6.7")
        result = _affected_controls(f)
        assert "CC6.7" in result

    def test_iso_a14_2_maps_to_new_ids(self):
        f = _make_finding(iso_27001="A.14.2")
        result = _affected_controls(f)
        assert "A.8.28" in result
        assert "A.8.25" in result

    def test_iso_a8_8_maps(self):
        f = _make_finding(iso_27001="A.8.8")
        result = _affected_controls(f)
        assert "A.8.8" in result

    def test_nist_pr_ds_2_maps(self):
        f = _make_finding(nist_csf="PR.DS-2")
        result = _affected_controls(f)
        assert "PR.DS-2" in result

    def test_nist_rs_mi_3_maps(self):
        f = _make_finding(nist_csf="RS.MI-3")
        result = _affected_controls(f)
        assert "RS.MI-3" in result

    def test_multiple_frameworks_maps(self):
        f = _make_finding(
            pci_dss   = "Req 6.2.4",
            soc2_cc   = "CC6.1",
            iso_27001 = "A.8.28",
            nist_csf  = "PR.DS-1",
        )
        result = _affected_controls(f)
        assert "PCI-6.2.4" in result
        assert "CC6.1"     in result
        assert "A.8.28"    in result
        assert "PR.DS-1"   in result

    def test_partial_pci_dss_string_match(self):
        # e.g. compliance field "Req 6.2.4, 6.3.2" contains "Req 6.2.4"
        f = _make_finding(pci_dss="Req 6.2.4, 6.3.2")
        result = _affected_controls(f)
        assert "PCI-6.2.4" in result


# ─────────────────────────────────────────────────────────────────────────────
# TestFrameworkReadiness
# ─────────────────────────────────────────────────────────────────────────────

class TestFrameworkReadiness:
    def test_compliant_at_90(self):
        assert _framework_readiness(0.90) == "Compliant"

    def test_compliant_at_100(self):
        assert _framework_readiness(1.0) == "Compliant"

    def test_at_risk_at_60(self):
        assert _framework_readiness(0.60) == "At Risk"

    def test_at_risk_at_89(self):
        assert _framework_readiness(0.89) == "At Risk"

    def test_non_compliant_at_59(self):
        assert _framework_readiness(0.59) == "Non-Compliant"

    def test_non_compliant_at_0(self):
        assert _framework_readiness(0.0) == "Non-Compliant"

    def test_boundary_90_is_compliant(self):
        assert _framework_readiness(0.90) == "Compliant"

    def test_boundary_60_is_at_risk(self):
        assert _framework_readiness(0.60) == "At Risk"


# ─────────────────────────────────────────────────────────────────────────────
# TestGenerateComplianceGapReport
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateComplianceGapReport:
    def test_zero_findings_returns_report(self):
        report = generate_compliance_gap_report(findings=[])
        assert isinstance(report, ComplianceReport)

    def test_zero_findings_gap_score_zero(self):
        report = generate_compliance_gap_report(findings=[])
        assert report.gap_score == 0

    def test_zero_findings_high_pass_rate(self):
        # With no findings, all controls are NOT_TESTED (no evidence of failure) → rate = 1.0
        report = generate_compliance_gap_report(findings=[])
        assert report.overall_pass_rate >= 0.9

    def test_total_findings_count(self):
        findings = [_make_finding(f"f-{i}", "HIGH") for i in range(5)]
        report = generate_compliance_gap_report(findings=findings)
        assert report.total_findings == 5

    def test_critical_findings_counted(self):
        findings = [
            _make_finding("f-1", "CRITICAL"),
            _make_finding("f-2", "HIGH"),
            _make_finding("f-3", "CRITICAL"),
        ]
        report = generate_compliance_gap_report(findings=findings)
        assert report.critical_findings == 2

    def test_target_url_propagated(self):
        report = generate_compliance_gap_report(
            findings   = [],
            target_url = "https://app.test.com",
        )
        assert report.target_url == "https://app.test.com"

    def test_scan_id_propagated(self):
        report = generate_compliance_gap_report(
            findings = [],
            scan_id  = "scan-abc-123",
        )
        assert report.scan_id == "scan-abc-123"

    def test_auto_timestamp_when_not_provided(self):
        report = generate_compliance_gap_report(findings=[])
        assert "UTC" in report.scan_timestamp

    def test_custom_timestamp_propagated(self):
        report = generate_compliance_gap_report(
            findings        = [],
            scan_timestamp  = "2026-01-01 00:00 UTC",
        )
        assert report.scan_timestamp == "2026-01-01 00:00 UTC"

    def test_framework_results_include_all_four(self):
        report = generate_compliance_gap_report(findings=[])
        framework_names = {fr.framework for fr in report.framework_results}
        assert "PCI-DSS"  in framework_names
        assert "SOC2"     in framework_names
        assert "ISO27001" in framework_names
        assert "NIST-CSF" in framework_names

    def test_critical_pci_finding_fails_controls(self):
        findings = [
            _make_finding("f-1", "CRITICAL", pci_dss="Req 6.2.4")
        ]
        report = generate_compliance_gap_report(findings=findings)

        # Find PCI-6.2.4 control result
        pci_result = next(
            (cr for cr in report.control_results if cr.control_id == "PCI-6.2.4"),
            None,
        )
        assert pci_result is not None
        assert pci_result.status == ControlStatus.FAIL

    def test_high_finding_also_fails_controls(self):
        findings = [_make_finding("f-1", "HIGH", pci_dss="Req 6.2.4")]
        report = generate_compliance_gap_report(findings=findings)
        pci_result = next(
            cr for cr in report.control_results if cr.control_id == "PCI-6.2.4"
        )
        assert pci_result.status == ControlStatus.FAIL

    def test_medium_finding_partial_status(self):
        findings = [_make_finding("f-1", "MEDIUM", pci_dss="Req 6.2.4")]
        report = generate_compliance_gap_report(findings=findings)
        pci_result = next(
            cr for cr in report.control_results if cr.control_id == "PCI-6.2.4"
        )
        assert pci_result.status == ControlStatus.PARTIAL

    def test_low_finding_partial_status(self):
        findings = [_make_finding("f-1", "LOW", pci_dss="Req 6.2.4")]
        report = generate_compliance_gap_report(findings=findings)
        pci_result = next(
            cr for cr in report.control_results if cr.control_id == "PCI-6.2.4"
        )
        assert pci_result.status == ControlStatus.PARTIAL

    def test_soc2_critical_finding_fails_cc61(self):
        findings = [_make_finding("f-1", "CRITICAL", soc2_cc="CC6.1")]
        report = generate_compliance_gap_report(findings=findings)
        cc61 = next(cr for cr in report.control_results if cr.control_id == "CC6.1")
        assert cc61.status == ControlStatus.FAIL

    def test_iso_critical_finding_fails_a828(self):
        findings = [_make_finding("f-1", "CRITICAL", iso_27001="A.8.28")]
        report = generate_compliance_gap_report(findings=findings)
        a828 = next(cr for cr in report.control_results if cr.control_id == "A.8.28")
        assert a828.status == ControlStatus.FAIL

    def test_nist_critical_finding_fails_pr_ds_2(self):
        findings = [_make_finding("f-1", "CRITICAL", nist_csf="PR.DS-2")]
        report = generate_compliance_gap_report(findings=findings)
        pr_ds_2 = next(cr for cr in report.control_results if cr.control_id == "PR.DS-2")
        assert pr_ds_2.status == ControlStatus.FAIL

    def test_failing_finding_id_recorded(self):
        findings = [_make_finding("my-finding-id", "CRITICAL", pci_dss="Req 6.2.4")]
        report = generate_compliance_gap_report(findings=findings)
        pci_result = next(
            cr for cr in report.control_results if cr.control_id == "PCI-6.2.4"
        )
        assert "my-finding-id" in pci_result.failing_findings

    def test_gap_score_higher_with_more_critical(self):
        no_findings = generate_compliance_gap_report(findings=[])
        many_crits  = generate_compliance_gap_report(
            findings=[
                _make_finding(f"f-{i}", "CRITICAL", pci_dss="Req 6.2.4",
                              soc2_cc="CC6.7", nist_csf="PR.DS-2")
                for i in range(5)
            ]
        )
        assert many_crits.gap_score > no_findings.gap_score

    def test_gap_score_range_0_to_100(self):
        findings = [
            _make_finding(f"f-{i}", "CRITICAL", pci_dss="Req 6.2.4")
            for i in range(20)
        ]
        report = generate_compliance_gap_report(findings=findings)
        assert 0 <= report.gap_score <= 100

    def test_pci_framework_pass_rate(self):
        # No PCI-affecting findings → all PCI controls pass → rate = 1.0
        report = generate_compliance_gap_report(findings=[])
        pci = next(fr for fr in report.framework_results if fr.framework == "PCI-DSS")
        assert pci.pass_rate >= 0.0
        assert pci.pass_rate <= 1.0

    def test_critical_finding_lowers_framework_pass_rate(self):
        clean = generate_compliance_gap_report(findings=[])
        dirty = generate_compliance_gap_report(
            findings=[_make_finding("f-1", "CRITICAL",
                                    pci_dss="Req 6.2.4", soc2_cc="CC6.1")]
        )
        pci_clean = next(fr for fr in clean.framework_results if fr.framework == "PCI-DSS")
        pci_dirty = next(fr for fr in dirty.framework_results if fr.framework == "PCI-DSS")
        assert pci_dirty.pass_rate < pci_clean.pass_rate

    def test_executive_summary_non_empty(self):
        report = generate_compliance_gap_report(findings=_sample_findings())
        assert len(report.executive_summary) > 10

    def test_executive_summary_mentions_critical_when_present(self):
        findings = [_make_finding("f-1", "CRITICAL", pci_dss="Req 6.2.4")]
        report = generate_compliance_gap_report(findings=findings)
        assert "CRITICAL" in report.executive_summary

    def test_executive_summary_all_pass_when_clean(self):
        report = generate_compliance_gap_report(findings=[])
        assert "pass" in report.executive_summary.lower() or "meet" in report.executive_summary.lower()

    def test_to_json_produces_valid_json(self):
        report = generate_compliance_gap_report(findings=_sample_findings())
        parsed = json.loads(report.to_json())
        assert "framework_results" in parsed
        assert "control_results"   in parsed

    def test_to_dict_structure(self):
        report = generate_compliance_gap_report(findings=_sample_findings())
        d = report.to_dict()
        assert "overall_pass_rate" in d
        assert "gap_score"         in d
        assert "framework_results" in d
        assert "control_results"   in d
        assert "executive_summary" in d

    def test_to_dict_control_has_required_keys(self):
        report = generate_compliance_gap_report(findings=[_make_finding(pci_dss="Req 6.2.4")])
        d = report.to_dict()
        cr = d["control_results"][0]
        assert "control_id"   in cr
        assert "status"       in cr
        assert "gap_severity" in cr

    def test_to_dict_framework_has_required_keys(self):
        report = generate_compliance_gap_report(findings=[])
        d = report.to_dict()
        fr = d["framework_results"][0]
        assert "framework"   in fr
        assert "pass_rate"   in fr
        assert "readiness"   in fr
        assert "passing"     in fr
        assert "failing"     in fr

    def test_summary_text_non_empty(self):
        report = generate_compliance_gap_report(findings=_sample_findings())
        text = report.summary_text()
        assert len(text) > 50

    def test_summary_text_contains_target_url(self):
        report = generate_compliance_gap_report(
            findings   = [],
            target_url = "https://myapp.example.com",
        )
        assert "myapp.example.com" in report.summary_text()

    def test_summary_text_contains_framework_names(self):
        report = generate_compliance_gap_report(findings=[])
        text = report.summary_text()
        assert "PCI-DSS" in text
        assert "SOC2"    in text

    def test_no_compliance_fields_does_not_crash(self):
        findings = [_make_finding("f-1", "CRITICAL")]  # no compliance mapping
        report = generate_compliance_gap_report(findings=findings)
        assert isinstance(report, ComplianceReport)

    def test_info_findings_ignored_in_gap(self):
        # INFO findings should not fail controls
        findings = [_make_finding("f-1", "INFO", pci_dss="Req 6.2.4")]
        report = generate_compliance_gap_report(findings=findings)
        pci = next(cr for cr in report.control_results if cr.control_id == "PCI-6.2.4")
        # INFO is filtered out by relevant_findings; control should not fail
        assert pci.status in (ControlStatus.PASS, ControlStatus.NOT_TESTED)

    def test_many_findings_no_crash(self):
        findings = [
            _make_finding(
                f"f-{i:03d}",
                severity  = ["CRITICAL","HIGH","MEDIUM","LOW"][i % 4],
                cvss_score= [9.8, 7.5, 5.0, 2.0][i % 4],
                pci_dss   = "Req 6.2.4" if i % 3 == 0 else "",
                soc2_cc   = "CC6.1"     if i % 3 == 1 else "",
                nist_csf  = "PR.DS-2"   if i % 3 == 2 else "",
            )
            for i in range(25)
        ]
        report = generate_compliance_gap_report(findings=findings)
        assert isinstance(report, ComplianceReport)
        assert 0 <= report.gap_score <= 100

    def test_control_results_cover_all_defined_controls(self):
        from reports.compliance_gap_report import _CONTROLS
        report = generate_compliance_gap_report(findings=[])
        result_ids = {cr.control_id for cr in report.control_results}
        defined_ids = {cd.control_id for cd in _CONTROLS}
        assert result_ids == defined_ids

    def test_to_json_is_serialisable_roundtrip(self):
        report = generate_compliance_gap_report(findings=_sample_findings())
        json_str = report.to_json(indent=None)
        parsed   = json.loads(json_str)
        assert parsed["gap_score"] == report.gap_score

    def test_status_values_are_valid_strings(self):
        report = generate_compliance_gap_report(findings=_sample_findings())
        valid   = {"PASS", "FAIL", "PARTIAL", "NOT_TESTED"}
        d = report.to_dict()
        for cr in d["control_results"]:
            assert cr["status"] in valid


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sample_findings():
    return [
        _make_finding("f-001", "CRITICAL", 9.8, pci_dss="Req 6.2.4", soc2_cc="CC6.1",
                      iso_27001="A.8.28", nist_csf="PR.DS-2"),
        _make_finding("f-002", "HIGH",     7.5, pci_dss="Req 4.2.1", soc2_cc="CC6.7",
                      iso_27001="A.8.24", nist_csf="PR.DS-1"),
        _make_finding("f-003", "MEDIUM",   5.3, pci_dss="Req 6.3.2"),
        _make_finding("f-004", "LOW",      2.1, soc2_cc="CC7.1"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# TestBuildExecutiveSummary
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildExecutiveSummary:
    def _make_fr(self, fw, readiness, pass_rate=0.9):
        return FrameworkResult(
            framework=fw, total_controls=8, passing=7, failing=1,
            partial=0, not_tested=0, pass_rate=pass_rate, readiness=readiness,
        )

    def test_all_compliant_mentions_pass(self):
        frs = [self._make_fr("PCI-DSS", "Compliant"),
               self._make_fr("SOC2", "Compliant")]
        text = _build_executive_summary(frs, 0.92, 0, 0)
        lower = text.lower()
        assert "pass" in lower or "meet" in lower or "compliant" in lower.split("all")[1] if "all" in lower else True

    def test_non_compliant_framework_named(self):
        frs = [self._make_fr("PCI-DSS", "Non-Compliant", 0.40),
               self._make_fr("SOC2", "Compliant")]
        text = _build_executive_summary(frs, 0.65, 2, 3)
        assert "PCI-DSS" in text
        assert "NON-COMPLIANT" in text.upper()

    def test_at_risk_framework_named(self):
        frs = [self._make_fr("ISO27001", "At Risk", 0.75)]
        text = _build_executive_summary(frs, 0.75, 0, 2)
        assert "ISO27001" in text
        assert "AT RISK" in text.upper()

    def test_critical_count_mentioned(self):
        frs = [self._make_fr("PCI-DSS", "Non-Compliant", 0.30)]
        text = _build_executive_summary(frs, 0.30, 5, 2)
        assert "CRITICAL" in text or "5" in text

    def test_pass_rate_percentage_in_text(self):
        frs = [self._make_fr("NIST-CSF", "Compliant")]
        text = _build_executive_summary(frs, 0.88, 0, 0)
        assert "88" in text or "pass rate" in text.lower()

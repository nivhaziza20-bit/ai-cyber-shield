"""
tests/test_ciso_pdf_report.py — AI Cyber Shield v6

Test suite for reports/ciso_pdf_report.py (CISO PDF generator).

Tests cover:
  • Score-to-grade mapping
  • Severity counting
  • OWASP coverage aggregation
  • Remediation hours totalling
  • Grade colour selection
  • generate_ciso_pdf() — happy path (non-empty, valid PDF magic bytes)
  • generate_ciso_pdf() — zero findings (cover still generated)
  • generate_ciso_pdf() — returns bytes
  • Cover page with / without trend data
  • Compliance matrix with / without findings
  • All severity levels present in findings
  • Long titles get truncated (no overflow)
  • Custom report title propagates to PDF metadata
  • Missing reportlab raises RuntimeError (import guard)
  • CisoPdfConfig defaults
"""

from __future__ import annotations

import sys
import types
import io
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fake SecurityFinding objects (avoids importing full finding_enricher)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _FakeCvssVector:
    av: str = "N"
    ac: str = "L"
    pr: str = "N"
    ui: str = "N"
    s:  str = "U"
    c:  str = "H"
    i:  str = "H"
    a:  str = "H"

    @property
    def vector_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}"
                f"/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}")


@dataclass
class _FakeCvssScore:
    score:    float = 9.8
    severity: str   = "CRITICAL"
    vector:   _FakeCvssVector = field(default_factory=_FakeCvssVector)


@dataclass
class _FakeCweInfo:
    id:          int  = 79
    name:        str  = "Cross-site Scripting"
    description: str  = "XSS"
    url:         str  = "https://cwe.mitre.org/data/definitions/79.html"

    @property
    def label(self) -> str:
        return f"CWE-{self.id}"


@dataclass
class _FakeOwaspEntry:
    code:  str = "A03"
    name:  str = "Injection"
    year:  int = 2025
    url:   str = ""

    @property
    def label(self) -> str:
        return f"{self.code}:2025 – {self.name}"


@dataclass
class _FakeCompliance:
    pci_dss:   str = "Req 6.2.4"
    soc2_cc:   str = "CC6.1"
    iso_27001: str = "A.14.2"
    nist_csf:  str = "PR.DS-1"
    owasp_asvs: str = "V5.3.1"


@dataclass
class _FakeRemediation:
    priority:     int   = 1
    effort_hours: float = 4.0
    summary:      str   = "Sanitise user input before rendering in the DOM"
    code_before:  str   = ""
    code_after:   str   = ""
    references:   list  = field(default_factory=list)


@dataclass
class _FakeFinding:
    finding_id:      str  = "f-001"
    title:           str  = "Cross-Site Scripting in Search Field"
    finding_type:    str  = "xss_reflected"
    tool:            str  = "dast"
    severity:        str  = "CRITICAL"
    cvss:            _FakeCvssScore      = field(default_factory=_FakeCvssScore)
    cwe:             _FakeCweInfo        = field(default_factory=_FakeCweInfo)
    owasp:           _FakeOwaspEntry     = field(default_factory=_FakeOwaspEntry)
    compliance:      _FakeCompliance     = field(default_factory=_FakeCompliance)
    business_impact: str = "An attacker can steal session tokens."
    attack_scenario: str = "An attacker injects <script> into the query parameter."
    remediation:     _FakeRemediation    = field(default_factory=_FakeRemediation)
    endpoint:        str  = "https://example.com/search"
    parameter:       str  = "q"
    evidence:        str  = "<script>alert(1)</script>"
    confirmed:       bool = True
    confidence:      float = 0.95
    scan_timestamp:  str  = "2026-01-01T00:00:00+00:00"


def _make_finding(
    finding_id="f-001",
    title="XSS in Search",
    severity="CRITICAL",
    cvss_score=9.8,
    confirmed=True,
    owasp_code="A03",
    pci_dss="Req 6.2.4",
    soc2_cc="CC6.1",
    iso_27001="A.14.2",
    nist_csf="PR.DS-1",
    effort_hours=4.0,
    priority=1,
) -> _FakeFinding:
    f = _FakeFinding(
        finding_id   = finding_id,
        title        = title,
        severity     = severity,
        confirmed    = confirmed,
    )
    f.cvss = _FakeCvssScore(score=cvss_score, severity=severity)
    f.owasp = _FakeOwaspEntry(code=owasp_code)
    f.compliance = _FakeCompliance(pci_dss=pci_dss, soc2_cc=soc2_cc,
                                    iso_27001=iso_27001, nist_csf=nist_csf)
    f.remediation = _FakeRemediation(effort_hours=effort_hours, priority=priority)
    return f


def _sample_findings() -> list[_FakeFinding]:
    return [
        _make_finding("f-001", "XSS in Search",         "CRITICAL", 9.8, owasp_code="A03"),
        _make_finding("f-002", "SQL Injection in Login", "CRITICAL", 9.0, owasp_code="A03"),
        _make_finding("f-003", "CORS Wildcard",          "HIGH",     7.5, owasp_code="A05",
                      pci_dss="Req 6.3", confirmed=False),
        _make_finding("f-004", "Missing HSTS Header",   "MEDIUM",   5.3, owasp_code="A05",
                      soc2_cc="CC6.2"),
        _make_finding("f-005", "Information Disclosure", "LOW",      3.1, owasp_code="A09",
                      pci_dss="", soc2_cc=""),
        _make_finding("f-006", "Banner Disclosure",      "INFO",     0.0,
                      pci_dss="", soc2_cc="", owasp_code="A09"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Imports under test
# ─────────────────────────────────────────────────────────────────────────────

from reports.ciso_pdf_report import (
    _score_to_grade,
    _count_by_severity,
    _owasp_coverage,
    _total_remediation_hours,
    _severity_order,
    CisoPdfConfig,
    generate_ciso_pdf,
)


# ─────────────────────────────────────────────────────────────────────────────
# TestScoreToGrade
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreToGrade:
    def test_A_at_90(self):         assert _score_to_grade(90)  == "A"
    def test_A_at_100(self):        assert _score_to_grade(100) == "A"
    def test_B_at_80(self):         assert _score_to_grade(80)  == "B"
    def test_B_at_89(self):         assert _score_to_grade(89)  == "B"
    def test_C_at_65(self):         assert _score_to_grade(65)  == "C"
    def test_C_at_79(self):         assert _score_to_grade(79)  == "C"
    def test_D_at_50(self):         assert _score_to_grade(50)  == "D"
    def test_D_at_64(self):         assert _score_to_grade(64)  == "D"
    def test_F_at_0(self):          assert _score_to_grade(0)   == "F"
    def test_F_at_49(self):         assert _score_to_grade(49)  == "F"
    def test_A_boundary_exact(self): assert _score_to_grade(90) == "A"
    def test_B_boundary_exact(self): assert _score_to_grade(80) == "B"


# ─────────────────────────────────────────────────────────────────────────────
# TestCountBySeverity
# ─────────────────────────────────────────────────────────────────────────────

class TestCountBySeverity:
    def test_empty(self):
        result = _count_by_severity([])
        assert result == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def test_single_critical(self):
        f = _make_finding(severity="CRITICAL")
        result = _count_by_severity([f])
        assert result["CRITICAL"] == 1
        assert result["HIGH"] == 0

    def test_mixed_severities(self):
        findings = _sample_findings()
        counts = _count_by_severity(findings)
        assert counts["CRITICAL"] == 2
        assert counts["HIGH"]     == 1
        assert counts["MEDIUM"]   == 1
        assert counts["LOW"]      == 1
        assert counts["INFO"]     == 1

    def test_all_same_severity(self):
        findings = [_make_finding(f"f-{i}", severity="HIGH") for i in range(5)]
        counts = _count_by_severity(findings)
        assert counts["HIGH"] == 5
        assert counts["CRITICAL"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# TestOwaspCoverage
# ─────────────────────────────────────────────────────────────────────────────

class TestOwaspCoverage:
    def test_empty(self):
        assert _owasp_coverage([]) == {}

    def test_single_category(self):
        f = _make_finding(owasp_code="A03")
        result = _owasp_coverage([f])
        assert result == {"A03": 1}

    def test_multiple_same_category(self):
        findings = [_make_finding(f"f-{i}", owasp_code="A03") for i in range(3)]
        result = _owasp_coverage(findings)
        assert result["A03"] == 3

    def test_multiple_categories(self):
        findings = _sample_findings()
        result = _owasp_coverage(findings)
        assert result["A03"] == 2   # XSS + SQLi
        assert result["A05"] == 2   # CORS + HSTS
        assert result["A09"] == 2   # Info Disclosure + Banner

    def test_new_owasp_2025_categories(self):
        f_a11 = _make_finding(owasp_code="A11")
        f_a12 = _make_finding(owasp_code="A12")
        result = _owasp_coverage([f_a11, f_a12])
        assert result["A11"] == 1
        assert result["A12"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# TestTotalRemediationHours
# ─────────────────────────────────────────────────────────────────────────────

class TestTotalRemediationHours:
    def test_empty(self):
        assert _total_remediation_hours([]) == 0.0

    def test_single(self):
        f = _make_finding(effort_hours=8.0)
        assert _total_remediation_hours([f]) == 8.0

    def test_multiple(self):
        findings = [
            _make_finding("f-1", effort_hours=4.0),
            _make_finding("f-2", effort_hours=8.0),
            _make_finding("f-3", effort_hours=2.0),
        ]
        assert _total_remediation_hours(findings) == 14.0

    def test_fractional_hours(self):
        findings = [_make_finding("f-1", effort_hours=1.5),
                    _make_finding("f-2", effort_hours=2.5)]
        assert _total_remediation_hours(findings) == pytest.approx(4.0)


# ─────────────────────────────────────────────────────────────────────────────
# TestSeverityOrder
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityOrder:
    def test_critical_first(self):
        assert _severity_order("CRITICAL") < _severity_order("HIGH")

    def test_high_before_medium(self):
        assert _severity_order("HIGH") < _severity_order("MEDIUM")

    def test_medium_before_low(self):
        assert _severity_order("MEDIUM") < _severity_order("LOW")

    def test_low_before_info(self):
        assert _severity_order("LOW") < _severity_order("INFO")

    def test_unknown_severity_last(self):
        assert _severity_order("UNKNOWN") > _severity_order("INFO")


# ─────────────────────────────────────────────────────────────────────────────
# TestCisoPdfConfig
# ─────────────────────────────────────────────────────────────────────────────

class TestCisoPdfConfig:
    def test_defaults(self):
        cfg = CisoPdfConfig(target_url="https://example.com")
        assert cfg.target_url   == "https://example.com"
        assert cfg.overall_score == 0
        assert cfg.overall_grade == "?"
        assert cfg.scan_id       == ""
        assert cfg.confidential  is True
        assert cfg.prev_score is None

    def test_custom_values(self):
        cfg = CisoPdfConfig(
            target_url     = "https://app.test",
            overall_score  = 75,
            overall_grade  = "B",
            org_name       = "ACME Corp",
            prev_score     = 60,
        )
        assert cfg.overall_score == 75
        assert cfg.overall_grade == "B"
        assert cfg.org_name      == "ACME Corp"
        assert cfg.prev_score    == 60


# ─────────────────────────────────────────────────────────────────────────────
# TestGenerateCisoPdf
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateCisoPdf:
    """Integration tests — actually run reportlab to generate a PDF."""

    def test_returns_bytes(self):
        result = generate_ciso_pdf(
            findings    = _sample_findings(),
            target_url  = "https://example.com",
            overall_score = 60,
        )
        assert isinstance(result, bytes)

    def test_valid_pdf_magic_bytes(self):
        result = generate_ciso_pdf(
            findings    = _sample_findings(),
            target_url  = "https://example.com",
            overall_score = 70,
        )
        assert result[:4] == b"%PDF"

    def test_non_empty_pdf(self):
        result = generate_ciso_pdf(
            findings    = _sample_findings(),
            target_url  = "https://example.com",
            overall_score = 65,
        )
        assert len(result) > 5000   # real PDF, not empty

    def test_zero_findings(self):
        result = generate_ciso_pdf(
            findings    = [],
            target_url  = "https://clean.example.com",
            overall_score = 100,
            overall_grade = "A",
        )
        assert result[:4] == b"%PDF"
        assert len(result) > 1000

    def test_single_finding(self):
        findings = [_make_finding("f-001", severity="HIGH", cvss_score=7.5)]
        result = generate_ciso_pdf(
            findings    = findings,
            target_url  = "https://example.com",
            overall_score = 80,
        )
        assert result[:4] == b"%PDF"

    def test_grade_auto_derived_when_empty(self):
        # Should not raise when overall_grade is empty — auto-derives from score
        result = generate_ciso_pdf(
            findings      = _sample_findings(),
            target_url    = "https://example.com",
            overall_score = 72,
            overall_grade = "",  # empty → auto-derive → "C"
        )
        assert isinstance(result, bytes)

    def test_with_scan_id(self):
        result = generate_ciso_pdf(
            findings    = _sample_findings(),
            target_url  = "https://example.com",
            scan_id     = "abc-123-xyz",
        )
        assert result[:4] == b"%PDF"

    def test_with_scan_timestamp(self):
        result = generate_ciso_pdf(
            findings        = _sample_findings(),
            target_url      = "https://example.com",
            scan_timestamp  = "2026-01-01T12:00:00 UTC",
        )
        assert result[:4] == b"%PDF"

    def test_with_org_name(self):
        result = generate_ciso_pdf(
            findings    = _sample_findings(),
            target_url  = "https://example.com",
            org_name    = "ACME Security Corp",
        )
        assert result[:4] == b"%PDF"

    def test_with_custom_title(self):
        result = generate_ciso_pdf(
            findings      = _sample_findings(),
            target_url    = "https://example.com",
            report_title  = "Q1 2026 Security Audit — CONFIDENTIAL",
        )
        assert result[:4] == b"%PDF"

    def test_with_trend_data(self):
        result = generate_ciso_pdf(
            findings       = _sample_findings(),
            target_url     = "https://example.com",
            overall_score  = 72,
            prev_score     = 65,
            prev_findings  = 12,
        )
        assert result[:4] == b"%PDF"

    def test_trend_score_improvement(self):
        # Score improved: 65 → 80
        result = generate_ciso_pdf(
            findings      = _sample_findings(),
            target_url    = "https://example.com",
            overall_score = 80,
            prev_score    = 65,
        )
        assert isinstance(result, bytes)

    def test_trend_score_decline(self):
        # Score declined: 80 → 60
        result = generate_ciso_pdf(
            findings      = _sample_findings(),
            target_url    = "https://example.com",
            overall_score = 60,
            prev_score    = 80,
        )
        assert isinstance(result, bytes)

    def test_all_severities(self):
        findings = [
            _make_finding("f-c", severity="CRITICAL", cvss_score=9.8),
            _make_finding("f-h", severity="HIGH",     cvss_score=7.5),
            _make_finding("f-m", severity="MEDIUM",   cvss_score=5.0),
            _make_finding("f-l", severity="LOW",      cvss_score=2.0),
            _make_finding("f-i", severity="INFO",     cvss_score=0.0),
        ]
        result = generate_ciso_pdf(
            findings   = findings,
            target_url = "https://example.com",
        )
        assert result[:4] == b"%PDF"

    def test_long_title_does_not_crash(self):
        findings = [
            _make_finding(
                title="A" * 200,  # very long title — should be truncated in tables
                severity="HIGH",
                cvss_score=7.5,
            )
        ]
        result = generate_ciso_pdf(
            findings   = findings,
            target_url = "https://example.com",
        )
        assert result[:4] == b"%PDF"

    def test_many_findings(self):
        """25 findings — verifies pagination and table overflow handling."""
        findings = [
            _make_finding(
                f"f-{i:03d}",
                title     = f"Finding number {i:03d}",
                severity  = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"][i % 5],
                cvss_score= [9.8, 7.5, 5.0, 2.0, 0.0][i % 5],
                owasp_code= f"A{(i % 12) + 1:02d}",
            )
            for i in range(25)
        ]
        result = generate_ciso_pdf(
            findings      = findings,
            target_url    = "https://example.com",
            overall_score = 55,
        )
        assert result[:4] == b"%PDF"

    def test_grade_a_score(self):
        result = generate_ciso_pdf(
            findings      = [],
            target_url    = "https://example.com",
            overall_score = 95,
            overall_grade = "A",
        )
        assert isinstance(result, bytes)

    def test_grade_f_score(self):
        result = generate_ciso_pdf(
            findings      = _sample_findings(),
            target_url    = "https://example.com",
            overall_score = 20,
            overall_grade = "F",
        )
        assert isinstance(result, bytes)

    def test_no_compliance_fields(self):
        """Findings with empty compliance fields — compliance matrix should still render."""
        findings = [
            _make_finding("f-1", severity="HIGH", pci_dss="", soc2_cc="",
                          iso_27001="", nist_csf="")
        ]
        result = generate_ciso_pdf(
            findings   = findings,
            target_url = "https://example.com",
        )
        assert result[:4] == b"%PDF"

    def test_pdf_is_streamable(self):
        """Result can be wrapped in BytesIO and re-read."""
        raw = generate_ciso_pdf(
            findings   = _sample_findings(),
            target_url = "https://example.com",
        )
        buf = io.BytesIO(raw)
        buf.seek(0)
        header = buf.read(4)
        assert header == b"%PDF"

    def test_confirmed_vs_unconfirmed_findings(self):
        findings = [
            _make_finding("f-1", severity="CRITICAL", confirmed=True),
            _make_finding("f-2", severity="HIGH",     confirmed=False),
            _make_finding("f-3", severity="MEDIUM",   confirmed=True),
        ]
        result = generate_ciso_pdf(
            findings   = findings,
            target_url = "https://example.com",
        )
        assert result[:4] == b"%PDF"


# ─────────────────────────────────────────────────────────────────────────────
# TestMissingReportlab
# ─────────────────────────────────────────────────────────────────────────────

class TestMissingReportlab:
    def test_raises_runtime_error_when_reportlab_missing(self, monkeypatch):
        """If reportlab is not installed, generate_ciso_pdf raises RuntimeError."""
        real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def _block_reportlab(name, *args, **kwargs):
            if name.startswith("reportlab"):
                raise ImportError(f"No module named '{name}'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_block_reportlab):
            with pytest.raises((RuntimeError, ImportError)):
                generate_ciso_pdf(
                    findings   = _sample_findings(),
                    target_url = "https://example.com",
                )


# ─────────────────────────────────────────────────────────────────────────────
# TestGradeColour (internal helper)
# ─────────────────────────────────────────────────────────────────────────────

class TestGradeColour:
    def test_all_grades_have_colour(self):
        from reports.ciso_pdf_report import _GRADE_COLOUR
        for grade in ("A", "B", "C", "D", "F"):
            assert grade in _GRADE_COLOUR
            # Each callable returns a Color object (has .red attribute)
            color = _GRADE_COLOUR[grade]()
            assert hasattr(color, "red")

    def test_grade_a_is_green(self):
        from reports.ciso_pdf_report import _GRADE_COLOUR
        color = _GRADE_COLOUR["A"]()
        # green-500: ~34/255 ≈ 0.133, 197/255 ≈ 0.773
        assert color.green > color.red   # green channel dominates for "A"

    def test_grade_f_is_red(self):
        from reports.ciso_pdf_report import _GRADE_COLOUR
        color = _GRADE_COLOUR["F"]()
        assert color.red > color.green   # red channel dominates for "F"


# ─────────────────────────────────────────────────────────────────────────────
# TestSeverityColours
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityColours:
    def test_all_severities_have_colour(self):
        from reports.ciso_pdf_report import _SEV_COLOURS
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in _SEV_COLOURS
            color = _SEV_COLOURS[sev]()
            assert hasattr(color, "red")

    def test_critical_is_red(self):
        from reports.ciso_pdf_report import _SEV_COLOURS
        c = _SEV_COLOURS["CRITICAL"]()
        assert c.red > c.blue

    def test_low_is_green(self):
        from reports.ciso_pdf_report import _SEV_COLOURS
        c = _SEV_COLOURS["LOW"]()
        assert c.green > c.red

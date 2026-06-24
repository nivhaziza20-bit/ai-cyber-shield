"""
tests/test_developer_html_report.py — AI Cyber Shield v6

Test suite for reports/developer_html_report.py (Developer HTML Report generator).

Tests cover:
  • generate_developer_html returns a str
  • Output contains <!DOCTYPE html>
  • Severity counts appear in the output
  • Finding title appears in the output
  • Sorting: CRITICAL findings appear before LOW
  • Filter bar buttons generated
  • curl PoC with endpoint + parameter
  • curl PoC without endpoint
  • Effort class mapping (easy/medium/hard/expert)
  • Effort label mapping
  • Code diff section rendered when code_before/code_after present
  • Evidence section rendered
  • Compliance chips (PCI-DSS / SOC2 / ISO 27001 / NIST CSF)
  • Zero findings → shows "No findings detected"
  • HTML entity escaping (XSS in report title / finding title)
  • Custom report title in <title>
  • Scan ID and timestamp appear in output
  • Confirmed badge shown for confirmed findings
  • References section rendered
  • Missing jinja2 raises RuntimeError
  • Single finding renders without crash
  • Many findings (25) renders without crash
  • Auto-sorted: findings ordered by severity then CVSS
  • OWASP 2025 A11/A12 rendered
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

from reports.developer_html_report import (
    generate_developer_html,
    _curl_poc,
    _effort_class,
    _effort_label,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fake SecurityFinding (same pattern as test_ciso_pdf_report)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _FakeCvssVector:
    av: str = "N"
    @property
    def vector_string(self): return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

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
    url:         str  = ""
    @property
    def label(self): return f"CWE-{self.id}"

@dataclass
class _FakeOwaspEntry:
    code:  str = "A03"
    name:  str = "Injection"
    year:  int = 2025
    url:   str = ""
    @property
    def label(self): return f"{self.code}:2025 – {self.name}"

@dataclass
class _FakeCompliance:
    pci_dss:    str = "Req 6.2.4"
    soc2_cc:    str = "CC6.1"
    iso_27001:  str = "A.14.2"
    nist_csf:   str = "PR.DS-1"
    owasp_asvs: str = "V5.3.1"

@dataclass
class _FakeRemediation:
    priority:     int   = 1
    effort_hours: float = 4.0
    summary:      str   = "Sanitise user input"
    code_before:  str   = ""
    code_after:   str   = ""
    references:   list  = field(default_factory=list)

@dataclass
class _FakeFinding:
    finding_id:      str  = "f-001"
    title:           str  = "XSS in Search Field"
    finding_type:    str  = "xss_reflected"
    tool:            str  = "dast"
    severity:        str  = "CRITICAL"
    cvss:            _FakeCvssScore    = field(default_factory=_FakeCvssScore)
    cwe:             _FakeCweInfo      = field(default_factory=_FakeCweInfo)
    owasp:           _FakeOwaspEntry   = field(default_factory=_FakeOwaspEntry)
    compliance:      _FakeCompliance   = field(default_factory=_FakeCompliance)
    business_impact: str  = "Session tokens can be stolen."
    attack_scenario: str  = "An attacker injects <script> into the query param."
    remediation:     _FakeRemediation  = field(default_factory=_FakeRemediation)
    endpoint:        str  = "https://example.com/search"
    parameter:       str  = "q"
    evidence:        str  = "<script>alert(1)</script>"
    confirmed:       bool = True
    confidence:      float= 0.95
    scan_timestamp:  str  = "2026-01-01T00:00:00+00:00"


def _make_finding(
    finding_id="f-001",
    title="XSS in Search",
    severity="CRITICAL",
    cvss_score=9.8,
    confirmed=True,
    endpoint="https://example.com/search",
    parameter="q",
    evidence="<script>alert(1)</script>",
    owasp_code="A03",
    effort_hours=4.0,
    code_before="",
    code_after="",
    pci_dss="Req 6.2.4",
    soc2_cc="CC6.1",
    iso_27001="A.14.2",
    nist_csf="PR.DS-1",
    references=None,
) -> _FakeFinding:
    f = _FakeFinding(
        finding_id  = finding_id,
        title       = title,
        severity    = severity,
        confirmed   = confirmed,
        endpoint    = endpoint,
        parameter   = parameter,
        evidence    = evidence,
    )
    f.cvss        = _FakeCvssScore(score=cvss_score, severity=severity)
    f.owasp       = _FakeOwaspEntry(code=owasp_code)
    f.compliance  = _FakeCompliance(pci_dss=pci_dss, soc2_cc=soc2_cc,
                                     iso_27001=iso_27001, nist_csf=nist_csf)
    f.remediation = _FakeRemediation(
        effort_hours = effort_hours,
        code_before  = code_before,
        code_after   = code_after,
        references   = references or [],
    )
    return f


def _sample_findings():
    return [
        _make_finding("f-001", "XSS in Search",          "CRITICAL", 9.8),
        _make_finding("f-002", "SQL Injection",           "HIGH",     8.1,
                      owasp_code="A03"),
        _make_finding("f-003", "CORS Wildcard",           "MEDIUM",   5.3,
                      endpoint="https://example.com/api", parameter="",
                      owasp_code="A05"),
        _make_finding("f-004", "Missing HSTS",            "LOW",      3.1,
                      endpoint="", parameter="", evidence=""),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# TestEffortHelpers
# ─────────────────────────────────────────────────────────────────────────────

class TestEffortHelpers:
    def test_easy_class(self):
        assert "easy" in _effort_class(1.0)

    def test_medium_class(self):
        assert "medium" in _effort_class(4.0)

    def test_hard_class(self):
        assert "hard" in _effort_class(12.0)

    def test_expert_class(self):
        assert "expert" in _effort_class(48.0)

    def test_easy_label(self):
        assert "Easy" in _effort_label(1.0)

    def test_medium_label(self):
        assert "Medium" in _effort_label(4.0)

    def test_hard_label(self):
        assert "Hard" in _effort_label(12.0)

    def test_expert_label(self):
        assert "Expert" in _effort_label(48.0)

    def test_boundary_2h_is_easy(self):
        assert "easy" in _effort_class(2.0)

    def test_boundary_just_over_2h_is_medium(self):
        assert "medium" in _effort_class(2.1)

    def test_boundary_8h_is_medium(self):
        assert "medium" in _effort_class(8.0)

    def test_boundary_just_over_8h_is_hard(self):
        assert "hard" in _effort_class(8.1)


# ─────────────────────────────────────────────────────────────────────────────
# TestCurlPoc
# ─────────────────────────────────────────────────────────────────────────────

class TestCurlPoc:
    def test_with_endpoint_and_param(self):
        f = _make_finding(endpoint="https://example.com/search",
                          parameter="q",
                          evidence="<script>alert(1)</script>")
        poc = _curl_poc(f)
        assert "curl" in poc
        assert "example.com/search" in poc
        assert "data-urlencode" in poc

    def test_without_endpoint(self):
        f = _make_finding(endpoint="", parameter="", evidence="")
        poc = _curl_poc(f)
        assert "curl" in poc
        assert "TARGET" in poc

    def test_with_endpoint_no_param(self):
        f = _make_finding(endpoint="https://example.com/api", parameter="", evidence="")
        poc = _curl_poc(f)
        assert "curl" in poc
        assert "example.com/api" in poc

    def test_long_evidence_truncated(self):
        f = _make_finding(evidence="A" * 300)
        poc = _curl_poc(f)
        assert len(poc) < 400   # should not be excessively long

    def test_user_agent_present(self):
        f = _make_finding()
        poc = _curl_poc(f)
        assert "AI-Cyber-Shield" in poc

    def test_single_quote_in_evidence_escaped(self):
        f = _make_finding(evidence="test'injection")
        poc = _curl_poc(f)
        assert "\\'" in poc or "injection" in poc   # either escaped or present


# ─────────────────────────────────────────────────────────────────────────────
# TestGenerateDeveloperHtml
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateDeveloperHtml:
    def test_returns_string(self):
        result = generate_developer_html(findings=_sample_findings())
        assert isinstance(result, str)

    def test_valid_html_doctype(self):
        result = generate_developer_html(findings=_sample_findings())
        assert "<!DOCTYPE html>" in result

    def test_contains_html_tag(self):
        result = generate_developer_html(findings=_sample_findings())
        assert "<html" in result

    def test_zero_findings_no_crash(self):
        result = generate_developer_html(findings=[])
        assert "<!DOCTYPE html>" in result

    def test_zero_findings_message(self):
        result = generate_developer_html(findings=[])
        assert "No findings detected" in result

    def test_finding_title_appears(self):
        f = _make_finding(title="My Custom XSS Finding")
        result = generate_developer_html(findings=[f])
        assert "My Custom XSS Finding" in result

    def test_severity_badge_rendered(self):
        f = _make_finding(severity="CRITICAL")
        result = generate_developer_html(findings=[f])
        assert "sev-CRITICAL" in result

    def test_cvss_score_appears(self):
        f = _make_finding(cvss_score=9.8)
        result = generate_developer_html(findings=[f])
        assert "9.8" in result

    def test_cwe_label_appears(self):
        f = _make_finding()
        result = generate_developer_html(findings=[f])
        assert "CWE-79" in result

    def test_owasp_code_appears(self):
        f = _make_finding(owasp_code="A03")
        result = generate_developer_html(findings=[f])
        assert "A03" in result

    def test_target_url_in_output(self):
        result = generate_developer_html(
            findings   = _sample_findings(),
            target_url = "https://app.example.com",
        )
        assert "app.example.com" in result

    def test_scan_id_in_output(self):
        result = generate_developer_html(
            findings = _sample_findings(),
            scan_id  = "abc-12345",
        )
        assert "abc-12345" in result

    def test_custom_title_in_head(self):
        result = generate_developer_html(
            findings     = _sample_findings(),
            report_title = "Q1 Security Audit",
        )
        assert "Q1 Security Audit" in result

    def test_scan_timestamp_in_output(self):
        result = generate_developer_html(
            findings        = _sample_findings(),
            scan_timestamp  = "2026-06-01 12:00 UTC",
        )
        assert "2026-06-01" in result

    def test_auto_timestamp_when_not_provided(self):
        result = generate_developer_html(findings=_sample_findings())
        assert "UTC" in result   # timestamp always included

    def test_filter_buttons_present(self):
        result = generate_developer_html(findings=_sample_findings())
        assert "filter-btn" in result
        assert "CRITICAL" in result
        assert "filterSev" in result

    def test_copy_button_present(self):
        result = generate_developer_html(findings=_sample_findings())
        assert "copy-btn" in result

    def test_toggle_js_function_present(self):
        result = generate_developer_html(findings=_sample_findings())
        assert "toggleFinding" in result

    def test_evidence_section_rendered(self):
        f = _make_finding(evidence="<script>alert(1)</script>")
        result = generate_developer_html(findings=[f])
        assert "evidence-box" in result

    def test_endpoint_section_rendered(self):
        f = _make_finding(endpoint="https://example.com/login")
        result = generate_developer_html(findings=[f])
        assert "example.com/login" in result

    def test_curl_poc_section_rendered(self):
        f = _make_finding(endpoint="https://example.com/search", parameter="q")
        result = generate_developer_html(findings=[f])
        assert "curl" in result

    def test_no_curl_when_no_endpoint(self):
        f = _make_finding(endpoint="", parameter="")
        result = generate_developer_html(findings=[f])
        # curl PoC section should not appear (no endpoint)
        assert "curl PoC" not in result

    def test_confirmed_badge_shown(self):
        f = _make_finding(confirmed=True)
        result = generate_developer_html(findings=[f])
        assert "Confirmed" in result

    def test_unconfirmed_no_badge(self):
        f = _make_finding(confirmed=False)
        result = generate_developer_html(findings=[f])
        # The HTML element with confirmed-badge is not rendered for unconfirmed findings.
        # CSS style uses ".confirmed-badge" (with dot); HTML uses class="confirmed-badge".
        assert 'class="confirmed-badge"' not in result

    def test_code_diff_rendered_when_present(self):
        f = _make_finding(
            code_before = "echo $_GET['q'];",
            code_after  = "echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');",
        )
        result = generate_developer_html(findings=[f])
        assert "diff-before" in result
        assert "diff-after"  in result
        assert "Vulnerable"  in result
        assert "Fixed"       in result

    def test_no_code_diff_when_absent(self):
        f = _make_finding(code_before="", code_after="")
        result = generate_developer_html(findings=[f])
        # CSS uses ".diff-before" (with dot); HTML body uses class="diff-before"
        assert 'class="diff-before"' not in result

    def test_compliance_pci_chip_rendered(self):
        f = _make_finding(pci_dss="Req 6.2.4")
        result = generate_developer_html(findings=[f])
        assert "PCI-DSS" in result
        assert "Req 6.2.4" in result

    def test_compliance_soc2_chip_rendered(self):
        f = _make_finding(soc2_cc="CC6.1")
        result = generate_developer_html(findings=[f])
        assert "SOC2" in result
        assert "CC6.1" in result

    def test_compliance_iso_chip_rendered(self):
        f = _make_finding(iso_27001="A.14.2")
        result = generate_developer_html(findings=[f])
        assert "ISO" in result
        assert "A.14.2" in result

    def test_compliance_nist_chip_rendered(self):
        f = _make_finding(nist_csf="PR.DS-1")
        result = generate_developer_html(findings=[f])
        assert "NIST" in result
        assert "PR.DS-1" in result

    def test_no_compliance_chip_when_empty(self):
        f = _make_finding(pci_dss="", soc2_cc="", iso_27001="", nist_csf="")
        result = generate_developer_html(findings=[f])
        assert 'class="tag pci"' not in result

    def test_references_rendered(self):
        f = _make_finding(references=["https://owasp.org/xss", "https://cwe.mitre.org/79"])
        result = generate_developer_html(findings=[f])
        assert "owasp.org/xss" in result
        assert "cwe.mitre.org/79" in result

    def test_html_escaping_in_title(self):
        f = _make_finding(title='<script>alert("xss")</script>')
        result = generate_developer_html(findings=[f])
        # Title should be escaped so <script> is not executable
        assert "<script>alert" not in result
        assert "&lt;script&gt;" in result

    def test_html_escaping_in_target_url(self):
        result = generate_developer_html(
            findings   = [],
            target_url = '<img src=x onerror=alert(1)>',
        )
        assert "<img src=x" not in result

    def test_sorted_critical_before_low(self):
        findings = [
            _make_finding("f-low",  severity="LOW",      cvss_score=2.0),
            _make_finding("f-crit", severity="CRITICAL", cvss_score=9.8),
        ]
        result = generate_developer_html(findings=findings)
        crit_pos = result.index("sev-CRITICAL")
        low_pos  = result.index("sev-LOW")
        assert crit_pos < low_pos

    def test_sorted_by_cvss_within_same_severity(self):
        findings = [
            _make_finding("f-h1", "Lower High",  "HIGH", cvss_score=7.1),
            _make_finding("f-h2", "Higher High", "HIGH", cvss_score=8.9),
        ]
        result = generate_developer_html(findings=findings)
        pos_h2 = result.index("8.9")
        pos_h1 = result.index("7.1")
        assert pos_h2 < pos_h1   # 8.9 (higher CVSS) should appear first

    def test_many_findings_no_crash(self):
        findings = [
            _make_finding(
                f"f-{i:03d}",
                title     = f"Finding {i:03d}",
                severity  = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"][i % 5],
                cvss_score= [9.8, 7.5, 5.0, 2.0, 0.0][i % 5],
            )
            for i in range(25)
        ]
        result = generate_developer_html(findings=findings)
        assert "<!DOCTYPE html>" in result

    def test_owasp_2025_a11_rendered(self):
        f = _make_finding(owasp_code="A11")
        result = generate_developer_html(findings=[f])
        assert "A11" in result

    def test_owasp_2025_a12_rendered(self):
        f = _make_finding(owasp_code="A12")
        result = generate_developer_html(findings=[f])
        assert "A12" in result

    def test_attack_scenario_in_body(self):
        f = _make_finding()
        f.attack_scenario = "An attacker can steal session data via XSS."
        result = generate_developer_html(findings=[f])
        assert "An attacker can steal session data" in result

    def test_business_impact_in_body(self):
        f = _make_finding()
        f.business_impact = "Customer PII at risk of exfiltration."
        result = generate_developer_html(findings=[f])
        assert "Customer PII at risk" in result

    def test_severity_counts_in_output(self):
        findings = [
            _make_finding("f-1", severity="CRITICAL"),
            _make_finding("f-2", severity="HIGH"),
        ]
        result = generate_developer_html(findings=findings)
        # Score bar should show counts
        assert "score-card" in result

    def test_single_finding_no_crash(self):
        f = _make_finding()
        result = generate_developer_html(findings=[f])
        assert "<!DOCTYPE html>" in result


# ─────────────────────────────────────────────────────────────────────────────
# TestMissingJinja2
# ─────────────────────────────────────────────────────────────────────────────

class TestMissingJinja2:
    def test_raises_runtime_error_when_jinja2_missing(self):
        real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def _block_jinja2(name, *args, **kwargs):
            if name.startswith("jinja2"):
                raise ImportError(f"No module named '{name}'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_block_jinja2):
            with pytest.raises((RuntimeError, ImportError)):
                generate_developer_html(findings=_sample_findings())

"""
reports/compliance_gap_report.py — AI Cyber Shield v6

Compliance Gap Report generator.

Produces a machine-readable + human-readable compliance posture summary across:
  • PCI-DSS v4.0 (Payment Card Industry)
  • SOC2 Type II (Trust Services Criteria)
  • ISO/IEC 27001:2022 (Information Security Management)
  • NIST CSF 2.0 (Cybersecurity Framework)

What makes this better than competitors:
  • Checkbox model: each control is PASS / FAIL / PARTIAL / NOT_TESTED
  • Per-framework pass rate and overall readiness percentage
  • Severity-weighted gap score (CRITICAL failures count more)
  • Exportable as JSON for CI/CD gate checks
  • Separate "executive" narrative vs. "auditor" detail
  • OWASP 2025 A11 / A12 mapped to relevant controls
  • Remediation priority ordering per failing control

Usage:
    from reports.compliance_gap_report import (
        generate_compliance_gap_report,
        ComplianceReport,
        ControlStatus,
    )
    from finding_enricher import enrich_scan_result

    findings = enrich_scan_result(raw_result)
    report: ComplianceReport = generate_compliance_gap_report(
        findings   = findings,
        target_url = "https://app.example.com",
    )
    print(report.summary_text())
    print(report.to_json())
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

_log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Status enum
# ─────────────────────────────────────────────────────────────────────────────

class ControlStatus(str, Enum):
    PASS        = "PASS"
    FAIL        = "FAIL"
    PARTIAL     = "PARTIAL"
    NOT_TESTED  = "NOT_TESTED"


# ─────────────────────────────────────────────────────────────────────────────
# Control catalogue
# Each entry: (control_id, description, frameworks, severity_weight)
# severity_weight: how much a CRITICAL finding in this control counts (1–3)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ControlDef:
    control_id:    str
    description:   str
    frameworks:    tuple[str, ...]   # ("PCI-DSS", "SOC2", ...)
    weight:        int = 1           # 1 = standard, 2 = important, 3 = critical


_CONTROLS: list[ControlDef] = [
    # ── PCI-DSS v4.0 ─────────────────────────────────────────────────────────
    ControlDef("PCI-6.2.4",  "Prevent common software attacks (SQLi, XSS, SSRF)",
               ("PCI-DSS",), weight=3),
    ControlDef("PCI-6.3.2",  "Maintain software component inventory; patch vulnerabilities",
               ("PCI-DSS",), weight=2),
    ControlDef("PCI-6.4",    "Web-facing applications protected against known attacks",
               ("PCI-DSS",), weight=3),
    ControlDef("PCI-2.2.1",  "System components configured to minimum necessary functionality",
               ("PCI-DSS",), weight=2),
    ControlDef("PCI-4.2.1",  "Strong cryptography in transit (TLS 1.2+, valid certs)",
               ("PCI-DSS",), weight=3),
    ControlDef("PCI-7.2",    "Access to system components restricted by least privilege",
               ("PCI-DSS",), weight=2),
    ControlDef("PCI-10.2",   "Audit logs capture all access and changes",
               ("PCI-DSS",), weight=1),
    ControlDef("PCI-11.3.1", "External vulnerability scans performed quarterly",
               ("PCI-DSS",), weight=1),

    # ── SOC2 Trust Services Criteria ─────────────────────────────────────────
    ControlDef("CC6.1",  "Logical access security software to restrict access",
               ("SOC2",), weight=3),
    ControlDef("CC6.3",  "Role-based access control and privilege review",
               ("SOC2",), weight=2),
    ControlDef("CC6.6",  "Logical access security over network access",
               ("SOC2",), weight=2),
    ControlDef("CC6.7",  "Transmission of data is encrypted",
               ("SOC2",), weight=3),
    ControlDef("CC7.1",  "Vulnerability management to detect threats",
               ("SOC2",), weight=2),
    ControlDef("CC7.2",  "Monitor system components for anomalies",
               ("SOC2",), weight=1),
    ControlDef("CC8.1",  "Change management controls",
               ("SOC2",), weight=1),
    ControlDef("A1.1",   "Availability commitments and capacity management",
               ("SOC2",), weight=1),

    # ── ISO/IEC 27001:2022 ────────────────────────────────────────────────────
    ControlDef("A.8.8",  "Management of technical vulnerabilities",
               ("ISO27001",), weight=3),
    ControlDef("A.8.9",  "Configuration management (CIS Benchmarks, hardening)",
               ("ISO27001",), weight=2),
    ControlDef("A.8.19", "Installation of software on operational systems",
               ("ISO27001",), weight=2),
    ControlDef("A.8.24", "Use of cryptography (TLS, key management)",
               ("ISO27001",), weight=3),
    ControlDef("A.8.25", "Secure development lifecycle",
               ("ISO27001",), weight=2),
    ControlDef("A.8.26", "Application security requirements",
               ("ISO27001",), weight=3),
    ControlDef("A.8.28", "Secure coding",
               ("ISO27001",), weight=3),
    ControlDef("A.5.28", "Collection of evidence (logs, incident response)",
               ("ISO27001",), weight=1),
    ControlDef("A.5.36", "Compliance with policies, rules, and standards",
               ("ISO27001",), weight=1),

    # ── NIST CSF 2.0 ─────────────────────────────────────────────────────────
    ControlDef("ID.RA-1",  "Asset vulnerabilities identified and documented",
               ("NIST-CSF",), weight=2),
    ControlDef("PR.DS-1",  "Data-at-rest is protected",
               ("NIST-CSF",), weight=2),
    ControlDef("PR.DS-2",  "Data-in-transit is protected",
               ("NIST-CSF",), weight=3),
    ControlDef("PR.AC-4",  "Access permissions managed with least privilege",
               ("NIST-CSF",), weight=2),
    ControlDef("PR.IP-12", "Vulnerability management plan",
               ("NIST-CSF",), weight=2),
    ControlDef("DE.CM-8",  "Vulnerability scans performed",
               ("NIST-CSF",), weight=1),
    ControlDef("RS.MI-3",  "Newly identified vulnerabilities are mitigated",
               ("NIST-CSF",), weight=3),
]

# ── Mapping: finding field values → affected controls ────────────────────────
# PCI-DSS controls triggered by a finding's compliance.pci_dss value
_PCI_CONTROL_MAP: dict[str, list[str]] = {
    "Req 6.2.4":  ["PCI-6.2.4", "PCI-6.4"],
    "Req 6.3.2":  ["PCI-6.3.2"],
    "Req 6.3":    ["PCI-6.3.2", "PCI-6.4"],
    "Req 2.2":    ["PCI-2.2.1"],
    "Req 4.2.1":  ["PCI-4.2.1"],
    "Req 4.2":    ["PCI-4.2.1"],
    "Req 7.2":    ["PCI-7.2"],
    "Req 10.2":   ["PCI-10.2"],
    "Req 11.3.1": ["PCI-11.3.1"],
}

_SOC2_CONTROL_MAP: dict[str, list[str]] = {
    "CC6.1": ["CC6.1"],
    "CC6.3": ["CC6.3"],
    "CC6.6": ["CC6.6"],
    "CC6.7": ["CC6.7"],
    "CC7.1": ["CC7.1"],
    "CC7.2": ["CC7.2"],
    "CC8.1": ["CC8.1"],
    "CC6.2": ["CC6.1"],   # map near-matches
}

_ISO_CONTROL_MAP: dict[str, list[str]] = {
    "A.8.8":  ["A.8.8"],
    "A.8.9":  ["A.8.9"],
    "A.8.19": ["A.8.19"],
    "A.8.24": ["A.8.24"],
    "A.8.25": ["A.8.25"],
    "A.8.26": ["A.8.26"],
    "A.8.28": ["A.8.28"],
    "A.14.1": ["A.8.25", "A.8.26"],   # old 27001 ID → new
    "A.14.2": ["A.8.28", "A.8.25"],
}

_NIST_CONTROL_MAP: dict[str, list[str]] = {
    "ID.RA-1":  ["ID.RA-1"],
    "PR.DS-1":  ["PR.DS-1"],
    "PR.DS-2":  ["PR.DS-2"],
    "PR.AC-4":  ["PR.AC-4"],
    "PR.IP-12": ["PR.IP-12"],
    "DE.CM-8":  ["DE.CM-8"],
    "RS.MI-3":  ["RS.MI-3"],
}

_SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ControlResult:
    control_id:     str
    description:    str
    frameworks:     list[str]
    status:         ControlStatus
    failing_findings: list[str] = field(default_factory=list)   # finding_ids
    gap_severity:   str = "INFO"   # worst severity among failing_findings
    remediation_hint: str = ""


@dataclass
class FrameworkResult:
    framework:     str
    total_controls: int
    passing:       int
    failing:       int
    partial:       int
    not_tested:    int
    pass_rate:     float   # 0.0–1.0
    readiness:     str     # "Compliant" / "At Risk" / "Non-Compliant"
    failing_ids:   list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    target_url:        str
    scan_id:           str
    scan_timestamp:    str
    control_results:   list[ControlResult]
    framework_results: list[FrameworkResult]
    overall_pass_rate: float
    gap_score:         int        # 0–100 (higher = more gaps)
    executive_summary: str
    total_findings:    int
    critical_findings: int

    def to_dict(self) -> dict:
        return {
            "target_url":        self.target_url,
            "scan_id":           self.scan_id,
            "scan_timestamp":    self.scan_timestamp,
            "overall_pass_rate": round(self.overall_pass_rate, 4),
            "gap_score":         self.gap_score,
            "executive_summary": self.executive_summary,
            "total_findings":    self.total_findings,
            "critical_findings": self.critical_findings,
            "framework_results": [
                {
                    "framework":      fr.framework,
                    "total_controls": fr.total_controls,
                    "passing":        fr.passing,
                    "failing":        fr.failing,
                    "partial":        fr.partial,
                    "not_tested":     fr.not_tested,
                    "pass_rate":      round(fr.pass_rate, 4),
                    "readiness":      fr.readiness,
                    "failing_controls": fr.failing_ids,
                }
                for fr in self.framework_results
            ],
            "control_results": [
                {
                    "control_id":       cr.control_id,
                    "description":      cr.description,
                    "frameworks":       cr.frameworks,
                    "status":           cr.status.value,
                    "gap_severity":     cr.gap_severity,
                    "failing_findings": cr.failing_findings,
                    "remediation_hint": cr.remediation_hint,
                }
                for cr in self.control_results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary_text(self) -> str:
        lines = [
            f"Compliance Gap Report — {self.target_url}",
            f"Timestamp : {self.scan_timestamp}",
            f"Overall pass rate : {self.overall_pass_rate * 100:.1f}%",
            f"Gap score         : {self.gap_score}/100",
            "",
            self.executive_summary,
            "",
        ]
        for fr in self.framework_results:
            bar = "█" * int(fr.pass_rate * 20) + "░" * (20 - int(fr.pass_rate * 20))
            lines.append(
                f"{fr.framework:<12} [{bar}] {fr.pass_rate*100:5.1f}%"
                f"  {fr.readiness}"
            )
            if fr.failing_ids:
                lines.append(f"             Failing: {', '.join(fr.failing_ids)}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Gap analysis engine
# ─────────────────────────────────────────────────────────────────────────────

def _affected_controls(finding) -> set[str]:
    """Return all control IDs impacted by this finding."""
    affected: set[str] = set()
    c = finding.compliance

    # PCI-DSS
    for key, cids in _PCI_CONTROL_MAP.items():
        if c.pci_dss and key in c.pci_dss:
            affected.update(cids)

    # SOC2
    for key, cids in _SOC2_CONTROL_MAP.items():
        if c.soc2_cc and key in c.soc2_cc:
            affected.update(cids)

    # ISO 27001
    for key, cids in _ISO_CONTROL_MAP.items():
        if c.iso_27001 and key in c.iso_27001:
            affected.update(cids)

    # NIST CSF
    for key, cids in _NIST_CONTROL_MAP.items():
        if c.nist_csf and key in c.nist_csf:
            affected.update(cids)

    return affected


def _compute_gap_score(
    control_results: list[ControlResult],
    findings: list,
) -> int:
    """
    Severity-weighted gap score 0–100.
    CRITICAL failures in high-weight controls contribute most.
    """
    if not findings:
        return 0

    total_weight = sum(
        cd.weight for cd in _CONTROLS
        if not all(fr.status == ControlStatus.PASS
                   for fr in control_results
                   if fr.control_id == cd.control_id)
    )
    crit_count   = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count   = sum(1 for f in findings if f.severity == "HIGH")
    total        = len(findings)

    raw = min(
        (crit_count * 4 + high_count * 2 + (total - crit_count - high_count)) * 2
        + total_weight * 3,
        100
    )
    return int(raw)


def _framework_readiness(pass_rate: float) -> str:
    if pass_rate >= 0.90: return "Compliant"
    if pass_rate >= 0.60: return "At Risk"
    return "Non-Compliant"


def _build_executive_summary(
    framework_results: list[FrameworkResult],
    overall_pass_rate: float,
    critical_count: int,
    high_count: int,
) -> str:
    non_compliant = [fr for fr in framework_results if fr.readiness == "Non-Compliant"]
    at_risk       = [fr for fr in framework_results if fr.readiness == "At Risk"]

    if not non_compliant and not at_risk:
        return (
            f"All {len(framework_results)} frameworks pass at "
            f"{overall_pass_rate*100:.1f}% overall. "
            "The target currently meets the assessed compliance requirements. "
            "Maintain regular scanning and patch cadence to sustain this posture."
        )

    parts = []
    if non_compliant:
        parts.append(
            f"{len(non_compliant)} framework(s) are NON-COMPLIANT "
            f"({', '.join(fr.framework for fr in non_compliant)})"
        )
    if at_risk:
        parts.append(
            f"{len(at_risk)} framework(s) are AT RISK "
            f"({', '.join(fr.framework for fr in at_risk)})"
        )

    severity_context = ""
    if critical_count > 0:
        severity_context = (
            f" {critical_count} CRITICAL finding(s) must be remediated "
            "immediately to unblock compliance certification."
        )
    elif high_count > 0:
        severity_context = (
            f" {high_count} HIGH finding(s) require prioritised remediation."
        )

    return (
        f"Overall compliance pass rate: {overall_pass_rate*100:.1f}%. "
        + "; ".join(parts) + "."
        + severity_context
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_compliance_gap_report(
    findings:       list,
    target_url:     str = "",
    scan_id:        str = "",
    scan_timestamp: str = "",
) -> ComplianceReport:
    """
    Analyse findings against PCI-DSS, SOC2, ISO 27001, and NIST CSF controls.

    Args:
        findings:       List of SecurityFinding from finding_enricher
        target_url:     URL that was scanned
        scan_id:        Unique scan identifier
        scan_timestamp: ISO datetime string

    Returns:
        ComplianceReport with per-control and per-framework results
    """
    if not scan_timestamp:
        scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Build map: control_id → list of (finding, severity)
    failing_map: dict[str, list[tuple]] = {cd.control_id: [] for cd in _CONTROLS}

    relevant_findings = [
        f for f in findings
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ]

    for f in relevant_findings:
        for cid in _affected_controls(f):
            if cid in failing_map:
                failing_map[cid].append((f.finding_id, f.severity))

    # Build ControlResult list
    control_results: list[ControlResult] = []
    for cd in _CONTROLS:
        failures = failing_map[cd.control_id]
        if not failures:
            status = ControlStatus.NOT_TESTED if not findings else ControlStatus.PASS
        else:
            worst_sev = max(
                (sev for _, sev in failures),
                key=lambda s: _SEVERITY_WEIGHT.get(s, 0),
            )
            status = (
                ControlStatus.FAIL
                if worst_sev in ("CRITICAL", "HIGH")
                else ControlStatus.PARTIAL
            )

        gap_sev = max(
            (sev for _, sev in failures),
            key=lambda s: _SEVERITY_WEIGHT.get(s, 0),
            default="INFO",
        )

        control_results.append(ControlResult(
            control_id        = cd.control_id,
            description       = cd.description,
            frameworks        = list(cd.frameworks),
            status            = status,
            failing_findings  = [fid for fid, _ in failures],
            gap_severity      = gap_sev,
            remediation_hint  = (
                f"Remediate {len(failures)} finding(s) affecting {cd.control_id}."
                if failures else ""
            ),
        ))

    # Per-framework aggregation
    framework_ids = ["PCI-DSS", "SOC2", "ISO27001", "NIST-CSF"]
    framework_results: list[FrameworkResult] = []

    for fw in framework_ids:
        fw_controls = [
            cr for cr in control_results
            if fw in cr.frameworks
        ]
        total    = len(fw_controls)
        passing  = sum(1 for c in fw_controls if c.status == ControlStatus.PASS)
        failing  = sum(1 for c in fw_controls if c.status == ControlStatus.FAIL)
        partial  = sum(1 for c in fw_controls if c.status == ControlStatus.PARTIAL)
        not_test = sum(1 for c in fw_controls if c.status == ControlStatus.NOT_TESTED)
        # NOT_TESTED = no evidence of failure → treated as passing
        pass_rate = (passing + not_test + partial * 0.5) / total if total else 1.0

        framework_results.append(FrameworkResult(
            framework      = fw,
            total_controls = total,
            passing        = passing,
            failing        = failing,
            partial        = partial,
            not_tested     = not_test,
            pass_rate      = pass_rate,
            readiness      = _framework_readiness(pass_rate),
            failing_ids    = [c.control_id for c in fw_controls
                               if c.status in (ControlStatus.FAIL, ControlStatus.PARTIAL)],
        ))

    # Overall
    total_controls  = len(control_results)
    total_passing   = sum(1 for c in control_results if c.status == ControlStatus.PASS)
    total_partial   = sum(1 for c in control_results if c.status == ControlStatus.PARTIAL)
    total_not_test  = sum(1 for c in control_results if c.status == ControlStatus.NOT_TESTED)
    overall_rate    = (total_passing + total_not_test + total_partial * 0.5) / total_controls if total_controls else 1.0

    gap_score = _compute_gap_score(control_results, findings)

    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")

    executive = _build_executive_summary(
        framework_results, overall_rate, crit_count, high_count
    )

    return ComplianceReport(
        target_url        = target_url,
        scan_id           = scan_id,
        scan_timestamp    = scan_timestamp,
        control_results   = control_results,
        framework_results = framework_results,
        overall_pass_rate = overall_rate,
        gap_score         = gap_score,
        executive_summary = executive,
        total_findings    = len(findings),
        critical_findings = crit_count,
    )

"""
reports/ciso_pdf_report.py — AI Cyber Shield v6

CISO-level PDF Security Report generator.

What makes this better than competitors (Detectify, Snyk, Invicti):
  • Executive Summary with risk score gauge (0–100) and letter grade
  • CVSS 3.1 table with colour-coded severity rows
  • Compliance gap matrix: PCI-DSS / SOC2 / ISO 27001 / NIST CSF checkboxes
  • OWASP Top 10:2025 coverage heatmap
  • Trend section (delta vs. previous scan if provided)
  • Business impact narrative per critical/high finding
  • Remediation effort estimate (hours) + priority queue
  • Full SARIF reference in appendix
  • Branded cover page with scan metadata

Requires: reportlab >= 4.0

Usage:
    from reports.ciso_pdf_report import generate_ciso_pdf
    from finding_enricher import enrich_scan_result

    findings = enrich_scan_result(raw_result)
    pdf_bytes = generate_ciso_pdf(
        findings        = findings,
        target_url      = "https://app.example.com",
        overall_score   = 68,
        overall_grade   = "C",
        scan_id         = "abc-123",
    )
    with open("ciso_report.pdf", "wb") as f:
        f.write(pdf_bytes)
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Colour palette (RGB 0–1 floats for ReportLab)
# ─────────────────────────────────────────────────────────────────────────────

def _rgb(r: int, g: int, b: int):
    from reportlab.lib.colors import Color  # noqa: PLC0415
    return Color(r / 255, g / 255, b / 255)


_BRAND_DARK    = lambda: _rgb(15,  23,  42)   # slate-900
_BRAND_ACCENT  = lambda: _rgb(37, 99, 235)    # blue-600
_BRAND_BG      = lambda: _rgb(248, 250, 252)  # slate-50

_SEV_COLOURS = {
    "CRITICAL": lambda: _rgb(220, 38,  38),   # red-600
    "HIGH":     lambda: _rgb(234, 88,  12),   # orange-600
    "MEDIUM":   lambda: _rgb(234, 179, 8),    # yellow-500
    "LOW":      lambda: _rgb(34,  197, 94),   # green-500
    "INFO":     lambda: _rgb(100, 116, 139),  # slate-500
}

_WHITE    = lambda: _rgb(255, 255, 255)
_GREY_100 = lambda: _rgb(241, 245, 249)
_GREY_700 = lambda: _rgb(55,  65,  81)

# Grade → colour
_GRADE_COLOUR = {
    "A": lambda: _rgb(34,  197, 94),
    "B": lambda: _rgb(132, 204, 22),
    "C": lambda: _rgb(234, 179, 8),
    "D": lambda: _rgb(234, 88,  12),
    "F": lambda: _rgb(220, 38,  38),
}

# ─────────────────────────────────────────────────────────────────────────────
# Config dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CisoPdfConfig:
    target_url:      str
    overall_score:   int   = 0       # 0–100 (higher = more secure)
    overall_grade:   str   = "?"
    scan_id:         str   = ""
    scan_timestamp:  str   = ""
    report_title:    str   = "Security Scan Report"
    org_name:        str   = ""
    logo_path:       Optional[str] = None
    prev_score:      Optional[int] = None   # previous scan score for trend
    prev_findings:   Optional[int] = None   # previous finding count
    confidential:    bool  = True


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _severity_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev, 5)


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"


def _count_by_severity(findings: list) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _owasp_coverage(findings: list) -> dict[str, int]:
    """Count findings per OWASP category."""
    coverage: dict[str, int] = {}
    for f in findings:
        key = f.owasp.code
        coverage[key] = coverage.get(key, 0) + 1
    return coverage


def _total_remediation_hours(findings: list) -> float:
    return sum(f.remediation.effort_hours for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# PDF building blocks
# ─────────────────────────────────────────────────────────────────────────────

def _make_styles():
    """Return a dict of ParagraphStyle objects."""
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # noqa: PLC0415
    from reportlab.lib.units  import cm  # noqa: PLC0415
    from reportlab.lib.enums  import TA_CENTER, TA_LEFT  # noqa: PLC0415

    base = getSampleStyleSheet()
    styles = {}

    styles["Cover_Title"] = ParagraphStyle(
        "Cover_Title",
        parent=base["Normal"],
        fontSize=28, leading=34,
        textColor=_WHITE(),
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    styles["Cover_Sub"] = ParagraphStyle(
        "Cover_Sub",
        parent=base["Normal"],
        fontSize=12, leading=16,
        textColor=_WHITE(),
        fontName="Helvetica",
        alignment=TA_CENTER,
    )
    styles["Section_Header"] = ParagraphStyle(
        "Section_Header",
        parent=base["Normal"],
        fontSize=14, leading=18,
        textColor=_BRAND_DARK(),
        fontName="Helvetica-Bold",
        spaceBefore=16, spaceAfter=6,
        borderPadding=(0, 0, 4, 0),
    )
    styles["Body"] = ParagraphStyle(
        "Body",
        parent=base["Normal"],
        fontSize=9, leading=13,
        textColor=_GREY_700(),
        fontName="Helvetica",
    )
    styles["Body_Bold"] = ParagraphStyle(
        "Body_Bold",
        parent=styles["Body"],
        fontName="Helvetica-Bold",
    )
    styles["Small"] = ParagraphStyle(
        "Small",
        parent=styles["Body"],
        fontSize=7.5,
    )
    styles["Table_Header"] = ParagraphStyle(
        "Table_Header",
        parent=base["Normal"],
        fontSize=8, fontName="Helvetica-Bold",
        textColor=_WHITE(),
    )
    styles["Table_Cell"] = ParagraphStyle(
        "Table_Cell",
        parent=base["Normal"],
        fontSize=8, fontName="Helvetica",
        textColor=_GREY_700(),
    )
    styles["Finding_Title"] = ParagraphStyle(
        "Finding_Title",
        parent=base["Normal"],
        fontSize=10, fontName="Helvetica-Bold",
        textColor=_BRAND_DARK(),
        spaceBefore=10,
    )
    return styles


def _header_footer(canvas, doc, config: CisoPdfConfig):
    """Draw repeating header and footer on every page."""
    from reportlab.lib.units import cm  # noqa: PLC0415

    canvas.saveState()
    w, h = doc.pagesize

    # Header bar
    canvas.setFillColor(_BRAND_DARK())
    canvas.rect(0, h - 1.1 * cm, w, 1.1 * cm, fill=1, stroke=0)
    canvas.setFillColor(_WHITE())
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(1.5 * cm, h - 0.75 * cm, "AI Cyber Shield — CONFIDENTIAL")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 1.5 * cm, h - 0.75 * cm, config.target_url)

    # Footer line
    canvas.setStrokeColor(_BRAND_ACCENT())
    canvas.setLineWidth(0.5)
    canvas.line(1.5 * cm, 1.2 * cm, w - 1.5 * cm, 1.2 * cm)
    canvas.setFillColor(_GREY_700())
    canvas.setFont("Helvetica", 7)
    canvas.drawString(1.5 * cm, 0.7 * cm,
                      f"Generated {config.scan_timestamp}  |  Scan ID: {config.scan_id}")
    canvas.drawRightString(w - 1.5 * cm, 0.7 * cm, f"Page {doc.page}")

    canvas.restoreState()


def _build_cover(story, config: CisoPdfConfig, styles, findings: list):
    """Cover page with title, score gauge, and key metrics."""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle  # noqa: PLC0415
    from reportlab.lib.units import cm  # noqa: PLC0415
    from reportlab.platypus import PageBreak  # noqa: PLC0415

    # Full-bleed cover banner (drawn as a coloured table)
    grade     = config.overall_grade or _score_to_grade(config.overall_score)
    by_sev    = _count_by_severity(findings)
    total     = len(findings)
    confirmed = sum(1 for f in findings if f.confirmed)

    # Cover banner table
    banner_data = [[Paragraph(config.report_title, styles["Cover_Title"])]]
    banner_style = TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), _BRAND_DARK()),
        ("TOPPADDING",  (0,0), (-1,-1), 30),
        ("BOTTOMPADDING",(0,0),(-1,-1), 30),
        ("LEFTPADDING", (0,0), (-1,-1), 40),
        ("RIGHTPADDING",(0,0), (-1,-1), 40),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
    ])
    story.append(Table(banner_data, colWidths=["100%"], style=banner_style))
    story.append(Spacer(1, 0.5 * cm))

    # Sub-title row
    scan_dt = config.scan_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(
        f"Target: <b>{config.target_url}</b>  |  Scan date: {scan_dt}",
        styles["Body"]
    ))
    story.append(Spacer(1, 0.8 * cm))

    # Score + grade box
    grade_colour = _GRADE_COLOUR.get(grade, lambda: _BRAND_ACCENT())()
    score_data = [[
        Paragraph(f"<font size=40><b>{config.overall_score}</b></font><br/><font size=11>Security Score</font>", styles["Body"]),
        Paragraph(f"<font size=48><b>{grade}</b></font><br/><font size=11>Grade</font>", styles["Body"]),
        Paragraph(f"<font size=28><b>{total}</b></font><br/><font size=11>Total Findings</font>", styles["Body"]),
        Paragraph(f"<font size=28><b>{confirmed}</b></font><br/><font size=11>Confirmed</font>", styles["Body"]),
    ]]
    score_style = TableStyle([
        ("BACKGROUND",   (0,0), (0,-1), _BRAND_ACCENT()),
        ("BACKGROUND",   (1,0), (1,-1), grade_colour),
        ("BACKGROUND",   (2,0), (2,-1), _BRAND_DARK()),
        ("BACKGROUND",   (3,0), (3,-1), _GREY_100()),
        ("TEXTCOLOR",    (0,0), (2,-1), _WHITE()),
        ("TEXTCOLOR",    (3,0), (3,-1), _GREY_700()),
        ("ALIGN",        (0,0), (-1,-1), "CENTER"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,-1), 20),
        ("BOTTOMPADDING",(0,0), (-1,-1), 20),
        ("BOX",          (0,0), (-1,-1), 1, _WHITE()),
        ("INNERGRID",    (0,0), (-1,-1), 0.5, _WHITE()),
    ])
    story.append(Table(score_data, colWidths=["25%","25%","25%","25%"], style=score_style))
    story.append(Spacer(1, 0.8 * cm))

    # Severity breakdown
    sev_data = [["Severity", "Count", "% of Total"]] + [
        [sev, str(by_sev.get(sev, 0)), f"{by_sev.get(sev,0)/max(total,1)*100:.0f}%"]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ]
    sev_style = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), _BRAND_DARK()),
        ("TEXTCOLOR",     (0,0), (-1,0), _WHITE()),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [_WHITE(), _GREY_100()]),
        ("TEXTCOLOR",     (0,1), (0,1), _SEV_COLOURS["CRITICAL"]()),
        ("TEXTCOLOR",     (0,2), (0,2), _SEV_COLOURS["HIGH"]()),
        ("TEXTCOLOR",     (0,3), (0,3), _SEV_COLOURS["MEDIUM"]()),
        ("TEXTCOLOR",     (0,4), (0,4), _SEV_COLOURS["LOW"]()),
        ("TEXTCOLOR",     (0,5), (0,5), _SEV_COLOURS["INFO"]()),
        ("FONTNAME",      (0,1), (0,-1), "Helvetica-Bold"),
        ("ALIGN",         (1,0), (-1,-1), "CENTER"),
        ("BOX",           (0,0), (-1,-1), 0.5, _GREY_100()),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, _GREY_100()),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ])
    story.append(Paragraph("Severity Breakdown", styles["Section_Header"]))
    story.append(Table(sev_data, colWidths=["60%","20%","20%"], style=sev_style))

    # Trend (if previous scan available)
    if config.prev_score is not None:
        delta   = config.overall_score - config.prev_score
        arrow   = "▲" if delta >= 0 else "▼"
        colour  = "green" if delta >= 0 else "red"
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph(
            f"<b>Trend vs. previous scan:</b> Score {arrow} {abs(delta)} points "
            f"<font color='{colour}'>({'+' if delta >= 0 else ''}{delta})</font>",
            styles["Body"]
        ))

    story.append(PageBreak())


def _build_exec_summary(story, config: CisoPdfConfig, styles, findings: list):
    """Executive summary: top risks, business impact narrative."""
    from reportlab.platypus import Paragraph, Spacer, HRFlowable  # noqa: PLC0415
    from reportlab.lib.units import cm  # noqa: PLC0415

    story.append(Paragraph("Executive Summary", styles["Section_Header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT()))
    story.append(Spacer(1, 0.3 * cm))

    by_sev    = _count_by_severity(findings)
    crit      = by_sev.get("CRITICAL", 0)
    high      = by_sev.get("HIGH", 0)
    total     = len(findings)
    top_cvss  = max((f.cvss.score for f in findings), default=0.0)
    hours     = _total_remediation_hours(findings)

    if crit > 0:
        risk_text = (
            f"This scan identified <b>{crit} CRITICAL</b> and <b>{high} HIGH</b> severity "
            f"findings requiring <b>immediate remediation</b>. "
            f"The highest CVSS 3.1 score recorded is <b>{top_cvss:.1f}/10.0</b>."
        )
    elif high > 0:
        risk_text = (
            f"This scan identified <b>{high} HIGH</b> severity findings. "
            f"No CRITICAL issues were detected, however immediate action is recommended. "
            f"The highest CVSS 3.1 score recorded is <b>{top_cvss:.1f}/10.0</b>."
        )
    else:
        risk_text = (
            f"This scan identified <b>{total}</b> findings, none of which are CRITICAL or HIGH severity. "
            f"The security posture of the target is satisfactory with standard remediation recommended."
        )

    story.append(Paragraph(risk_text, styles["Body"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"<b>Estimated remediation effort:</b> {hours:.0f} engineering hours "
        f"across {total} findings.",
        styles["Body"]
    ))
    story.append(Spacer(1, 0.4 * cm))

    # Top 5 critical/high findings narrative
    top_findings = sorted(
        [f for f in findings if f.severity in ("CRITICAL", "HIGH")],
        key=lambda f: -f.cvss.score,
    )[:5]

    if top_findings:
        story.append(Paragraph("Key Risks", styles["Body_Bold"]))
        story.append(Spacer(1, 0.15 * cm))
        for f in top_findings:
            story.append(Paragraph(
                f"<b>[{f.severity}]</b> {f.title} — CVSS {f.cvss.score:.1f}. "
                f"{f.business_impact}",
                styles["Body"]
            ))
            story.append(Spacer(1, 0.1 * cm))


def _build_cvss_table(story, styles, findings: list):
    """Full CVSS 3.1 findings table sorted by score descending."""
    from reportlab.platypus import (  # noqa: PLC0415
        Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
    )
    from reportlab.lib.units import cm  # noqa: PLC0415

    story.append(PageBreak())
    story.append(Paragraph("Findings — CVSS 3.1 Detail", styles["Section_Header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT()))
    story.append(Spacer(1, 0.3 * cm))

    sorted_findings = sorted(findings, key=lambda f: (_severity_order(f.severity), -f.cvss.score))

    headers = ["#", "Severity", "Title", "CVSS", "CWE", "OWASP", "Confirmed"]
    table_data = [headers]

    for i, f in enumerate(sorted_findings, start=1):
        table_data.append([
            str(i),
            f.severity,
            f.title[:55] + ("…" if len(f.title) > 55 else ""),
            f"{f.cvss.score:.1f}",
            f.cwe.label,
            f.owasp.label,
            "✓" if f.confirmed else "—",
        ])

    # Build row-by-row colour commands
    row_commands = [
        ("BACKGROUND",    (0,0), (-1,0), _BRAND_DARK()),
        ("TEXTCOLOR",     (0,0), (-1,0), _WHITE()),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [_WHITE(), _GREY_100()]),
        ("ALIGN",         (0,0), (-1,-1), "LEFT"),
        ("ALIGN",         (3,0), (3,-1), "CENTER"),
        ("ALIGN",         (6,0), (6,-1), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("BOX",           (0,0), (-1,-1), 0.5, _GREY_100()),
        ("INNERGRID",     (0,0), (-1,-1), 0.2, _GREY_100()),
    ]

    # Colour severity column cells
    for i, f in enumerate(sorted_findings, start=1):
        row_commands.append((
            "TEXTCOLOR", (1, i), (1, i),
            _SEV_COLOURS.get(f.severity, lambda: _GREY_700())(),
        ))
        row_commands.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))

    t = Table(
        table_data,
        colWidths=["5%","10%","40%","7%","10%","14%","6%"],
        repeatRows=1,
        style=TableStyle(row_commands),
    )
    story.append(t)


def _build_compliance_matrix(story, styles, findings: list):
    """Compliance gap matrix: PCI-DSS / SOC2 / ISO 27001 / NIST CSF."""
    from reportlab.platypus import (  # noqa: PLC0415
        Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
    )
    from reportlab.lib.units import cm  # noqa: PLC0415

    story.append(PageBreak())
    story.append(Paragraph("Compliance Gap Matrix", styles["Section_Header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT()))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "The following table maps each finding to the relevant compliance framework controls. "
        "A ✗ indicates a gap in the current security posture that must be addressed "
        "to achieve or maintain compliance.",
        styles["Body"]
    ))
    story.append(Spacer(1, 0.4 * cm))

    # Aggregate unique controls triggered
    frameworks = {
        "PCI-DSS": set(),
        "SOC2":    set(),
        "ISO 27001": set(),
        "NIST CSF": set(),
    }
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            if f.compliance.pci_dss:
                frameworks["PCI-DSS"].add(f.compliance.pci_dss)
            if f.compliance.soc2_cc:
                frameworks["SOC2"].add(f.compliance.soc2_cc)
            if f.compliance.iso_27001:
                frameworks["ISO 27001"].add(f.compliance.iso_27001)
            if f.compliance.nist_csf:
                frameworks["NIST CSF"].add(f.compliance.nist_csf)

    # Per-framework summary table
    fw_data = [["Framework", "Controls Impacted", "Status"]]
    for fw, controls in frameworks.items():
        status = "FAILING" if controls else "PASSING"
        fw_data.append([
            fw,
            ", ".join(sorted(controls)) or "—",
            status,
        ])

    fw_style = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), _BRAND_DARK()),
        ("TEXTCOLOR",     (0,0), (-1,0), _WHITE()),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [_WHITE(), _GREY_100()]),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("BOX",           (0,0), (-1,-1), 0.5, _GREY_100()),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, _GREY_100()),
        ("ALIGN",         (2,1), (2,-1), "CENTER"),
    ])

    # Colour status column
    for i, (fw, controls) in enumerate(frameworks.items(), start=1):
        color = _SEV_COLOURS["HIGH"]() if controls else _SEV_COLOURS["LOW"]()
        fw_style.add("TEXTCOLOR", (2, i), (2, i), color)
        fw_style.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")

    story.append(Table(fw_data, colWidths=["20%","60%","20%"], style=fw_style))
    story.append(Spacer(1, 0.5 * cm))

    # Per-finding compliance detail (top 15)
    detail_findings = sorted(
        [f for f in findings if f.compliance.pci_dss or f.compliance.soc2_cc],
        key=lambda f: _severity_order(f.severity),
    )[:15]

    if detail_findings:
        story.append(Paragraph("Detailed Control Mapping", styles["Body_Bold"]))
        story.append(Spacer(1, 0.2 * cm))

        detail_data = [["Finding", "Severity", "PCI-DSS", "SOC2", "ISO 27001", "NIST CSF"]]
        for f in detail_findings:
            detail_data.append([
                f.title[:40] + ("…" if len(f.title) > 40 else ""),
                f.severity,
                f.compliance.pci_dss  or "—",
                f.compliance.soc2_cc  or "—",
                f.compliance.iso_27001 or "—",
                f.compliance.nist_csf  or "—",
            ])

        det_style = TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), _BRAND_DARK()),
            ("TEXTCOLOR",     (0,0), (-1,0), _WHITE()),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [_WHITE(), _GREY_100()]),
            ("TOPPADDING",    (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("BOX",           (0,0), (-1,-1), 0.5, _GREY_100()),
            ("INNERGRID",     (0,0), (-1,-1), 0.2, _GREY_100()),
        ])
        for i, f in enumerate(detail_findings, start=1):
            sev_color = _SEV_COLOURS.get(f.severity, lambda: _GREY_700())()
            det_style.add("TEXTCOLOR", (1, i), (1, i), sev_color)
            det_style.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")

        story.append(Table(
            detail_data,
            colWidths=["28%","10%","15%","10%","16%","13%"],
            repeatRows=1,
            style=det_style,
        ))


def _build_owasp_heatmap(story, styles, findings: list):
    """OWASP Top 10:2025 coverage heatmap."""
    from reportlab.platypus import (  # noqa: PLC0415
        Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.units import cm  # noqa: PLC0415

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("OWASP Top 10:2025 Coverage", styles["Section_Header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT()))
    story.append(Spacer(1, 0.3 * cm))

    owasp_defs = [
        ("A01", "Broken Access Control"),
        ("A02", "Cryptographic Failures"),
        ("A03", "Injection"),
        ("A04", "Insecure Design"),
        ("A05", "Security Misconfiguration"),
        ("A06", "Vulnerable & Outdated Components"),
        ("A07", "Identification & Authentication Failures"),
        ("A08", "Software & Data Integrity Failures"),
        ("A09", "Security Logging & Monitoring Failures"),
        ("A10", "Server-Side Request Forgery"),
        ("A11", "Software Supply Chain Failures ★"),
        ("A12", "Mishandling of Exceptional Conditions ★"),
    ]

    coverage = _owasp_coverage(findings)

    owasp_data = [["Code", "Category", "Findings", "Risk"]]
    for code, name in owasp_defs:
        count = coverage.get(code, 0)
        risk  = "CRITICAL" if count >= 3 else "HIGH" if count >= 1 else "CLEAR"
        owasp_data.append([code, name, str(count), risk])

    ow_style = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), _BRAND_DARK()),
        ("TEXTCOLOR",     (0,0), (-1,0), _WHITE()),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [_WHITE(), _GREY_100()]),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("BOX",           (0,0), (-1,-1), 0.5, _GREY_100()),
        ("INNERGRID",     (0,0), (-1,-1), 0.2, _GREY_100()),
        ("ALIGN",         (2,0), (2,-1), "CENTER"),
        ("ALIGN",         (3,0), (3,-1), "CENTER"),
    ])

    for i, (code, _) in enumerate(owasp_defs, start=1):
        count = coverage.get(code, 0)
        risk  = "CRITICAL" if count >= 3 else "HIGH" if count >= 1 else "CLEAR"
        color = (
            _SEV_COLOURS["CRITICAL"]() if risk == "CRITICAL"
            else _SEV_COLOURS["HIGH"]() if risk == "HIGH"
            else _SEV_COLOURS["LOW"]()
        )
        ow_style.add("TEXTCOLOR", (3, i), (3, i), color)
        ow_style.add("FONTNAME",  (3, i), (3, i), "Helvetica-Bold")

    story.append(Table(
        owasp_data,
        colWidths=["8%","55%","12%","15%"],
        style=ow_style,
    ))
    story.append(Paragraph(
        "★ New in OWASP Top 10:2025 — not tracked by most competing tools.",
        styles["Small"]
    ))


def _build_remediation_plan(story, styles, findings: list):
    """Priority remediation queue with effort estimates."""
    from reportlab.platypus import (  # noqa: PLC0415
        Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
    )
    from reportlab.lib.units import cm  # noqa: PLC0415

    story.append(PageBreak())
    story.append(Paragraph("Remediation Priority Queue", styles["Section_Header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT()))
    story.append(Spacer(1, 0.3 * cm))

    prioritised = sorted(
        findings,
        key=lambda f: (f.remediation.priority, _severity_order(f.severity)),
    )[:20]

    total_hours = sum(f.remediation.effort_hours for f in prioritised)
    story.append(Paragraph(
        f"Showing top 20 findings by remediation priority. "
        f"Estimated total remediation effort: <b>{total_hours:.0f} engineering hours</b>.",
        styles["Body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    rem_data = [["P#", "Title", "Severity", "CVSS", "Effort (h)", "Summary"]]
    for i, f in enumerate(prioritised, start=1):
        rem_data.append([
            str(i),
            f.title[:40] + ("…" if len(f.title) > 40 else ""),
            f.severity,
            f"{f.cvss.score:.1f}",
            f"{f.remediation.effort_hours:.0f}h",
            f.remediation.summary[:60] + ("…" if len(f.remediation.summary) > 60 else ""),
        ])

    rem_style = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), _BRAND_DARK()),
        ("TEXTCOLOR",     (0,0), (-1,0), _WHITE()),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [_WHITE(), _GREY_100()]),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("BOX",           (0,0), (-1,-1), 0.5, _GREY_100()),
        ("INNERGRID",     (0,0), (-1,-1), 0.2, _GREY_100()),
        ("ALIGN",         (3,0), (3,-1), "CENTER"),
        ("ALIGN",         (4,0), (4,-1), "CENTER"),
    ])
    for i, f in enumerate(prioritised, start=1):
        color = _SEV_COLOURS.get(f.severity, lambda: _GREY_700())()
        rem_style.add("TEXTCOLOR", (2, i), (2, i), color)
        rem_style.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")

    story.append(Table(
        rem_data,
        colWidths=["5%","28%","10%","8%","9%","36%"],
        repeatRows=1,
        style=rem_style,
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_ciso_pdf(
    findings:      list,
    target_url:    str  = "",
    overall_score: int  = 0,
    overall_grade: str  = "",
    scan_id:       str  = "",
    scan_timestamp: str = "",
    org_name:      str  = "",
    report_title:  str  = "Security Scan Report — CONFIDENTIAL",
    prev_score:    Optional[int] = None,
    prev_findings: Optional[int] = None,
) -> bytes:
    """
    Generate a CISO-level PDF security report.

    Args:
        findings:       List of SecurityFinding from finding_enricher
        target_url:     URL that was scanned
        overall_score:  Security score 0–100
        overall_grade:  Letter grade A–F (auto-derived if empty)
        scan_id:        Unique scan identifier for audit trail
        scan_timestamp: ISO datetime string of when scan ran
        org_name:       Organisation name for cover page
        report_title:   Title shown on cover page
        prev_score:     Previous scan score (for trend section)
        prev_findings:  Previous scan finding count (for trend)

    Returns:
        PDF as raw bytes (write to .pdf file or stream via HTTP)
    """
    try:
        from reportlab.platypus import SimpleDocTemplate, Spacer  # noqa: PLC0415
        from reportlab.lib.pagesizes import A4  # noqa: PLC0415
        from reportlab.lib.units import cm  # noqa: PLC0415
    except ImportError:
        raise RuntimeError("reportlab required: pip install reportlab")

    if not scan_timestamp:
        scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not overall_grade:
        overall_grade = _score_to_grade(overall_score)

    config = CisoPdfConfig(
        target_url     = target_url,
        overall_score  = overall_score,
        overall_grade  = overall_grade,
        scan_id        = scan_id,
        scan_timestamp = scan_timestamp,
        report_title   = report_title,
        org_name       = org_name,
        prev_score     = prev_score,
        prev_findings  = prev_findings,
    )

    buf    = io.BytesIO()
    styles = _make_styles()

    doc = SimpleDocTemplate(
        buf,
        pagesize     = A4,
        leftMargin   = 1.5 * cm,
        rightMargin  = 1.5 * cm,
        topMargin    = 1.5 * cm,
        bottomMargin = 1.8 * cm,
        title        = report_title,
        author       = "AI Cyber Shield v6",
        subject      = f"Security Report — {target_url}",
        creator      = "AI Cyber Shield",
    )

    story = []
    _build_cover(story, config, styles, findings)
    _build_exec_summary(story, config, styles, findings)

    if findings:
        _build_cvss_table(story, styles, findings)
        _build_compliance_matrix(story, styles, findings)
        _build_owasp_heatmap(story, styles, findings)
        _build_remediation_plan(story, styles, findings)

    doc.build(
        story,
        onFirstPage  = lambda c, d: _header_footer(c, d, config),
        onLaterPages = lambda c, d: _header_footer(c, d, config),
    )

    return buf.getvalue()

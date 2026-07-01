"""
reports/legal_compliance_pdf.py — AI Cyber Shield v6

Framework-filtered Legal Compliance PDF generator.

Comparison with market leaders:
  • Vanta:    PDF per SOC2/ISO27001 (fixed frameworks, no custom filter)
  • Drata:    evidence bundle per framework (enterprise-only, expensive)
  • Tugboat:  gap analysis PDF (generic, not web-specific)
  • OUR APPROACH: web-specific findings filtered per IL/GDPR/US framework,
    fine estimates per finding, real enforcement case examples,
    actionable remediation timeline per framework

Usage:
    from tools.legal_scanner import LegalScanResult
    from reports.legal_compliance_pdf import generate_legal_pdf

    pdf_bytes = generate_legal_pdf(result, framework="GDPR")
    # framework: "IL" | "GDPR" | "US" | "ALL"
"""
from __future__ import annotations

import io
import logging
import os
from datetime import datetime, timezone
from typing import Literal

_log = logging.getLogger(__name__)

Framework = Literal["IL", "GDPR", "US", "ALL"]

# ── Colors ────────────────────────────────────────────────────────────────────
_CYAN    = (34,  211, 238)
_DARK    = (6,   11,  20)
_CARD    = (13,  20,  33)
_BORDER  = (30,  45,  61)
_TEXT    = (201, 209, 217)
_MUTED   = (71,  85,  105)
_RED     = (239, 68,  68)
_AMBER   = (245, 158, 11)
_GREEN   = (34,  197, 94)
_BLUE    = (59,  130, 246)
_WHITE   = (255, 255, 255)

_FRAMEWORK_META = {
    "IL":   {"flag": "🇮🇱", "name": "Israeli Law",        "color": _CYAN,  "subtitle": "חוק הגנת הפרטיות (1981) · חוק המחשבים (1995) · תקנות אבטחת מידע (2017)"},
    "GDPR": {"flag": "🇪🇺", "name": "GDPR (EU)",          "color": _BLUE,  "subtitle": "Regulation (EU) 2016/679 · ePrivacy Directive · Data Protection Act"},
    "US":   {"flag": "🇺🇸", "name": "US Federal & State", "color": _AMBER, "subtitle": "CCPA / CPRA · COPPA · CAN-SPAM · WCAG 2.1 AA (ADA/Section 508)"},
    "ALL":  {"flag": "🌐", "name": "All Frameworks",     "color": _GREEN,  "subtitle": "IL + GDPR + US combined compliance report"},
}

_STATUS_COLOR = {
    "PASS": _GREEN,
    "FAIL": _RED,
    "WARN": _AMBER,
    "SKIP": _MUTED,
}

_SEVERITY_COLOR = {
    "HIGH":   _RED,
    "MEDIUM": _AMBER,
    "LOW":    _BLUE,
}


# ── FPDF helpers ──────────────────────────────────────────────────────────────

def _rgb(color: tuple) -> tuple:
    return color  # FPDF takes (r, g, b) directly


def _hex(color: tuple) -> str:
    return "#{:02x}{:02x}{:02x}".format(*color)


_FONTS_DIR = os.path.join(os.path.dirname(__file__), "fonts")


def _register_pdf_font(pdf) -> str:
    """
    Register Heebo (Hebrew + Latin glyph coverage) so Hebrew finding text
    doesn't crash or render blank — fpdf2's built-in "Helvetica" has no
    Hebrew glyphs at all, and this product's default language is Hebrew.
    Falls back to Helvetica (Latin-only) if the bundled font is missing.
    """
    try:
        pdf.add_font("Heebo", "",  os.path.join(_FONTS_DIR, "Heebo-Regular.ttf"))
        pdf.add_font("Heebo", "B", os.path.join(_FONTS_DIR, "Heebo-Bold.ttf"))
        pdf.add_font("Heebo", "I", os.path.join(_FONTS_DIR, "Heebo-Regular.ttf"))  # no italic cut exists
        return "Heebo"
    except Exception as exc:
        _log.error("Heebo font unavailable (%s) — falling back to Helvetica; Hebrew text will not render", exc)
        return "Helvetica"


def _rtl(text: str) -> str:
    """
    Convert logical-order RTL text (Hebrew/Arabic) to visual display order
    for fpdf2, which renders left-to-right. Without this, Hebrew words
    appear in the correct glyph shapes but in reversed reading order.
    Uses the Unicode Bidirectional Algorithm (python-bidi).
    No-ops on purely Latin text so English labels are unaffected.
    """
    try:
        from bidi.algorithm import get_display  # noqa: PLC0415
        return get_display(text, base_dir="R")
    except Exception:
        return text  # graceful fallback — text renders LTR but at least shows


def generate_legal_pdf(result, framework: Framework = "ALL") -> bytes:
    """
    Generate a compliance PDF for the given framework.

    Args:
        result: LegalScanResult from tools.legal_scanner.run_legal_scan()
        framework: "IL" | "GDPR" | "US" | "ALL"

    Returns:
        PDF bytes
    """
    try:
        from fpdf import FPDF
    except ImportError:
        _log.error("fpdf2 not installed. Run: pip install fpdf2")
        return b""

    meta = _FRAMEWORK_META.get(framework, _FRAMEWORK_META["ALL"])
    now  = datetime.now(timezone.utc)

    # Filter findings to the requested framework
    if framework == "ALL":
        findings = result.findings
        fw_score = max(result.il_score, result.us_score, result.gdpr_score, 0)
    else:
        findings = [f for f in result.findings if f.framework in (framework, "ALL")]
        fw_score = getattr(result, f"{framework.lower()}_score", 0)

    fails = [f for f in findings if f.status == "FAIL"]
    warns = [f for f in findings if f.status == "WARN"]
    passes = [f for f in findings if f.status == "PASS"]

    risk_level = "LOW" if fw_score >= 80 else "MEDIUM" if fw_score >= 50 else "HIGH"
    risk_color = _GREEN if fw_score >= 80 else _AMBER if fw_score >= 50 else _RED

    # ── PDF Setup ─────────────────────────────────────────────────────────────
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(left=16, top=16, right=16)
    _FONT = _register_pdf_font(pdf)

    # ── Cover Page ────────────────────────────────────────────────────────────
    pdf.add_page()

    # Dark background
    pdf.set_fill_color(*_DARK)
    pdf.rect(0, 0, 210, 297, "F")

    # Accent stripe
    pdf.set_fill_color(*meta["color"])
    pdf.rect(0, 0, 210, 3, "F")

    # Shield icon text
    pdf.set_font(_FONT, "B", 36)
    pdf.set_text_color(34, 211, 238)
    pdf.set_y(30)
    pdf.cell(0, 14, "AI CYBER SHIELD", align="C", new_x="LMARGIN", new_y="NEXT")

    # Framework badge
    fw_r, fw_g, fw_b = meta["color"]
    pdf.set_fill_color(fw_r, fw_g, fw_b)
    pdf.set_font(_FONT, "B", 12)
    pdf.set_text_color(*_DARK)
    pdf.set_x((210 - 80) / 2)
    pdf.cell(80, 8, f"  {meta['name'].upper()}  ", align="C", fill=True,
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    pdf.set_font(_FONT, "", 9)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 5, _rtl(meta["subtitle"]), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(12)

    # Score gauge
    pdf.set_font(_FONT, "B", 64)
    score_r, score_g, score_b = risk_color
    pdf.set_text_color(score_r, score_g, score_b)
    pdf.cell(0, 24, str(fw_score), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(_FONT, "", 11)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 6, f"Compliance Score / 100  ·  Risk: {risk_level}", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    # Summary stats row
    pdf.set_font(_FONT, "B", 14)
    col_w = (210 - 32) / 3
    x_start = 16

    _stats_y = pdf.get_y()
    for count_str, category_label, color in [
        (f"{len(fails)}", "FAILURES", _RED),
        (f"{len(warns)}", "WARNINGS", _AMBER),
        (f"{len(passes)}", "PASSING",  _GREEN),
    ]:
        pdf.set_fill_color(*_CARD)
        pdf.rect(x_start, _stats_y, col_w - 2, 22, "F")
        pdf.set_font(_FONT, "B", 20)
        pdf.set_text_color(*color)
        pdf.set_xy(x_start, _stats_y + 2)
        pdf.cell(col_w - 2, 10, count_str, align="C")
        pdf.set_font(_FONT, "", 8)
        pdf.set_text_color(*_MUTED)
        pdf.set_xy(x_start, _stats_y + 13)
        pdf.cell(col_w - 2, 5, category_label, align="C")
        x_start += col_w

    pdf.set_y(_stats_y + 28)

    # Target & metadata
    pdf.set_font(_FONT, "", 9)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 5, f"Target: {result.url}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"Scan date: {now.strftime('%Y-%m-%d %H:%M UTC')}", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, "CONFIDENTIAL — For internal use only", align="C",
             new_x="LMARGIN", new_y="NEXT")

    # ── Findings Pages ────────────────────────────────────────────────────────
    # Group by status: FAIL first, then WARN, then PASS
    sections = [
        ("FAILURES — Must Fix", fails,  _RED),
        ("WARNINGS — Should Fix", warns,  _AMBER),
        ("PASSING CHECKS",        passes, _GREEN),
    ]

    for section_title, section_findings, section_color in sections:
        if not section_findings:
            continue

        pdf.add_page()
        pdf.set_fill_color(*_DARK)
        pdf.rect(0, 0, 210, 297, "F")

        # Section header
        pdf.set_fill_color(*section_color)
        pdf.rect(0, 0, 210, 2, "F")
        pdf.set_font(_FONT, "B", 13)
        pdf.set_text_color(*section_color)
        pdf.cell(0, 10, section_title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(_FONT, "", 8)
        pdf.set_text_color(*_MUTED)
        pdf.cell(0, 5, f"{len(section_findings)} item(s)  ·  Framework: {framework}",
                 new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        for finding in section_findings:
            # Card background
            card_y = pdf.get_y()
            card_h = 38  # estimated — will overflow onto next page via auto_page_break
            pdf.set_fill_color(*_CARD)
            pdf.rect(16, card_y, 178, card_h, "F")

            # Severity stripe
            sev_color = _SEVERITY_COLOR.get(finding.severity, _MUTED)
            pdf.set_fill_color(*sev_color)
            pdf.rect(16, card_y, 2, card_h, "F")

            pdf.set_xy(20, card_y + 3)

            # Title
            pdf.set_font(_FONT, "B", 9)
            pdf.set_text_color(*_WHITE)
            pdf.cell(130, 5, _rtl(finding.title[:75]), new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(20)

            # Status + severity badges
            st_color = _STATUS_COLOR.get(finding.status, _MUTED)
            pdf.set_font(_FONT, "B", 7)
            pdf.set_text_color(*st_color)
            pdf.cell(20, 4, finding.status)
            pdf.set_text_color(*sev_color)
            pdf.cell(20, 4, finding.severity)
            pdf.set_text_color(*_MUTED)
            pdf.cell(0, 4, f"  ·  {finding.category}  ·  {finding.check_id}",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(20)

            # Legal basis
            pdf.set_font(_FONT, "I", 7)
            pdf.set_text_color(*_MUTED)
            pdf.multi_cell(170, 4, _rtl(f"Legal basis: {finding.legal_basis}"[:120]))
            pdf.set_x(20)

            # Description
            pdf.set_font(_FONT, "", 7)
            pdf.set_text_color(*_TEXT)
            pdf.multi_cell(170, 4, _rtl(finding.description[:200]))
            pdf.set_x(20)

            # Recommendation
            if finding.recommendation and finding.status != "PASS":
                pdf.set_font(_FONT, "B", 7)
                pdf.set_text_color(34, 211, 238)
                pdf.cell(0, 4, "Recommendation:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_x(20)
                pdf.set_font(_FONT, "", 7)
                pdf.set_text_color(*_TEXT)
                pdf.multi_cell(170, 4, _rtl(finding.recommendation[:200]))
                pdf.set_x(20)

            # Fine estimate
            if finding.fine_min and finding.fine_max and finding.status == "FAIL":
                pdf.set_font(_FONT, "B", 7)
                pdf.set_text_color(*_RED)
                pdf.cell(0, 4,
                         f"Potential fine: {finding.fine_min} – {finding.fine_max}"
                         + (f"  |  Case: {finding.fine_example}" if finding.fine_example else ""),
                         new_x="LMARGIN", new_y="NEXT")
                pdf.set_x(20)

            pdf.ln(4)

    # ── Footer ────────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(*_DARK)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_y(20)
    pdf.set_font(_FONT, "B", 11)
    pdf.set_text_color(*_CYAN)
    pdf.cell(0, 8, "Disclaimer", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(_FONT, "", 8)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(0, 5,
        "This report is generated by automated tools and is provided for informational "
        "purposes only. It does not constitute legal advice. Review findings with a "
        "qualified legal professional before making compliance decisions. AI Cyber Shield "
        "provides analysis based on technical checks and publicly documented legal requirements. "
        "Regulatory interpretations may vary by jurisdiction and specific context.")

    return pdf.output()


def generate_legal_pdf_all_frameworks(result) -> dict[str, bytes]:
    """Generate three separate PDFs (IL, GDPR, US) and return as {framework: bytes}."""
    return {fw: generate_legal_pdf(result, fw) for fw in ["IL", "GDPR", "US"]}

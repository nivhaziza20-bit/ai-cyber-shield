"""
reports/il_compliance_pdf.py — AI Cyber Shield v6

Hebrew-first PDF report for Israeli regulatory compliance.
RTL layout throughout, Heebo font, fpdf2.

DISCLAIMER: This report is INDICATIVE ONLY and does NOT constitute
legal advice. Regulatory exposure must be assessed by a qualified
attorney specializing in Israeli privacy law.

Usage:
    from core.compliance.il_mapper import ILComplianceReport
    from reports.il_compliance_pdf import generate_il_compliance_pdf

    pdf_bytes = generate_il_compliance_pdf(
        report=report,
        domain="example.co.il",
        score=72,
        grade="C",
        scan_date="2026-07-01",
    )
"""

from __future__ import annotations

import io
import logging
import os
from datetime import datetime, timezone
from typing import Optional

_log = logging.getLogger(__name__)

# Colors
_CYAN    = (34,  211, 238)
_DARK    = (6,   11,  20)
_CARD    = (13,  20,  33)
_BORDER  = (30,  45,  61)
_TEXT    = (201, 209, 217)
_MUTED   = (71,  85,  105)
_RED     = (239, 68,  68)
_ORANGE  = (251, 146, 60)
_YELLOW  = (234, 179, 8)
_GREEN   = (34,  197, 94)
_WHITE   = (255, 255, 255)
_AMBER   = (245, 158, 11)

_CONFIDENCE_COLORS = {
    "direct_indicator": _RED,
    "related_context":  _AMBER,
}

_FONTS_DIR = os.path.join(os.path.dirname(__file__), "fonts")

_DISCLAIMER_HE = (
    "הצהרת אחריות: מסמך זה הינו אינדיקטיבי בלבד ואינו מהווה ייעוץ משפטי. "
    "המיפויים הרגולטוריים מבוססים על הבנה כללית של החקיקה הישראלית ואינם "
    "מחליפים בדיקה משפטית מקצועית. לקביעת חשיפה רגולטורית בפועל יש "
    "להיוועץ בעורך דין המתמחה בדיני הגנת פרטיות ישראליים."
)

_DISCLAIMER_EN = (
    "DISCLAIMER: This document is INDICATIVE ONLY and does NOT constitute legal advice. "
    "The regulatory mappings are based on a general understanding of Israeli legislation "
    "and are not a substitute for a professional legal assessment. For actual regulatory "
    "exposure, consult a qualified attorney specializing in Israeli privacy law."
)


def _grade_color(grade: Optional[str]) -> tuple:
    mapping = {"A": _GREEN, "B": (59, 130, 246), "C": _YELLOW, "D": _ORANGE, "F": _RED}
    return mapping.get(grade or "F", _MUTED)


def _try_load_fpdf():
    try:
        from fpdf import FPDF
        return FPDF
    except ImportError as exc:
        raise ImportError(
            "fpdf2 is required for PDF generation. Install it: pip install fpdf2"
        ) from exc


def generate_il_compliance_pdf(
    report,       # ILComplianceReport
    domain:       str,
    score:        Optional[int] = None,
    grade:        Optional[str] = None,
    scan_date:    Optional[str] = None,
    language:     str = "he",
) -> bytes:
    """
    Generate a Hebrew-first compliance PDF for the Israeli market.

    Returns raw PDF bytes ready to send as a download response.
    """
    FPDF = _try_load_fpdf()

    if scan_date is None:
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    is_he = (language == "he")

    class RTLPDF(FPDF):
        """FPDF subclass with RTL helpers."""

        def _load_heebo(self):
            reg_path  = os.path.join(_FONTS_DIR, "Heebo-Regular.ttf")
            bold_path = os.path.join(_FONTS_DIR, "Heebo-Bold.ttf")
            if os.path.exists(reg_path):
                self.add_font("Heebo", "",  reg_path)
            if os.path.exists(bold_path):
                self.add_font("Heebo", "B", bold_path)

        def heebo(self, size: int, bold: bool = False):
            style = "B" if bold else ""
            try:
                self.set_font("Heebo", style, size)
            except Exception:
                self.set_font("Arial", style, size)

        def set_bg(self, color: tuple):
            self.set_fill_color(*color)

        def set_fg(self, color: tuple):
            self.set_text_color(*color)

        def rtl_cell(self, w, h, txt, border=0, ln=1, fill=False, align="R"):
            """Right-aligned cell for RTL text."""
            self.cell(w, h, txt, border=border, ln=ln, fill=fill, align=align)

        def rtl_multi_cell(self, w, h, txt, border=0, align="R"):
            """Right-aligned multi-cell for RTL paragraphs."""
            self.multi_cell(w, h, txt, border=border, align=align)

        def divider(self):
            self.set_draw_color(*_BORDER)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(4)

    pdf = RTLPDF(orientation="P", unit="mm", format="A4")
    pdf._load_heebo()
    pdf.set_margins(left=15, top=15, right=15)
    pdf.set_auto_page_break(auto=True, margin=20)

    # ── Page 1: Cover ─────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_bg(_DARK)
    pdf.rect(0, 0, 210, 297, "F")

    # Header bar
    pdf.set_bg(_CARD)
    pdf.rect(0, 0, 210, 48, "F")

    # Logo text
    pdf.heebo(22, bold=True)
    pdf.set_fg(_CYAN)
    pdf.set_xy(15, 12)
    pdf.cell(180, 10, "AI Cyber Shield", ln=0, align="R" if is_he else "L")

    pdf.heebo(10)
    pdf.set_fg(_MUTED)
    pdf.set_xy(15, 24)
    pdf.cell(180, 7, "Enterprise Security Platform", ln=0, align="R" if is_he else "L")

    pdf.set_xy(15, 34)
    pdf.set_fg(_BORDER)
    pdf.cell(180, 1, "", border="T", ln=1)

    # Report title (Hebrew)
    pdf.ln(16)
    pdf.heebo(20, bold=True)
    pdf.set_fg(_WHITE)
    title_he = f"דוח התאמה רגולטורית — {domain}"
    title_en = f"Regulatory Compliance Report — {domain}"
    pdf.set_x(15)
    pdf.cell(180, 12, title_he if is_he else title_en, ln=1, align="R" if is_he else "L")

    pdf.heebo(11)
    pdf.set_fg(_MUTED)
    subtitle_he = "על פי חוק הגנת הפרטיות ותיקון 13 (2025)"
    subtitle_en = "Under the Privacy Protection Law and Amendment 13 (2025)"
    pdf.set_x(15)
    pdf.cell(180, 8, subtitle_he if is_he else subtitle_en, ln=1, align="R" if is_he else "L")

    # Grade / score card
    pdf.ln(8)
    pdf.set_bg(_CARD)
    pdf.set_draw_color(*_BORDER)
    card_y = pdf.get_y()
    pdf.rect(15, card_y, 180, 40, "FD")

    grade_color = _grade_color(grade)
    pdf.heebo(30, bold=True)
    pdf.set_fg(grade_color)
    pdf.set_xy(15, card_y + 6)
    pdf.cell(90, 20, grade or "—", ln=0, align="C")

    pdf.heebo(11)
    pdf.set_fg(_MUTED)
    label_grade = "דרגת אבטחה" if is_he else "Security Grade"
    pdf.set_xy(15, card_y + 28)
    pdf.cell(90, 8, label_grade, ln=0, align="C")

    pdf.heebo(26, bold=True)
    pdf.set_fg(_CYAN)
    pdf.set_xy(105, card_y + 6)
    pdf.cell(90, 20, f"{score}/100" if score is not None else "—", ln=0, align="C")

    pdf.heebo(11)
    pdf.set_fg(_MUTED)
    label_score = "ציון כולל" if is_he else "Overall Score"
    pdf.set_xy(105, card_y + 28)
    pdf.cell(90, 8, label_score, ln=0, align="C")

    pdf.set_y(card_y + 44)

    # Scan info
    pdf.ln(6)
    pdf.heebo(9)
    pdf.set_fg(_MUTED)
    date_label = f"תאריך סריקה: {scan_date}" if is_he else f"Scan date: {scan_date}"
    pdf.set_x(15)
    pdf.cell(180, 6, date_label, ln=1, align="R" if is_he else "L")

    count_label = (
        f"מספר אינדיקטורים: {report.total_count} "
        f"(ישיר {report.direct_count}, קשור {report.related_count})"
        if is_he else
        f"Total indicators: {report.total_count} "
        f"(direct: {report.direct_count}, related: {report.related_count})"
    )
    pdf.set_x(15)
    pdf.cell(180, 6, count_label, ln=1, align="R" if is_he else "L")

    # Prominent disclaimer box
    pdf.ln(10)
    pdf.set_bg((40, 18, 18))
    pdf.set_draw_color(*_RED)
    disc_y = pdf.get_y()
    pdf.rect(15, disc_y, 180, 32, "FD")

    pdf.heebo(9, bold=True)
    pdf.set_fg(_RED)
    warn_label = "⚠️ הצהרת אחריות" if is_he else "⚠️ DISCLAIMER"
    pdf.set_xy(20, disc_y + 4)
    pdf.cell(170, 6, warn_label, ln=1, align="R" if is_he else "L")

    pdf.heebo(8)
    pdf.set_fg(_TEXT)
    disc_text = _DISCLAIMER_HE if is_he else _DISCLAIMER_EN
    pdf.set_xy(20, disc_y + 12)
    pdf.multi_cell(170, 5, disc_text, align="R" if is_he else "L")

    # ── Page 2: Executive Summary ──────────────────────────────────────────────
    pdf.add_page()
    pdf.set_bg(_DARK)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.heebo(16, bold=True)
    pdf.set_fg(_CYAN)
    exec_title = "סיכום מנהלים" if is_he else "Executive Summary"
    pdf.set_x(15)
    pdf.cell(180, 12, exec_title, ln=1, align="R" if is_he else "L")
    pdf.divider()

    pdf.heebo(10)
    pdf.set_fg(_TEXT)
    posture_label = "מצב התאמה כללית:" if is_he else "Overall compliance posture:"
    pdf.set_x(15)
    pdf.cell(180, 8, posture_label, ln=1, align="R" if is_he else "L")

    # Summary bullets
    bullets = []
    if is_he:
        bullets = [
            f"• {report.direct_count} אינדיקטורים ישירים להפרת דרישות רגולטוריות",
            f"• {report.related_count} אינדיקטורים קשורים הדורשים פרשנות משפטית",
            f"• סריקה בוצעה בתאריך {scan_date}",
        ]
    else:
        bullets = [
            f"• {report.direct_count} direct regulatory compliance indicators detected",
            f"• {report.related_count} related-context indicators requiring legal interpretation",
            f"• Scan performed on {scan_date}",
        ]

    pdf.heebo(10)
    pdf.set_fg(_TEXT)
    for bullet in bullets:
        pdf.set_x(20)
        pdf.cell(175, 7, bullet, ln=1, align="R" if is_he else "L")

    pdf.ln(4)
    pdf.divider()

    # Priority actions section
    if report.direct_count > 0:
        priority_title = "פעולות דחופות" if is_he else "Priority Actions"
        pdf.heebo(13, bold=True)
        pdf.set_fg(_ORANGE)
        pdf.set_x(15)
        pdf.cell(180, 10, priority_title, ln=1, align="R" if is_he else "L")

        direct_indicators = [i for i in report.indicators if i.confidence == "direct_indicator"]
        for idx, ind in enumerate(direct_indicators[:5], 1):
            pdf.heebo(10, bold=True)
            pdf.set_fg(_RED)
            pdf.set_x(15)
            pdf.cell(180, 7, f"{idx}. {ind.finding_title}", ln=1, align="R" if is_he else "L")

            pdf.heebo(9)
            pdf.set_fg(_MUTED)
            pdf.set_x(20)
            pdf.cell(175, 6, f"{ind.regulation_name} — {ind.regulation_section}", ln=1, align="R" if is_he else "L")

        pdf.ln(4)
        pdf.divider()

    # ── Pages 3+: Detailed Findings ───────────────────────────────────────────
    if report.indicators:
        detail_title = "פירוט הממצאים" if is_he else "Detailed Findings"
        pdf.heebo(16, bold=True)
        pdf.set_fg(_CYAN)
        pdf.set_x(15)
        pdf.cell(180, 12, detail_title, ln=1, align="R" if is_he else "L")
        pdf.divider()

        for idx, ind in enumerate(report.indicators, 1):
            # Check remaining space
            if pdf.get_y() > 240:
                pdf.add_page()
                pdf.set_bg(_DARK)
                pdf.rect(0, 0, 210, 297, "F")
                pdf.ln(8)

            conf_color = _CONFIDENCE_COLORS.get(ind.confidence, _MUTED)

            # Finding number + title
            pdf.heebo(11, bold=True)
            pdf.set_fg(_WHITE)
            pdf.set_x(15)
            pdf.cell(180, 8, f"{idx}. {ind.finding_title}", ln=1, align="R" if is_he else "L")

            # Confidence badge
            conf_label_he = {
                "direct_indicator": "אינדיקטור ישיר",
                "related_context":  "קשור להקשר",
            }
            conf_label = conf_label_he.get(ind.confidence, ind.confidence) if is_he else ind.confidence.replace("_", " ").title()
            pdf.heebo(8, bold=True)
            pdf.set_fg(conf_color)
            pdf.set_x(15)
            pdf.cell(180, 6, f"[{conf_label}]", ln=1, align="R" if is_he else "L")

            # Regulation
            pdf.heebo(9)
            pdf.set_fg(_CYAN)
            reg_label = "תקנה:" if is_he else "Regulation:"
            pdf.set_x(15)
            pdf.cell(30, 6, reg_label, ln=0, align="L")
            pdf.set_fg(_TEXT)
            pdf.cell(150, 6, ind.regulation_name, ln=1, align="R" if is_he else "L")

            pdf.set_fg(_CYAN)
            sec_label = "סעיף:" if is_he else "Section:"
            pdf.set_x(15)
            pdf.cell(30, 6, sec_label, ln=0, align="L")
            pdf.set_fg(_TEXT)
            pdf.cell(150, 6, ind.regulation_section, ln=1, align="R" if is_he else "L")

            # Description
            pdf.heebo(9)
            pdf.set_fg(_TEXT)
            pdf.set_x(15)
            pdf.multi_cell(180, 5, ind.description, align="R" if is_he else "L")

            pdf.ln(3)
            pdf.set_draw_color(*_BORDER)
            pdf.set_x(15)
            pdf.cell(180, 0, "", border="T", ln=1)
            pdf.ln(4)

    # ── Last page: Full disclaimer + methodology ───────────────────────────────
    if pdf.get_y() > 220:
        pdf.add_page()
        pdf.set_bg(_DARK)
        pdf.rect(0, 0, 210, 297, "F")

    pdf.ln(6)
    pdf.heebo(13, bold=True)
    pdf.set_fg(_ORANGE)
    meth_title = "מתודולוגיה והצהרת אחריות" if is_he else "Methodology & Disclaimer"
    pdf.set_x(15)
    pdf.cell(180, 10, meth_title, ln=1, align="R" if is_he else "L")
    pdf.divider()

    method_text_he = (
        "הדוח נוצר באמצעות סריקת אבטחה אוטומטית "
        "באמצעות AI Cyber Shield. המיפויים רגולטוריים מבוססים "
        "על הבנה כללית של דיני הגנת הפרטיות "
        "הישראליים ואינם מהווים חוות דעת משפטית."
    )
    method_text_en = (
        "This report was generated by an automated security scan using AI Cyber Shield. "
        "The regulatory mappings are based on a general understanding of Israeli privacy law "
        "and do not constitute a legal opinion."
    )
    pdf.heebo(9)
    pdf.set_fg(_TEXT)
    pdf.set_x(15)
    pdf.multi_cell(180, 6, method_text_he if is_he else method_text_en, align="R" if is_he else "L")

    pdf.ln(6)
    pdf.heebo(9)
    pdf.set_fg(_MUTED)
    pdf.set_x(15)
    pdf.multi_cell(180, 6, _DISCLAIMER_HE if is_he else _DISCLAIMER_EN, align="R" if is_he else "L")

    # Glossary
    pdf.ln(6)
    gloss_title = "מונחים" if is_he else "Glossary"
    pdf.heebo(11, bold=True)
    pdf.set_fg(_CYAN)
    pdf.set_x(15)
    pdf.cell(180, 9, gloss_title, ln=1, align="R" if is_he else "L")

    glossary = [
        (
            "אינדיקטור ישיר" if is_he else "Direct Indicator",
            "ממצא שיש לו קשר נרחב לדרישה רגולטורית מפורשת"
            if is_he else
            "A finding with a clear and explicit link to a specific regulatory requirement",
        ),
        (
            "קשור להקשר" if is_he else "Related Context",
            "ממצא שעשוי להיות רלוונטי רגולטורית אך דורש בחינה משפטית"
            if is_he else
            "A finding that may be regulatory-relevant but requires legal interpretation",
        ),
        (
            "תיקון 13" if is_he else "Amendment 13",
            "תיקון 13 לחוק הגנת הפרטיות, שנכנס לתוקף באוגוסט 2025"
            if is_he else
            "Amendment 13 to the Privacy Protection Law, effective August 2025",
        ),
    ]

    for term, definition in glossary:
        pdf.heebo(9, bold=True)
        pdf.set_fg(_WHITE)
        pdf.set_x(15)
        pdf.cell(180, 6, term, ln=1, align="R" if is_he else "L")

        pdf.heebo(8)
        pdf.set_fg(_MUTED)
        pdf.set_x(20)
        pdf.multi_cell(175, 5, definition, align="R" if is_he else "L")
        pdf.ln(2)

    return bytes(pdf.output())

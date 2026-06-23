"""
PDF Exporter — standalone utility (no Streamlit imports).

Converts a URL security audit result dict (from run_url_security_audit)
or a plain Markdown string into a formatted PDF.

Two public functions
────────────────────
  create_pdf_from_result(result: dict) -> bytes
      Full-featured PDF: cover page, score card, category table,
      critical findings list, then the Markdown report body.

  create_pdf_from_markdown(markdown_text: str) -> bytes
      Lightweight fallback: strips Markdown and renders as plain text.
      Used by the legacy code scanner PDF.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos


# ─────────────────────────────────────────────────────────────────────────────
# Grade colour map (R, G, B)
# ─────────────────────────────────────────────────────────────────────────────

_GRADE_COLOR: dict[str, tuple[int, int, int]] = {
    "A": (39, 174, 96),    # green
    "B": (52, 152, 219),   # blue
    "C": (243, 156, 18),   # orange
    "D": (231, 76, 60),    # red
    "F": (192, 57, 43),    # dark red
}


# ─────────────────────────────────────────────────────────────────────────────
# Markdown → plain text
# ─────────────────────────────────────────────────────────────────────────────

def _strip_markdown(text: str) -> str:
    """
    Convert Markdown to plain text safe for PDF embedding.

    Rules:
    - Code fences (```) are replaced with indented text.
    - Headers (# at start of line) → text only.
    - Bold/italic markers (** * _ __) → text only.
    - Link syntax [text](url) → text.
    - Table separator rows (|---|) → removed.
    - Inline code (`code`) → text.
    All other # and * (hex colours, exponents, C++ pointers) are preserved.
    """
    lines = text.splitlines()
    output: list[str] = []
    in_code = False

    for line in lines:
        if line.strip().startswith("```"):
            in_code = not in_code
            if not in_code:
                output.append("")
            continue
        if in_code:
            output.append("    " + line)
            continue

        line = re.sub(r"^#{1,6}\s+", "", line)
        line = re.sub(r"\*{1,3}(\S[^*]*?\S|\S)\*{1,3}", r"\1", line)
        line = re.sub(r"_{1,2}(\S[^_]*?\S|\S)_{1,2}", r"\1", line)
        line = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)
        line = re.sub(r"`([^`]+)`", r"\1", line)
        if re.match(r"^\s*\|[\s\-:|]+\|\s*$", line):
            continue
        output.append(line)

    return "\n".join(output)


def _safe_text(text: str) -> str:
    """Replace characters FPDF Helvetica can't encode with ASCII equivalents."""
    replacements = {
        "’": "'",  "‘": "'",
        "“": '"',  "”": '"',
        "—": "--", "–": "-",
        "•": "*",  "…": "...",
        "→": "->", "←": "<-",
        "é": "e",  "è": "e",
        "à": "a",  "â": "a",
        "ü": "u",  "ö": "o",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    # Encode to latin-1, ignoring anything that still can't be represented
    return text.encode("latin-1", errors="ignore").decode("latin-1")


# ─────────────────────────────────────────────────────────────────────────────
# FPDF subclass with header/footer
# ─────────────────────────────────────────────────────────────────────────────

class _ReportPDF(FPDF):
    def __init__(self, title: str = "AI Cyber Shield — Security Report"):
        super().__init__()
        self._title = title
        self.set_auto_page_break(auto=True, margin=18)

    def header(self):
        self.set_font("Helvetica", style="B", size=9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, _safe_text(self._title), align="L",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", size=8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 5,
                  _safe_text(f"Page {self.page_no()} -- AI Cyber Shield | Defensive use only"),
                  align="C")
        self.set_text_color(0, 0, 0)

    def section_title(self, text: str):
        self.ln(3)
        self.set_font("Helvetica", style="B", size=12)
        self.set_fill_color(240, 243, 246)
        self.cell(0, 8, _safe_text(text), fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)
        self.set_font("Helvetica", size=10)

    def kv_row(self, label: str, value: str, bold_value: bool = False):
        self.set_font("Helvetica", style="B", size=10)
        self.cell(50, 6, _safe_text(label + ":"))
        style = "B" if bold_value else ""
        self.set_font("Helvetica", style=style, size=10)
        self.cell(0, 6, _safe_text(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Helvetica", size=10)


# ─────────────────────────────────────────────────────────────────────────────
# Score bar (visual)
# ─────────────────────────────────────────────────────────────────────────────

def _score_bar(pdf: _ReportPDF, label: str, score: int, weight: int):
    """Render one row of the category score table with a colour bar."""
    bar_width   = 60          # max bar width in mm
    bar_height  = 4
    bar_filled  = bar_width * score / 100

    # Choose colour based on score
    if score >= 75:
        r, g, b = 39, 174, 96
    elif score >= 50:
        r, g, b = 243, 156, 18
    else:
        r, g, b = 231, 76, 60

    row_y = pdf.get_y()

    pdf.set_font("Helvetica", size=9)
    pdf.cell(55, 6, _safe_text(label))
    pdf.cell(12, 6, f"{score}/100", align="R")
    pdf.cell(4, 6, "")

    # Bar background
    pdf.set_fill_color(220, 220, 220)
    pdf.rect(pdf.get_x(), row_y + 1, bar_width, bar_height, style="F")
    # Bar fill
    pdf.set_fill_color(r, g, b)
    if bar_filled > 0:
        pdf.rect(pdf.get_x(), row_y + 1, bar_filled, bar_height, style="F")

    pdf.set_x(pdf.get_x() + bar_width + 2)
    pdf.cell(12, 6, f"wt:{weight}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_fill_color(255, 255, 255)


# ─────────────────────────────────────────────────────────────────────────────
# Public: full report PDF from result dict
# ─────────────────────────────────────────────────────────────────────────────

_CATEGORY_LABELS = {
    "ssl":               "SSL / TLS",
    "headers":           "Security Headers",
    "html":              "Page Content & JS",
    "tech":              "Technology Stack",
    "crawler":           "Crawler Findings",
    "cors_csp":          "CORS & CSP",
    "dns":               "DNS Security",
    "exposure":          "Exposed Files",
    "hsts_preload":      "HSTS Preload",
    "open_redirect":     "Open Redirects",
    "waf":               "WAF Protection",
    "cert_transparency": "Certificate Transparency",
    "api_spec":          "API Spec Exposure",
    "subdomain_takeover":"Subdomain Takeover",
    "port_scanner":      "Open Ports",
    "cookie_security":   "Cookie Security",
    "deep_js_crawler":   "Deep JS / SPA Crawler",
}

_WEIGHTS = {
    "ssl": 13, "headers": 9, "html": 9, "tech": 5, "crawler": 7,
    "cors_csp": 6, "dns": 6, "exposure": 6, "hsts_preload": 5,
    "open_redirect": 5, "waf": 3, "cert_transparency": 1,
    "api_spec": 5, "subdomain_takeover": 6,
    "port_scanner": 5, "cookie_security": 5, "deep_js_crawler": 4,
}


def create_pdf_from_result(result: dict) -> bytes:
    """
    Build a full-featured PDF from a run_url_security_audit() result dict.

    Sections:
      1. Cover / score card (grade badge, URL, date, overall score)
      2. Category scores table with colour bars
      3. Critical findings list
      4. Full LLM report body
    """
    url           = result.get("url", "")
    grade         = result.get("overall_grade", "?")
    score         = result.get("overall_score", 0)
    category_scores = result.get("category_scores", {})
    critical      = result.get("critical_findings", [])
    report_md     = result.get("raw_output", "No report generated.")
    scan_date     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    grade_color = _GRADE_COLOR.get(grade, (100, 100, 100))
    pdf = _ReportPDF(title=f"AI Cyber Shield — {url[:50]}")
    pdf.add_page()

    # ── 1. Cover ──────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", style="B", size=20)
    pdf.set_text_color(33, 47, 61)
    pdf.cell(0, 12, "AI Cyber Shield", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=12)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 7, "Web Security Audit Report", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Grade badge
    r, g, b = grade_color
    badge_w, badge_h = 30, 16
    badge_x = (pdf.w - badge_w) / 2
    pdf.set_fill_color(r, g, b)
    pdf.rect(badge_x, pdf.get_y(), badge_w, badge_h, style="F")
    pdf.set_font("Helvetica", style="B", size=18)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(badge_x, pdf.get_y() + 2)
    pdf.cell(badge_w, badge_h - 4, grade, align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(badge_h + 2)

    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 8, f"Score: {score}/100", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.set_font("Helvetica", size=10)
    pdf.kv_row("Target URL", url)
    pdf.kv_row("Scan Date",  scan_date)
    pdf.kv_row("Grade",      f"{grade}  ({score}/100)", bold_value=True)
    pdf.kv_row("Tools Run",  "16 parallel security scanners")
    pdf.ln(4)

    # ── 2. Category scores ────────────────────────────────────────────────────
    pdf.section_title("Category Scores")
    pdf.set_font("Helvetica", size=9)
    for key, label in _CATEGORY_LABELS.items():
        cat_score = category_scores.get(key, 0)
        weight    = _WEIGHTS.get(key, 0)
        _score_bar(pdf, label, cat_score, weight)
    pdf.ln(2)

    # ── 3. Critical findings ──────────────────────────────────────────────────
    if critical:
        pdf.section_title("Critical Findings")
        pdf.set_font("Helvetica", size=9)
        for i, finding in enumerate(critical, 1):
            pdf.set_fill_color(255, 235, 235)
            text = _safe_text(f"{i}. {finding}")
            pdf.multi_cell(0, 6, text, fill=True,
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
        pdf.ln(2)

    # ── 4. Full report ────────────────────────────────────────────────────────
    pdf.section_title("Full Security Report")
    plain = _strip_markdown(report_md)
    pdf.set_font("Helvetica", size=9)
    for line in plain.splitlines():
        safe_line = _safe_text(line)
        if safe_line.strip():
            pdf.multi_cell(0, 5, safe_line,
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.ln(3)

    return bytes(pdf.output())


# ─────────────────────────────────────────────────────────────────────────────
# Public: lightweight Markdown → PDF (used by legacy code scanner)
# ─────────────────────────────────────────────────────────────────────────────

def create_pdf_from_markdown(markdown_text: str) -> bytes:
    """
    Convert a Markdown security report to a plain-text PDF.
    Suitable for the code scanner output which has no structured result dict.
    """
    clean = _strip_markdown(markdown_text)
    pdf   = _ReportPDF(title="AI Cyber Shield -- Code Security Report")
    pdf.add_page()

    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(0, 10, "AI Cyber Shield - Security Report", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)
    pdf.set_font("Helvetica", size=10)

    for line in clean.splitlines():
        safe_line = _safe_text(line)
        if safe_line.strip():
            pdf.multi_cell(0, 6, safe_line,
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.ln(3)

    return bytes(pdf.output())


# ─────────────────────────────────────────────────────────────────────────────
# Back-compat shim — cyber_shield_pdf_app.py calls create_pdf(str)
# ─────────────────────────────────────────────────────────────────────────────

def create_pdf(markdown_text: str) -> bytes:
    """Alias kept for backward compatibility with cyber_shield_pdf_app.py."""
    return create_pdf_from_markdown(markdown_text)

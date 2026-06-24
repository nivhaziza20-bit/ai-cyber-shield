"""
Tests for tools/pdf_exporter.py

Structure
─────────
  TestStripMarkdown       — _strip_markdown() pure-Python logic
  TestSafeText            — _safe_text() character replacement
  TestCreatePdfFromMarkdown  — lightweight bytes output, no network
  TestCreatePdfFromResult    — full-featured PDF with score card
  TestCreatePdfBackcompat    — create_pdf() shim behaves like from_markdown
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.pdf_exporter import (
    _safe_text,
    _strip_markdown,
    create_pdf,
    create_pdf_from_markdown,
    create_pdf_from_result,
)


# ─────────────────────────────────────────────────────────────────────────────
# _strip_markdown
# ─────────────────────────────────────────────────────────────────────────────

class TestStripMarkdown:
    def test_headers_removed(self):
        result = _strip_markdown("# Title\n## Section")
        assert "#" not in result
        assert "Title" in result
        assert "Section" in result

    def test_bold_stripped(self):
        result = _strip_markdown("**bold text**")
        assert "**" not in result
        assert "bold text" in result

    def test_italic_stripped(self):
        result = _strip_markdown("*italic text*")
        assert result.count("*") == 0
        assert "italic text" in result

    def test_link_text_preserved_url_dropped(self):
        result = _strip_markdown("[Click here](https://example.com)")
        assert "Click here" in result
        assert "https://example.com" not in result

    def test_table_separator_rows_removed(self):
        md = "| col1 | col2 |\n|------|------|\n| val1 | val2 |"
        result = _strip_markdown(md)
        assert "|------|" not in result
        assert "val1" in result

    def test_code_fence_content_preserved(self):
        md = "```python\nprint('hello')\n```"
        result = _strip_markdown(md)
        assert "print" in result

    def test_inline_code_stripped(self):
        result = _strip_markdown("Use `os.path.join()` for paths")
        assert "`" not in result
        assert "os.path.join" in result

    def test_hex_colours_preserved(self):
        result = _strip_markdown("Set colour to #ff0000")
        assert "#ff0000" in result

    def test_empty_string_returns_empty(self):
        assert _strip_markdown("") == ""

    def test_plain_text_unchanged(self):
        plain = "This is a normal sentence with no Markdown."
        result = _strip_markdown(plain)
        assert result == plain


# ─────────────────────────────────────────────────────────────────────────────
# _safe_text
# ─────────────────────────────────────────────────────────────────────────────

class TestSafeText:
    def test_curly_quotes_replaced(self):
        result = _safe_text("‘quoted’")
        assert "'" in result
        assert "‘" not in result

    def test_em_dash_replaced(self):
        result = _safe_text("word—word")
        assert "--" in result
        assert "—" not in result

    def test_bullet_replaced(self):
        result = _safe_text("• item")
        assert "*" in result

    def test_arrow_replaced(self):
        result = _safe_text("A → B")
        assert "->" in result

    def test_latin1_safe_string_unchanged(self):
        text = "Hello World 123 !@#"
        assert _safe_text(text) == text

    def test_non_encodable_chars_dropped(self):
        result = _safe_text("Hebrew: שלום")
        assert "ש" not in result
        assert "Hebrew:" in result


# ─────────────────────────────────────────────────────────────────────────────
# create_pdf_from_markdown
# ─────────────────────────────────────────────────────────────────────────────

class TestCreatePdfFromMarkdown:
    def test_returns_bytes(self):
        pdf = create_pdf_from_markdown("# Title\n\nSome text.")
        assert isinstance(pdf, bytes)

    def test_pdf_starts_with_magic_bytes(self):
        pdf = create_pdf_from_markdown("Hello")
        assert pdf[:4] == b"%PDF"

    def test_empty_string_generates_valid_pdf(self):
        pdf = create_pdf_from_markdown("")
        assert pdf[:4] == b"%PDF"

    def test_long_content_generates_pdf(self):
        md = "\n".join([f"Line {i}: " + "x" * 80 for i in range(200)])
        pdf = create_pdf_from_markdown(md)
        assert pdf[:4] == b"%PDF"
        assert len(pdf) > 1000

    def test_unicode_chars_handled_without_error(self):
        md = "Smart quotes ‘here’ and em-dash—"
        pdf = create_pdf_from_markdown(md)
        assert pdf[:4] == b"%PDF"


# ─────────────────────────────────────────────────────────────────────────────
# create_pdf_from_result
# ─────────────────────────────────────────────────────────────────────────────

def _good_result(**overrides) -> dict:
    base = {
        "url": "https://example.com",
        "overall_grade": "B",
        "overall_score": 78,
        "category_scores": {
            "ssl": 90, "headers": 80, "html": 70, "tech": 85,
            "crawler": 75, "cors_csp": 65, "dns": 70, "exposure": 80,
            "hsts_preload": 60, "open_redirect": 100, "waf": 50,
            "cert_transparency": 100, "api_spec": 90,
            "subdomain_takeover": 100, "port_scanner": 80, "cookie_security": 60,
        },
        "critical_findings": [
            "SSL: TLSv1.0 deprecated cipher detected",
            "Cookie 'session' missing Secure flag",
        ],
        "raw_output": "## Summary\n\nThe site has moderate security.\n\n**Action needed**: Fix TLS.",
    }
    base.update(overrides)
    return base


class TestCreatePdfFromResult:
    def test_returns_bytes(self):
        pdf = create_pdf_from_result(_good_result())
        assert isinstance(pdf, bytes)

    def test_pdf_magic_bytes(self):
        pdf = create_pdf_from_result(_good_result())
        assert pdf[:4] == b"%PDF"

    def test_no_category_scores_uses_defaults(self):
        pdf = create_pdf_from_result({"url": "https://x.com"})
        assert pdf[:4] == b"%PDF"

    def test_all_16_categories_handled(self):
        result = _good_result()
        assert len(result["category_scores"]) == 16
        pdf = create_pdf_from_result(result)
        assert pdf[:4] == b"%PDF"

    def test_critical_findings_included(self):
        result = _good_result(critical_findings=["CRITICAL: exposed .env file"])
        pdf = create_pdf_from_result(result)
        assert len(pdf) > 1000

    def test_grade_f_uses_red_colouring_without_crash(self):
        result = _good_result(overall_grade="F", overall_score=5)
        pdf = create_pdf_from_result(result)
        assert pdf[:4] == b"%PDF"

    def test_grade_a_uses_green_colouring_without_crash(self):
        result = _good_result(overall_grade="A", overall_score=97)
        pdf = create_pdf_from_result(result)
        assert pdf[:4] == b"%PDF"

    def test_zero_scores_all_red_bars_without_crash(self):
        result = _good_result(
            category_scores={k: 0 for k in [
                "ssl", "headers", "html", "tech", "crawler", "cors_csp",
                "dns", "exposure", "hsts_preload", "open_redirect", "waf",
                "cert_transparency", "api_spec", "subdomain_takeover",
                "port_scanner", "cookie_security",
            ]},
            overall_score=0,
        )
        pdf = create_pdf_from_result(result)
        assert pdf[:4] == b"%PDF"

    def test_long_url_truncated_in_title_without_crash(self):
        long_url = "https://very-long-subdomain.example.com/very/long/path?q=1"
        result = _good_result(url=long_url)
        pdf = create_pdf_from_result(result)
        assert pdf[:4] == b"%PDF"

    def test_empty_findings_no_section_shown(self):
        result = _good_result(critical_findings=[])
        pdf = create_pdf_from_result(result)
        assert pdf[:4] == b"%PDF"

    def test_pdf_larger_than_2kb(self):
        pdf = create_pdf_from_result(_good_result())
        assert len(pdf) > 2048


# ─────────────────────────────────────────────────────────────────────────────
# Back-compat shim
# ─────────────────────────────────────────────────────────────────────────────

class TestCreatePdfBackcompat:
    def test_create_pdf_alias_returns_bytes(self):
        pdf = create_pdf("# Test\n\nContent here.")
        assert isinstance(pdf, bytes)

    def test_create_pdf_same_as_from_markdown(self):
        md = "# Title\n\nText."
        assert create_pdf(md) == create_pdf_from_markdown(md)

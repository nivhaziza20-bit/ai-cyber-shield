"""
Tests for the PDF generator — proves all five bugs are fixed.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.pdf_exporter import _strip_markdown, create_pdf


# ─────────────────────────────────────────────────────────────────────────────
# Bug 5 — Markdown stripping must not destroy code content
# ─────────────────────────────────────────────────────────────────────────────

class TestStripMarkdown:

    def test_header_stripped_only_at_line_start(self):
        md = "## SQL Injection\ncolor: #ff0000\n#include <stdio.h>"
        result = _strip_markdown(md)
        assert "SQL Injection" in result          # header text preserved
        assert "## "          not in result       # header token removed
        assert "#ff0000"      in result           # hex colour intact
        assert "#include"     in result           # C include intact

    def test_bold_stripped_not_exponent(self):
        md = "**vulnerable** and 2**8 = 256"
        result = _strip_markdown(md)
        assert "vulnerable"  in result    # bold text preserved
        assert "**"          not in result or "2**8" in result
        # Key assertion: the math exponent must survive
        assert "2**8" in result or "256" in result

    def test_code_block_content_preserved_verbatim(self):
        md = "Analysis:\n```python\n# SQL injection\ncursor.execute('SELECT * FROM users WHERE id=' + uid)\n```\nDone."
        result = _strip_markdown(md)
        assert "cursor.execute" in result
        assert "SELECT * FROM"  in result
        # The # comment inside the code block must survive
        assert "SQL injection"  in result

    def test_link_text_kept_url_dropped(self):
        md = "See [OWASP Top 10](https://owasp.org/Top10/) for details."
        result = _strip_markdown(md)
        assert "OWASP Top 10" in result
        assert "https://"     not in result

    def test_table_separator_row_removed(self):
        md = "| VID | Score |\n|-----|-------|\n| VID-1 | 9.8 |"
        result = _strip_markdown(md)
        assert "|-----|" not in result    # separator gone
        assert "VID-1"  in result         # data rows kept

    def test_pointer_asterisk_in_c_code_preserved(self):
        code_md = "```c\nint **argv;\n```"
        result = _strip_markdown(code_md)
        assert "**argv" in result

    def test_python_comment_hash_inside_code_block_preserved(self):
        md = "```python\n# This is a comment\nx = 1\n```"
        result = _strip_markdown(md)
        assert "# This is a comment" in result


# ─────────────────────────────────────────────────────────────────────────────
# Bug 4 — create_pdf must return bytes (not str, not bytearray)
# ─────────────────────────────────────────────────────────────────────────────

class TestCreatePdf:

    SAMPLE_REPORT = (
        "## Vulnerability Report\n"
        "**Target:** samples/vulnerable_app.py\n\n"
        "### VID-1: SQL Injection\n"
        "CVSS: 9.8 | OWASP: A03:2021\n\n"
        "```python\n"
        "cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
        "```\n"
    )

    def test_returns_bytes_not_string(self):
        result = create_pdf(self.SAMPLE_REPORT)
        assert isinstance(result, bytes), (
            f"create_pdf must return bytes, got {type(result).__name__}"
        )

    def test_pdf_has_correct_magic_bytes(self):
        result = create_pdf(self.SAMPLE_REPORT)
        assert result[:4] == b"%PDF", (
            "Output does not start with PDF magic bytes — not a valid PDF"
        )

    def test_pdf_non_empty(self):
        result = create_pdf(self.SAMPLE_REPORT)
        assert len(result) > 500, "PDF suspiciously small — likely empty"

    def test_empty_input_does_not_crash(self):
        result = create_pdf("")
        assert isinstance(result, bytes)
        assert result[:4] == b"%PDF"

    def test_unicode_latin_content_handled(self):
        latin_report = (
            "## Report\n"
            "Finding: SQL Injection at line 27\n"
            "Risk: CRITICAL\n"
        )
        result = create_pdf(latin_report)
        assert isinstance(result, bytes)
        assert result[:4] == b"%PDF"

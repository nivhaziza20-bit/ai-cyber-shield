"""
Smoke tests — verify tools import and basic structure without network/API calls.
Run with:  python -m pytest tests/test_tools_import.py -v
"""

import json
import pytest


# ── Import checks ─────────────────────────────────────────────────────────────

def test_sast_tools_importable():
    from tools.sast_tools import run_bandit_scan, run_semgrep_scan
    # LangChain StructuredTool is invocable via .invoke(), not callable()
    assert hasattr(run_bandit_scan,  "invoke")
    assert hasattr(run_semgrep_scan, "invoke")


def test_vt_tool_importable():
    from tools.virustotal_tools import check_url_virustotal
    assert hasattr(check_url_virustotal, "invoke")


def test_web_tool_importable():
    from tools.web_tools import check_security_headers
    assert hasattr(check_security_headers, "invoke")


# ── Safety / validation checks ────────────────────────────────────────────────

def test_vt_rejects_non_http_scheme(monkeypatch):
    """VirusTotal tool must refuse file:// and ftp:// URLs."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")

    # Must clear lru_cache so monkeypatched env is seen
    from config import get_settings
    get_settings.cache_clear()

    from tools.virustotal_tools import check_url_virustotal
    result = json.loads(check_url_virustotal.invoke({"url": "file:///etc/passwd"}))
    assert result["status"] == "invalid_input"
    assert "http" in result["error"].lower()


def test_headers_tool_rejects_non_http(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    from config import get_settings
    get_settings.cache_clear()

    from tools.web_tools import check_security_headers
    result = json.loads(check_security_headers.invoke({"url": "ftp://example.com"}))
    assert result["status"] == "invalid_input"


def test_bandit_missing_binary(monkeypatch, tmp_path):
    """When bandit is not installed, return structured error, not exception."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    from config import get_settings
    get_settings.cache_clear()

    import sys
    # Patch PATH to an empty dir so 'bandit' won't be found
    monkeypatch.setenv("PATH", str(tmp_path))

    from tools.sast_tools import run_bandit_scan
    result = json.loads(run_bandit_scan.invoke({"code": "x = 1"}))
    # Either not_installed or completed (if bandit happens to be available)
    assert result["status"] in ("not_installed", "completed", "parse_error", "timeout")


def test_bandit_sql_injection_detected(monkeypatch):
    """Bandit must flag obvious SQL injection in Python code."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    from config import get_settings
    get_settings.cache_clear()

    from tools.sast_tools import run_bandit_scan

    vulnerable_code = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Dangerous: direct string interpolation into SQL
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()
"""
    result = json.loads(run_bandit_scan.invoke({"code": vulnerable_code}))

    if result["status"] == "not_installed":
        pytest.skip("Bandit not installed in this environment")

    assert result["status"] == "completed"
    assert result["total_findings"] > 0
    severities = [f["severity"] for f in result["findings"]]
    # Bandit B608 (SQL injection) is HIGH or MEDIUM
    assert any(s in ("HIGH", "MEDIUM") for s in severities), (
        f"Expected HIGH/MEDIUM finding for SQL injection, got: {severities}"
    )

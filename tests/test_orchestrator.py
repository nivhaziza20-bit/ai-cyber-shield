"""
Orchestrator tests — validate pipeline wiring, error propagation,
and result structure without making live LLM or API calls.

Each test patches the three run_* functions so tests are fast and free.
"""

import json
import pytest
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────────────

MOCK_SCANNER_OUTPUT = json.dumps({
    "scan_target_description": "Python code with SQL injection",
    "tools_executed": ["run_bandit_scan", "run_semgrep_scan"],
    "bandit_results": {
        "tool": "bandit", "status": "completed", "total_findings": 1,
        "severity_summary": {"high": 1, "medium": 0, "low": 0},
        "findings": [{
            "id": "B608", "name": "hardcoded_sql_expressions",
            "severity": "HIGH", "confidence": "MEDIUM",
            "description": "Possible SQL injection via string-based query construction.",
            "line_number": 7, "code_snippet": "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)",
        }],
    },
    "semgrep_results": None,
    "virustotal_results": None,
    "headers_results": None,
})

MOCK_ANALYST_OUTPUT = """## Vulnerability Report
**Target:** Python code with SQL injection
**Overall Risk Level:** HIGH

### Confirmed Findings

#### [HIGH] VID-1: SQL Injection via String Concatenation
| Field | Value |
|-------|-------|
| **OWASP 2021** | A03:2021 – Injection |
| **CVSS v3.1 Score** | 8.8 (HIGH) |
"""

MOCK_REMEDIATION_OUTPUT = """## Remediation Playbook

### Fix for VID-1: SQL Injection via String Concatenation

#### Before (Vulnerable)
```python
cursor.execute("SELECT * FROM users WHERE id=" + user_id)
```

#### After (Secure)
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```
"""


@pytest.fixture(autouse=True)
def patch_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    from config import get_settings
    from agents.llm import get_llm
    get_settings.cache_clear()
    get_llm.cache_clear()


# ─────────────────────────────────────────────────────────────────────────────
# Happy path
# ─────────────────────────────────────────────────────────────────────────────

@patch("orchestrator.run_remediation", return_value=MOCK_REMEDIATION_OUTPUT)
@patch("orchestrator.run_analyst", return_value=MOCK_ANALYST_OUTPUT)
@patch("orchestrator.run_scanner", return_value={"output": MOCK_SCANNER_OUTPUT, "intermediate_steps": []})
def test_full_pipeline_success(mock_scan, mock_analyse, mock_remediate):
    from orchestrator import SecurityPipeline

    pipeline = SecurityPipeline(verbose=False)
    result = pipeline.run("Scan this code: x = 1", scanner_only=False)

    assert result.overall_status == "success"
    assert result.scanner.status == "success"
    assert result.analyst.status == "success"
    assert result.remediation.status == "success"

    assert result.scanner.output == MOCK_SCANNER_OUTPUT
    assert result.analyst.output == MOCK_ANALYST_OUTPUT
    assert result.remediation.output == MOCK_REMEDIATION_OUTPUT

    assert result.total_duration_seconds >= 0

    mock_scan.assert_called_once()
    mock_analyse.assert_called_once_with(MOCK_SCANNER_OUTPUT)
    mock_remediate.assert_called_once_with(MOCK_ANALYST_OUTPUT)


# ─────────────────────────────────────────────────────────────────────────────
# Scanner-only mode
# ─────────────────────────────────────────────────────────────────────────────

@patch("orchestrator.run_analyst")
@patch("orchestrator.run_scanner", return_value={"output": MOCK_SCANNER_OUTPUT, "intermediate_steps": []})
def test_scanner_only_skips_downstream(mock_scan, mock_analyse):
    from orchestrator import SecurityPipeline

    pipeline = SecurityPipeline(verbose=False)
    result = pipeline.run("Scan this", scanner_only=True)

    assert result.scanner.status == "success"
    assert result.analyst.status == "skipped"
    assert result.remediation.status == "skipped"
    assert result.overall_status == "partial"
    mock_analyse.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Scanner failure propagates correctly
# ─────────────────────────────────────────────────────────────────────────────

@patch("orchestrator.run_analyst")
@patch("orchestrator.run_scanner", side_effect=RuntimeError("Bandit binary not found"))
def test_scanner_failure_skips_analyst_and_remediation(mock_scan, mock_analyse):
    from orchestrator import SecurityPipeline

    pipeline = SecurityPipeline(verbose=False)
    result = pipeline.run("Scan this")

    assert result.scanner.status == "failed"
    assert result.analyst.status == "skipped"
    assert result.remediation.status == "skipped"
    assert result.overall_status == "failed"
    assert "Bandit binary not found" in result.scanner.error
    mock_analyse.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Analyst failure skips remediation
# ─────────────────────────────────────────────────────────────────────────────

@patch("orchestrator.run_remediation")
@patch("orchestrator.run_analyst", side_effect=RuntimeError("LLM API timeout"))
@patch("orchestrator.run_scanner", return_value={"output": MOCK_SCANNER_OUTPUT, "intermediate_steps": []})
def test_analyst_failure_skips_remediation(mock_scan, mock_analyse, mock_remediate):
    from orchestrator import SecurityPipeline

    pipeline = SecurityPipeline(verbose=False)
    result = pipeline.run("Scan this")

    assert result.scanner.status == "success"
    assert result.analyst.status == "failed"
    assert result.remediation.status == "skipped"
    assert result.overall_status == "partial"
    mock_remediate.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Report saving
# ─────────────────────────────────────────────────────────────────────────────

@patch("orchestrator.run_remediation", return_value=MOCK_REMEDIATION_OUTPUT)
@patch("orchestrator.run_analyst", return_value=MOCK_ANALYST_OUTPUT)
@patch("orchestrator.run_scanner", return_value={"output": MOCK_SCANNER_OUTPUT, "intermediate_steps": []})
def test_save_reports_creates_files(mock_scan, mock_analyse, mock_remediate, tmp_path):
    from orchestrator import SecurityPipeline

    pipeline = SecurityPipeline(verbose=False)
    result = pipeline.run("Scan this")
    saved = result.save_reports(tmp_path)

    assert "scanner" in saved
    assert "analyst" in saved
    assert "remediation" in saved
    assert "summary" in saved

    assert saved["scanner"].exists()
    assert saved["analyst"].exists()
    assert saved["remediation"].exists()

    # Analyst output is Markdown
    content = saved["analyst"].read_text(encoding="utf-8")
    assert "Vulnerability Report" in content

    # Summary is valid JSON
    summary = json.loads(saved["summary"].read_text(encoding="utf-8"))
    assert summary["overall_status"] == "success"


# ─────────────────────────────────────────────────────────────────────────────
# PipelineResult overall_status logic
# ─────────────────────────────────────────────────────────────────────────────

def test_overall_status_all_success():
    from orchestrator import PipelineResult, StageResult
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    r = PipelineResult(
        target_description="test",
        started_at=now, completed_at=now,
        total_duration_seconds=1.0,
        scanner=StageResult(status="success"),
        analyst=StageResult(status="success"),
        remediation=StageResult(status="success"),
        overall_status="success",
    )
    assert r.is_success()


def test_overall_status_partial():
    from orchestrator import PipelineResult, StageResult
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    r = PipelineResult(
        target_description="test",
        started_at=now, completed_at=now,
        total_duration_seconds=1.0,
        scanner=StageResult(status="success"),
        analyst=StageResult(status="failed", error="timeout"),
        remediation=StageResult(status="skipped"),
        overall_status="partial",
    )
    assert not r.is_success()
    assert r.overall_status == "partial"

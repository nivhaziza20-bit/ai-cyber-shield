"""
tests/integration/test_orchestrator.py — AI Cyber Shield v6

Integration tests for the 3-stage agent orchestration pipeline:
  Scanner → Analyst → Remediation

Uses SecurityPipeline from orchestrator.py.
All LLM calls are mocked via patching agents module functions.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from unittest.mock import patch
import pytest

from orchestrator import SecurityPipeline, PipelineResult, StageResult


# run_scanner returns {"output": str, "intermediate_steps": list}
# run_analyst / run_remediation return str directly
_SCANNER_RAW_OUTPUT = '{"target":"https://example.com","findings":["XSS"],"score":72}'
_MOCK_SCANNER_DICT  = {"output": _SCANNER_RAW_OUTPUT, "intermediate_steps": []}
_MOCK_ANALYST_OUT   = "## Analyst Report\n\n**Risk:** HIGH\n\nCVSS 8.1 — XSS in search form."
_MOCK_REMEDIATION_OUT = "## Remediation\n\n1. Escape all user input\n2. Set CSP header"


class TestOrchestratorStages:
    """
    Brief 1 — tests/integration/test_orchestrator.py (5 tests).
    Verifies the pipeline chains stages correctly.
    """

    @patch("orchestrator.run_scanner")
    @patch("orchestrator.run_analyst")
    @patch("orchestrator.run_remediation")
    def test_three_stages_all_complete(
        self, mock_remediation, mock_analyst, mock_scanner
    ):
        mock_scanner.return_value   = _MOCK_SCANNER_DICT
        mock_analyst.return_value   = _MOCK_ANALYST_OUT
        mock_remediation.return_value = _MOCK_REMEDIATION_OUT

        pipeline = SecurityPipeline(verbose=False)
        result = pipeline.run("Analyze https://example.com for vulnerabilities")

        assert isinstance(result, PipelineResult)
        assert result.scanner.status     == "success"
        assert result.analyst.status     == "success"
        assert result.remediation.status == "success"
        assert result.overall_status     == "success"

    @patch("orchestrator.run_scanner")
    @patch("orchestrator.run_analyst")
    @patch("orchestrator.run_remediation")
    def test_scanner_output_reaches_analyst(
        self, mock_remediation, mock_analyst, mock_scanner
    ):
        mock_scanner.return_value   = _MOCK_SCANNER_DICT
        mock_analyst.return_value   = _MOCK_ANALYST_OUT
        mock_remediation.return_value = _MOCK_REMEDIATION_OUT

        SecurityPipeline(verbose=False).run("test target")

        # Analyst must have been called with scanner's extracted output text
        analyst_args = mock_analyst.call_args[0][0]
        assert _SCANNER_RAW_OUTPUT in analyst_args

    @patch("orchestrator.run_scanner")
    @patch("orchestrator.run_analyst")
    @patch("orchestrator.run_remediation")
    def test_analyst_output_reaches_remediation(
        self, mock_remediation, mock_analyst, mock_scanner
    ):
        mock_scanner.return_value   = _MOCK_SCANNER_DICT
        mock_analyst.return_value   = _MOCK_ANALYST_OUT
        mock_remediation.return_value = _MOCK_REMEDIATION_OUT

        SecurityPipeline(verbose=False).run("test target")

        remediation_args = mock_remediation.call_args[0][0]
        assert _MOCK_ANALYST_OUT in remediation_args

    @patch("orchestrator.run_scanner")
    @patch("orchestrator.run_analyst")
    @patch("orchestrator.run_remediation")
    def test_timing_captured(
        self, mock_remediation, mock_analyst, mock_scanner
    ):
        mock_scanner.return_value   = _MOCK_SCANNER_DICT
        mock_analyst.return_value   = _MOCK_ANALYST_OUT
        mock_remediation.return_value = _MOCK_REMEDIATION_OUT

        result = SecurityPipeline(verbose=False).run("test target")

        assert result.total_duration_seconds >= 0
        assert result.scanner.duration_seconds >= 0

    @patch("orchestrator.run_scanner")
    @patch("orchestrator.run_analyst")
    @patch("orchestrator.run_remediation")
    def test_scanner_failure_skips_subsequent_stages(
        self, mock_remediation, mock_analyst, mock_scanner
    ):
        mock_scanner.side_effect = RuntimeError("Scanner tool crashed")

        result = SecurityPipeline(verbose=False).run("test target")

        assert result.scanner.status == "failed"
        # Pipeline captures failure without raising
        assert result.overall_status in ("partial", "failed")
        # Analyst and Remediation must be skipped when Scanner fails
        assert mock_analyst.call_count    == 0
        assert mock_remediation.call_count == 0
        assert result.analyst.status     == "skipped"
        assert result.remediation.status == "skipped"

"""
Tests that prove Bug 4 (silent failure) and Bug 5 (fragile trigger) are fixed.
Run with:  python -m pytest tests/test_alerts.py -v
"""

import pytest
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────────────────────────────────────
# Bug 5 — fragile alert trigger
# ─────────────────────────────────────────────────────────────────────────────

from crew_pipeline_with_alerts import _extract_high_severity_findings


class TestExtractHighSeverityFindings:

    # Strings that the ORIGINAL code would have incorrectly triggered on
    FALSE_POSITIVES = [
        "Highly recommended to use parameterised queries.",
        "The High Court ruling on data privacy...",
        "This is a high-traffic endpoint.",
        "## High Risk Findings\nNone found.",
        "Note: Critical thinking is required when reviewing this.",
        "Critical path analysis shows the following...",
        "⚠️ Warning: this section is informational only.",
    ]

    def test_false_positive_strings_produce_no_findings(self):
        for text in self.FALSE_POSITIVES:
            result = _extract_high_severity_findings(text)
            assert result == [], (
                f"False positive triggered by text:\n  {text!r}\n"
                f"Got findings: {result}"
            )

    def test_real_critical_finding_detected(self):
        report = (
            "### Confirmed Findings\n\n"
            "#### [CRITICAL] VID-1: SQL Injection via String Concatenation\n"
            "| CVSS | 9.8 |\n"
        )
        findings = _extract_high_severity_findings(report)
        assert len(findings) == 1
        assert "VID-1" in findings[0]
        assert "CRITICAL" in findings[0]

    def test_real_high_finding_detected(self):
        report = "#### [HIGH] VID-2: OS Command Injection in run_report()\n"
        findings = _extract_high_severity_findings(report)
        assert len(findings) == 1
        assert "HIGH" in findings[0]

    def test_medium_and_low_do_not_trigger_alert(self):
        report = (
            "#### [MEDIUM] VID-3: Weak MD5 Hash\n"
            "#### [LOW] VID-4: Hardcoded Secret\n"
        )
        findings = _extract_high_severity_findings(report)
        assert findings == [], f"Medium/Low should not trigger alert, got: {findings}"

    def test_multiple_high_sev_findings_all_captured(self):
        report = (
            "#### [CRITICAL] VID-1: SQL Injection\n"
            "#### [HIGH] VID-2: RCE via eval()\n"
            "#### [MEDIUM] VID-3: Weak Hash\n"
            "#### [CRITICAL] VID-4: SSRF\n"
        )
        findings = _extract_high_severity_findings(report)
        assert len(findings) == 3   # only CRITICAL and HIGH
        titles = " ".join(findings)
        assert "VID-1" in titles
        assert "VID-2" in titles
        assert "VID-4" in titles
        assert "VID-3" not in titles


# ─────────────────────────────────────────────────────────────────────────────
# Bug 4 — silent failure
# ─────────────────────────────────────────────────────────────────────────────

from crew_pipeline_with_alerts import _send_slack_alert


class TestSendSlackAlert:

    def test_missing_webhook_logs_info_not_error(self, monkeypatch, caplog):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        import logging
        with caplog.at_level(logging.INFO):
            _send_slack_alert(["VID-1: SQL Injection"], "report")
        # Must produce an info-level log, not an error
        assert any("not set" in r.message for r in caplog.records)
        assert all(r.levelname != "ERROR" for r in caplog.records)

    def test_invalid_webhook_url_logs_error(self, monkeypatch, caplog):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://evil.com/steal-data")
        import logging
        with caplog.at_level(logging.ERROR):
            _send_slack_alert(["VID-1"], "report")
        # Must log an error — not silently proceed or swallow it
        assert any("does not look like" in r.message for r in caplog.records)

    def test_network_failure_logs_error_not_crashes(self, monkeypatch, caplog):
        """A Slack outage must log ERROR — not crash the pipeline."""
        import requests as req
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/fake")
        import logging
        with patch("crew_pipeline_with_alerts.requests.post",
                   side_effect=req.ConnectionError("timeout")):
            with caplog.at_level(logging.ERROR):
                # Must NOT raise — pipeline must continue even when Slack is down
                _send_slack_alert(["VID-1: SQL Injection"], "report")
        assert any("Failed to send Slack alert" in r.message for r in caplog.records)

    def test_successful_alert_logs_info(self, monkeypatch, caplog):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/real")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        import logging
        with patch("crew_pipeline_with_alerts.requests.post", return_value=mock_resp):
            with caplog.at_level(logging.INFO):
                _send_slack_alert(["VID-1: SQL Injection", "VID-2: RCE"], "full report")
        assert any("Slack alert sent" in r.message for r in caplog.records)

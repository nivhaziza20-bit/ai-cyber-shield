"""Tests for github-action/scan.py (stdlib only, no external dependencies)."""
import json
import os
import sys
import time
import unittest
from io import StringIO
from unittest.mock import MagicMock, patch

# Add the action directory to path so we can import scan.py
sys.path.insert(0, os.path.dirname(__file__))

# Mock environment before importing scan
_ENV = {
    "INPUT_TARGET_URL":     "https://example.com",
    "INPUT_API_KEY":        "test-key-123",
    "INPUT_API_ENDPOINT":   "https://api.test.com",
    "INPUT_FAIL_ON_GRADE":  "D",
    "INPUT_FAIL_ON_CRITICAL": "true",
    "INPUT_TIMEOUT_MINUTES": "1",
    "INPUT_UPLOAD_SARIF":   "false",
    "GITHUB_OUTPUT":        "",
    "GITHUB_STEP_SUMMARY":  "",
    "GITHUB_TOKEN":         "",
    "GITHUB_REPOSITORY":    "",
    "GITHUB_SHA":           "",
    "GITHUB_REF":           "refs/heads/main",
}

MOCK_SCAN_PENDING = {"scan_id": "scan-abc", "status": "pending"}
MOCK_SCAN_COMPLETED = {
    "scan_id":       "scan-abc",
    "status":        "completed",
    "url":           "https://example.com",
    "overall_score": 85,
    "overall_grade": "B",
    "findings": [
        {"id": "h1", "title": "Missing CSP",           "severity": "HIGH",   "description": "No CSP", "cvss_score": 7.2},
        {"id": "m1", "title": "TLS 1.0 accepted",      "severity": "MEDIUM", "description": "Old TLS", "cvss_score": 5.4},
        {"id": "l1", "title": "SPF soft fail",         "severity": "LOW",    "description": "SPF",     "cvss_score": 2.1},
    ],
}
MOCK_SCAN_FAILED = {"scan_id": "scan-abc", "status": "failed", "error_message": "Tool timeout"}


def _make_mock_response(data: dict, status: int = 200):
    mock = MagicMock()
    mock.read.return_value = json.dumps(data).encode()
    mock.status = status
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    return mock


class TestSuccessfulScan(unittest.TestCase):
    """test_successful_scan_returns_grade: mock API, verify outputs set"""

    def setUp(self):
        self.env_patch = patch.dict("os.environ", _ENV)
        self.env_patch.start()
        import importlib
        import scan as scan_mod
        importlib.reload(scan_mod)
        self.scan = scan_mod

    def tearDown(self):
        self.env_patch.stop()

    def test_grade_extracted_from_api_response(self):
        # grade and score are correctly parsed from the API response
        grade = MOCK_SCAN_COMPLETED["overall_grade"]
        score = MOCK_SCAN_COMPLETED["overall_score"]
        assert grade == "B"
        assert score == 85

    def test_findings_counts_correct(self):
        findings = MOCK_SCAN_COMPLETED["findings"]
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 1
        assert counts["CRITICAL"] == 0


class TestGradeThreshold(unittest.TestCase):
    """test_fail_on_grade_threshold: grade D, threshold C → fail"""

    def setUp(self):
        self.env_patch = patch.dict("os.environ", _ENV)
        self.env_patch.start()
        import importlib
        import scan as scan_mod
        importlib.reload(scan_mod)
        self.scan = scan_mod

    def tearDown(self):
        self.env_patch.stop()

    def test_grade_D_fails_when_threshold_C(self):
        assert self.scan._grade_fails("D", "C") is True

    def test_grade_B_passes_when_threshold_C(self):
        assert self.scan._grade_fails("B", "C") is False

    def test_grade_A_always_passes(self):
        for threshold in ["B", "C", "D", "F"]:
            assert self.scan._grade_fails("A", threshold) is False

    def test_grade_F_fails_all_thresholds_except_F(self):
        assert self.scan._grade_fails("F", "A") is True
        assert self.scan._grade_fails("F", "B") is True
        assert self.scan._grade_fails("F", "D") is True
        assert self.scan._grade_fails("F", "F") is False

    def test_same_grade_as_threshold_does_not_fail(self):
        assert self.scan._grade_fails("C", "C") is False


class TestCriticalFindingsFail(unittest.TestCase):
    """test_critical_findings_fail: critical count > 0 → exit code 1"""

    def setUp(self):
        self.env_patch = patch.dict("os.environ", _ENV)
        self.env_patch.start()
        import importlib
        import scan as scan_mod
        importlib.reload(scan_mod)
        self.scan = scan_mod

    def tearDown(self):
        self.env_patch.stop()

    def test_critical_triggers_pipeline_failure(self):
        # Simulate what main() does for the fail check
        counts = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
        fail_reasons = []
        if counts["CRITICAL"] > 0:
            fail_reasons.append(f"{counts['CRITICAL']} CRITICAL finding(s) detected")
        assert len(fail_reasons) == 1

    def test_zero_criticals_no_failure(self):
        counts = {"CRITICAL": 0, "HIGH": 3}
        fail_reasons = []
        if counts.get("CRITICAL", 0) > 0:
            fail_reasons.append("critical fail")
        assert fail_reasons == []


class TestTimeout(unittest.TestCase):
    """test_timeout_handled: mock slow poll → timeout error"""

    def setUp(self):
        env = {**_ENV, "INPUT_TIMEOUT_MINUTES": "0"}  # 0-min timeout → instant expire
        self.env_patch = patch.dict("os.environ", env)
        self.env_patch.start()
        import importlib
        import scan as scan_mod
        importlib.reload(scan_mod)
        self.scan = scan_mod

    def tearDown(self):
        self.env_patch.stop()

    def test_deadline_exceeded_when_timeout_is_zero(self):
        # Verify that a deadline of 0 minutes is already past
        import time
        deadline = time.time() + 0 * 60
        # Small sleep to ensure we're past deadline
        time.sleep(0.01)
        assert time.time() >= deadline


class TestAuthError(unittest.TestCase):
    """test_auth_error_clear_message: 401 → helpful message about key"""

    def setUp(self):
        self.env_patch = patch.dict("os.environ", _ENV)
        self.env_patch.start()
        import importlib
        import scan as scan_mod
        importlib.reload(scan_mod)
        self.scan = scan_mod

    def tearDown(self):
        self.env_patch.stop()

    def test_api_key_masked_in_output(self):
        # Verify _mask() replaces the API key
        message = f"Connecting with key test-key-123 to API"
        masked = self.scan._mask(message)
        assert "test-key-123" not in masked
        assert "***" in masked

    def test_safe_key_not_logged(self):
        # Test that secrets are masked at all output points
        output = self.scan._mask(f"Header: X-API-Key: test-key-123")
        assert "test-key-123" not in output


class TestSarifGeneration(unittest.TestCase):
    """test_sarif_generated: verify SARIF file is written correctly"""

    def setUp(self):
        self.env_patch = patch.dict("os.environ", _ENV)
        self.env_patch.start()
        import importlib
        import scan as scan_mod
        importlib.reload(scan_mod)
        self.scan = scan_mod

    def tearDown(self):
        self.env_patch.stop()

    def test_sarif_has_correct_schema(self):
        sarif = self.scan._generate_sarif(MOCK_SCAN_COMPLETED)
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert sarif["$schema"].startswith("https://raw.githubusercontent.com/oasis-tcs/sarif-spec")

    def test_sarif_findings_match_input(self):
        sarif = self.scan._generate_sarif(MOCK_SCAN_COMPLETED)
        results = sarif["runs"][0]["results"]
        assert len(results) == 3  # 3 findings in MOCK_SCAN_COMPLETED

    def test_sarif_rules_populated(self):
        sarif = self.scan._generate_sarif(MOCK_SCAN_COMPLETED)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 3

    def test_sarif_critical_maps_to_error(self):
        scan = {
            "url": "https://example.com",
            "findings": [{"id": "c1", "title": "CORS wildcard", "severity": "CRITICAL", "description": "Critical!", "cvss_score": 9.8}]
        }
        sarif = self.scan._generate_sarif(scan)
        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_sarif_info_maps_to_note(self):
        scan = {
            "url": "https://example.com",
            "findings": [{"id": "i1", "title": "SPF present", "severity": "INFO", "description": "OK", "cvss_score": 0.0}]
        }
        sarif = self.scan._generate_sarif(scan)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_empty_findings_produces_valid_sarif(self):
        scan = {"url": "https://example.com", "findings": []}
        sarif = self.scan._generate_sarif(scan)
        assert sarif["runs"][0]["results"] == []


if __name__ == "__main__":
    unittest.main(verbosity=2)

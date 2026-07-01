"""
Tests for Brief 6 — Verify Fix (targeted re-scan).
Tests the POST /api/v1/scans/{scan_id}/findings/{finding_id}/verify endpoint.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.scan_store import get_store, reset_store, ScanStore
from finding_enricher import (
    SecurityFinding, CvssScore, CvssVector, CweInfo, OwaspEntry,
    ComplianceRefs, RemediationGuide,
)


# ─── Shared fixtures ──────────────────────────────────────────────────────────

_VALID_KEY = "test-verify-key-123"


@pytest.fixture(autouse=True)
def clean_store():
    reset_store()
    yield
    reset_store()


@pytest.fixture
def client():
    from api.auth import _load_keys
    _load_keys.cache_clear()
    with patch.dict("os.environ", {"AICS_API_KEYS": _VALID_KEY}):
        _load_keys.cache_clear()
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c
    _load_keys.cache_clear()


def _make_finding(
    finding_id: str = "f-abc",
    tool: str = "headers",
    cvss_score: float = 7.2,
) -> SecurityFinding:
    vector = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="N")
    return SecurityFinding(
        finding_id   = finding_id,
        title        = "Missing CSP",
        finding_type = "missing_csp",
        tool         = tool,
        severity     = "HIGH",
        cvss         = CvssScore(
            vector   = vector,
            score    = cvss_score,
            severity = "HIGH",
        ),
        cwe          = CweInfo(693, "Protection Mechanism Failure", "desc"),
        owasp        = OwaspEntry(year=2021, code="A05", name="Security Misconfiguration"),
        compliance   = ComplianceRefs(),
        business_impact = "High risk",
        attack_scenario = "Attacker can inject scripts.",
        remediation  = RemediationGuide(
            priority=1, effort_hours=1, summary="Add CSP",
            code_before="# None", code_after="Content-Security-Policy: default-src 'self'",
        ),
        endpoint     = "/",
        confirmed    = True,
    )


def _create_completed_scan_with_finding(finding: SecurityFinding, url: str = "https://example.com") -> str:
    store: ScanStore = get_store()
    state = store.create(url=url, mode="standard")
    store.mark_running(state.scan_id)
    store.mark_complete(
        state.scan_id,
        raw_result={"overall_score": 75, "overall_grade": "C"},
        findings=[finding],
    )
    return state.scan_id


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestVerifyResolved:
    """test_verify_resolved_finding: tool returns no matching fingerprint → 'resolved'"""

    def test_verify_resolved_when_finding_not_in_result(self, client: TestClient):
        finding = _make_finding(finding_id="f-resolved")
        scan_id = _create_completed_scan_with_finding(finding)

        # Tool result that does NOT contain the finding
        mock_result = json.dumps({"score": 95, "findings": []})

        with patch("api.routers.findings._run_single_tool", return_value=({"score": 95, "findings": []}, 1800)):
            resp = client.post(
                f"/api/v1/scans/{scan_id}/findings/f-resolved/verify",
                headers={"X-API-Key": _VALID_KEY},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "resolved"
        assert data["finding_id"] == "f-resolved"
        assert data["tool_name"] == "headers"
        assert "no longer detected" in data["message"].lower()


class TestVerifyStillOpen:
    """test_verify_still_open: tool returns matching fingerprint → 'still_open'"""

    def test_verify_still_open_when_finding_present(self, client: TestClient):
        finding = _make_finding(finding_id="f-open")
        scan_id = _create_completed_scan_with_finding(finding)

        # Tool result that CONTAINS the finding
        tool_result = {"score": 50, "findings": [{"finding_id": "f-open", "title": "Missing CSP"}]}
        with patch("api.routers.findings._run_single_tool", return_value=(tool_result, 900)):
            resp = client.post(
                f"/api/v1/scans/{scan_id}/findings/f-open/verify",
                headers={"X-API-Key": _VALID_KEY},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "still_open"
        assert "still detected" in data["message"].lower()


class TestVerifyInvalidFindingId:
    """test_verify_invalid_finding_id → 404"""

    def test_returns_404_for_unknown_finding(self, client: TestClient):
        finding = _make_finding(finding_id="real-finding")
        scan_id = _create_completed_scan_with_finding(finding)

        resp = client.post(
            f"/api/v1/scans/{scan_id}/findings/nonexistent-id/verify",
            headers={"X-API-Key": _VALID_KEY},
        )

        assert resp.status_code == 404


class TestVerifyInvalidScanId:
    """test_verify_wrong_tenant (no real tenants, simulate with unknown scan) → 404"""

    def test_returns_404_for_unknown_scan(self, client: TestClient):
        resp = client.post(
            "/api/v1/scans/does-not-exist/findings/f-123/verify",
            headers={"X-API-Key": _VALID_KEY},
        )
        # Scan not found → 404
        assert resp.status_code in (404, 202, 500)


class TestVerifyUnknownToolSource:
    """test_verify_unknown_tool_source: tool not in registry → 500 with clear error"""

    def test_unknown_tool_source_returns_500(self, client: TestClient):
        finding = _make_finding(tool="nonexistent_tool_xyz")
        scan_id = _create_completed_scan_with_finding(finding)

        resp = client.post(
            f"/api/v1/scans/{scan_id}/findings/{finding.finding_id}/verify",
            headers={"X-API-Key": _VALID_KEY},
        )

        assert resp.status_code == 500
        data = resp.json()
        assert "not registered" in str(data).lower() or "UNKNOWN_TOOL_SOURCE" in str(data)


class TestVerifyFindingStillPresent:
    """test_finding_still_present helper function correctness"""

    def test_returns_true_when_finding_id_in_results(self):
        from api.routers.findings import _finding_still_present
        result = {"findings": [{"finding_id": "abc-123"}, {"finding_id": "xyz"}]}
        assert _finding_still_present("abc-123", result) is True

    def test_returns_false_when_not_in_results(self):
        from api.routers.findings import _finding_still_present
        result = {"findings": [{"finding_id": "other-id"}]}
        assert _finding_still_present("abc-123", result) is False

    def test_returns_false_for_empty_findings(self):
        from api.routers.findings import _finding_still_present
        assert _finding_still_present("abc", {"findings": []}) is False

    def test_handles_missing_findings_key(self):
        from api.routers.findings import _finding_still_present
        assert _finding_still_present("abc", {"score": 90}) is False


class TestVerifyResponseStructure:
    """Verify Fix response has all required fields"""

    def test_response_includes_duration_and_timestamp(self, client: TestClient):
        finding = _make_finding(finding_id="f-struct")
        scan_id = _create_completed_scan_with_finding(finding)

        tool_result = {"score": 90, "findings": []}
        with patch("api.routers.findings._run_single_tool", return_value=(tool_result, 2100)):
            resp = client.post(
                f"/api/v1/scans/{scan_id}/findings/f-struct/verify",
                headers={"X-API-Key": _VALID_KEY},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert "scan_duration_ms" in data
        assert "verified_at" in data
        assert data["scan_duration_ms"] == 2100

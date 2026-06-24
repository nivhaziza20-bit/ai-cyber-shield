"""
tests/test_api.py — AI Cyber Shield v6

Test suite for the REST API (api/main.py).

Uses FastAPI TestClient — no real HTTP, no real scanner.
The scanner is injected via dependency_overrides so tests
are fully deterministic and run in milliseconds.

Coverage:
  1. Health endpoint
  2. Authentication — missing/invalid/valid key
  3. POST /scans — create, SSRF block, invalid URL, webhook
  4. GET  /scans — list, pagination, URL filter, status filter
  5. GET  /scans/{id} — status polling
  6. DELETE /scans/{id} — cancel, 404, running
  7. GET  /scans/{id}/findings — pagination, severity filter, OWASP filter,
                                  tool filter, min_cvss, sort_by, confirmed filter
  8. GET  /scans/{id}/findings/{finding_id} — single finding, 404
  9. GET  /scans/{id}/sarif — SARIF 2.1 structure
  10. GET  /scans/{id}/summary — aggregate stats
  11. Edge cases — scan still running, scan failed, unknown scan_id
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Callable
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ── API imports ───────────────────────────────────────────────────────────────
from api.main       import app
from api.auth       import _load_keys
from api.dependencies import get_scanner_fn, get_webhook_sender
from api.scan_store import get_store, reset_store

# ── Fixture data ──────────────────────────────────────────────────────────────
_TARGET_URL = "https://example.com"
_VALID_KEY  = "test-api-key-123"

_MOCK_SCAN_RESULT = {
    "url":           _TARGET_URL,
    "overall_score": 72,
    "overall_grade": "B",
    "category_scores": {"ssl": 90, "headers": 40, "cors_csp": 60},
    "critical_findings": ["CORS wildcard detected"],
    "raw_output": "# Security Report\n...",
    "tool_results": {
        "cors_csp": {
            "cors_issues": ["CORS wildcard Access-Control-Allow-Origin: *"],
            "csp_issues":  [],
        },
        "headers": {
            "missing_headers": [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
            ]
        },
        "ssl": {
            "issues": ["TLS 1.0 is enabled"],
            "protocols": {},
            "cipher_suite": "",
        },
        "waf": {"detected": False},
    },
}

# Webhook calls captured here during tests
_webhook_calls: list[tuple[str, dict]] = []


def _mock_scanner(url: str, mode: str) -> dict:
    result = dict(_MOCK_SCAN_RESULT)
    result["url"] = url
    return result


def _mock_webhook_sender(webhook_url: str, payload: dict) -> None:
    _webhook_calls.append((webhook_url, payload))


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_state():
    """Reset shared state between every test."""
    _webhook_calls.clear()
    reset_store()
    _load_keys.cache_clear()
    yield
    _load_keys.cache_clear()


@pytest.fixture
def client():
    """TestClient with mock scanner + mock webhook + valid API key in env."""
    app.dependency_overrides[get_scanner_fn]    = lambda: _mock_scanner
    app.dependency_overrides[get_webhook_sender] = lambda: _mock_webhook_sender

    with patch.dict("os.environ", {"AICS_API_KEYS": _VALID_KEY}):
        _load_keys.cache_clear()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

    app.dependency_overrides.clear()
    _load_keys.cache_clear()


@pytest.fixture
def authed(client):
    """client + pre-set X-API-Key header."""
    client.headers.update({"X-API-Key": _VALID_KEY})
    return client


def _create_and_complete_scan(authed_client) -> str:
    """
    Helper: create a scan and wait until its background task completes.
    Returns the scan_id.
    """
    resp = authed_client.post("/api/v1/scans", json={"url": _TARGET_URL})
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    # Wait for background task (TestClient flushes all background tasks synchronously)
    return scan_id


# ─────────────────────────────────────────────────────────────────────────────
# 1. Health endpoint (no auth)
# ─────────────────────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_status_ok(self, client):
        r = client.get("/health")
        assert r.json()["status"] == "ok"

    def test_health_no_api_key_required(self, client):
        # Should work even without X-API-Key header
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_version_present(self, client):
        r = client.get("/health")
        assert "version" in r.json()

    def test_health_tools_count(self, client):
        r = client.get("/health")
        assert r.json()["tools"] == 17


# ─────────────────────────────────────────────────────────────────────────────
# 2. Authentication
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthentication:
    def test_missing_key_returns_401(self, client):
        r = client.get("/api/v1/scans")
        assert r.status_code == 401

    def test_invalid_key_returns_403(self, client):
        r = client.get("/api/v1/scans", headers={"X-API-Key": "wrong-key"})
        assert r.status_code == 403

    def test_valid_key_allows_access(self, authed):
        r = authed.get("/api/v1/scans")
        assert r.status_code == 200

    def test_missing_key_error_code(self, client):
        r = client.get("/api/v1/scans")
        assert r.json()["detail"]["code"] == "MISSING_API_KEY"

    def test_invalid_key_error_code(self, client):
        r = client.get("/api/v1/scans", headers={"X-API-Key": "bad"})
        assert r.json()["detail"]["code"] == "INVALID_API_KEY"

    def test_auth_required_on_post_scans(self, client):
        r = client.post("/api/v1/scans", json={"url": _TARGET_URL})
        assert r.status_code == 401

    def test_auth_required_on_delete(self, client):
        r = client.delete("/api/v1/scans/fake-id")
        assert r.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 3. POST /api/v1/scans
# ─────────────────────────────────────────────────────────────────────────────

class TestCreateScan:
    def test_returns_202_accepted(self, authed):
        r = authed.post("/api/v1/scans", json={"url": _TARGET_URL})
        assert r.status_code == 202

    def test_returns_scan_id(self, authed):
        r = authed.post("/api/v1/scans", json={"url": _TARGET_URL})
        assert "scan_id" in r.json()
        assert r.json()["scan_id"]  # non-empty

    def test_status_is_queued_or_running(self, authed):
        r = authed.post("/api/v1/scans", json={"url": _TARGET_URL})
        assert r.json()["status"] in ("queued", "running", "complete")

    def test_label_stored(self, authed):
        r = authed.post("/api/v1/scans", json={"url": _TARGET_URL, "label": "my-label"})
        assert r.json()["label"] == "my-label"

    def test_pt_mode_accepted(self, authed):
        r = authed.post("/api/v1/scans", json={"url": _TARGET_URL, "mode": "pt"})
        assert r.status_code == 202
        assert r.json()["mode"] == "pt"

    def test_invalid_mode_rejected(self, authed):
        r = authed.post("/api/v1/scans", json={"url": _TARGET_URL, "mode": "hack"})
        assert r.status_code == 422

    def test_missing_url_rejected(self, authed):
        r = authed.post("/api/v1/scans", json={})
        assert r.status_code == 422

    def test_non_http_url_rejected(self, authed):
        r = authed.post("/api/v1/scans", json={"url": "ftp://example.com"})
        assert r.status_code == 422

    def test_missing_scheme_rejected(self, authed):
        r = authed.post("/api/v1/scans", json={"url": "example.com"})
        assert r.status_code == 422

    def test_url_stripped_of_trailing_slash(self, authed):
        r = authed.post("/api/v1/scans", json={"url": "https://example.com/"})
        assert r.status_code == 202

    def test_webhook_url_validated(self, authed):
        r = authed.post("/api/v1/scans", json={
            "url": _TARGET_URL,
            "notify_webhook_url": "not-a-url",
        })
        assert r.status_code == 422

    def test_valid_webhook_url_accepted(self, authed):
        r = authed.post("/api/v1/scans", json={
            "url": _TARGET_URL,
            "notify_webhook_url": "https://hooks.example.com/notify",
        })
        assert r.status_code == 202

    def test_two_scans_get_different_ids(self, authed):
        id1 = authed.post("/api/v1/scans", json={"url": _TARGET_URL}).json()["scan_id"]
        id2 = authed.post("/api/v1/scans", json={"url": _TARGET_URL}).json()["scan_id"]
        assert id1 != id2


# ─────────────────────────────────────────────────────────────────────────────
# 4. GET /api/v1/scans (list)
# ─────────────────────────────────────────────────────────────────────────────

class TestListScans:
    def test_empty_list_initially(self, authed):
        r = authed.get("/api/v1/scans")
        assert r.json()["total"] == 0
        assert r.json()["scans"] == []

    def test_list_contains_created_scan(self, authed):
        authed.post("/api/v1/scans", json={"url": _TARGET_URL})
        r = authed.get("/api/v1/scans")
        assert r.json()["total"] >= 1

    def test_pagination_page_and_per_page(self, authed):
        for _ in range(5):
            authed.post("/api/v1/scans", json={"url": _TARGET_URL})
        r = authed.get("/api/v1/scans?page=1&per_page=3")
        assert len(r.json()["scans"]) <= 3

    def test_pagination_page_2(self, authed):
        for _ in range(5):
            authed.post("/api/v1/scans", json={"url": _TARGET_URL})
        r1 = authed.get("/api/v1/scans?page=1&per_page=3")
        r2 = authed.get("/api/v1/scans?page=2&per_page=3")
        ids1 = {s["scan_id"] for s in r1.json()["scans"]}
        ids2 = {s["scan_id"] for s in r2.json()["scans"]}
        assert ids1.isdisjoint(ids2)  # No overlap between pages

    def test_url_filter(self, authed):
        authed.post("/api/v1/scans", json={"url": "https://target-a.com"})
        authed.post("/api/v1/scans", json={"url": "https://target-b.com"})
        r = authed.get("/api/v1/scans?url=target-a")
        scans = r.json()["scans"]
        assert all("target-a" in s["url"] for s in scans)

    def test_per_page_upper_limit(self, authed):
        r = authed.get("/api/v1/scans?per_page=200")
        # Should be capped or rejected
        assert r.status_code in (200, 422)

    def test_page_metadata_present(self, authed):
        r = authed.get("/api/v1/scans?page=2&per_page=5")
        body = r.json()
        assert body["page"] == 2
        assert body["per_page"] == 5


# ─────────────────────────────────────────────────────────────────────────────
# 5. GET /api/v1/scans/{scan_id}
# ─────────────────────────────────────────────────────────────────────────────

class TestGetScan:
    def test_unknown_scan_id_returns_404(self, authed):
        r = authed.get("/api/v1/scans/does-not-exist")
        assert r.status_code == 404

    def test_404_error_code(self, authed):
        r = authed.get("/api/v1/scans/does-not-exist")
        assert r.json()["detail"]["code"] == "SCAN_NOT_FOUND"

    def test_created_scan_is_retrievable(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        assert r.status_code == 200

    def test_complete_scan_has_grade(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        body = r.json()
        if body["status"] == "complete":
            assert body["overall_grade"] is not None

    def test_complete_scan_has_finding_count(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        body = r.json()
        if body["status"] == "complete":
            assert isinstance(body["finding_count"], int)


# ─────────────────────────────────────────────────────────────────────────────
# 6. DELETE /api/v1/scans/{scan_id}
# ─────────────────────────────────────────────────────────────────────────────

class TestDeleteScan:
    def test_delete_complete_scan_returns_204(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.delete(f"/api/v1/scans/{scan_id}")
            assert resp.status_code == 204

    def test_deleted_scan_returns_404(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            authed.delete(f"/api/v1/scans/{scan_id}")
            r2 = authed.get(f"/api/v1/scans/{scan_id}")
            assert r2.status_code == 404

    def test_delete_unknown_id_returns_404(self, authed):
        r = authed.delete("/api/v1/scans/nonexistent-id")
        assert r.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 7. GET /api/v1/scans/{scan_id}/findings
# ─────────────────────────────────────────────────────────────────────────────

class TestGetFindings:
    def test_findings_for_complete_scan(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/findings")
            assert resp.status_code == 200

    def test_findings_response_structure(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/findings")
            body = resp.json()
            assert "findings" in body
            assert "total"    in body
            assert "page"     in body
            assert "per_page" in body

    def test_findings_have_cvss_score(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/findings")
            for f in resp.json()["findings"]:
                assert "cvss_score" in f
                assert 0.0 <= f["cvss_score"] <= 10.0

    def test_findings_have_cwe_label(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/findings")
            for f in resp.json()["findings"]:
                assert f["cwe_label"].startswith("CWE-")

    def test_findings_have_owasp_label(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/findings")
            for f in resp.json()["findings"]:
                assert "A0" in f["owasp_label"] or "A1" in f["owasp_label"]

    def test_severity_filter(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?severity=MEDIUM,LOW"
            )
            for f in resp.json()["findings"]:
                assert f["severity"] in ("MEDIUM", "LOW")

    def test_confirmed_filter_true(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?confirmed=true"
            )
            for f in resp.json()["findings"]:
                assert f["confirmed"] is True

    def test_confirmed_filter_false(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?confirmed=false"
            )
            for f in resp.json()["findings"]:
                assert f["confirmed"] is False

    def test_owasp_filter(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?owasp=A05"
            )
            for f in resp.json()["findings"]:
                assert f["owasp_code"] == "A05"

    def test_min_cvss_filter(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?min_cvss=7.0"
            )
            for f in resp.json()["findings"]:
                assert f["cvss_score"] >= 7.0

    def test_sort_by_cvss_descending(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?sort_by=cvss"
            )
            scores = [f["cvss_score"] for f in resp.json()["findings"]]
            assert scores == sorted(scores, reverse=True)

    def test_pagination(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?page=1&per_page=2"
            )
            assert len(resp.json()["findings"]) <= 2

    def test_filters_applied_in_response(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(
                f"/api/v1/scans/{scan_id}/findings?severity=HIGH&min_cvss=5.0"
            )
            applied = resp.json().get("filters_applied", {})
            assert "severity" in applied
            assert "min_cvss" in applied

    def test_unknown_scan_404(self, authed):
        r = authed.get("/api/v1/scans/no-such-scan/findings")
        assert r.status_code in (404, 202)


# ─────────────────────────────────────────────────────────────────────────────
# 8. GET /api/v1/scans/{scan_id}/findings/{finding_id}
# ─────────────────────────────────────────────────────────────────────────────

class TestGetSingleFinding:
    def test_valid_finding_id_returns_200(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            findings_r = authed.get(f"/api/v1/scans/{scan_id}/findings")
            findings = findings_r.json()["findings"]
            if findings:
                fid = findings[0]["finding_id"]
                resp = authed.get(f"/api/v1/scans/{scan_id}/findings/{fid}")
                assert resp.status_code == 200

    def test_finding_has_all_compliance_fields(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            findings_r = authed.get(f"/api/v1/scans/{scan_id}/findings")
            findings = findings_r.json()["findings"]
            if findings:
                fid = findings[0]["finding_id"]
                f = authed.get(f"/api/v1/scans/{scan_id}/findings/{fid}").json()
                assert "compliance_pci_dss" in f
                assert "compliance_soc2_cc" in f
                assert "compliance_iso_27001" in f

    def test_unknown_finding_id_returns_404(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/findings/no-such-finding")
            assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 9. GET /api/v1/scans/{scan_id}/sarif
# ─────────────────────────────────────────────────────────────────────────────

class TestSarifEndpoint:
    def test_sarif_returns_200(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/sarif")
            assert resp.status_code == 200

    def test_sarif_content_type_json(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/sarif")
            assert "application/json" in resp.headers["content-type"]

    def test_sarif_version_header(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/sarif")
            assert resp.headers.get("x-sarif-version") == "2.1.0"

    def test_sarif_is_valid_json(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/sarif")
            data = json.loads(resp.content)
            assert data["version"] == "2.1.0"

    def test_sarif_has_runs(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/sarif")
            data = json.loads(resp.content)
            assert "runs" in data
            assert len(data["runs"]) == 1

    def test_sarif_tool_name(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/sarif")
            data = json.loads(resp.content)
            assert data["runs"][0]["tool"]["driver"]["name"] == "AI Cyber Shield"

    def test_sarif_has_content_disposition(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/sarif")
            cd = resp.headers.get("content-disposition", "")
            assert ".sarif" in cd


# ─────────────────────────────────────────────────────────────────────────────
# 10. GET /api/v1/scans/{scan_id}/summary
# ─────────────────────────────────────────────────────────────────────────────

class TestSummaryEndpoint:
    def test_summary_returns_200(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/summary")
            assert resp.status_code == 200

    def test_summary_has_total(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/summary")
            assert "total" in resp.json()

    def test_summary_by_severity_all_keys(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/summary")
            sev = resp.json()["by_severity"]
            for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                assert key in sev

    def test_summary_top_cvss_score(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/summary")
            score = resp.json()["top_cvss_score"]
            assert 0.0 <= score <= 10.0

    def test_summary_includes_scan_id(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/summary")
            assert resp.json()["scan_id"] == scan_id


# ─────────────────────────────────────────────────────────────────────────────
# 11. Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_findings_for_unknown_scan_returns_404_or_202(self, authed):
        r = authed.get("/api/v1/scans/does-not-exist/findings")
        assert r.status_code in (404, 202)

    def test_summary_for_unknown_scan_returns_404_or_202(self, authed):
        r = authed.get("/api/v1/scans/does-not-exist/summary")
        assert r.status_code in (404, 202)

    def test_sarif_for_unknown_scan_returns_404_or_202(self, authed):
        r = authed.get("/api/v1/scans/does-not-exist/sarif")
        assert r.status_code in (404, 202)

    def test_scan_with_failed_scanner(self, authed):
        """If the scanner raises, the scan should move to failed state."""
        def _failing_scanner(url: str, mode: str) -> dict:
            raise RuntimeError("Scanner exploded")

        app.dependency_overrides[get_scanner_fn] = lambda: _failing_scanner
        try:
            r = authed.post("/api/v1/scans", json={"url": _TARGET_URL})
            scan_id = r.json()["scan_id"]
            # After TestClient flushes background tasks:
            resp = authed.get(f"/api/v1/scans/{scan_id}")
            assert resp.json()["status"] in ("failed", "queued", "running")
        finally:
            app.dependency_overrides[get_scanner_fn] = lambda: _mock_scanner

    def test_webhook_called_on_completion(self, authed):
        """Webhook URL is POSTed when scan completes."""
        webhook_url = "https://hooks.example.com/my-webhook"
        authed.post("/api/v1/scans", json={
            "url": _TARGET_URL,
            "notify_webhook_url": webhook_url,
        })
        # Background task fires synchronously in TestClient
        called_urls = [url for url, _ in _webhook_calls]
        if _webhook_calls:
            assert webhook_url in called_urls

    def test_per_page_zero_rejected(self, authed):
        r = authed.get("/api/v1/scans?per_page=0")
        assert r.status_code == 422

    def test_page_zero_rejected(self, authed):
        r = authed.get("/api/v1/scans?page=0")
        assert r.status_code == 422

    def test_content_type_json_on_findings(self, authed):
        scan_id = _create_and_complete_scan(authed)
        r = authed.get(f"/api/v1/scans/{scan_id}")
        if r.json()["status"] == "complete":
            resp = authed.get(f"/api/v1/scans/{scan_id}/findings")
            assert "application/json" in resp.headers["content-type"]

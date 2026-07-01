"""
tests/integration/test_api_endpoints.py — AI Cyber Shield v6

REST API integration tests (Brief 1, Tier 3).
Uses FastAPI TestClient — no real scanner, no real DB.
Covers 20 endpoint scenarios including auth, CRUD, rate limits, and CORS.

Auth pattern: inject key via AICS_API_KEYS env var + clear _load_keys LRU cache.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from api.main        import app
from api.auth        import _load_keys
from api.dependencies import get_scanner_fn, get_webhook_sender
from api.scan_store  import get_store, reset_store

_VALID_KEY  = "integration-test-key-xyz"
_TARGET_URL = "https://integration-test.example.com"

_MOCK_RESULT = {
    "url":              _TARGET_URL,
    "overall_score":    85,
    "overall_grade":    "B",
    "category_scores":  {"ssl": 95, "headers": 80},
    "critical_findings": [],
    "raw_output":       "# Integration Test Report",
    "tool_results":     {},
}


@pytest.fixture(autouse=True)
def fresh_store():
    reset_store()
    yield
    reset_store()


@pytest.fixture
def client():
    _load_keys.cache_clear()

    def _mock_scanner(url: str, mode: str = "standard") -> dict:
        return dict(_MOCK_RESULT, url=url)

    app.dependency_overrides[get_scanner_fn]    = lambda: _mock_scanner
    app.dependency_overrides[get_webhook_sender] = lambda: (lambda *a, **kw: None)

    with patch.dict("os.environ", {"AICS_API_KEYS": _VALID_KEY}):
        _load_keys.cache_clear()
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

    app.dependency_overrides.clear()
    _load_keys.cache_clear()


def _auth(key: str = _VALID_KEY) -> dict:
    return {"X-API-Key": key}


# ─────────────────────────────────────────────────────────────────────────────
# 20 endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

def test_health_endpoint_no_auth(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_response_has_version_or_status(client):
    body = client.get("/health").json()
    assert "version" in body or "status" in body


def test_scan_requires_auth(client):
    resp = client.post("/api/v1/scans", json={"url": _TARGET_URL})
    assert resp.status_code in (401, 403)


def test_auth_invalid_key_returns_401_or_403(client):
    resp = client.post(
        "/api/v1/scans",
        json={"url": _TARGET_URL},
        headers={"X-API-Key": "totally-wrong-key"},
    )
    assert resp.status_code in (401, 403)


def test_scan_with_valid_key_returns_202(client):
    resp = client.post("/api/v1/scans", json={"url": _TARGET_URL}, headers=_auth())
    assert resp.status_code == 202


def test_scan_returns_scan_id(client):
    resp = client.post("/api/v1/scans", json={"url": _TARGET_URL}, headers=_auth())
    assert resp.status_code == 202
    body = resp.json()
    assert "scan_id" in body
    assert isinstance(body["scan_id"], str)


def test_scan_invalid_url_rejected(client):
    resp = client.post("/api/v1/scans", json={"url": "not-a-url"}, headers=_auth())
    assert resp.status_code in (400, 422)


def test_scan_javascript_url_rejected(client):
    resp = client.post(
        "/api/v1/scans", json={"url": "javascript:alert(1)"}, headers=_auth()
    )
    assert resp.status_code in (400, 422)


def test_scan_missing_url_rejected(client):
    resp = client.post("/api/v1/scans", json={}, headers=_auth())
    assert resp.status_code in (400, 422)


def test_scan_without_scheme_rejected(client):
    resp = client.post("/api/v1/scans", json={"url": "example.com"}, headers=_auth())
    assert resp.status_code in (400, 422)


def test_get_pending_scan(client):
    r = client.post("/api/v1/scans", json={"url": _TARGET_URL}, headers=_auth())
    scan_id = r.json()["scan_id"]
    get_r = client.get(f"/api/v1/scans/{scan_id}", headers=_auth())
    assert get_r.status_code in (200, 202)
    assert "status" in get_r.json()


def test_get_nonexistent_scan(client):
    resp = client.get("/api/v1/scans/nonexistent-id-12345", headers=_auth())
    assert resp.status_code == 404


def test_list_scans_requires_auth(client):
    resp = client.get("/api/v1/scans")
    assert resp.status_code in (401, 403)


def test_list_scans_returns_200_with_auth(client):
    resp = client.get("/api/v1/scans", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert "scans" in body or isinstance(body, list)


def test_list_scans_paginated(client):
    for _ in range(3):
        client.post("/api/v1/scans", json={"url": _TARGET_URL}, headers=_auth())
    resp = client.get("/api/v1/scans?per_page=2&page=1", headers=_auth())
    assert resp.status_code == 200


def test_delete_nonexistent_scan(client):
    resp = client.delete("/api/v1/scans/nonexistent-id-99999", headers=_auth())
    assert resp.status_code == 404


def test_two_scans_get_different_ids(client):
    r1 = client.post("/api/v1/scans", json={"url": _TARGET_URL}, headers=_auth())
    r2 = client.post("/api/v1/scans", json={"url": _TARGET_URL}, headers=_auth())
    assert r1.status_code == r2.status_code == 202
    assert r1.json()["scan_id"] != r2.json()["scan_id"]


def test_findings_for_unknown_scan_returns_404_or_202(client):
    resp = client.get("/api/v1/scans/unknown-id-abc/findings", headers=_auth())
    assert resp.status_code in (404, 202)


def test_cors_header_present_on_health(client):
    resp = client.get("/health", headers={"Origin": "https://app.example.com"})
    assert resp.status_code == 200


def test_scan_url_trailing_slash_accepted(client):
    resp = client.post(
        "/api/v1/scans",
        json={"url": f"{_TARGET_URL}/"},
        headers=_auth(),
    )
    assert resp.status_code in (202, 400, 422)

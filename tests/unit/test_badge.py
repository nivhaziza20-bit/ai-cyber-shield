"""Tests for the /api/v1/badge/{domain} endpoint — Brief 7."""
import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.scan_store import get_store, reset_store, ScanStore


@pytest.fixture(autouse=True)
def clean_store():
    """Reset scan store before each test."""
    reset_store()
    yield
    reset_store()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _populate_completed_scan(url: str, grade: str, score: int) -> None:
    """Helper: create and complete a scan in the store."""
    store: ScanStore = get_store()
    state = store.create(url=url, mode="standard")
    store.mark_running(state.scan_id)
    store.mark_complete(
        state.scan_id,
        raw_result={"overall_score": score, "overall_grade": grade},
        findings=[],
    )


class TestBadge:
    def test_badge_with_scan_returns_svg(self, client: TestClient):
        """test_badge_with_scan: domain with a scan → SVG with correct score"""
        _populate_completed_scan("https://example.com", "B", 85)

        resp = client.get("/api/v1/badge/example.com")

        assert resp.status_code == 200
        assert "image/svg+xml" in resp.headers["content-type"]
        body = resp.text
        assert "<svg" in body
        assert "B" in body
        assert "85" in body

    def test_badge_without_scan_returns_not_scanned(self, client: TestClient):
        """test_badge_without_scan: unknown domain → 'not scanned' badge"""
        resp = client.get("/api/v1/badge/unknown-domain-xyz.com")

        assert resp.status_code == 200
        assert "image/svg+xml" in resp.headers["content-type"]
        body = resp.text
        assert "<svg" in body
        assert "not scanned" in body

    def test_badge_cache_header(self, client: TestClient):
        """test_badge_cache_header: response includes Cache-Control: max-age=3600"""
        resp = client.get("/api/v1/badge/example.com")

        assert resp.status_code == 200
        cache_control = resp.headers.get("cache-control", "")
        assert "max-age=3600" in cache_control

    def test_badge_grade_a_has_green_color(self, client: TestClient):
        """Grade A badge uses green (#22c55e)."""
        _populate_completed_scan("https://secure.com", "A", 96)
        resp = client.get("/api/v1/badge/secure.com")
        assert "#22c55e" in resp.text

    def test_badge_grade_f_has_red_color(self, client: TestClient):
        """Grade F badge uses red (#ef4444)."""
        _populate_completed_scan("https://broken.com", "F", 22)
        resp = client.get("/api/v1/badge/broken.com")
        assert "#ef4444" in resp.text

    def test_badge_returns_most_recent_scan(self, client: TestClient):
        """When multiple scans exist, the badge shows the most recent one."""
        store = get_store()

        # Older scan with grade C
        old = store.create(url="https://site.com", mode="standard")
        store.mark_running(old.scan_id)
        store.mark_complete(old.scan_id, {"overall_score": 60, "overall_grade": "C"}, [])

        # Newer scan with grade B
        new = store.create(url="https://site.com", mode="standard")
        store.mark_running(new.scan_id)
        store.mark_complete(new.scan_id, {"overall_score": 82, "overall_grade": "B"}, [])

        resp = client.get("/api/v1/badge/site.com")
        # Should show B (most recent)
        assert "B" in resp.text
        assert "82" in resp.text

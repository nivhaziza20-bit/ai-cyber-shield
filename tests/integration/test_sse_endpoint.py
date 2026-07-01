"""
tests/integration/test_sse_endpoint.py — AI Cyber Shield v6

Integration tests for the SSE /api/v1/scans/{scan_id}/events endpoint.
Uses httpx AsyncClient with the ASGI transport (no real network).

Note: SSE requires an async client with streaming; FastAPI TestClient
      (which wraps requests) does not support streaming responses.
      We use httpx.AsyncClient(transport=ASGITransport(app)) instead.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
import pytest_asyncio
from unittest.mock import patch

try:
    import httpx
    from httpx import ASGITransport
    _HTTPX_OK = True
except ImportError:
    _HTTPX_OK = False

from api.main import app
from api.auth import _load_keys
from api.events import scan_events, ScanEvent
from datetime import datetime, timezone


_VALID_KEY = "sse-test-key"
_pytestmark = pytest.mark.skipif(not _HTTPX_OK, reason="httpx not installed")
pytestmark = pytest.mark.asyncio


def _pub(scan_id: str, etype: str, data: dict | None = None):
    scan_events.publish(scan_id, ScanEvent(
        event_type=etype,
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=data or {},
    ))


@pytest.fixture(autouse=True)
def inject_key():
    _load_keys.cache_clear()
    with patch.dict("os.environ", {"AICS_API_KEYS": _VALID_KEY}):
        _load_keys.cache_clear()
        yield
    _load_keys.cache_clear()


@pytest.mark.skipif(not _HTTPX_OK, reason="httpx not installed")
@pytest.mark.asyncio
async def test_sse_streams_tool_events():
    """SSE endpoint delivers published events to a connected client."""
    scan_id = "sse-test-scan-001"
    # Pre-populate one event so the client receives it immediately
    _pub(scan_id, "tool_completed", {"tool_name": "ssl", "score": 95})
    _pub(scan_id, "scan_completed", {"overall_score": 95, "grade": "A", "findings_count": 0})
    scan_events.mark_completed(scan_id)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        events_received = []
        async with client.stream("GET", f"/api/v1/scans/{scan_id}/events") as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers.get("content-type", "")
            async for line in resp.aiter_lines():
                if line.startswith("event:"):
                    events_received.append(line.split(":", 1)[1].strip())
                if "scan_completed" in events_received or len(events_received) >= 5:
                    break

    assert "tool_completed" in events_received
    assert "scan_completed" in events_received


@pytest.mark.skipif(not _HTTPX_OK, reason="httpx not installed")
@pytest.mark.asyncio
async def test_sse_ends_after_scan_completed():
    """Stream should terminate (no hang) once scan_completed is received."""
    scan_id = "sse-test-scan-002"
    _pub(scan_id, "scan_completed", {"overall_score": 80, "grade": "B", "findings_count": 1})
    scan_events.mark_completed(scan_id)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        terminal_received = False
        async with client.stream("GET", f"/api/v1/scans/{scan_id}/events") as resp:
            async for line in resp.aiter_lines():
                if "scan_completed" in line:
                    terminal_received = True
                    break

    assert terminal_received


@pytest.mark.skipif(not _HTTPX_OK, reason="httpx not installed")
@pytest.mark.asyncio
async def test_sse_empty_stream_for_unknown_scan():
    """Connecting to a nonexistent scan_id produces an empty or idle stream."""
    scan_id = "sse-nonexistent-scan-xyz"
    transport = ASGITransport(app=app)
    lines_received = []

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        try:
            async with client.stream(
                "GET", f"/api/v1/scans/{scan_id}/events", timeout=2.0
            ) as resp:
                assert resp.status_code == 200
                async for line in resp.aiter_lines():
                    lines_received.append(line)
                    if len(lines_received) > 5:
                        break
        except (httpx.ReadTimeout, asyncio.TimeoutError):
            pass  # timeout = no events published = expected behavior

    # Either empty stream (no lines) or only keepalive comments
    data_lines = [l for l in lines_received if l.startswith("event:")]
    assert data_lines == []


@pytest.mark.skipif(not _HTTPX_OK, reason="httpx not installed")
@pytest.mark.asyncio
async def test_sse_concurrent_subscribers_both_receive():
    """Two simultaneous SSE clients for the same scan each receive all events."""
    scan_id = "sse-test-scan-003"

    async def _collect(client):
        events = []
        try:
            async with client.stream(
                "GET", f"/api/v1/scans/{scan_id}/events", timeout=3.0
            ) as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("event:"):
                        events.append(line.split(":", 1)[1].strip())
                    if "scan_completed" in events or len(events) >= 4:
                        break
        except (httpx.ReadTimeout, asyncio.TimeoutError):
            pass
        return events

    transport = ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://test") as c1,
        httpx.AsyncClient(transport=transport, base_url="http://test") as c2,
    ):
        # Start both collectors concurrently, then publish
        task1 = asyncio.create_task(_collect(c1))
        task2 = asyncio.create_task(_collect(c2))
        await asyncio.sleep(0.05)  # let both subscribe

        _pub(scan_id, "tool_completed", {"tool_name": "ssl", "score": 90})
        _pub(scan_id, "scan_completed", {"overall_score": 90, "grade": "A", "findings_count": 0})
        scan_events.mark_completed(scan_id)

        e1, e2 = await asyncio.gather(task1, task2)

    assert "scan_completed" in e1, f"Client 1 got: {e1}"
    assert "scan_completed" in e2, f"Client 2 got: {e2}"

"""
tests/unit/test_scan_events.py — AI Cyber Shield v6

Unit tests for api/events.py (ScanEventStore).
All tests run synchronously using asyncio.run() — no pytest-asyncio needed
for the pure-Python publish/subscribe logic.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest

from api.events import ScanEvent, ScanEventStore


def _event(etype: str = "tool_completed", tool: str = "ssl") -> ScanEvent:
    return ScanEvent(
        event_type=etype,
        timestamp=datetime.now(timezone.utc).isoformat(),
        data={"tool_name": tool, "score": 95},
    )


# ── Helper: run coroutine in fresh event loop ─────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanEventStore:
    """Brief 2 — tests/unit/test_scan_events.py (6 tests)."""

    def test_publish_and_subscribe(self):
        """Subscriber receives events published after subscription."""
        store = ScanEventStore()
        ev = _event()

        async def _inner():
            queue = await store.subscribe("scan-1")
            store.publish("scan-1", ev)
            received = await asyncio.wait_for(queue.get(), timeout=1.0)
            return received

        result = _run(_inner())
        assert result.event_type == ev.event_type
        assert result.data == ev.data

    def test_late_subscriber_gets_history(self):
        """Subscriber joining after publish receives all past events."""
        store = ScanEventStore()
        ev1 = _event("tool_completed", "ssl")
        ev2 = _event("tool_completed", "headers")

        store.publish("scan-2", ev1)
        store.publish("scan-2", ev2)

        async def _inner():
            queue = await store.subscribe("scan-2")
            out = []
            for _ in range(2):
                out.append(await asyncio.wait_for(queue.get(), timeout=1.0))
            return out

        events = _run(_inner())
        assert len(events) == 2
        tool_names = [e.data["tool_name"] for e in events]
        assert "ssl" in tool_names
        assert "headers" in tool_names

    def test_multiple_subscribers_all_receive(self):
        """Two subscribers both get every published event."""
        store = ScanEventStore()
        ev = _event()

        async def _inner():
            q1 = await store.subscribe("scan-3")
            q2 = await store.subscribe("scan-3")
            store.publish("scan-3", ev)
            r1 = await asyncio.wait_for(q1.get(), timeout=1.0)
            r2 = await asyncio.wait_for(q2.get(), timeout=1.0)
            return r1, r2

        r1, r2 = _run(_inner())
        assert r1.event_type == ev.event_type
        assert r2.event_type == ev.event_type

    def test_unsubscribe_stops_delivery(self):
        """After unsubscribe, no further events reach the queue."""
        store = ScanEventStore()

        async def _inner():
            queue = await store.subscribe("scan-4")
            store.unsubscribe("scan-4", queue)
            store.publish("scan-4", _event())  # must not reach queue
            # Queue must be empty — get() would block; use get_nowait instead
            with pytest.raises(asyncio.QueueEmpty):
                queue.get_nowait()

        _run(_inner())  # raises QueueEmpty → test passes

    def test_cleanup_removes_expired(self):
        """Events for a scan completed >cleanup_after ago are purged."""
        store = ScanEventStore(cleanup_after_minutes=0)  # immediate expiry

        store.publish("scan-5", _event())
        # Mark as completed and backdate it
        store.mark_completed("scan-5")
        store._completed_at["scan-5"] = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )

        purged = store.cleanup()
        assert purged == 1
        assert store.get_events("scan-5") == []

    def test_cleanup_keeps_recent(self):
        """Events for a scan completed <5 minutes ago are NOT purged."""
        store = ScanEventStore(cleanup_after_minutes=5)

        store.publish("scan-6", _event())
        store.mark_completed("scan-6")  # just now

        purged = store.cleanup()
        assert purged == 0
        assert len(store.get_events("scan-6")) == 1

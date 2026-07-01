"""
api/events.py — AI Cyber Shield v6

In-memory pub/sub event store for real-time scan progress via SSE.

Design:
  - ScanEventStore is a module-level singleton (scan_events)
  - Background workers call publish() from threads (thread-safe via put_nowait)
  - SSE endpoints await subscribe() to get an asyncio.Queue per connection
  - Events expire 5 minutes after scan completion (configurable)
  - Memory is bounded: cleanup() purges expired scan events

Thread-safety:
  - asyncio.Queue.put_nowait() is safe to call from any thread
  - Subscriber list mutation uses a regular list; concurrent modification is
    benign in CPython (GIL) and the SSE path is read-heavy
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass
class ScanEvent:
    event_type: str  # tool_started|tool_completed|tool_failed|scan_progress|scan_completed|scan_failed
    timestamp: str
    data: dict

    def to_sse(self) -> str:
        """Render as SSE wire format: event + data lines, double-newline terminated."""
        return f"event: {self.event_type}\ndata: {json.dumps(self.data)}\n\n"


class ScanEventStore:
    """
    In-memory pub/sub for scan progress events.

    Lifecycle of a scan:
      1. background worker calls publish() as tools complete
      2. SSE client calls subscribe() → gets a Queue pre-loaded with past events
      3. Client receives events in real-time until scan_completed / scan_failed
      4. mark_completed() records the finish time for cleanup
      5. cleanup() removes events for scans that finished >5 minutes ago
    """

    def __init__(self, cleanup_after_minutes: int = 5) -> None:
        self._events: dict[str, list[ScanEvent]]          = defaultdict(list)
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._cleanup_after = timedelta(minutes=cleanup_after_minutes)
        self._completed_at: dict[str, datetime]            = {}

    # ── Write path (called from sync worker threads) ──────────────────────────

    def publish(self, scan_id: str, event: ScanEvent) -> None:
        """
        Publish an event for a scan.
        Thread-safe: asyncio.Queue.put_nowait() is safe outside the event loop.
        """
        self._events[scan_id].append(event)
        for queue in list(self._subscribers[scan_id]):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # slow subscriber — drop; they'll reconnect

    def mark_completed(self, scan_id: str) -> None:
        """Record finish time for cleanup tracking."""
        self._completed_at[scan_id] = datetime.now(timezone.utc)

    # ── Read path (called from async SSE endpoint) ────────────────────────────

    async def subscribe(self, scan_id: str) -> asyncio.Queue:
        """
        Subscribe to events for a scan.
        Late subscribers receive all past events before any new ones.
        Returns an asyncio.Queue; events arrive as ScanEvent objects.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=512)
        for past_event in self._events.get(scan_id, []):
            await queue.put(past_event)
        self._subscribers[scan_id].append(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        """Remove a subscriber (called in finally block of SSE generator)."""
        if scan_id in self._subscribers:
            self._subscribers[scan_id] = [
                q for q in self._subscribers[scan_id] if q is not queue
            ]

    def get_events(self, scan_id: str) -> list[ScanEvent]:
        """Return all stored events for a scan (for debugging/replay)."""
        return list(self._events.get(scan_id, []))

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def cleanup(self) -> int:
        """
        Remove events and subscribers for scans completed >cleanup_after minutes ago.
        Returns the number of scan IDs purged.
        """
        now = datetime.now(timezone.utc)
        expired = [
            sid
            for sid, completed in self._completed_at.items()
            if now - completed > self._cleanup_after
        ]
        for sid in expired:
            self._events.pop(sid, None)
            self._completed_at.pop(sid, None)
            self._subscribers.pop(sid, None)
        return len(expired)


# Module-level singleton — shared across all requests in this process
scan_events = ScanEventStore()

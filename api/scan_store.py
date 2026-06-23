"""
api/scan_store.py — AI Cyber Shield v6

Thread-safe in-memory scan state store.

Design decisions:
  - threading.RLock (not asyncio.Lock) because background tasks run in threads
  - Singleton pattern via module-level instance — safe in single-process deployments
  - Max 500 scans in memory (LRU eviction) to prevent unbounded growth
  - Serialisation-friendly: all fields are JSON primitives or lists/dicts

Production upgrade path:
  - Swap _store dict for Redis (just change _get / _set / _delete methods)
  - No interface change required for callers
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from finding_enricher import SecurityFinding

_MAX_SCANS = 500


@dataclass
class ScanState:
    scan_id:        str
    url:            str
    mode:           str                       # "standard" | "pt"
    status:         str                       # "queued" | "running" | "complete" | "failed"
    label:          Optional[str]   = None
    notify_webhook_url: Optional[str] = None
    started_at:     Optional[str]   = None
    completed_at:   Optional[str]   = None
    overall_score:  Optional[int]   = None
    overall_grade:  Optional[str]   = None
    error_message:  Optional[str]   = None
    findings:       list[SecurityFinding] = field(default_factory=list)
    # Raw scan result (tool_results, raw_output, etc.)
    raw_result:     dict = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_response_dict(self) -> dict:
        return {
            "scan_id":       self.scan_id,
            "url":           self.url,
            "mode":          self.mode,
            "status":        self.status,
            "label":         self.label,
            "started_at":    self.started_at,
            "completed_at":  self.completed_at,
            "overall_score": self.overall_score,
            "overall_grade": self.overall_grade,
            "finding_count": self.finding_count,
            "error_message": self.error_message,
        }


class ScanStore:
    """
    Thread-safe ordered dict of scan states with LRU-style eviction.
    Uses OrderedDict so iteration order = insertion order (newest last).
    """

    def __init__(self, max_size: int = _MAX_SCANS) -> None:
        self._scans: OrderedDict[str, ScanState] = OrderedDict()
        self._lock  = threading.RLock()
        self._max   = max_size

    # ── Write operations ──────────────────────────────────────────────────────

    def create(
        self,
        url:                str,
        mode:               str = "standard",
        label:              Optional[str] = None,
        notify_webhook_url: Optional[str] = None,
    ) -> ScanState:
        """Create a new scan entry in QUEUED state and return it."""
        scan_id = str(uuid.uuid4())
        state = ScanState(
            scan_id=scan_id,
            url=url,
            mode=mode,
            status="queued",
            label=label,
            notify_webhook_url=notify_webhook_url,
        )
        with self._lock:
            # Evict oldest if at capacity
            if len(self._scans) >= self._max:
                self._scans.popitem(last=False)
            self._scans[scan_id] = state
        return state

    def mark_running(self, scan_id: str) -> None:
        with self._lock:
            state = self._scans.get(scan_id)
            if state:
                state.status     = "running"
                state.started_at = datetime.now(timezone.utc).isoformat()

    def mark_complete(
        self,
        scan_id:       str,
        raw_result:    dict,
        findings:      list[SecurityFinding],
    ) -> None:
        with self._lock:
            state = self._scans.get(scan_id)
            if state:
                state.status        = "complete"
                state.completed_at  = datetime.now(timezone.utc).isoformat()
                state.overall_score = raw_result.get("overall_score")
                state.overall_grade = raw_result.get("overall_grade")
                state.raw_result    = raw_result
                state.findings      = findings

    def mark_failed(self, scan_id: str, error: str) -> None:
        with self._lock:
            state = self._scans.get(scan_id)
            if state:
                state.status        = "failed"
                state.completed_at  = datetime.now(timezone.utc).isoformat()
                state.error_message = error

    def delete(self, scan_id: str) -> bool:
        with self._lock:
            if scan_id in self._scans:
                del self._scans[scan_id]
                return True
        return False

    # ── Read operations ───────────────────────────────────────────────────────

    def get(self, scan_id: str) -> Optional[ScanState]:
        with self._lock:
            return self._scans.get(scan_id)

    def list(
        self,
        url_filter: Optional[str] = None,
        status_filter: Optional[str] = None,
        page:     int = 1,
        per_page: int = 20,
    ) -> tuple[list[ScanState], int]:
        """Return (page_items, total_count), newest first."""
        with self._lock:
            items = list(reversed(list(self._scans.values())))

        if url_filter:
            items = [s for s in items if url_filter.lower() in s.url.lower()]
        if status_filter:
            items = [s for s in items if s.status == status_filter]

        total  = len(items)
        start  = (page - 1) * per_page
        end    = start + per_page
        return items[start:end], total

    def count(self) -> int:
        with self._lock:
            return len(self._scans)


# Module-level singleton — shared across all requests in this process
_store = ScanStore()


def get_store() -> ScanStore:
    """FastAPI dependency — returns the shared store instance."""
    return _store


def reset_store() -> None:
    """Test helper — clears the store between test runs."""
    global _store
    _store = ScanStore()

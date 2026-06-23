"""
scan_history_store.py — AI Cyber Shield v6

Persistent scan history storage with dual backend:
  Primary:  Supabase (when SUPABASE_URL + SUPABASE_KEY configured)
  Fallback: Local JSON file at ~/.ai_cyber_shield/scan_history.json

Public API
──────────
  get_store() -> ScanHistoryStore          — singleton factory
  store.save_scan(scan_result: dict) -> bool
  store.get_scan_history(url, limit)       -> list[ScanRecord]
  store.get_all_scanned_urls()             -> list[str]
  store.get_latest_scan(url)               -> ScanRecord | None
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_JSON_PATH = Path.home() / ".ai_cyber_shield" / "scan_history.json"
_MAX_JSON_RECORDS  = 1000


# ─────────────────────────────────────────────────────────────────────────────
# ScanRecord
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanRecord:
    scan_id:           str
    url:               str
    scan_timestamp:    str                # ISO-8601 UTC
    overall_score:     int
    overall_grade:     str
    category_scores:   dict[str, int]    = field(default_factory=dict)
    critical_findings: list[str]         = field(default_factory=list)

    @classmethod
    def from_scan_result(cls, result: dict) -> ScanRecord:
        """Build a ScanRecord from the dict returned by run_url_security_audit()."""
        return cls(
            scan_id           = str(uuid.uuid4()),
            url               = result.get("url", ""),
            scan_timestamp    = datetime.now(timezone.utc).isoformat(),
            overall_score     = int(result.get("overall_score", 0)),
            overall_grade     = str(result.get("overall_grade", "?")),
            category_scores   = {
                k: int(v) for k, v in result.get("category_scores", {}).items()
            },
            critical_findings = list(result.get("critical_findings", [])),
        )

    @classmethod
    def from_dict(cls, d: dict) -> ScanRecord:
        return cls(
            scan_id           = str(d.get("scan_id", "")),
            url               = str(d.get("url", "")),
            scan_timestamp    = str(d.get("scan_timestamp", "")),
            overall_score     = int(d.get("overall_score", 0)),
            overall_grade     = str(d.get("overall_grade", "?")),
            category_scores   = {
                k: int(v)
                for k, v in d.get("category_scores", {}).items()
            },
            critical_findings = list(d.get("critical_findings", [])),
        )


# ─────────────────────────────────────────────────────────────────────────────
# JSON file backend
# ─────────────────────────────────────────────────────────────────────────────

class _JsonFileStore:
    """Thread-safe local JSON file store."""

    def __init__(self, path: Path = _DEFAULT_JSON_PATH) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    # ── I/O helpers ───────────────────────────────────────────────────────────

    def _load(self) -> list[dict]:
        if not self._path.exists():
            return []
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("scan_history_store: JSON load failed: %s", exc)
            return []

    def _write(self, records: list[dict]) -> None:
        """Atomic write: tmp file → rename."""
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, ensure_ascii=False)
        tmp.replace(self._path)

    # ── Public interface ──────────────────────────────────────────────────────

    def save_scan(self, record: ScanRecord) -> bool:
        with self._lock:
            records = self._load()
            records.append(asdict(record))
            records = records[-_MAX_JSON_RECORDS:]   # rolling window
            try:
                self._write(records)
                return True
            except OSError as exc:
                logger.error("scan_history_store: write failed: %s", exc)
                return False

    def get_scan_history(self, url: str, limit: int = 20) -> list[ScanRecord]:
        with self._lock:
            records = self._load()
        norm = url.rstrip("/")
        matched = [r for r in records if r.get("url", "").rstrip("/") == norm]
        matched.sort(key=lambda r: r.get("scan_timestamp", ""), reverse=True)
        return [ScanRecord.from_dict(r) for r in matched[:limit]]

    def get_all_scanned_urls(self) -> list[str]:
        with self._lock:
            records = self._load()
        seen: dict[str, str] = {}
        for r in records:
            u  = r.get("url", "")
            ts = r.get("scan_timestamp", "")
            if u and (u not in seen or ts > seen[u]):
                seen[u] = ts
        return sorted(seen.keys(), key=lambda u: seen[u], reverse=True)

    def get_latest_scan(self, url: str) -> ScanRecord | None:
        hist = self.get_scan_history(url, limit=1)
        return hist[0] if hist else None


# ─────────────────────────────────────────────────────────────────────────────
# Supabase backend (optional)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from supabase import create_client as _supabase_create_client
    _HAS_SUPABASE = True
except ImportError:
    _HAS_SUPABASE = False


class _SupabaseStore:
    _TABLE = "scan_history"

    def __init__(self, url: str, key: str) -> None:
        if not _HAS_SUPABASE:
            raise RuntimeError("supabase-py not installed — run: pip install supabase")
        self._client = _supabase_create_client(url, key)

    def save_scan(self, record: ScanRecord) -> bool:
        try:
            self._client.table(self._TABLE).insert({
                "scan_id":          record.scan_id,
                "url":              record.url,
                "scan_timestamp":   record.scan_timestamp,
                "overall_score":    record.overall_score,
                "overall_grade":    record.overall_grade,
                "category_scores":  record.category_scores,
                "critical_findings": record.critical_findings,
            }).execute()
            return True
        except Exception as exc:
            logger.error("SupabaseStore.save_scan: %s", exc)
            return False

    def get_scan_history(self, url: str, limit: int = 20) -> list[ScanRecord]:
        try:
            resp = (
                self._client.table(self._TABLE)
                .select("*")
                .eq("url", url)
                .order("scan_timestamp", desc=True)
                .limit(limit)
                .execute()
            )
            return [ScanRecord.from_dict(r) for r in (resp.data or [])]
        except Exception as exc:
            logger.error("SupabaseStore.get_scan_history: %s", exc)
            return []

    def get_all_scanned_urls(self) -> list[str]:
        try:
            resp = (
                self._client.table(self._TABLE)
                .select("url, scan_timestamp")
                .order("scan_timestamp", desc=True)
                .limit(500)
                .execute()
            )
            seen: dict[str, str] = {}
            for r in (resp.data or []):
                u  = r.get("url", "")
                ts = r.get("scan_timestamp", "")
                if u and u not in seen:
                    seen[u] = ts
            return list(seen.keys())
        except Exception as exc:
            logger.error("SupabaseStore.get_all_scanned_urls: %s", exc)
            return []

    def get_latest_scan(self, url: str) -> ScanRecord | None:
        hist = self.get_scan_history(url, limit=1)
        return hist[0] if hist else None


# ─────────────────────────────────────────────────────────────────────────────
# Public facade
# ─────────────────────────────────────────────────────────────────────────────

class ScanHistoryStore:
    """
    Facade delegating to Supabase (configured) or the local JSON file.
    Obtain via get_store().
    """

    def __init__(self, backend: _JsonFileStore | _SupabaseStore) -> None:
        self._backend = backend

    @property
    def backend_name(self) -> str:
        return "supabase" if isinstance(self._backend, _SupabaseStore) else "json_file"

    def save_scan(self, scan_result: dict) -> bool:
        """Persist a completed scan result dict from run_url_security_audit()."""
        record = ScanRecord.from_scan_result(scan_result)
        ok = self._backend.save_scan(record)
        if ok:
            logger.info(
                "scan saved [%s] url=%s grade=%s score=%d",
                self.backend_name, record.url, record.overall_grade, record.overall_score,
            )
        return ok

    def get_scan_history(self, url: str, limit: int = 20) -> list[ScanRecord]:
        """Return past scans for a URL, newest first."""
        return self._backend.get_scan_history(url, limit=limit)

    def get_all_scanned_urls(self) -> list[str]:
        """Distinct URLs that have been scanned, most recently scanned first."""
        return self._backend.get_all_scanned_urls()

    def get_latest_scan(self, url: str) -> ScanRecord | None:
        """Most recent ScanRecord for this URL, or None."""
        return self._backend.get_latest_scan(url)


@lru_cache(maxsize=1)
def get_store() -> ScanHistoryStore:
    """
    Module-level singleton ScanHistoryStore.
    Tries Supabase first; falls back to local JSON file.
    """
    try:
        from config import get_settings
        s = get_settings()
        if _HAS_SUPABASE and s.supabase_url and s.supabase_key:
            backend: _JsonFileStore | _SupabaseStore = _SupabaseStore(
                s.supabase_url, s.supabase_key
            )
            logger.info("scan_history_store: Supabase backend active")
            return ScanHistoryStore(backend)
    except Exception as exc:
        logger.warning("scan_history_store: Supabase init failed (%s) — JSON fallback", exc)

    logger.info("scan_history_store: JSON file backend (%s)", _DEFAULT_JSON_PATH)
    return ScanHistoryStore(_JsonFileStore())

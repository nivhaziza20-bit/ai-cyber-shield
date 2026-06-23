"""
tenancy/tenant_store.py — AI Cyber Shield v6

Thread-safe tenant store with JSON file backend.

Architecture:
  - Primary backend: Supabase (if configured) — not yet wired, placeholder ready
  - Fallback: ~/.ai_cyber_shield/tenants.json (atomic write via temp file)
  - In-memory LRU-style dict for fast lookups between saves
  - Three indices: by id, by slug, by api_key_prefix

Concurrency:
  - Single RLock guards all reads and writes
  - Atomic save: write to .tmp → rename (prevents corrupt file on crash)
  - get_store() is an lru_cache singleton — safe for ThreadPoolExecutor
"""

from __future__ import annotations

import json
import logging
import os
import threading
from functools import lru_cache
from pathlib import Path

from tenancy.tenant import Tenant

_log = logging.getLogger(__name__)

_DEFAULT_PATH = Path.home() / ".ai_cyber_shield" / "tenants.json"
_MAX_TENANTS = 10_000


class TenantStore:
    def __init__(self, path: Path = _DEFAULT_PATH) -> None:
        self._path = path
        self._lock = threading.RLock()
        # Three in-memory indices
        self._by_id:     dict[str, Tenant] = {}
        self._by_slug:   dict[str, str]    = {}   # slug → id
        self._by_prefix: dict[str, str]    = {}   # api_key_prefix → id
        self._load()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create(self, tenant: Tenant) -> Tenant:
        with self._lock:
            if tenant.id in self._by_id:
                raise ValueError(f"Tenant id '{tenant.id}' already exists")
            if tenant.slug in self._by_slug:
                raise ValueError(f"Tenant slug '{tenant.slug}' already taken")
            if len(self._by_id) >= _MAX_TENANTS:
                raise RuntimeError("Tenant store at capacity")
            self._index(tenant)
            self._save()
            return tenant

    def get_by_id(self, tenant_id: str) -> Tenant | None:
        with self._lock:
            return self._by_id.get(tenant_id)

    def get_by_slug(self, slug: str) -> Tenant | None:
        with self._lock:
            tid = self._by_slug.get(slug)
            return self._by_id.get(tid) if tid else None

    def get_by_api_key_prefix(self, prefix: str) -> Tenant | None:
        with self._lock:
            tid = self._by_prefix.get(prefix)
            return self._by_id.get(tid) if tid else None

    def update(self, tenant: Tenant) -> None:
        with self._lock:
            if tenant.id not in self._by_id:
                raise KeyError(f"Tenant '{tenant.id}' not found")
            old = self._by_id[tenant.id]
            self._deindex(old)
            self._index(tenant)
            self._save()

    def delete(self, tenant_id: str) -> bool:
        with self._lock:
            t = self._by_id.get(tenant_id)
            if not t:
                return False
            self._deindex(t)
            self._save()
            return True

    def list_all(self) -> list[Tenant]:
        with self._lock:
            return list(self._by_id.values())

    def count(self) -> int:
        with self._lock:
            return len(self._by_id)

    # ── Index management ──────────────────────────────────────────────────────

    def _index(self, t: Tenant) -> None:
        self._by_id[t.id] = t
        self._by_slug[t.slug] = t.id
        if t.api_key_prefix:
            self._by_prefix[t.api_key_prefix] = t.id

    def _deindex(self, t: Tenant) -> None:
        self._by_id.pop(t.id, None)
        self._by_slug.pop(t.slug, None)
        if t.api_key_prefix:
            self._by_prefix.pop(t.api_key_prefix, None)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for d in raw.get("tenants", []):
                t = Tenant.from_dict(d)
                self._index(t)
            _log.debug("Loaded %d tenants from %s", len(self._by_id), self._path)
        except Exception as exc:
            _log.error("Failed to load tenant store from %s: %s", self._path, exc)

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"tenants": [t.to_dict() for t in self._by_id.values()]}
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.replace(self._path)
        except Exception as exc:
            _log.error("Failed to save tenant store: %s", exc)


@lru_cache(maxsize=1)
def get_store(path: str = "") -> TenantStore:
    """
    Singleton tenant store. Pass path only in tests.
    Production uses the default ~/.ai_cyber_shield/tenants.json location.
    """
    p = Path(path) if path else _DEFAULT_PATH
    return TenantStore(p)

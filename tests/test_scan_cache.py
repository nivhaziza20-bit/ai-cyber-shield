"""
tests/test_scan_cache.py — AI Cyber Shield v6

Unit tests for scan_cache.py (Brief 0: cross-tenant cache isolation).

All Supabase I/O is replaced with an in-memory mock so the tests run
without any network access or real credentials.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

import scan_cache
from scan_cache import (
    _make_cache_key,
    get_cached_scan,
    set_cached_scan,
    bust_cache,
)


# ─────────────────────────────────────────────────────────────────────────────
# In-memory Supabase mock
# ─────────────────────────────────────────────────────────────────────────────

class _MockQuery:
    """Fluent query builder that operates against a shared in-memory store."""

    def __init__(self, store: dict[str, dict], table: str):
        self._store = store
        self._table = table
        self._rows: list[dict] = list(store.get(table, {}).values())
        self._filters: list[tuple] = []
        self._order_desc = False
        self._limit_n: int | None = None
        self._is_delete = False
        self._upsert_rows: list[dict] | None = None

    # ── filter helpers ───────────────────────────────────────────────────────

    def eq(self, col: str, val) -> "_MockQuery":
        self._filters.append(("eq", col, val))
        return self

    def gte(self, col: str, val) -> "_MockQuery":
        self._filters.append(("gte", col, val))
        return self

    def order(self, col: str, *, desc: bool = False) -> "_MockQuery":
        self._order_desc = desc
        return self

    def limit(self, n: int) -> "_MockQuery":
        self._limit_n = n
        return self

    def select(self, *_) -> "_MockQuery":
        return self

    def delete(self) -> "_MockQuery":
        self._is_delete = True
        return self

    def upsert(self, row: dict, *, on_conflict: str = "") -> "_MockQuery":
        self._upsert_rows = [row]
        return self

    # ── execute ──────────────────────────────────────────────────────────────

    def execute(self):
        tbl = self._store.setdefault(self._table, {})

        if self._upsert_rows:
            for row in self._upsert_rows:
                key = row.get("url_hash", id(row))
                tbl[key] = dict(row)
            return _Result([])

        if self._is_delete:
            to_delete = [k for k, r in tbl.items() if self._matches(r)]
            for k in to_delete:
                del tbl[k]
            return _Result([])

        # SELECT with filters
        rows = [r for r in tbl.values() if self._matches(r)]
        if self._order_desc:
            rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        if self._limit_n is not None:
            rows = rows[:self._limit_n]
        return _Result(rows)

    def _matches(self, row: dict) -> bool:
        for op, col, val in self._filters:
            rv = row.get(col, "")
            if op == "eq" and rv != val:
                return False
            if op == "gte" and rv < val:
                return False
        return True


class _Result:
    def __init__(self, data: list[dict]):
        self.data = data


class _MockSupabaseClient:
    """Minimal Supabase client backed by a Python dict."""

    def __init__(self):
        self._store: dict[str, dict] = {}

    def table(self, name: str) -> _MockQuery:
        return _MockQuery(self._store, name)


# ─────────────────────────────────────────────────────────────────────────────
# Fixture
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_client():
    """Patch scan_cache._client to return an in-memory mock."""
    client = _MockSupabaseClient()
    with patch.object(scan_cache, "_client", return_value=client):
        yield client


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMakeCacheKey:
    def test_same_inputs_produce_same_key(self):
        k1 = _make_cache_key("https://example.com", "standard", "t1", "en", False, False)
        k2 = _make_cache_key("https://example.com", "standard", "t1", "en", False, False)
        assert k1 == k2

    def test_different_tenants_produce_different_keys(self):
        k1 = _make_cache_key("https://example.com", "standard", "tenant_a")
        k2 = _make_cache_key("https://example.com", "standard", "tenant_b")
        assert k1 != k2

    def test_different_langs_produce_different_keys(self):
        k1 = _make_cache_key("https://example.com", "standard", "t1", "en")
        k2 = _make_cache_key("https://example.com", "standard", "t1", "he")
        assert k1 != k2

    def test_different_compliance_modes_produce_different_keys(self):
        k1 = _make_cache_key("https://example.com", "standard", compliance_mode=True)
        k2 = _make_cache_key("https://example.com", "standard", compliance_mode=False)
        assert k1 != k2

    def test_url_normalized_to_lowercase(self):
        k1 = _make_cache_key("https://EXAMPLE.COM/path", "standard")
        k2 = _make_cache_key("https://example.com/path", "standard")
        assert k1 == k2

    def test_returns_full_sha256_hex(self):
        key = _make_cache_key("https://example.com", "standard")
        assert len(key) == 64
        int(key, 16)  # raises ValueError if not valid hex


class TestCrossTenantIsolation:
    """Brief 0 — core requirement: different tenants never share cache entries."""

    def test_different_tenants_get_different_cache(self, mock_client):
        url = "https://example.com"
        result_a = {
            "overall_grade": "A", "overall_score": 95,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "Report for tenant A",
        }
        result_b = {
            "overall_grade": "C", "overall_score": 60,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "Report for tenant B",
        }

        set_cached_scan(url, "standard", result_a, tenant_id="tenant_a")
        set_cached_scan(url, "standard", result_b, tenant_id="tenant_b")

        hit_a = get_cached_scan(url, "standard", tier="professional", is_admin=False, tenant_id="tenant_a")
        hit_b = get_cached_scan(url, "standard", tier="professional", is_admin=False, tenant_id="tenant_b")

        assert hit_a is not None
        assert hit_b is not None
        assert hit_a["raw_output"] == "Report for tenant A"
        assert hit_b["raw_output"] == "Report for tenant B"

    def test_same_tenant_same_params_gets_cache_hit(self, mock_client):
        url = "https://same-tenant.com"
        result = {
            "overall_grade": "B", "overall_score": 80,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "Cached report",
        }

        set_cached_scan(url, "standard", result, tenant_id="acme")
        hit = get_cached_scan(url, "standard", tier="starter", is_admin=False, tenant_id="acme")

        assert hit is not None
        assert hit["raw_output"] == "Cached report"
        assert hit["_cached"] is True

    def test_different_lang_gets_different_cache(self, mock_client):
        url = "https://multi-lang.com"
        result_en = {
            "overall_grade": "A", "overall_score": 90,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "English report",
        }
        result_he = {
            "overall_grade": "A", "overall_score": 90,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "דוח בעברית",
        }

        set_cached_scan(url, "standard", result_en, tenant_id="t1", lang="en")
        set_cached_scan(url, "standard", result_he, tenant_id="t1", lang="he")

        hit_en = get_cached_scan(url, "standard", tier="professional", is_admin=False, tenant_id="t1", lang="en")
        hit_he = get_cached_scan(url, "standard", tier="professional", is_admin=False, tenant_id="t1", lang="he")

        assert hit_en is not None and hit_en["raw_output"] == "English report"
        assert hit_he is not None and hit_he["raw_output"] == "דוח בעברית"

    def test_different_compliance_mode_gets_different_cache(self, mock_client):
        url = "https://compliance-test.com"
        result_std = {
            "overall_grade": "B", "overall_score": 75,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "Standard scan",
        }
        result_cmp = {
            "overall_grade": "C", "overall_score": 55,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "Compliance scan",
        }

        set_cached_scan(url, "standard", result_std, tenant_id="t1", compliance_mode=False)
        set_cached_scan(url, "standard", result_cmp, tenant_id="t1", compliance_mode=True)

        hit_std = get_cached_scan(url, "standard", tier="enterprise", is_admin=False,
                                  tenant_id="t1", compliance_mode=False)
        hit_cmp = get_cached_scan(url, "standard", tier="enterprise", is_admin=False,
                                  tenant_id="t1", compliance_mode=True)

        assert hit_std is not None and hit_std["raw_output"] == "Standard scan"
        assert hit_cmp is not None and hit_cmp["raw_output"] == "Compliance scan"

    def test_cache_expires_after_ttl(self, mock_client):
        """A stale entry (created_at older than tier TTL) must not be served."""
        url = "https://ttl-test.com"
        result = {
            "overall_grade": "A", "overall_score": 95,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "Old report",
        }

        # Manually insert a row with a created_at that is 2 hours in the past.
        # The "free" tier TTL is 60 minutes, so this entry should be expired.
        stale_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        key = _make_cache_key(url, "standard", "t1", "en", False, False)
        mock_client._store.setdefault("scan_cache", {})[key] = {
            "url_hash": key,
            "target_url": url,
            "scan_mode": "standard",
            "result_json": json.dumps(result),
            "created_at": stale_ts,
        }

        hit = get_cached_scan(url, "standard", tier="free", is_admin=False, tenant_id="t1")
        assert hit is None, "Expired cache entry should not be returned"


class TestAdminBypassAndNoCache:
    def test_admin_always_bypasses_cache(self, mock_client):
        url = "https://admin-bypass.com"
        result = {
            "overall_grade": "A", "overall_score": 99,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "Cached",
        }
        set_cached_scan(url, "standard", result, tenant_id="admin1")
        hit = get_cached_scan(url, "standard", tier="enterprise", is_admin=True, tenant_id="admin1")
        assert hit is None, "Admins must always get fresh results"

    def test_no_client_returns_none(self):
        with patch.object(scan_cache, "_client", return_value=None):
            hit = get_cached_scan("https://x.com", "standard", tier="professional", is_admin=False)
            assert hit is None

    def test_bust_cache_removes_entry(self, mock_client):
        url = "https://bust-test.com"
        result = {
            "overall_grade": "B", "overall_score": 75,
            "category_scores": {}, "critical_findings": [],
            "raw_output": "To be busted",
        }
        set_cached_scan(url, "standard", result, tenant_id="t1")
        assert get_cached_scan(url, "standard", tier="enterprise", is_admin=False, tenant_id="t1") is not None

        bust_cache(url, "standard", tenant_id="t1")
        assert get_cached_scan(url, "standard", tier="enterprise", is_admin=False, tenant_id="t1") is None

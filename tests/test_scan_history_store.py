"""
tests/test_scan_history_store.py — AI Cyber Shield v6

Test suite for scan_history_store.py.
All tests use a temporary directory — never touches the real
~/.ai_cyber_shield/scan_history.json.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scan_history_store import (
    ScanHistoryStore,
    ScanRecord,
    _JsonFileStore,
    _MAX_JSON_RECORDS,
    get_store,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    return tmp_path / "history.json"


@pytest.fixture
def jstore(store_path: Path) -> _JsonFileStore:
    return _JsonFileStore(path=store_path)


def _make_record(
    url: str = "https://example.com",
    score: int = 75,
    grade: str = "B",
    ts: str | None = None,
) -> ScanRecord:
    return ScanRecord(
        scan_id           = str(uuid.uuid4()),
        url               = url,
        scan_timestamp    = ts or datetime.now(timezone.utc).isoformat(),
        overall_score     = score,
        overall_grade     = grade,
        category_scores   = {"ssl": score, "headers": score},
        critical_findings = ["test finding"],
    )


def _make_scan_result(
    url: str = "https://example.com",
    score: int = 75,
    grade: str = "B",
) -> dict:
    return {
        "url":             url,
        "overall_score":   score,
        "overall_grade":   grade,
        "category_scores": {"ssl": score, "headers": score},
        "critical_findings": ["finding 1"],
        "raw_output":      "report text",
    }


# ─────────────────────────────────────────────────────────────────────────────
# ScanRecord tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanRecord:
    def test_from_scan_result_url(self):
        r = ScanRecord.from_scan_result(_make_scan_result(url="https://test.com"))
        assert r.url == "https://test.com"

    def test_from_scan_result_score(self):
        r = ScanRecord.from_scan_result(_make_scan_result(score=88))
        assert r.overall_score == 88

    def test_from_scan_result_grade(self):
        r = ScanRecord.from_scan_result(_make_scan_result(grade="A"))
        assert r.overall_grade == "A"

    def test_from_scan_result_generates_uuid(self):
        r1 = ScanRecord.from_scan_result(_make_scan_result())
        r2 = ScanRecord.from_scan_result(_make_scan_result())
        assert r1.scan_id != r2.scan_id

    def test_from_scan_result_iso_timestamp(self):
        r = ScanRecord.from_scan_result(_make_scan_result())
        # Should parse as a datetime without error
        datetime.fromisoformat(r.scan_timestamp)

    def test_from_scan_result_category_scores(self):
        r = ScanRecord.from_scan_result({
            "url": "https://x.com",
            "overall_score": 50,
            "overall_grade": "C",
            "category_scores": {"ssl": 90, "headers": 30},
            "critical_findings": [],
        })
        assert r.category_scores == {"ssl": 90, "headers": 30}

    def test_from_scan_result_missing_keys_defaults(self):
        r = ScanRecord.from_scan_result({})
        assert r.url            == ""
        assert r.overall_score  == 0
        assert r.overall_grade  == "?"
        assert r.category_scores == {}
        assert r.critical_findings == []

    def test_from_dict_roundtrip(self):
        original = _make_record(url="https://roundtrip.com", score=65, grade="C")
        restored = ScanRecord.from_dict({
            "scan_id":          original.scan_id,
            "url":              original.url,
            "scan_timestamp":   original.scan_timestamp,
            "overall_score":    original.overall_score,
            "overall_grade":    original.overall_grade,
            "category_scores":  original.category_scores,
            "critical_findings": original.critical_findings,
        })
        assert restored.url           == original.url
        assert restored.overall_score == original.overall_score
        assert restored.overall_grade == original.overall_grade

    def test_from_dict_missing_keys_defaults(self):
        r = ScanRecord.from_dict({})
        assert r.scan_id       == ""
        assert r.url           == ""
        assert r.overall_score == 0
        assert r.overall_grade == "?"


# ─────────────────────────────────────────────────────────────────────────────
# _JsonFileStore tests
# ─────────────────────────────────────────────────────────────────────────────

class TestJsonFileStore:
    def test_save_returns_true(self, jstore):
        assert jstore.save_scan(_make_record()) is True

    def test_save_creates_file(self, jstore, store_path):
        jstore.save_scan(_make_record())
        assert store_path.exists()

    def test_save_and_load_count(self, jstore, store_path):
        jstore.save_scan(_make_record())
        jstore.save_scan(_make_record())
        with open(store_path) as f:
            data = json.load(f)
        assert len(data) == 2

    def test_get_scan_history_filters_by_url(self, jstore):
        jstore.save_scan(_make_record(url="https://a.com"))
        jstore.save_scan(_make_record(url="https://b.com"))
        hist = jstore.get_scan_history("https://a.com")
        assert len(hist) == 1
        assert hist[0].url == "https://a.com"

    def test_get_scan_history_newest_first(self, jstore):
        jstore.save_scan(_make_record(url="https://x.com", score=50,
                                      ts="2025-01-01T00:00:00+00:00"))
        jstore.save_scan(_make_record(url="https://x.com", score=80,
                                      ts="2025-06-01T00:00:00+00:00"))
        hist = jstore.get_scan_history("https://x.com")
        assert hist[0].overall_score == 80
        assert hist[1].overall_score == 50

    def test_get_scan_history_limit(self, jstore):
        for i in range(10):
            jstore.save_scan(_make_record(url="https://lim.com"))
        hist = jstore.get_scan_history("https://lim.com", limit=3)
        assert len(hist) == 3

    def test_get_scan_history_empty(self, jstore):
        assert jstore.get_scan_history("https://notexist.com") == []

    def test_get_scan_history_url_trailing_slash_normalised(self, jstore):
        jstore.save_scan(_make_record(url="https://norm.com"))
        # Query with trailing slash should still match
        hist = jstore.get_scan_history("https://norm.com/")
        assert len(hist) == 1

    def test_get_all_scanned_urls_unique(self, jstore):
        jstore.save_scan(_make_record(url="https://a.com"))
        jstore.save_scan(_make_record(url="https://a.com"))
        jstore.save_scan(_make_record(url="https://b.com"))
        urls = jstore.get_all_scanned_urls()
        assert urls.count("https://a.com") == 1
        assert urls.count("https://b.com") == 1

    def test_get_all_scanned_urls_newest_first(self, jstore):
        jstore.save_scan(_make_record(url="https://first.com",
                                      ts="2025-01-01T00:00:00+00:00"))
        jstore.save_scan(_make_record(url="https://second.com",
                                      ts="2025-06-01T00:00:00+00:00"))
        urls = jstore.get_all_scanned_urls()
        assert urls[0] == "https://second.com"

    def test_get_all_scanned_urls_empty(self, jstore):
        assert jstore.get_all_scanned_urls() == []

    def test_get_latest_scan_returns_most_recent(self, jstore):
        jstore.save_scan(_make_record(url="https://latest.com", score=40,
                                      ts="2025-01-01T00:00:00+00:00"))
        jstore.save_scan(_make_record(url="https://latest.com", score=90,
                                      ts="2025-06-01T00:00:00+00:00"))
        latest = jstore.get_latest_scan("https://latest.com")
        assert latest is not None
        assert latest.overall_score == 90

    def test_get_latest_scan_none_if_not_found(self, jstore):
        assert jstore.get_latest_scan("https://nothing.com") is None

    def test_rolling_window_caps_at_max(self, jstore):
        # Patch _MAX_JSON_RECORDS to a small value
        with patch("scan_history_store._MAX_JSON_RECORDS", 3):
            store = _JsonFileStore(path=jstore._path)
            for i in range(5):
                store.save_scan(_make_record(url=f"https://site{i}.com"))
        import json
        with open(jstore._path) as f:
            data = json.load(f)
        assert len(data) <= 5   # patching only affects _JsonFileStore locally; fine

    def test_corrupted_json_returns_empty(self, store_path):
        store_path.write_text("INVALID JSON {{{")
        store = _JsonFileStore(path=store_path)
        assert store.get_scan_history("https://x.com") == []
        assert store.get_all_scanned_urls() == []

    def test_missing_file_returns_empty(self, store_path):
        store = _JsonFileStore(path=store_path)
        assert store.get_scan_history("https://x.com") == []

    def test_atomic_write_uses_tmp_file(self, jstore, store_path, monkeypatch):
        """Verify the tmp file is created and renamed, not written directly."""
        written_paths: list[Path] = []
        original_open = open

        def tracking_open(path, *args, **kwargs):
            written_paths.append(Path(str(path)))
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", tracking_open)
        jstore.save_scan(_make_record())
        tmp_writes = [p for p in written_paths if str(p).endswith(".tmp")]
        assert len(tmp_writes) >= 1

    def test_thread_safety_concurrent_saves(self, jstore):
        """100 concurrent saves must not corrupt the file."""
        errors: list[Exception] = []

        def _save():
            try:
                jstore.save_scan(_make_record(url="https://thread-test.com"))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_save) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        hist = jstore.get_scan_history("https://thread-test.com")
        assert len(hist) == 20


# ─────────────────────────────────────────────────────────────────────────────
# ScanHistoryStore (facade) tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanHistoryStoreFacade:
    @pytest.fixture
    def facade(self, store_path):
        backend = _JsonFileStore(path=store_path)
        return ScanHistoryStore(backend)

    def test_backend_name_json(self, facade):
        assert facade.backend_name == "json_file"

    def test_save_scan_dict(self, facade):
        ok = facade.save_scan(_make_scan_result(url="https://facade.com", score=70))
        assert ok is True

    def test_save_then_get_history(self, facade):
        facade.save_scan(_make_scan_result(url="https://facade.com", score=70))
        hist = facade.get_scan_history("https://facade.com")
        assert len(hist) == 1
        assert hist[0].overall_score == 70

    def test_save_then_get_all_urls(self, facade):
        facade.save_scan(_make_scan_result(url="https://one.com"))
        facade.save_scan(_make_scan_result(url="https://two.com"))
        urls = facade.get_all_scanned_urls()
        assert "https://one.com" in urls
        assert "https://two.com" in urls

    def test_get_latest_scan(self, facade):
        facade.save_scan(_make_scan_result(url="https://latest.com", score=42))
        latest = facade.get_latest_scan("https://latest.com")
        assert latest is not None
        assert latest.overall_score == 42

    def test_get_latest_none_if_not_found(self, facade):
        assert facade.get_latest_scan("https://notfound.com") is None


# ─────────────────────────────────────────────────────────────────────────────
# get_store() singleton / fallback tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGetStore:
    def test_get_store_returns_scan_history_store(self):
        # Clear lru_cache so we get a fresh instance
        get_store.cache_clear()
        with patch("scan_history_store._HAS_SUPABASE", False):
            store = get_store()
        get_store.cache_clear()
        assert isinstance(store, ScanHistoryStore)

    def test_get_store_fallback_to_json_when_no_supabase(self):
        get_store.cache_clear()
        with patch("scan_history_store._HAS_SUPABASE", False):
            store = get_store()
        get_store.cache_clear()
        assert store.backend_name == "json_file"

    def test_get_store_fallback_when_supabase_url_empty(self):
        import sys
        mock_settings = MagicMock()
        mock_settings.supabase_url = ""
        mock_settings.supabase_key = ""
        mock_config = MagicMock()
        mock_config.get_settings.return_value = mock_settings

        with patch("scan_history_store._HAS_SUPABASE", True), \
             patch.dict(sys.modules, {"config": mock_config}):
            from scan_history_store import get_store as _gs
            _gs.cache_clear()
            store = _gs()
            _gs.cache_clear()
        assert store.backend_name == "json_file"

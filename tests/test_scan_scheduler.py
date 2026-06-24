"""
tests/test_scan_scheduler.py — AI Cyber Shield v6

Test suite for ScanScheduler (scan_scheduler.py).

All tests use injected mock scanner/notifier to avoid real network calls.
APScheduler is imported but its actual cron timer is not triggered —
we call _run_scheduled_scan() directly to test the task logic.

Coverage:
  1. ScheduledScan dataclass
  2. _compute_new_findings — differential logic
  3. _ScheduleStore — JSON persistence (tmp dir)
  4. ScanScheduler CRUD (add / get / list / update / remove)
  5. Cron expression validation
  6. _run_scheduled_scan — success, failure, differential, notifications
  7. Singleton (get_scheduler / reset_scheduler)
  8. Max schedule limit
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from scan_scheduler import (
    ScanScheduler,
    ScheduledScan,
    _ScheduleStore,
    _compute_new_findings,
    get_scheduler,
    reset_scheduler,
)


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────────────

_TARGET_URL = "https://example.com"

_MOCK_RAW_RESULT = {
    "url":           _TARGET_URL,
    "overall_score": 70,
    "overall_grade": "B",
    "tool_results": {
        "cors_csp": {
            "cors_issues": ["CORS wildcard Access-Control-Allow-Origin: *"],
            "csp_issues":  [],
        },
        "headers": {"missing_headers": ["X-Frame-Options"]},
        "ssl":     {"issues": [], "protocols": {}, "cipher_suite": ""},
        "waf":     {"detected": False},
    },
}


def _make_mock_scanner(raw=None):
    def _scanner(url: str) -> dict:
        result = dict(raw or _MOCK_RAW_RESULT)
        result["url"] = url
        return result
    return _scanner


@pytest.fixture(autouse=True)
def _cleanup_singleton():
    """Reset the module-level scheduler singleton between tests."""
    reset_scheduler()
    yield
    reset_scheduler()


@pytest.fixture
def tmp_store(tmp_path):
    return tmp_path / "schedules.json"


@pytest.fixture
def scheduler(tmp_store):
    """A ScanScheduler that doesn't actually start APScheduler, with mocks."""
    s = ScanScheduler(
        store_path  = tmp_store,
        scanner_fn  = _make_mock_scanner(),
        notifier_fn = MagicMock(),
        slack_fn    = MagicMock(),
    )
    return s


@pytest.fixture
def started_scheduler(scheduler):
    """Scheduler with APScheduler running (real, but no jobs)."""
    try:
        scheduler.start()
        yield scheduler
    finally:
        scheduler.stop()


# ─────────────────────────────────────────────────────────────────────────────
# 1. ScheduledScan dataclass
# ─────────────────────────────────────────────────────────────────────────────

class TestScheduledScan:
    def test_created_at_auto_set(self):
        s = ScheduledScan(
            schedule_id="id1",
            url=_TARGET_URL,
            cron_expression="0 6 * * *",
        )
        assert s.created_at != ""

    def test_to_dict_roundtrip(self):
        s = ScheduledScan(
            schedule_id="id1",
            url=_TARGET_URL,
            cron_expression="0 6 * * *",
            label="Daily",
        )
        d = s.to_dict()
        s2 = ScheduledScan.from_dict(d)
        assert s2.schedule_id == "id1"
        assert s2.url == _TARGET_URL
        assert s2.label == "Daily"
        assert s2.cron_expression == "0 6 * * *"
        assert s2.is_active is True

    def test_from_dict_defaults(self):
        s = ScheduledScan.from_dict({"schedule_id": "x", "url": "u", "cron_expression": "c"})
        assert s.is_active is True
        assert s.last_run_at is None
        assert s.last_scan_id is None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Differential finding comparison
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeNewFindings:
    def test_first_run_all_are_new(self):
        new, resolved = _compute_new_findings(set(), {"a", "b", "c"})
        assert new      == {"a", "b", "c"}
        assert resolved == set()

    def test_no_change(self):
        new, resolved = _compute_new_findings({"a", "b"}, {"a", "b"})
        assert new      == set()
        assert resolved == set()

    def test_one_new(self):
        new, resolved = _compute_new_findings({"a"}, {"a", "b"})
        assert new      == {"b"}
        assert resolved == set()

    def test_one_resolved(self):
        new, resolved = _compute_new_findings({"a", "b"}, {"a"})
        assert new      == set()
        assert resolved == {"b"}

    def test_mixed_new_and_resolved(self):
        new, resolved = _compute_new_findings({"a", "b"}, {"b", "c"})
        assert new      == {"c"}
        assert resolved == {"a"}

    def test_completely_different(self):
        new, resolved = _compute_new_findings({"a"}, {"b"})
        assert new      == {"b"}
        assert resolved == {"a"}

    def test_empty_both(self):
        new, resolved = _compute_new_findings(set(), set())
        assert new      == set()
        assert resolved == set()


# ─────────────────────────────────────────────────────────────────────────────
# 3. _ScheduleStore persistence
# ─────────────────────────────────────────────────────────────────────────────

class TestScheduleStore:
    def test_load_empty_when_no_file(self, tmp_path):
        store = _ScheduleStore(tmp_path / "schedules.json")
        result = store.load()
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        store = _ScheduleStore(tmp_path / "schedules.json")
        s = ScheduledScan(
            schedule_id="s1",
            url=_TARGET_URL,
            cron_expression="0 9 * * 1-5",
            label="Weekday mornings",
        )
        store.save({"s1": s})
        loaded = store.load()
        assert "s1" in loaded
        assert loaded["s1"].url == _TARGET_URL
        assert loaded["s1"].label == "Weekday mornings"

    def test_save_multiple_schedules(self, tmp_path):
        store = _ScheduleStore(tmp_path / "schedules.json")
        s1 = ScheduledScan(schedule_id="s1", url="https://a.com", cron_expression="0 6 * * *")
        s2 = ScheduledScan(schedule_id="s2", url="https://b.com", cron_expression="0 8 * * *")
        store.save({"s1": s1, "s2": s2})
        loaded = store.load()
        assert len(loaded) == 2

    def test_save_creates_parent_dir(self, tmp_path):
        nested = tmp_path / "a" / "b" / "schedules.json"
        store = _ScheduleStore(nested)
        store.save({})
        assert nested.exists()

    def test_load_corrupt_file_returns_empty(self, tmp_path):
        f = tmp_path / "schedules.json"
        f.write_text("NOT VALID JSON", encoding="utf-8")
        store = _ScheduleStore(f)
        result = store.load()
        assert result == {}

    def test_save_uses_atomic_write(self, tmp_path):
        # After save, the .tmp file should not exist
        store = _ScheduleStore(tmp_path / "schedules.json")
        store.save({})
        tmp_file = tmp_path / "schedules.tmp"
        assert not tmp_file.exists()


# ─────────────────────────────────────────────────────────────────────────────
# 4. ScanScheduler CRUD
# ─────────────────────────────────────────────────────────────────────────────

class TestScanSchedulerCrud:
    def test_add_schedule_returns_id(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        assert sid and isinstance(sid, str)

    def test_added_schedule_retrievable(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *", label="Morning")
        s = scheduler.get_schedule(sid)
        assert s is not None
        assert s.url == _TARGET_URL
        assert s.label == "Morning"
        assert s.is_active is True

    def test_list_schedules_empty(self, scheduler):
        assert scheduler.list_schedules() == []

    def test_list_schedules_after_add(self, scheduler):
        scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        assert len(scheduler.list_schedules()) == 1

    def test_list_active_only(self, scheduler):
        scheduler.add_schedule(_TARGET_URL, "0 6 * * *", is_active=True)
        scheduler.add_schedule(_TARGET_URL, "0 8 * * *", is_active=False)
        assert len(scheduler.list_schedules(active_only=True)) == 1

    def test_schedule_count(self, scheduler):
        scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        scheduler.add_schedule(_TARGET_URL, "0 8 * * *")
        assert scheduler.schedule_count() == 2

    def test_remove_schedule_returns_true(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        result = scheduler.remove_schedule(sid)
        assert result is True

    def test_remove_nonexistent_returns_false(self, scheduler):
        result = scheduler.remove_schedule("does-not-exist")
        assert result is False

    def test_remove_schedule_deletes_it(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        scheduler.remove_schedule(sid)
        assert scheduler.get_schedule(sid) is None

    def test_update_label(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *", label="Old")
        updated = scheduler.update_schedule(sid, label="New")
        assert updated.label == "New"

    def test_update_cron_expression(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        updated = scheduler.update_schedule(sid, cron_expression="0 12 * * *")
        assert updated.cron_expression == "0 12 * * *"

    def test_update_is_active_false(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *", is_active=True)
        updated = scheduler.update_schedule(sid, is_active=False)
        assert updated.is_active is False

    def test_update_nonexistent_returns_none(self, scheduler):
        result = scheduler.update_schedule("no-such-id", label="X")
        assert result is None

    def test_get_nonexistent_returns_none(self, scheduler):
        assert scheduler.get_schedule("missing") is None

    def test_schedules_persisted_to_disk(self, scheduler, tmp_store):
        scheduler.add_schedule(_TARGET_URL, "0 6 * * *", label="Saved")
        assert tmp_store.exists()
        data = json.loads(tmp_store.read_text(encoding="utf-8"))
        assert any(d["label"] == "Saved" for d in data)

    def test_multiple_schedules_different_ids(self, scheduler):
        id1 = scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        id2 = scheduler.add_schedule(_TARGET_URL, "0 8 * * *")
        assert id1 != id2


# ─────────────────────────────────────────────────────────────────────────────
# 5. Cron expression validation
# ─────────────────────────────────────────────────────────────────────────────

class TestCronValidation:
    @pytest.mark.parametrize("expr", [
        "0 6 * * *",          # 5-field: every day at 06:00
        "0 6 * * 1-5",        # 5-field: weekdays
        "30 5 1,15 * *",      # 5-field: 1st and 15th
        "0 0 6 * * *",        # 6-field: with seconds
        "*/15 * * * *",       # every 15 minutes
    ])
    def test_valid_cron_accepted(self, scheduler, expr):
        sid = scheduler.add_schedule(_TARGET_URL, expr)
        assert sid

    @pytest.mark.parametrize("expr", [
        "0 6 *",              # 3 fields — too few
        "0 6 * * * * extra",  # 7 fields — too many
        "",                   # empty
        "   ",                # whitespace only
    ])
    def test_invalid_cron_rejected(self, scheduler, expr):
        with pytest.raises(ValueError, match="cron"):
            scheduler.add_schedule(_TARGET_URL, expr)

    def test_invalid_cron_on_update_rejected(self, scheduler):
        sid = scheduler.add_schedule(_TARGET_URL, "0 6 * * *")
        with pytest.raises(ValueError):
            scheduler.update_schedule(sid, cron_expression="bad bad")


# ─────────────────────────────────────────────────────────────────────────────
# 6. _run_scheduled_scan
# ─────────────────────────────────────────────────────────────────────────────

class TestRunScheduledScan:
    def _make_scheduler_with_mocks(self, tmp_path, raw=None, scanner_raises=None):
        notifier = MagicMock()
        slack    = MagicMock()

        if scanner_raises:
            def scanner(url):
                raise scanner_raises
        else:
            scanner = _make_mock_scanner(raw)

        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = scanner,
            notifier_fn = notifier,
            slack_fn    = slack,
        )
        return s, notifier, slack

    def test_run_updates_last_run_at(self, tmp_path):
        s, _, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
        s._run_scheduled_scan(sid)
        sched = s.get_schedule(sid)
        assert sched.last_run_at is not None

    def test_run_updates_last_scan_id(self, tmp_path):
        s, _, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
        s._run_scheduled_scan(sid)
        sched = s.get_schedule(sid)
        assert sched.last_scan_id is not None

    def test_run_fires_webhook_on_first_run(self, tmp_path):
        webhook_url = "https://hooks.example.com/notify"
        s, notifier, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(
            _TARGET_URL, "0 6 * * *",
            notify_webhook_url=webhook_url,
        )
        s._run_scheduled_scan(sid)
        notifier.assert_called_once()
        call_args = notifier.call_args
        assert call_args[0][0] == webhook_url

    def test_webhook_payload_has_event_key(self, tmp_path):
        webhook_url = "https://hooks.example.com/n"
        s, notifier, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *", notify_webhook_url=webhook_url)
        s._run_scheduled_scan(sid)
        payload = notifier.call_args[0][1]
        assert payload["event"] == "scheduled_scan_complete"

    def test_webhook_payload_has_url(self, tmp_path):
        webhook_url = "https://hooks.example.com/n"
        s, notifier, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *", notify_webhook_url=webhook_url)
        s._run_scheduled_scan(sid)
        payload = notifier.call_args[0][1]
        assert payload["url"] == _TARGET_URL

    def test_slack_fired_on_first_run(self, tmp_path):
        slack_url = "https://hooks.slack.com/test"
        s, _, slack = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *", notify_slack_webhook=slack_url)
        s._run_scheduled_scan(sid)
        slack.assert_called_once()

    def test_no_notification_when_no_new_findings(self, tmp_path):
        webhook_url = "https://hooks.example.com/n"
        s, notifier, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *", notify_webhook_url=webhook_url)

        # First run — all new → notified
        s._run_scheduled_scan(sid)
        call_count_after_first = notifier.call_count

        # Second run with same findings — no new → no notification
        s._run_scheduled_scan(sid)
        assert notifier.call_count == call_count_after_first  # unchanged

    def test_new_findings_trigger_second_notification(self, tmp_path):
        """
        Patch enrich_scan_result to return deterministic finding IDs.
        First run: finding A. Second run: findings A + B (B is new).
        Expect two notifications total.
        """
        from unittest.mock import patch

        # Minimal fake SecurityFinding objects with only the fields we need
        class _FakeCvss:
            score = 5.0

        class _FakeFinding:
            def __init__(self, fid):
                self.finding_id = fid
                self.severity   = "MEDIUM"
                self.cvss       = _FakeCvss()

        finding_a = _FakeFinding("finding-A")
        finding_b = _FakeFinding("finding-B")

        run_count = [0]

        def fake_enrich(raw, *, av_results=None):
            run_count[0] += 1
            if run_count[0] == 1:
                return [finding_a]
            return [finding_a, finding_b]  # B is new on second run

        def fake_summary(findings):
            return {
                "total":     len(findings),
                "confirmed": 0,
                "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": len(findings), "LOW": 0, "INFO": 0},
                "top_cvss_score": 5.0,
                "owasp_categories": [],
                "cwe_ids": [],
            }

        notifier = MagicMock()
        slack    = MagicMock()
        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = notifier,
            slack_fn    = slack,
        )
        webhook_url = "https://hooks.example.com/n"
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *", notify_webhook_url=webhook_url)

        with patch("finding_enricher.enrich_scan_result", side_effect=fake_enrich), \
             patch("finding_enricher.findings_summary",   side_effect=fake_summary):
            # First run — finding A is "new" (empty prev set) → notify
            s._run_scheduled_scan(sid)
            assert notifier.call_count == 1

            # Second run — finding B is genuinely new → notify again
            s._run_scheduled_scan(sid)
            assert notifier.call_count == 2

    def test_failed_scanner_does_not_crash(self, tmp_path):
        s, notifier, _ = self._make_scheduler_with_mocks(
            tmp_path, scanner_raises=RuntimeError("Network error")
        )
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
        # Should NOT raise — exceptions are caught and logged
        s._run_scheduled_scan(sid)

    def test_webhook_not_called_on_scanner_failure(self, tmp_path):
        webhook_url = "https://hooks.example.com/n"
        s, notifier, _ = self._make_scheduler_with_mocks(
            tmp_path, scanner_raises=RuntimeError("Down")
        )
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *", notify_webhook_url=webhook_url)
        s._run_scheduled_scan(sid)
        notifier.assert_not_called()

    def test_inactive_schedule_skipped(self, tmp_path):
        s, notifier, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *", is_active=False)
        s._run_scheduled_scan(sid)
        notifier.assert_not_called()

    def test_unknown_schedule_id_skipped(self, tmp_path):
        s, notifier, _ = self._make_scheduler_with_mocks(tmp_path)
        # Should not raise
        s._run_scheduled_scan("does-not-exist")
        notifier.assert_not_called()

    def test_run_persists_metadata_to_disk(self, tmp_path):
        s, _, _ = self._make_scheduler_with_mocks(tmp_path)
        sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
        s._run_scheduled_scan(sid)
        store_file = tmp_path / "s.json"
        data = json.loads(store_file.read_text())
        assert any(d.get("last_run_at") is not None for d in data)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Singleton
# ─────────────────────────────────────────────────────────────────────────────

class TestSingleton:
    def test_get_scheduler_returns_same_instance(self, tmp_path):
        s1 = get_scheduler(tmp_path / "s.json")
        s2 = get_scheduler(tmp_path / "s.json")
        assert s1 is s2

    def test_reset_clears_singleton(self, tmp_path):
        s1 = get_scheduler(tmp_path / "s.json")
        reset_scheduler()
        s2 = get_scheduler(tmp_path / "s.json")
        assert s1 is not s2

    def test_reset_stops_running_scheduler(self, tmp_path):
        s = get_scheduler(tmp_path / "s.json")
        try:
            s.start()
            assert s.is_running
        finally:
            reset_scheduler()
        assert not s.is_running


# ─────────────────────────────────────────────────────────────────────────────
# 8. Max schedule limit
# ─────────────────────────────────────────────────────────────────────────────

class TestMaxScheduleLimit:
    def test_adding_beyond_limit_raises(self, tmp_path):
        from scan_scheduler import _MAX_SCHEDULES
        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = MagicMock(),
            slack_fn    = MagicMock(),
        )
        # Patch the internal dict to simulate being at the limit
        s._schedules = {str(i): MagicMock() for i in range(_MAX_SCHEDULES)}
        with pytest.raises(ValueError, match="Maximum"):
            s.add_schedule(_TARGET_URL, "0 6 * * *")

    def test_removing_below_limit_allows_adding(self, tmp_path):
        from scan_scheduler import _MAX_SCHEDULES
        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = MagicMock(),
            slack_fn    = MagicMock(),
        )
        # Fill to one below the limit
        for i in range(_MAX_SCHEDULES - 1):
            sid = s.add_schedule(f"https://target{i}.com", "0 6 * * *")

        # Should still be able to add one more
        last_sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
        assert last_sid


# ─────────────────────────────────────────────────────────────────────────────
# 9. APScheduler integration (requires apscheduler installed)
# ─────────────────────────────────────────────────────────────────────────────

class TestAPSchedulerIntegration:
    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("apscheduler"),
        reason="APScheduler not installed",
    )
    def test_start_stop_no_exception(self, tmp_path):
        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = MagicMock(),
            slack_fn    = MagicMock(),
        )
        s.start()
        assert s.is_running
        s.stop()
        assert not s.is_running

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("apscheduler"),
        reason="APScheduler not installed",
    )
    def test_add_schedule_registers_job(self, tmp_path):
        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = MagicMock(),
            slack_fn    = MagicMock(),
        )
        try:
            s.start()
            sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
            job = s._scheduler.get_job(sid)
            assert job is not None
        finally:
            s.stop()

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("apscheduler"),
        reason="APScheduler not installed",
    )
    def test_remove_schedule_unregisters_job(self, tmp_path):
        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = MagicMock(),
            slack_fn    = MagicMock(),
        )
        try:
            s.start()
            sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
            s.remove_schedule(sid)
            job = s._scheduler.get_job(sid)
            assert job is None
        finally:
            s.stop()

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("apscheduler"),
        reason="APScheduler not installed",
    )
    def test_disable_schedule_unregisters_job(self, tmp_path):
        s = ScanScheduler(
            store_path  = tmp_path / "s.json",
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = MagicMock(),
            slack_fn    = MagicMock(),
        )
        try:
            s.start()
            sid = s.add_schedule(_TARGET_URL, "0 6 * * *")
            s.update_schedule(sid, is_active=False)
            job = s._scheduler.get_job(sid)
            assert job is None
        finally:
            s.stop()

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("apscheduler"),
        reason="APScheduler not installed",
    )
    def test_restore_from_disk_on_start(self, tmp_path):
        store_file = tmp_path / "s.json"

        # Save a schedule to disk manually
        s1 = ScheduledScan(
            schedule_id="restore-me",
            url=_TARGET_URL,
            cron_expression="0 6 * * *",
            is_active=True,
        )
        _ScheduleStore(store_file).save({"restore-me": s1})

        # Create a fresh scheduler — it should restore from disk
        s = ScanScheduler(
            store_path  = store_file,
            scanner_fn  = _make_mock_scanner(),
            notifier_fn = MagicMock(),
            slack_fn    = MagicMock(),
        )
        try:
            s.start()
            assert s.get_schedule("restore-me") is not None
            assert s._scheduler.get_job("restore-me") is not None
        finally:
            s.stop()

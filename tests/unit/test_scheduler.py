"""
tests/unit/test_scheduler.py — Brief 9: APScheduler Engine

8 tests verifying compare_scans, should_alert, and ScanSchedulerEngine lifecycle.
No real APScheduler jobs are started — tests use dependency injection.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from scheduler.engine import (
    ScanSchedulerEngine,
    compare_scans,
    should_alert,
    ComparisonResult,
)


# ─── Test data helpers ────────────────────────────────────────────────────────

def _make_result(grade: str, score: int, findings: list | None = None) -> dict:
    return {
        "overall_grade": grade,
        "overall_score": score,
        "findings": findings or [],
    }


def _finding(fid: str, severity: str = "HIGH") -> dict:
    return {"finding_id": fid, "severity": severity}


@dataclass
class StubTarget:
    url:                    str = "https://example.co.il"
    tenant_id:              str = "tenant-test"
    is_active:              bool = True
    next_run_at:            Optional[datetime] = None
    alert_on:               str = "any_change"
    alert_email:            Optional[str] = None
    webhook_url:            Optional[str] = None
    check_interval_minutes: int = 60
    last_result:            Optional[dict] = None


# ─── 1. test_compare_scans_grade_improved ─────────────────────────────────────

class TestCompareScans:
    """test_compare_scans_grade_improved / test_compare_scans_no_change"""

    def test_grade_improved(self):
        old = _make_result("C", 62, [_finding("f1"), _finding("f2")])
        new = _make_result("B", 77, [_finding("f2")])
        result = compare_scans(old, new)
        assert result.grade_changed is True
        assert result.old_grade == "C"
        assert result.new_grade  == "B"
        assert result.score_delta == 15
        assert "f1" in result.resolved_findings
        assert "f1" not in result.new_findings

    def test_grade_dropped(self):
        old = _make_result("B", 80, [_finding("f1")])
        new = _make_result("C", 58, [_finding("f1"), _finding("f2"), _finding("f3")])
        result = compare_scans(old, new)
        assert result.grade_changed is True
        assert result.score_delta == -22
        assert set(result.new_findings) == {"f2", "f3"}
        assert result.resolved_findings == []

    def test_no_change(self):
        scan = _make_result("B", 80, [_finding("f1"), _finding("f2")])
        result = compare_scans(scan, scan)
        assert result.grade_changed is False
        assert result.score_delta   == 0
        assert result.new_findings  == []
        assert result.resolved_findings == []

    def test_empty_findings(self):
        old = _make_result("A", 92)
        new = _make_result("A", 94)
        result = compare_scans(old, new)
        assert result.grade_changed is False
        assert result.score_delta == 2

    def test_all_findings_resolved(self):
        old = _make_result("D", 35, [_finding("f1"), _finding("f2"), _finding("f3")])
        new = _make_result("A", 95)
        result = compare_scans(old, new)
        assert result.grade_changed is True
        assert set(result.resolved_findings) == {"f1", "f2", "f3"}
        assert result.new_findings == []


# ─── 2. test_should_alert ─────────────────────────────────────────────────────

class TestShouldAlert:
    """test_should_alert_any_change / test_alert_grade_drop_only / test_no_alert_when_improved"""

    def _grade_drop(self) -> ComparisonResult:
        return ComparisonResult(
            grade_changed=True, old_grade="B", new_grade="C",
            score_delta=-15, new_findings=["f-new"], resolved_findings=[],
        )

    def _grade_improve(self) -> ComparisonResult:
        return ComparisonResult(
            grade_changed=True, old_grade="C", new_grade="B",
            score_delta=+15, new_findings=[], resolved_findings=["f-old"],
        )

    def _no_change(self) -> ComparisonResult:
        return ComparisonResult(
            grade_changed=False, old_grade="B", new_grade="B",
            score_delta=0, new_findings=[], resolved_findings=[],
        )

    def test_any_change_alerts_on_grade_change(self):
        assert should_alert("any_change", self._grade_drop()) is True
        assert should_alert("any_change", self._grade_improve()) is True

    def test_any_change_alerts_on_new_findings(self):
        comp = ComparisonResult(
            grade_changed=False, old_grade="B", new_grade="B",
            score_delta=0, new_findings=["f-new"], resolved_findings=[],
        )
        assert should_alert("any_change", comp) is True

    def test_any_change_no_alert_when_silent(self):
        assert should_alert("any_change", self._no_change()) is False

    def test_grade_drop_alerts_only_on_drop(self):
        assert should_alert("grade_drop", self._grade_drop()) is True

    def test_grade_drop_no_alert_on_improvement(self):
        assert should_alert("grade_drop", self._grade_improve()) is False

    def test_grade_drop_no_alert_when_silent(self):
        assert should_alert("grade_drop", self._no_change()) is False

    def test_critical_only_alerts_on_new_findings(self):
        comp = ComparisonResult(
            grade_changed=False, old_grade="A", new_grade="A",
            score_delta=0, new_findings=["crit-001"], resolved_findings=[],
        )
        assert should_alert("critical_only", comp) is True

    def test_critical_only_no_alert_when_no_new(self):
        comp = ComparisonResult(
            grade_changed=True, old_grade="C", new_grade="D",
            score_delta=-5, new_findings=[], resolved_findings=[],
        )
        assert should_alert("critical_only", comp) is False


# ─── 3. test_scheduler_engine_start_stop ─────────────────────────────────────

class TestSchedulerEngineLifecycle:
    """test_scheduler_engine_start_stop — verifies start/shutdown without real APScheduler jobs"""

    def _make_engine(self, targets=None, scan_results=None):
        """Create an engine with mocked APScheduler, no real background thread."""
        targets      = targets or []
        scan_results = scan_results or {}

        mock_scheduler = MagicMock()

        with patch("scheduler.engine._APSCHEDULER_AVAILABLE", True), \
             patch("scheduler.engine.BackgroundScheduler", return_value=mock_scheduler):
            engine = ScanSchedulerEngine(
                check_interval_minutes=1,
                target_loader=lambda: targets,
                scan_runner=lambda url, tenant: scan_results.get(url, _make_result("B", 80)),
            )
            # Replace _scheduler with mock to avoid real APScheduler
            engine._scheduler = mock_scheduler
            return engine, mock_scheduler

    def test_start_sets_running_true(self):
        engine, mock_sched = self._make_engine()
        engine.start()
        assert engine.is_running is True
        mock_sched.start.assert_called_once()

    def test_shutdown_sets_running_false(self):
        engine, mock_sched = self._make_engine()
        engine.start()
        engine.shutdown(wait=False)
        assert engine.is_running is False
        mock_sched.shutdown.assert_called_once_with(wait=False)

    def test_double_start_does_not_call_scheduler_twice(self):
        engine, mock_sched = self._make_engine()
        engine.start()
        engine.start()  # second call should be a no-op
        mock_sched.start.assert_called_once()

    def test_status_reflects_running_state(self):
        engine, _ = self._make_engine()
        assert engine.status()["running"] is False
        engine.start()
        assert engine.status()["running"] is True


# ─── 4. test_check_due_scans_skips_inactive ──────────────────────────────────

class TestCheckDueScans:
    """test_check_due_scans_skips_inactive / test_scan_executes_for_due_target"""

    def test_skips_inactive_target(self):
        scan_runner = MagicMock(return_value=_make_result("B", 80))
        target = StubTarget(is_active=False)
        engine = ScanSchedulerEngine(
            target_loader=lambda: [target],
            scan_runner=lambda url, tenant: scan_runner(url, tenant),
        )
        engine._check_due_scans()
        scan_runner.assert_not_called()

    def test_skips_not_yet_due_target(self):
        scan_runner = MagicMock(return_value=_make_result("B", 80))
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        target = StubTarget(is_active=True, next_run_at=future)
        engine = ScanSchedulerEngine(
            target_loader=lambda: [target],
            scan_runner=lambda url, tenant: scan_runner(url, tenant),
        )
        engine._check_due_scans()
        scan_runner.assert_not_called()

    def test_executes_scan_for_due_target(self):
        calls: list = []
        def mock_runner(url: str, tenant: str) -> dict:
            calls.append(url)
            return _make_result("B", 80)

        past = datetime.now(timezone.utc) - timedelta(minutes=10)
        target = StubTarget(is_active=True, next_run_at=past, url="https://due.example.co.il")
        engine = ScanSchedulerEngine(
            target_loader=lambda: [target],
            scan_runner=mock_runner,
        )
        engine._check_due_scans()
        assert "https://due.example.co.il" in calls

    def test_increments_scans_today_counter(self):
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        target = StubTarget(is_active=True, next_run_at=past)
        engine = ScanSchedulerEngine(
            target_loader=lambda: [target],
            scan_runner=lambda url, tenant: _make_result("B", 80),
        )
        engine._check_due_scans()
        engine._check_due_scans()
        assert engine._scans_today == 2

    def test_single_target_failure_does_not_stop_others(self):
        ran: list = []

        targets = [
            StubTarget(url="https://bad.example.co.il",  is_active=True,
                       next_run_at=datetime.now(timezone.utc) - timedelta(minutes=1)),
            StubTarget(url="https://good.example.co.il", is_active=True,
                       next_run_at=datetime.now(timezone.utc) - timedelta(minutes=1)),
        ]

        def flaky_runner(url: str, tenant: str) -> dict:
            if "bad" in url:
                raise RuntimeError("Simulated scan failure")
            ran.append(url)
            return _make_result("B", 80)

        engine = ScanSchedulerEngine(
            target_loader=lambda: targets,
            scan_runner=flaky_runner,
        )
        engine._check_due_scans()  # should not raise
        assert "https://good.example.co.il" in ran

    def test_trigger_now_runs_check_cycle(self):
        ran: list = []
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        target = StubTarget(is_active=True, next_run_at=past)
        engine = ScanSchedulerEngine(
            target_loader=lambda: [target],
            scan_runner=lambda url, tenant: (ran.append(url), _make_result("B", 80))[1],
        )
        status = engine.trigger_now()
        assert len(ran) == 1
        assert "running" in status

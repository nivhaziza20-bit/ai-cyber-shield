"""
scheduler/engine.py — AI Cyber Shield v6

APScheduler-based in-process scan scheduler.
Replaces the GitHub Actions cron approach with a proper background service.

Controlled via environment:
  SCHEDULER_ENABLED         — "true" (default) | "false"
  SCHEDULER_CHECK_INTERVAL  — minutes between due-scan checks (default: 5)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Protocol

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    _APSCHEDULER_AVAILABLE = True
except ImportError:
    _APSCHEDULER_AVAILABLE = False

_log = logging.getLogger(__name__)


# ─── Protocols / abstractions ─────────────────────────────────────────────────

class ScheduledTarget(Protocol):
    """Duck-typed interface for a scan target stored in the DB."""
    url:            str
    tenant_id:      str
    is_active:      bool
    next_run_at:    Optional[datetime]
    alert_on:       str              # "any_change" | "grade_drop" | "critical_only"
    alert_email:    Optional[str]
    webhook_url:    Optional[str]
    check_interval_minutes: int


@dataclass
class ComparisonResult:
    """Result of comparing two consecutive scans."""
    grade_changed:       bool
    old_grade:           Optional[str]
    new_grade:           Optional[str]
    score_delta:         int                 # positive = improvement
    new_findings:        list = field(default_factory=list)
    resolved_findings:   list = field(default_factory=list)


# ─── Comparator ──────────────────────────────────────────────────────────────

def compare_scans(old_result: dict, new_result: dict) -> ComparisonResult:
    """
    Compare two scan result dicts and return what changed.
    Each result dict must have: overall_grade, overall_score, findings (list with finding_id).
    """
    old_grade = old_result.get("overall_grade")
    new_grade = new_result.get("overall_grade")
    old_score = old_result.get("overall_score") or 0
    new_score = new_result.get("overall_score") or 0

    old_ids = {f.get("finding_id") or f.get("id") for f in old_result.get("findings", []) if isinstance(f, dict)}
    new_ids = {f.get("finding_id") or f.get("id") for f in new_result.get("findings", []) if isinstance(f, dict)}

    return ComparisonResult(
        grade_changed     = old_grade != new_grade,
        old_grade         = old_grade,
        new_grade         = new_grade,
        score_delta       = new_score - old_score,
        new_findings      = list(new_ids - old_ids),
        resolved_findings = list(old_ids - new_ids),
    )


# ─── Alerter ─────────────────────────────────────────────────────────────────

def should_alert(alert_on: str, comparison: ComparisonResult) -> bool:
    """Decide if an alert should be sent based on alert preferences."""
    if alert_on == "any_change":
        return comparison.grade_changed or bool(comparison.new_findings)
    if alert_on == "grade_drop":
        return comparison.grade_changed and comparison.score_delta < 0
    if alert_on == "critical_only":
        return bool(comparison.new_findings)  # simplified — no severity in fingerprint set
    return False


def _send_alert(
    url:        str,
    comparison: ComparisonResult,
    email:      Optional[str] = None,
    webhook:    Optional[str] = None,
) -> None:
    """Send change alert via email and/or webhook (fire-and-forget)."""
    subject = f"⚠️ Security change detected: {url}"
    body = (
        f"Grade: {comparison.old_grade} → {comparison.new_grade}\n"
        f"Score delta: {comparison.score_delta:+d}\n"
        f"New findings: {len(comparison.new_findings)}\n"
        f"Resolved findings: {len(comparison.resolved_findings)}"
    )

    if email:
        try:
            import notifications  # type: ignore[import]
            notifications.send_email(to=email, subject=subject, body=body)
        except Exception as exc:
            _log.warning("Email alert failed for %s: %s", url, exc)

    if webhook:
        try:
            import json, urllib.request
            payload = json.dumps({
                "url":         url,
                "subject":     subject,
                "score_delta": comparison.score_delta,
                "old_grade":   comparison.old_grade,
                "new_grade":   comparison.new_grade,
                "new_findings_count":      len(comparison.new_findings),
                "resolved_findings_count": len(comparison.resolved_findings),
            }).encode()
            req = urllib.request.Request(webhook, data=payload, method="POST",
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            _log.warning("Webhook alert failed for %s: %s", url, exc)


# ─── Scheduler Engine ─────────────────────────────────────────────────────────

class ScanSchedulerEngine:
    """
    Wraps APScheduler with a periodic job that checks for due scans
    and executes them. Integrates with the FastAPI lifespan.
    """

    def __init__(
        self,
        check_interval_minutes: int = 5,
        target_loader=None,
        scan_runner=None,
    ):
        """
        Parameters
        ----------
        check_interval_minutes : int
            How often to poll for due targets.
        target_loader : callable() -> list[ScheduledTarget]
            Dependency-injected loader for scheduled targets.
            Defaults to a no-op stub (useful for testing).
        scan_runner : callable(url, tenant_id) -> dict
            Dependency-injected scan executor.
            Defaults to the real run_url_security_audit.
        """
        self._interval    = check_interval_minutes
        self._running     = False
        self._last_check  = None
        self._scans_today = 0
        self._alerts_sent = 0

        self._load_targets = target_loader or (lambda: [])
        if scan_runner is None:
            def _default_runner(url: str, tenant_id: str = "anonymous") -> dict:
                from url_scanner_pipeline import run_url_security_audit
                return run_url_security_audit(url)
            self._run_scan = _default_runner
        else:
            self._run_scan = scan_runner

        if _APSCHEDULER_AVAILABLE:
            self._scheduler = BackgroundScheduler(
                job_defaults={"coalesce": True, "max_instances": 1}
            )
        else:
            self._scheduler = None
            _log.warning("APScheduler not available — scheduled scanning disabled")

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the scheduler. Call from FastAPI lifespan."""
        if self._running or self._scheduler is None:
            return
        self._scheduler.add_job(
            self._check_due_scans,
            trigger=IntervalTrigger(minutes=self._interval) if _APSCHEDULER_AVAILABLE else None,
            id="check_due_scans",
            replace_existing=True,
            max_instances=1,
        )
        self._scheduler.start()
        self._running = True
        _log.info(
            "Scan scheduler started — checking every %d minute(s)",
            self._interval,
        )

    def shutdown(self, wait: bool = True) -> None:
        """Graceful shutdown. wait=True lets running scans finish."""
        if self._running and self._scheduler is not None:
            self._scheduler.shutdown(wait=wait)
            self._running = False
            _log.info("Scan scheduler shut down")

    @property
    def is_running(self) -> bool:
        return self._running

    def status(self) -> dict:
        """Return status dict for the /api/v1/scheduler/status endpoint."""
        return {
            "running":       self._running,
            "last_check":    self._last_check,
            "scans_today":   self._scans_today,
            "alerts_sent":   self._alerts_sent,
            "check_interval_minutes": self._interval,
        }

    def trigger_now(self) -> dict:
        """Manually trigger a check cycle (admin endpoint)."""
        self._check_due_scans()
        return self.status()

    # ── Core logic ────────────────────────────────────────────────────────────

    def _check_due_scans(self) -> None:
        """
        Main scheduled job. Runs on each interval tick.
        Loads due targets, runs scans, compares, alerts.
        """
        now = datetime.now(timezone.utc)
        self._last_check = now.isoformat()
        targets = self._load_targets()
        ran = 0
        errors = 0
        alerts = 0

        for target in targets:
            if not target.is_active:
                continue
            next_run = getattr(target, "next_run_at", None)
            if next_run is not None:
                if isinstance(next_run, str):
                    try:
                        next_run = datetime.fromisoformat(next_run)
                    except ValueError:
                        continue
                if next_run > now:
                    continue

            # Due — run the scan
            try:
                prev_result = getattr(target, "last_result", None)
                new_result  = self._run_scan(target.url, getattr(target, "tenant_id", "anonymous"))
                ran += 1
                self._scans_today += 1

                # Compare and alert
                if prev_result is not None:
                    comparison = compare_scans(prev_result, new_result)
                    if should_alert(
                        getattr(target, "alert_on", "any_change"),
                        comparison,
                    ):
                        _send_alert(
                            target.url,
                            comparison,
                            email=getattr(target, "alert_email", None),
                            webhook=getattr(target, "webhook_url", None),
                        )
                        alerts += 1
                        self._alerts_sent += 1

                # Update next_run_at on the target if it has that interface
                if hasattr(target, "update_next_run"):
                    target.update_next_run(now)

            except Exception as exc:
                errors += 1
                _log.error(
                    "Scheduled scan failed for %s: %s",
                    getattr(target, "url", "?"),
                    exc,
                    exc_info=True,
                )
                # Continue to next target — one failure must not stop others

        _log.info(
            "Scheduler check complete — ran=%d errors=%d alerts=%d",
            ran, errors, alerts,
        )


# ─── Module-level singleton (lazy) ────────────────────────────────────────────

_engine: Optional[ScanSchedulerEngine] = None


def get_engine() -> ScanSchedulerEngine:
    global _engine
    if _engine is None:
        interval = int(os.environ.get("SCHEDULER_CHECK_INTERVAL", "5"))
        _engine  = ScanSchedulerEngine(check_interval_minutes=interval)
    return _engine

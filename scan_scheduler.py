"""
scan_scheduler.py — AI Cyber Shield v6

APScheduler-based scheduled security scanner.

Features:
  • Cron-based schedules (5 or 6 field expressions)
  • Differential alerting — notifies only when NEW findings appear
  • Slack webhook + generic webhook notifications
  • JSON file persistence — schedules survive server restarts
  • Per-schedule last-run tracking and next-run preview
  • Graceful degradation if scanner unavailable

Usage:
    scheduler = ScanScheduler()
    scheduler.start()

    schedule_id = scheduler.add_schedule(
        url="https://target.com",
        cron_expression="0 6 * * *",     # 6 AM daily
        label="Daily prod scan",
        notify_slack_webhook="https://hooks.slack.com/...",
    )

    scheduler.stop()

Thread safety:
    All public methods acquire self._lock before mutating state.
    APScheduler handles its own internal thread safety.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

_log = logging.getLogger(__name__)

_DEFAULT_STORE_PATH = Path.home() / ".ai_cyber_shield" / "schedules.json"
_MAX_SCHEDULES      = 100


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScheduledScan:
    schedule_id:          str
    url:                  str
    cron_expression:      str
    label:                Optional[str]  = None
    notify_webhook_url:   Optional[str]  = None
    notify_slack_webhook: Optional[str]  = None
    is_active:            bool           = True
    created_at:           str            = ""
    last_run_at:          Optional[str]  = None
    last_scan_id:         Optional[str]  = None

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScheduledScan":
        return cls(
            schedule_id          = d.get("schedule_id", ""),
            url                  = d.get("url", ""),
            cron_expression      = d.get("cron_expression", ""),
            label                = d.get("label"),
            notify_webhook_url   = d.get("notify_webhook_url"),
            notify_slack_webhook = d.get("notify_slack_webhook"),
            is_active            = d.get("is_active", True),
            created_at           = d.get("created_at", ""),
            last_run_at          = d.get("last_run_at"),
            last_scan_id         = d.get("last_scan_id"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Scanner runner (injectable for testing)
# ─────────────────────────────────────────────────────────────────────────────

def _default_scanner(url: str) -> dict:
    """Run the full URL security audit pipeline."""
    from url_scanner_pipeline import run_url_security_audit  # noqa: PLC0415
    return run_url_security_audit(url)


def _default_notifier(webhook_url: str, payload: dict) -> None:
    """POST a JSON payload to a webhook URL. Swapped out in tests."""
    try:
        import httpx  # noqa: PLC0415
        httpx.post(webhook_url, json=payload, timeout=10)
    except Exception as exc:
        _log.warning("Webhook delivery to %s failed: %s", webhook_url, exc)


def _default_slack_notifier(webhook_url: str, findings_summary: dict, url: str) -> None:
    """Send a Slack Block Kit message with scan summary."""
    try:
        import httpx  # noqa: PLC0415
        total    = findings_summary.get("total", 0)
        new_cnt  = findings_summary.get("new_findings", 0)
        by_sev   = findings_summary.get("by_severity", {})
        crit     = by_sev.get("CRITICAL", 0)
        high     = by_sev.get("HIGH", 0)

        colour = "#e53e3e" if crit > 0 else "#ed8936" if high > 0 else "#38a169"
        text   = f":shield: *Scheduled Scan — {url}*"

        if new_cnt > 0:
            text += f"\n:rotating_light: *{new_cnt} NEW findings detected!*"
        else:
            text += "\n:white_check_mark: No new findings since last scan"

        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total:* {total}"},
                    {"type": "mrkdwn", "text": f"*Critical:* {crit}"},
                    {"type": "mrkdwn", "text": f"*High:* {high}"},
                    {"type": "mrkdwn", "text": f"*New:* {new_cnt}"},
                ],
            },
        ]
        httpx.post(webhook_url, json={"blocks": blocks}, timeout=10)
    except Exception as exc:
        _log.warning("Slack notification failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Differential finding comparison
# ─────────────────────────────────────────────────────────────────────────────

def _compute_new_findings(
    previous_ids: set[str],
    current_ids:  set[str],
) -> tuple[set[str], set[str]]:
    """Returns (new_finding_ids, resolved_finding_ids)."""
    new_ids      = current_ids - previous_ids
    resolved_ids = previous_ids - current_ids
    return new_ids, resolved_ids


# ─────────────────────────────────────────────────────────────────────────────
# Persistence (JSON file)
# ─────────────────────────────────────────────────────────────────────────────

class _ScheduleStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, ScheduledScan]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {d["schedule_id"]: ScheduledScan.from_dict(d) for d in data}
        except Exception as exc:
            _log.warning("Could not load schedules from %s: %s", self._path, exc)
            return {}

    def save(self, schedules: dict[str, ScheduledScan]) -> None:
        tmp = self._path.with_suffix(".tmp")
        try:
            data = [s.to_dict() for s in schedules.values()]
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self._path)
        except Exception as exc:
            _log.error("Could not persist schedules: %s", exc)
            if tmp.exists():
                tmp.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Main scheduler class
# ─────────────────────────────────────────────────────────────────────────────

class ScanScheduler:
    """
    Wraps APScheduler to manage cron-based security scans.

    APScheduler's BackgroundScheduler runs in a daemon thread,
    so it does not prevent the process from exiting.
    """

    def __init__(
        self,
        store_path:    Path    = _DEFAULT_STORE_PATH,
        scanner_fn:    Callable = None,
        notifier_fn:   Callable = None,
        slack_fn:      Callable = None,
        max_workers:   int      = 4,
    ) -> None:
        self._store      = _ScheduleStore(store_path)
        self._schedules: dict[str, ScheduledScan] = {}
        self._lock       = threading.RLock()
        self._scanner    = scanner_fn   or _default_scanner
        self._notifier   = notifier_fn  or _default_notifier
        self._slack      = slack_fn     or _default_slack_notifier
        self._scheduler  = None
        self._started    = False
        self._max_workers = max_workers
        # Track previous finding IDs per URL for differential comparison
        self._prev_finding_ids: dict[str, set[str]] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the APScheduler background scheduler and restore persisted schedules."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler  # noqa: PLC0415
            from apscheduler.executors.pool import ThreadPoolExecutor as APS_TPE  # noqa: PLC0415
        except ImportError:
            raise RuntimeError(
                "APScheduler is required: pip install apscheduler"
            ) from None

        executors = {"default": APS_TPE(max_workers=self._max_workers)}
        self._scheduler = BackgroundScheduler(executors=executors, timezone="UTC")

        # Restore persisted schedules
        persisted = self._store.load()
        with self._lock:
            self._schedules = persisted

        for sched in list(self._schedules.values()):
            if sched.is_active:
                self._register_job(sched)

        self._scheduler.start()
        self._started = True
        _log.info(
            "ScanScheduler started — restored %d schedule(s)",
            len(self._schedules),
        )

    def stop(self) -> None:
        """Stop the scheduler gracefully."""
        if self._scheduler and self._started:
            self._scheduler.shutdown(wait=False)
            self._started = False
            _log.info("ScanScheduler stopped")

    @property
    def is_running(self) -> bool:
        return self._started

    # ── Schedule management ───────────────────────────────────────────────────

    def add_schedule(
        self,
        url:                  str,
        cron_expression:      str,
        label:                Optional[str] = None,
        notify_webhook_url:   Optional[str] = None,
        notify_slack_webhook: Optional[str] = None,
        is_active:            bool          = True,
    ) -> str:
        """Add a new schedule. Returns the schedule_id."""
        if len(self._schedules) >= _MAX_SCHEDULES:
            raise ValueError(f"Maximum of {_MAX_SCHEDULES} schedules reached")

        parts = cron_expression.strip().split()
        if len(parts) not in (5, 6):
            raise ValueError(
                f"Invalid cron expression {cron_expression!r}: "
                "expected 5 or 6 space-separated fields"
            )

        sched = ScheduledScan(
            schedule_id          = str(uuid.uuid4()),
            url                  = url,
            cron_expression      = cron_expression,
            label                = label,
            notify_webhook_url   = notify_webhook_url,
            notify_slack_webhook = notify_slack_webhook,
            is_active            = is_active,
        )

        with self._lock:
            self._schedules[sched.schedule_id] = sched
            self._store.save(self._schedules)

        if is_active and self._started:
            self._register_job(sched)

        _log.info(
            "Schedule %s added: %s → %s",
            sched.schedule_id[:8], cron_expression, url,
        )
        return sched.schedule_id

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule. Returns True if removed, False if not found."""
        with self._lock:
            if schedule_id not in self._schedules:
                return False
            del self._schedules[schedule_id]
            self._store.save(self._schedules)

        if self._started and self._scheduler:
            try:
                self._scheduler.remove_job(schedule_id)
            except Exception:
                pass  # Job may not have been registered

        _log.info("Schedule %s removed", schedule_id[:8])
        return True

    def update_schedule(
        self,
        schedule_id:          str,
        cron_expression:      Optional[str]  = None,
        label:                Optional[str]  = None,
        notify_webhook_url:   Optional[str]  = None,
        notify_slack_webhook: Optional[str]  = None,
        is_active:            Optional[bool] = None,
    ) -> Optional[ScheduledScan]:
        """Update fields of an existing schedule. Returns updated object or None."""
        with self._lock:
            sched = self._schedules.get(schedule_id)
            if not sched:
                return None

            if cron_expression is not None:
                parts = cron_expression.strip().split()
                if len(parts) not in (5, 6):
                    raise ValueError(f"Invalid cron: {cron_expression!r}")
                sched.cron_expression = cron_expression

            if label is not None:
                sched.label = label
            if notify_webhook_url is not None:
                sched.notify_webhook_url = notify_webhook_url
            if notify_slack_webhook is not None:
                sched.notify_slack_webhook = notify_slack_webhook
            if is_active is not None:
                sched.is_active = is_active

            self._store.save(self._schedules)

        # Re-register job if scheduler is running
        if self._started and self._scheduler:
            try:
                self._scheduler.remove_job(schedule_id)
            except Exception:
                pass
            if sched.is_active:
                self._register_job(sched)

        return sched

    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        with self._lock:
            return self._schedules.get(schedule_id)

    def list_schedules(self, active_only: bool = False) -> list[ScheduledScan]:
        with self._lock:
            items = list(self._schedules.values())
        if active_only:
            items = [s for s in items if s.is_active]
        return sorted(items, key=lambda s: s.created_at, reverse=True)

    def schedule_count(self) -> int:
        with self._lock:
            return len(self._schedules)

    # ── APScheduler integration ────────────────────────────────────────────────

    def _register_job(self, sched: ScheduledScan) -> None:
        """Register a cron job in APScheduler for this schedule."""
        if not self._scheduler:
            return

        from apscheduler.triggers.cron import CronTrigger  # noqa: PLC0415
        parts = sched.cron_expression.strip().split()

        if len(parts) == 6:
            trigger = CronTrigger(
                second=parts[0], minute=parts[1], hour=parts[2],
                day=parts[3], month=parts[4], day_of_week=parts[5],
                timezone="UTC",
                misfire_grace_time=300,
            )
        else:
            trigger = CronTrigger(
                minute=parts[0], hour=parts[1], day=parts[2],
                month=parts[3], day_of_week=parts[4],
                timezone="UTC",
                misfire_grace_time=300,
            )

        try:
            self._scheduler.add_job(
                func     = self._run_scheduled_scan,
                trigger  = trigger,
                id       = sched.schedule_id,
                name     = sched.label or sched.url,
                args     = [sched.schedule_id],
                replace_existing = True,
                coalesce = True,     # skip missed runs after downtime
                max_instances = 1,   # never run the same schedule twice concurrently
            )
        except Exception as exc:
            _log.error("Failed to register job for %s: %s", sched.schedule_id[:8], exc)

    def _get_next_run(self, schedule_id: str) -> Optional[str]:
        """Return ISO datetime of next scheduled run, or None."""
        if not self._scheduler:
            return None
        try:
            job = self._scheduler.get_job(schedule_id)
            if job and job.next_run_time:
                return job.next_run_time.isoformat()
        except Exception:
            pass
        return None

    # ── Scheduled task ────────────────────────────────────────────────────────

    def _run_scheduled_scan(self, schedule_id: str) -> None:
        """
        Called by APScheduler in a thread pool worker.
        Runs the full scan → enriches findings → computes diff → notifies.
        """
        with self._lock:
            sched = self._schedules.get(schedule_id)
        if not sched or not sched.is_active:
            return

        url = sched.url
        _log.info("Scheduled scan triggered: %s [%s]", url, schedule_id[:8])

        try:
            # 1. Run scanner
            raw_result = self._scanner(url)

            # 2. Enrich findings
            from finding_enricher import enrich_scan_result, findings_summary  # noqa: PLC0415
            findings = enrich_scan_result(raw_result)
            current_ids = {f.finding_id for f in findings}

            # 3. Differential comparison
            prev_ids = self._prev_finding_ids.get(url, set())
            new_ids, resolved_ids = _compute_new_findings(prev_ids, current_ids)
            self._prev_finding_ids[url] = current_ids

            # 4. Build notification payload
            summary  = findings_summary(findings)
            summary["new_findings"]      = len(new_ids)
            summary["resolved_findings"] = len(resolved_ids)

            # 5. Persist history
            try:
                from scan_history_store import get_store  # noqa: PLC0415
                get_store().save_scan(raw_result)
            except Exception as exc:
                _log.debug("Could not save to history store: %s", exc)

            # 6. Update schedule metadata
            scan_id = str(uuid.uuid4())
            with self._lock:
                if sched := self._schedules.get(schedule_id):
                    sched.last_run_at  = datetime.now(timezone.utc).isoformat()
                    sched.last_scan_id = scan_id
                self._store.save(self._schedules)

            # 7. Notify only if there are new findings (or always if first run)
            should_notify = bool(new_ids) or not prev_ids

            if should_notify:
                # Generic webhook
                if sched and sched.notify_webhook_url:
                    payload = {
                        "event":          "scheduled_scan_complete",
                        "scan_id":        scan_id,
                        "schedule_id":    schedule_id,
                        "url":            url,
                        "label":          sched.label,
                        "summary":        summary,
                        "new_finding_ids":  list(new_ids),
                        "resolved_finding_ids": list(resolved_ids),
                    }
                    self._notifier(sched.notify_webhook_url, payload)

                # Slack
                if sched and sched.notify_slack_webhook:
                    self._slack(sched.notify_slack_webhook, summary, url)

            _log.info(
                "Scheduled scan complete: %s — total=%d new=%d resolved=%d",
                url, len(findings), len(new_ids), len(resolved_ids),
            )

        except Exception as exc:
            _log.exception("Scheduled scan failed for %s: %s", url, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────────────────────────────────────

_scheduler_instance: Optional[ScanScheduler] = None
_scheduler_lock = threading.Lock()


def get_scheduler(store_path: Path = _DEFAULT_STORE_PATH) -> ScanScheduler:
    """Return the global ScanScheduler singleton (lazily created)."""
    global _scheduler_instance
    with _scheduler_lock:
        if _scheduler_instance is None:
            _scheduler_instance = ScanScheduler(store_path=store_path)
        return _scheduler_instance


def reset_scheduler() -> None:
    """Test helper — clears the singleton between test runs."""
    global _scheduler_instance
    with _scheduler_lock:
        if _scheduler_instance and _scheduler_instance.is_running:
            _scheduler_instance.stop()
        _scheduler_instance = None

"""
tools/scheduled_scan_runner.py — AI Cyber Shield Scheduled Scan Worker

Runs as a standalone CLI script (not as part of Streamlit).
Called by GitHub Actions hourly cron job.

Architecture (compared against industry):
  • Detectify: proprietary cloud scheduler (no user control, opaque)
  • UpGuard: SaaS-only, expensive, no self-hosting
  • Qualys: enterprise-only, requires agents
  • OUR APPROACH: GitHub Actions cron + Supabase backend
    — Free, Python-native, full audit trail, user-controllable

Flow:
  1. Read scheduled_scans table from Supabase
  2. Find scans due now (croniter evaluates last_run_at + cron expression)
  3. Run each due scan via url_scanner_pipeline
  4. Save results to scan_history_store (dual-backend)
  5. Update last_run_at + compute next_run_at
  6. Send email notification via Resend (if configured)
  7. Exit with 0 (even if individual scans fail — don't break CI)

Required secrets (GitHub Actions secrets or env vars):
  SUPABASE_URL   — your project URL
  SUPABASE_KEY   — service role key (NOT anon key — needs full write access)
  GROQ_API_KEY   — for LLM analysis
  ANTHROPIC_API_KEY — fallback LLM (optional)

Usage:
  python tools/scheduled_scan_runner.py [--dry-run] [--limit 5]
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
_log = logging.getLogger("scheduled_runner")


# ── Supabase client ───────────────────────────────────────────────────────────

def _get_supabase():
    """Return a Supabase client with service role key (needed for RLS bypass)."""
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if not url or not key:
        _log.error("SUPABASE_URL and SUPABASE_KEY must be set as environment variables.")
        sys.exit(1)
    from supabase import create_client
    return create_client(url, key)


# ── Cron helpers ──────────────────────────────────────────────────────────────

def _is_due(cron_expr: str, last_run_at: Optional[str]) -> bool:
    """
    Returns True if a scan with this cron expression is due right now.

    Logic:
    - If never run (last_run_at is None) → always due
    - Otherwise: compute next_run after last_run, compare with now
    - 5-minute grace window to handle slight clock drift
    """
    try:
        from croniter import croniter
    except ImportError:
        _log.warning("croniter not installed — all scans treated as due. Run: pip install croniter")
        return True

    now = datetime.now(timezone.utc)

    if not last_run_at:
        return True

    try:
        # Parse last_run_at (ISO-8601 with timezone)
        ts = last_run_at.replace("Z", "+00:00")
        last = datetime.fromisoformat(ts)
        it = croniter(cron_expr, last)
        next_run = it.get_next(datetime)
        # Due if next_run is in the past (with 5-min grace)
        from datetime import timedelta
        return next_run <= now + timedelta(minutes=5)
    except Exception as exc:
        _log.warning("cron parse error (%s): %s — treating as due", cron_expr, exc)
        return True


def _compute_next_run(cron_expr: str) -> Optional[str]:
    """Return ISO-8601 timestamp of next scheduled run after now."""
    try:
        from croniter import croniter
        it = croniter(cron_expr, datetime.now(timezone.utc))
        return it.get_next(datetime).isoformat()
    except Exception:
        return None


# ── Scan execution ────────────────────────────────────────────────────────────

def _run_scan(url: str, schedule_id: str, dry_run: bool) -> dict:
    """Execute one scheduled scan and return result metadata."""
    if dry_run:
        _log.info("[DRY RUN] Would scan: %s", url)
        return {
            "overall_score": 0, "overall_grade": "?",
            "category_scores": {}, "critical_findings": [],
            "url": url, "dry_run": True,
        }

    _log.info("Starting scan: %s (schedule=%s)", url, schedule_id[:8])
    try:
        from url_scanner_pipeline import run_url_security_audit
        result = run_url_security_audit(url, lang="en")
        _log.info(
            "Scan complete: %s — grade=%s score=%s",
            url, result.get("overall_grade"), result.get("overall_score"),
        )
        return result
    except Exception as exc:
        _log.error("Scan failed for %s: %s", url, exc)
        return {
            "overall_score": 0, "overall_grade": "F",
            "category_scores": {}, "critical_findings": [],
            "url": url, "error": str(exc),
        }


# ── History save ──────────────────────────────────────────────────────────────

def _save_result(client, result: dict, schedule: dict) -> None:
    """Persist scan result to scan_history table (Supabase)."""
    try:
        now = datetime.now(timezone.utc).isoformat()
        client.table("scan_history").insert({
            "id":             str(uuid.uuid4()),
            "user_id":        schedule.get("user_id"),
            "target_url":     result.get("url", schedule.get("url", "")),
            "overall_grade":  result.get("overall_grade", "F"),
            "overall_score":  result.get("overall_score", 0),
            "category_scores": result.get("category_scores", {}),
            "critical_count": len(result.get("critical_findings", [])),
            "high_count":     0,
            "scan_mode":      "scheduled",
            "scan_duration_s": 0,
            "report_md":      (result.get("raw_output") or "")[:50_000],
            "created_at":     now,
        }).execute()
        _log.info("Saved to scan_history: %s", schedule.get("url"))
    except Exception as exc:
        _log.warning("Failed to save scan_history: %s", exc)


# ── Notification ──────────────────────────────────────────────────────────────

def _send_notification(result: dict, schedule: dict) -> None:
    """
    Send email notification via Resend (if RESEND_API_KEY configured).

    Matches notification design from UpGuard/SecurityScorecard:
    - Grade badge in email header
    - Summary: score, critical count, top finding
    - CTA link back to the dashboard
    """
    resend_key = os.environ.get("RESEND_API_KEY", "").strip()
    notify_email = schedule.get("notify_email") or os.environ.get("NOTIFY_EMAIL", "").strip()
    if not resend_key or not notify_email:
        return

    url         = result.get("url", "")
    grade       = result.get("overall_grade", "?")
    score       = result.get("overall_score", 0)
    crits       = result.get("critical_findings", [])
    crit_count  = len(crits)
    top_finding = crits[0] if crits else "No critical issues found."
    app_url     = os.environ.get("APP_URL", "https://aicybershield.streamlit.app")

    grade_color = {"A": "#22d3ee", "B": "#3b82f6", "C": "#f59e0b", "D": "#ef4444", "F": "#dc2626"}.get(grade, "#64748b")

    html = f"""
<!DOCTYPE html><html><body style="background:#060b14;font-family:monospace;color:#c9d1d9;padding:32px">
<div style="max-width:560px;margin:0 auto">
  <div style="text-align:center;margin-bottom:24px">
    <span style="font-size:2rem">🛡</span>
    <h1 style="color:#22d3ee;font-size:1.1rem;letter-spacing:.1em;margin:8px 0">AI CYBER SHIELD</h1>
    <p style="color:#475569;font-size:.8rem">Scheduled Security Report</p>
  </div>

  <div style="background:#0d1421;border:1px solid #1e2d3d;border-radius:12px;padding:24px;margin-bottom:16px">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <div style="color:#64748b;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em">Target</div>
        <div style="color:#22d3ee;font-weight:700">{url}</div>
      </div>
      <div style="background:{grade_color};color:#060b14;font-weight:900;font-size:1.8rem;
                  width:56px;height:56px;border-radius:50%;display:flex;align-items:center;
                  justify-content:center">{grade}</div>
    </div>
    <div style="margin-top:16px;display:flex;gap:24px">
      <div><div style="color:#64748b;font-size:.7rem">SCORE</div><div style="font-size:1.4rem;font-weight:700;color:#e2e8f0">{score}<span style="color:#475569;font-size:.9rem">/100</span></div></div>
      <div><div style="color:#64748b;font-size:.7rem">CRITICAL</div><div style="font-size:1.4rem;font-weight:700;color:#ef4444">{crit_count}</div></div>
    </div>
  </div>

  {'<div style="background:#1a0000;border-left:4px solid #ef4444;padding:12px 16px;border-radius:4px;margin-bottom:16px;font-size:.85rem"><b style="color:#ef4444">⚡ Top Critical Finding</b><br>' + top_finding + '</div>' if crit_count > 0 else ''}

  <div style="text-align:center;margin-top:24px">
    <a href="{app_url}" style="background:{grade_color};color:#060b14;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:.9rem">View Full Report →</a>
  </div>

  <p style="color:#334155;font-size:.7rem;text-align:center;margin-top:32px">
    AI Cyber Shield · Scheduled scan · Unsubscribe by disabling the schedule in your dashboard
  </p>
</div>
</body></html>"""

    try:
        import httpx
        resp = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
            json={
                # TODO: switch back to "AI Cyber Shield <alerts@aicybershield.com>"
                # once that domain is added + DNS-verified in Resend. Until then,
                # Resend's shared sandbox sender works without domain verification,
                # but can only deliver to the email address the Resend account
                # itself was signed up with.
                "from":    "AI Cyber Shield <onboarding@resend.dev>",
                "to":      [notify_email],
                "subject": f"[{grade}] Security scan: {url} — score {score}/100",
                "html":    html,
            },
            timeout=10,
        )
        resp.raise_for_status()
        _log.info("Notification sent to %s", notify_email)
    except Exception as exc:
        _log.warning("Failed to send notification: %s", exc)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="AI Cyber Shield scheduled scan runner")
    parser.add_argument("--dry-run",  action="store_true", help="List due scans but don't run them")
    parser.add_argument("--limit",    type=int, default=20,  help="Max scans to run per invocation (default: 20)")
    parser.add_argument("--schedule-id", help="Run a specific schedule ID only")
    args = parser.parse_args()

    client = _get_supabase()

    # ── Fetch all enabled schedules ──────────────────────────────────────────
    try:
        q = client.table("scheduled_scans").select("*").eq("enabled", True)
        if args.schedule_id:
            q = q.eq("id", args.schedule_id)
        schedules = q.execute().data or []
    except Exception as exc:
        _log.error("Failed to fetch schedules: %s", exc)
        sys.exit(1)

    _log.info("Fetched %d enabled schedules", len(schedules))

    due = [s for s in schedules if _is_due(s.get("cron_expression", ""), s.get("last_run_at"))]
    _log.info("%d schedules are due for execution", len(due))

    if not due:
        _log.info("Nothing to do.")
        return

    run_count = 0
    fail_count = 0

    for sched in due[:args.limit]:
        url      = sched.get("url", "")
        sched_id = sched.get("id", "")
        label    = sched.get("label") or url

        if not url:
            continue

        _log.info("─── Running: %s [%s]", label, sched_id[:8])

        # 1. Mark as running (prevents double-execution if actions run concurrently)
        try:
            client.table("scheduled_scans").update({
                "last_run_at": datetime.now(timezone.utc).isoformat(),
                "status": "running",
            }).eq("id", sched_id).execute()
        except Exception as exc:
            _log.warning("Could not mark as running: %s", exc)

        # 2. Execute scan
        result = _run_scan(url, sched_id, dry_run=args.dry_run)
        ok = "error" not in result

        # 3. Save to history
        if not args.dry_run and ok:
            _save_result(client, result, sched)

        # 4. Send notification
        if not args.dry_run:
            _send_notification(result, sched)

        # 5. Update schedule (last_run_at, next_run_at, status, run_count)
        if not args.dry_run:
            try:
                cron_expr = sched.get("cron_expression", "")
                client.table("scheduled_scans").update({
                    "last_run_at":      datetime.now(timezone.utc).isoformat(),
                    "next_run_at":      _compute_next_run(cron_expr),
                    "status":           "ok" if ok else "error",
                    "last_grade":       result.get("overall_grade"),
                    "last_score":       result.get("overall_score"),
                    "run_count":        (sched.get("run_count") or 0) + 1,
                    "last_error":       result.get("error") if not ok else None,
                }).eq("id", sched_id).execute()
            except Exception as exc:
                _log.warning("Failed to update schedule: %s", exc)

        if ok:
            run_count += 1
        else:
            fail_count += 1

    _log.info("Done — %d succeeded, %d failed.", run_count, fail_count)
    # Exit 0 always — don't break CI pipeline for individual scan failures
    sys.exit(0)


if __name__ == "__main__":
    main()

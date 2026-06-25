"""
api/tasks.py — Celery task definitions for async scan execution

Each task:
  1. Marks the scan as RUNNING in ScanStore
  2. Executes the full scan pipeline (URL security audit)
  3. Enriches findings with EPSS / severity data
  4. Persists results in ScanStore
  5. Fires webhook callback if configured

Tasks are idempotent — re-running a completed scan_id is a no-op (the store
returns the cached result).  Celery's retry mechanism handles transient failures
(network timeouts, LLM rate limits) with exponential back-off.
"""

from __future__ import annotations

import logging
from typing import Optional

from api.worker import celery_app

_log = logging.getLogger(__name__)

# Guard: only define Celery tasks when Celery is configured
if celery_app is not None:

    @celery_app.task(
        name="aics.run_scan",
        bind=True,
        max_retries=3,
        default_retry_delay=15,   # seconds; Celery doubles this with exponential back-off
        acks_late=True,
    )
    def run_scan_task(
        self,
        scan_id:     str,
        url:         str,
        mode:        str,
        webhook_url: Optional[str] = None,
    ) -> dict:
        """
        Celery task: execute a full URL security scan.

        Args:
            scan_id:     UUID assigned at task creation (persisted in ScanStore).
            url:         Target URL.
            mode:        Scan mode string ("passive" | "standard" | "pt").
            webhook_url: Optional callback URL to POST results when complete.

        Returns:
            Summary dict: {scan_id, status, overall_score, overall_grade}

        Retry policy:
            Up to 3 retries on transient errors (network, LLM rate limit).
            Permanent errors (invalid URL, SSRF block) are not retried.
        """
        from api.scan_store import get_store
        from api.dependencies import get_scanner_fn, get_webhook_sender

        store          = get_store()
        scanner_fn     = get_scanner_fn()
        webhook_sender = get_webhook_sender()

        _log.info("Celery task: scan %s started — %s [%s]", scan_id, url, mode)
        store.mark_running(scan_id)

        try:
            # 1. Run the full scan pipeline (blocking, ~30-90 s)
            raw_result = scanner_fn(url, mode)

            # 2. Enrich with EPSS + extra metadata
            try:
                from finding_enricher import enrich_scan_result
                av_results = raw_result.pop("av_results", None)
                findings   = enrich_scan_result(raw_result, av_results=av_results)
            except Exception as enrich_err:
                _log.warning("Enrichment failed (non-fatal): %s", enrich_err)
                findings = []

            # 3. Persist
            store.mark_complete(scan_id, raw_result, findings)
            _log.info(
                "Celery task: scan %s complete — score=%s grade=%s",
                scan_id,
                raw_result.get("overall_score", "?"),
                raw_result.get("overall_grade", "?"),
            )

            # 4. Webhook callback
            if webhook_url:
                try:
                    webhook_sender(webhook_url, {"scan_id": scan_id, **raw_result})
                except Exception as wh_err:
                    _log.warning("Webhook delivery failed: %s", wh_err)

            return {
                "scan_id":       scan_id,
                "status":        "complete",
                "overall_score": raw_result.get("overall_score"),
                "overall_grade": raw_result.get("overall_grade"),
            }

        except Exception as exc:
            _log.error("Scan %s failed: %s", scan_id, exc, exc_info=True)

            # Determine whether this is retryable
            _permanent_errors = ("invalid_url", "ssrf_blocked", "permission_denied")
            is_permanent = any(tag in str(exc).lower() for tag in _permanent_errors)

            if is_permanent:
                store.mark_failed(scan_id, str(exc))
                raise  # no retry

            # Transient — retry with exponential back-off
            store.mark_failed(scan_id, f"Attempt {self.request.retries + 1} failed: {exc}")
            raise self.retry(exc=exc)


else:
    # Celery not configured — provide a no-op stub so imports don't break
    def run_scan_task(*args, **kwargs):  # type: ignore[misc]
        raise RuntimeError(
            "Celery is not configured.  Set REDIS_URL to enable the distributed task queue."
        )

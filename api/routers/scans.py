"""
api/routers/scans.py — AI Cyber Shield v6

Endpoints:
  POST   /api/v1/scans           — trigger a new scan (async background)
  GET    /api/v1/scans           — list scans (paginated, filterable)
  GET    /api/v1/scans/{scan_id} — get single scan status
  DELETE /api/v1/scans/{scan_id} — cancel or remove a scan
"""

from __future__ import annotations

import logging
from typing import Annotated, Callable, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status

from api.auth import verify_api_key
from api.dependencies import get_scanner_fn, get_webhook_sender
from api.models import ScanListResponse, ScanMode, ScanRequest, ScanResponse
from api.scan_store import ScanState, ScanStore, get_store
from finding_enricher import enrich_scan_result

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


# ─────────────────────────────────────────────────────────────────────────────
# Background task
# ─────────────────────────────────────────────────────────────────────────────

def _make_progress_callback(scan_id: str):
    """
    Build a progress_callback that publishes SSE events for a scan.
    Publishes scan_progress (percent complete) after each tool finishes.
    """
    from api.events import ScanEvent, scan_events  # noqa: PLC0415
    from datetime import datetime, timezone          # noqa: PLC0415

    completed = 0
    total = 17

    def _callback(event_type: str, data: dict) -> None:
        nonlocal completed
        ts = data.get("timestamp", datetime.now(timezone.utc).isoformat())
        scan_events.publish(scan_id, ScanEvent(event_type=event_type, timestamp=ts, data=data))
        if event_type in ("tool_completed", "tool_failed"):
            completed += 1
            scan_events.publish(scan_id, ScanEvent(
                event_type="scan_progress",
                timestamp=datetime.now(timezone.utc).isoformat(),
                data={"completed": completed, "total": total,
                      "percent": int((completed / total) * 100)},
            ))

    return _callback


def _execute_scan(
    scan_id:        str,
    url:            str,
    mode:           str,
    store:          ScanStore,
    scanner_fn:     Callable[[str, str], dict],
    webhook_sender: Callable[[str, dict], None],
    webhook_url:    Optional[str],
) -> None:
    """
    Runs in FastAPI's thread pool (sync background task).
    Executes the full scan pipeline and stores enriched findings.
    Publishes real-time SSE events via _make_progress_callback.
    """
    from api.events import ScanEvent, scan_events  # noqa: PLC0415
    from datetime import datetime, timezone          # noqa: PLC0415

    _log.info("Scan %s started: %s [%s]", scan_id, url, mode)
    store.mark_running(scan_id)
    progress_callback = _make_progress_callback(scan_id)

    try:
        # 1. Run the scanner (synchronous, ~30s) with progress reporting
        raw_result = scanner_fn(url, mode, progress_callback=progress_callback)

        # 2. Enrich findings
        av_results = raw_result.pop("av_results", None)
        findings   = enrich_scan_result(raw_result, av_results=av_results)

        # 3. Persist
        store.mark_complete(scan_id, raw_result, findings)
        _log.info(
            "Scan %s complete: score=%s grade=%s findings=%d",
            scan_id,
            raw_result.get("overall_score"),
            raw_result.get("overall_grade"),
            len(findings),
        )

        # 4. Publish terminal SSE event
        scan_events.publish(scan_id, ScanEvent(
            event_type="scan_completed",
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={
                "overall_score":  raw_result.get("overall_score"),
                "grade":          raw_result.get("overall_grade"),
                "findings_count": len(findings),
            },
        ))
        scan_events.mark_completed(scan_id)

        # 5. Webhook notification
        if webhook_url:
            payload = {
                "scan_id":       scan_id,
                "url":           url,
                "status":        "complete",
                "overall_score": raw_result.get("overall_score"),
                "overall_grade": raw_result.get("overall_grade"),
                "finding_count": len(findings),
            }
            webhook_sender(webhook_url, payload)

    except Exception as exc:
        _log.exception("Scan %s failed: %s", scan_id, exc)
        store.mark_failed(scan_id, str(exc))

        scan_events.publish(scan_id, ScanEvent(
            event_type="scan_failed",
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={"error": str(exc)[:500]},
        ))
        scan_events.mark_completed(scan_id)

        if webhook_url:
            try:
                webhook_sender(webhook_url, {
                    "scan_id": scan_id,
                    "url":     url,
                    "status":  "failed",
                    "error":   str(exc),
                })
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanResponse,
    summary="Trigger a new security scan",
)
async def create_scan(
    req:             ScanRequest,
    background_tasks: BackgroundTasks,
    store:           ScanStore      = Depends(get_store),
    scanner_fn:      Callable       = Depends(get_scanner_fn),
    webhook_sender:  Callable       = Depends(get_webhook_sender),
    _api_key:        str            = Depends(verify_api_key),
) -> ScanResponse:
    """
    Enqueue a security scan for the given URL.
    Returns immediately with status=queued.
    Poll GET /scans/{scan_id} for progress.
    """
    # SSRF guard — must be called before any outbound request
    try:
        from tools.http_utils import is_ssrf_blocked  # noqa: PLC0415
        if is_ssrf_blocked(req.url):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error":  "SSRF protection blocked this URL",
                    "code":   "SSRF_BLOCKED",
                    "detail": "The target URL resolves to a private or reserved IP address",
                },
            )
    except ImportError:
        pass  # SSRF guard module not present — allow (dev environment)

    state = store.create(
        url=req.url,
        mode=req.mode.value,
        label=req.label,
        notify_webhook_url=req.notify_webhook_url,
    )

    # ── Dispatch: Celery (distributed) or BackgroundTasks (single-process) ────
    from api.worker import is_celery_available  # noqa: PLC0415
    if is_celery_available():
        from api.tasks import run_scan_task  # noqa: PLC0415
        run_scan_task.apply_async(
            args=[state.scan_id, req.url, req.mode.value, req.notify_webhook_url],
            queue="aics_scans",
        )
        _log.info("Scan %s dispatched to Celery queue", state.scan_id)
    else:
        background_tasks.add_task(
            _execute_scan,
            state.scan_id,
            req.url,
            req.mode.value,
            store,
            scanner_fn,
            webhook_sender,
            req.notify_webhook_url,
        )
        _log.info("Scan %s dispatched to BackgroundTasks (Celery not configured)", state.scan_id)

    return ScanResponse(**state.to_response_dict())


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List all scans",
)
async def list_scans(
    url:      Optional[str] = Query(None, description="Filter by URL substring"),
    scan_status: Optional[str] = Query(None, alias="status",
                                       description="queued|running|complete|failed"),
    page:     int = Query(1,  ge=1,  description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    store:    ScanStore = Depends(get_store),
    _api_key: str       = Depends(verify_api_key),
) -> ScanListResponse:
    items, total = store.list(
        url_filter=url,
        status_filter=scan_status,
        page=page,
        per_page=per_page,
    )
    return ScanListResponse(
        scans=[ScanResponse(**s.to_response_dict()) for s in items],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan status and metadata",
)
async def get_scan(
    scan_id:  str,
    store:    ScanStore = Depends(get_store),
    _api_key: str       = Depends(verify_api_key),
) -> ScanResponse:
    state = store.get(scan_id)
    if not state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Scan not found", "code": "SCAN_NOT_FOUND"},
        )
    return ScanResponse(**state.to_response_dict())


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a completed or failed scan",
)
async def delete_scan(
    scan_id:  str,
    store:    ScanStore = Depends(get_store),
    _api_key: str       = Depends(verify_api_key),
) -> None:
    state = store.get(scan_id)
    if not state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Scan not found", "code": "SCAN_NOT_FOUND"},
        )
    if state.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error":  "Cannot delete a running scan",
                "code":   "SCAN_STILL_RUNNING",
                "detail": "Wait for the scan to complete before deleting",
            },
        )
    store.delete(scan_id)

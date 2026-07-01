"""
api/routers/events.py — AI Cyber Shield v6

Server-Sent Events endpoint for real-time scan progress.

SSE requires NO authentication — the scan_id UUID is the access token.
Only the entity that initiated the scan knows the scan_id, so there is
no practical way for a third party to subscribe to someone else's stream.

Wire format (text/event-stream):
  event: tool_completed
  data: {"tool_name": "ssl", "score": 95, "duration_ms": 2100}

  event: scan_progress
  data: {"completed": 3, "total": 17, "percent": 18}

  event: scan_completed
  data: {"overall_score": 87, "grade": "B", "findings_count": 2}

  : keepalive          ← sent every 30 s of silence to prevent proxy timeout
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from api.events import ScanEvent, scan_events

_log = logging.getLogger(__name__)

router = APIRouter(tags=["events"])


@router.get(
    "/scans/{scan_id}/events",
    summary="Stream real-time scan progress (SSE)",
    response_class=StreamingResponse,
)
async def stream_scan_events(scan_id: str, request: Request):
    """
    Subscribe to Server-Sent Events for a scan.

    Connect immediately after POST /api/v1/scans to receive:
      - tool_started / tool_completed / tool_failed per tool
      - scan_progress with percent complete
      - scan_completed or scan_failed at the end

    The stream terminates automatically after a terminal event.
    A keepalive comment is sent every 30 s to keep proxies from closing
    idle connections.
    """
    async def event_generator():
        queue = await scan_events.subscribe(scan_id)
        try:
            while True:
                if await request.is_disconnected():
                    _log.debug("SSE client disconnected: scan=%s", scan_id)
                    break
                try:
                    event: ScanEvent = await asyncio.wait_for(
                        queue.get(), timeout=30.0
                    )
                    yield event.to_sse()

                    if event.event_type in ("scan_completed", "scan_failed"):
                        break
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            scan_events.unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "Connection":       "keep-alive",
            "X-Accel-Buffering": "no",  # prevent Nginx from buffering SSE
        },
    )

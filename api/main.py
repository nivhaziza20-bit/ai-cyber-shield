"""
api/main.py — AI Cyber Shield v6

FastAPI application assembly.

Start locally:
    uvicorn api.main:app --reload --port 8000

Environment variables:
    AICS_API_KEYS       — comma-separated valid API keys
    AICS_CORS_ORIGINS   — comma-separated allowed CORS origins
                          (defaults to localhost dev origins if not set)
    AICS_ENV            — "production" | "development" (default: development)
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.events import scan_events
from api.models import ErrorResponse, HealthResponse
from api.routers import badge as badge_router
from api.routers import chat as chat_router
from api.routers import findings, scans
from api.routers import events as events_router
from api.routers import trends as trends_router
from scheduler.engine import get_engine as get_scheduler_engine

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────────────────────

_ENV  = os.environ.get("AICS_ENV", "development")
_IS_PROD = _ENV == "production"

_DEFAULT_ORIGINS = [
    "http://localhost:3000",   # Next.js dev
    "http://localhost:8501",   # Streamlit dev
    "http://localhost:8000",   # FastAPI self
]

_cors_env = os.environ.get("AICS_CORS_ORIGINS", "")
_CORS_ORIGINS = (
    [o.strip() for o in _cors_env.split(",") if o.strip()]
    if _cors_env
    else _DEFAULT_ORIGINS
)

# ─────────────────────────────────────────────────────────────────────────────
# Application lifespan
# ─────────────────────────────────────────────────────────────────────────────

async def _cleanup_loop() -> None:
    """Purge SSE event history for scans completed >5 minutes ago."""
    while True:
        await asyncio.sleep(300)  # run every 5 minutes
        purged = scan_events.cleanup()
        if purged:
            _log.debug("SSE event cleanup: purged %d expired scan(s)", purged)


@asynccontextmanager
async def lifespan(app_: FastAPI):
    _log.info("AI Cyber Shield API v6 starting — env=%s", _ENV)
    if not _IS_PROD:
        _log.warning(
            "Running in DEVELOPMENT mode. "
            "Set AICS_ENV=production and AICS_API_KEYS for deployment."
        )
    cleanup_task = asyncio.create_task(_cleanup_loop())

    # Start scan scheduler (unless disabled via env)
    _scheduler_enabled = os.environ.get("SCHEDULER_ENABLED", "true").lower() == "true"
    if _scheduler_enabled:
        try:
            get_scheduler_engine().start()
            _log.info("Scan scheduler started")
        except Exception as exc:
            _log.warning("Scan scheduler could not start: %s", exc)

    yield

    cleanup_task.cancel()
    if _scheduler_enabled:
        try:
            get_scheduler_engine().shutdown(wait=False)
        except Exception:
            pass
    _log.info("AI Cyber Shield API shutting down")


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Cyber Shield API",
    version="6.0.0",
    description=(
        "Enterprise security scanning API — 17-tool DAST pipeline with "
        "CVSS 3.1 scoring, OWASP 2025 mapping, and SARIF 2.1 export."
    ),
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
    lifespan=lifespan,
)

# CORS — never allow wildcard in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PATCH"],
    allow_headers=["X-API-Key", "Content-Type", "Accept"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Global error handlers
# ─────────────────────────────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Not found", "code": "NOT_FOUND", "path": str(request.url.path)},
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    _log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "code": "INTERNAL_ERROR"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Health endpoint (no auth — for load balancer / k8s probes)
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["health"],
    summary="Health check — no authentication required",
)
async def health() -> HealthResponse:
    return HealthResponse()


# ─────────────────────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────────────────────

app.include_router(scans.router,          prefix="/api/v1")
app.include_router(findings.router,       prefix="/api/v1")
app.include_router(events_router.router,  prefix="/api/v1")
app.include_router(badge_router.router,   prefix="/api/v1")
app.include_router(chat_router.router,    prefix="/api/v1")
app.include_router(trends_router.router,  prefix="/api/v1")

"""
api/worker.py — Celery worker for async scan execution

Migration path
──────────────
Currently the scanner runs in FastAPI's BackgroundTasks thread pool (one process,
blocking, no horizontal scale).  This module introduces a Celery worker that
off-loads scan execution to a Redis-backed task queue.

Activation
──────────
Set REDIS_URL in your environment/secrets:
  REDIS_URL=redis://localhost:6379/0

If REDIS_URL is absent, the system automatically falls back to BackgroundTasks
(existing behaviour) — no code changes required in the router.

Running the worker
──────────────────
  celery -A api.worker worker --loglevel=info --concurrency=4

Running with Docker Compose (recommended for production):
  services:
    redis: image: redis:7-alpine
    worker:
      build: .
      command: celery -A api.worker worker --loglevel=info
      environment: { REDIS_URL: redis://redis:6379/0 }

Scaling
───────
Multiple worker replicas can run against the same Redis broker.
Each worker consumes from the "aics_scans" queue — add more replicas behind a
load balancer to achieve horizontal scale without changing the FastAPI layer.

Security notes
──────────────
• REDIS_URL must be a private/internal URL — never expose Redis publicly.
• Celery result backend stores scan results in Redis temporarily.
  Results auto-expire after RESULT_TTL_S seconds (default: 24 hours).
"""

from __future__ import annotations

import logging
import os

_log = logging.getLogger(__name__)

REDIS_URL      = os.environ.get("REDIS_URL", "")
RESULT_TTL_S   = int(os.environ.get("AICS_CELERY_RESULT_TTL", str(86_400)))  # 24 h
TASK_QUEUE     = "aics_scans"

# ─────────────────────────────────────────────────────────────────────────────
# Celery app (only instantiated when REDIS_URL is set)
# ─────────────────────────────────────────────────────────────────────────────

celery_app = None

if REDIS_URL:
    try:
        from celery import Celery  # type: ignore[import]

        celery_app = Celery(
            "aics",
            broker=REDIS_URL,
            backend=REDIS_URL,
            include=["api.tasks"],
        )
        celery_app.conf.update(
            task_queues=None,            # use default queue routing
            task_default_queue=TASK_QUEUE,
            task_serializer="json",
            result_serializer="json",
            accept_content=["json"],
            result_expires=RESULT_TTL_S,
            worker_max_tasks_per_child=50,   # recycle workers after N tasks (memory)
            task_acks_late=True,             # re-queue on worker crash
            task_reject_on_worker_lost=True,
        )
        _log.info("Celery worker configured with broker: %s", REDIS_URL[:30] + "…")
    except ImportError:
        _log.warning(
            "celery package not installed — add celery>=5.3 + redis>=5.0 to requirements.txt "
            "to enable the distributed task queue.  Falling back to BackgroundTasks."
        )
        celery_app = None
else:
    _log.debug(
        "REDIS_URL not set — Celery disabled.  Scans run in FastAPI BackgroundTasks thread pool."
    )


def is_celery_available() -> bool:
    """Return True when the Celery worker is configured and can accept tasks."""
    return celery_app is not None

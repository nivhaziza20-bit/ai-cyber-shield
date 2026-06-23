"""
api/auth.py — AI Cyber Shield v6

API key authentication via X-API-Key header.

Keys are loaded from the AICS_API_KEYS environment variable
as a comma-separated list, e.g.:

    AICS_API_KEYS=key-prod-abc123,key-dev-xyz789

If the variable is not set, a default development key is used
(with a startup warning — never ship with the dev key in production).

Scopes (future-proofing):
  read  → GET endpoints only
  write → POST/DELETE (triggers scans)
  admin → all endpoints including schedule management
"""

from __future__ import annotations

import logging
import os
import secrets
from functools import lru_cache

from fastapi import Header, HTTPException, status

_log = logging.getLogger(__name__)

_DEV_KEY = "aics-dev-key-DO-NOT-USE-IN-PRODUCTION"

_ENV_VAR = "AICS_API_KEYS"


@lru_cache(maxsize=1)
def _load_keys() -> frozenset[str]:
    """
    Load API keys from environment. Cached after first call.
    Call _load_keys.cache_clear() in tests to reset between test runs.
    """
    raw = os.environ.get(_ENV_VAR, "").strip()
    if not raw:
        _log.warning(
            "AICS_API_KEYS not set — using insecure development key. "
            "Set the environment variable before deploying to production."
        )
        return frozenset([_DEV_KEY])

    keys = frozenset(k.strip() for k in raw.split(",") if k.strip())
    if not keys:
        raise RuntimeError(f"{_ENV_VAR} is set but contains no valid keys")

    _log.info("Loaded %d API key(s)", len(keys))
    return keys


def verify_api_key(x_api_key: str = Header(default=None)) -> str:
    """
    FastAPI dependency. Raises 401 if header is missing, 403 if key is invalid.
    Returns the key on success (can be used for logging/audit).

    Usage:
        @router.get("/resource")
        async def endpoint(api_key: str = Depends(verify_api_key)):
            ...
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Authentication required",
                "code":  "MISSING_API_KEY",
                "detail": "Provide your API key in the X-API-Key header",
            },
        )

    valid_keys = _load_keys()
    # Use secrets.compare_digest to prevent timing attacks
    if not any(secrets.compare_digest(x_api_key, k) for k in valid_keys):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Invalid API key",
                "code":  "INVALID_API_KEY",
                "detail": "The provided API key is not authorised",
            },
        )

    return x_api_key

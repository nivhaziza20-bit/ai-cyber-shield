"""Audit logger — records all user actions to Supabase audit_logs."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)


def log_action(
    action: str,
    *,
    target: str = "",
    details: dict[str, Any] | None = None,
    severity: str = "info",
) -> None:
    """
    Log a user action. Silent no-op if Supabase is not configured.

    Actions: login, logout, scan_start, scan_complete, scan_error,
             pt_request, pt_approved, pt_revoked, quota_exceeded, register
    Severity: info | warning | error
    """
    try:
        import streamlit as st
        from auth.streamlit_auth import get_current_user, _client

        client = _client()
        if client is None:
            return

        user = get_current_user()
        row: dict[str, Any] = {
            "action": action,
            "target": target or None,
            "details": details or {},
            "severity": severity,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if user:
            row["user_id"] = user.user_id
            row["user_email"] = user.email

        client.table("audit_logs").insert(row).execute()
    except Exception as exc:
        _log.debug("audit_log error: %s", exc)

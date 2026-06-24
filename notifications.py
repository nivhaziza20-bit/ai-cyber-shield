"""Send scan-complete email via Supabase Edge Function (Resend)."""
from __future__ import annotations
import logging
import streamlit as st

_log = logging.getLogger(__name__)


def notify_scan_complete(
    user_email: str,
    target_url: str,
    overall_grade: str,
    overall_score: int,
    critical_count: int,
    high_count: int,
    scan_duration_s: float,
) -> None:
    """
    Fire-and-forget: POST to the Supabase Edge Function that sends the scan email.
    Silently swallowed on any error — notifications are non-critical.
    """
    supabase_url = st.secrets.get("SUPABASE_URL", "")
    if not supabase_url:
        return

    edge_url = f"{supabase_url.rstrip('/')}/functions/v1/send-scan-email"
    service_key = st.secrets.get("SUPABASE_SERVICE_KEY", "") or st.secrets.get("SUPABASE_KEY", "")
    if not service_key:
        return

    payload = {
        "to":               user_email,
        "target_url":       target_url,
        "overall_grade":    overall_grade,
        "overall_score":    overall_score,
        "critical_count":   critical_count,
        "high_count":       high_count,
        "scan_duration_s":  round(scan_duration_s, 1),
    }

    try:
        import requests
        requests.post(
            edge_url,
            json=payload,
            headers={
                "Authorization": f"Bearer {service_key}",
                "Content-Type":  "application/json",
            },
            timeout=5,
        )
    except Exception as exc:
        _log.debug("notify_scan_complete: %s", exc)


def should_notify(user) -> bool:
    """Return True if the user has email notifications enabled (paid tier or admin)."""
    if user is None:
        return False
    return user.is_admin or user.is_paid

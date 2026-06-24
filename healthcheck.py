"""
Health check endpoint — returns service status.
Called by UptimeRobot, load balancers, and the API.
Accessible without auth at /?health=1
"""
from __future__ import annotations
import json
import time
import logging
import streamlit as st

_log = logging.getLogger(__name__)

_VERSION = "6.1.0"
_START_TIME = time.time()


def _check_supabase() -> str:
    try:
        url = st.secrets.get("SUPABASE_URL", "")
        key = st.secrets.get("SUPABASE_KEY", "")
        if not url or not key:
            return "not_configured"
        from supabase import create_client
        c = create_client(url, key)
        c.table("profiles").select("id").limit(1).execute()
        return "ok"
    except Exception as exc:
        _log.warning("healthcheck db: %s", exc)
        return "degraded"


def show_health_page() -> None:
    """Render a machine-readable health status page."""
    uptime_s = int(time.time() - _START_TIME)
    db_status = _check_supabase()

    overall = "ok" if db_status in ("ok", "not_configured") else "degraded"

    status = {
        "status":    overall,
        "version":   _VERSION,
        "uptime_s":  uptime_s,
        "components": {
            "database": db_status,
            "groq":     "configured" if st.secrets.get("GROQ_API_KEY") else "not_configured",
            "stripe":   "configured" if st.secrets.get("STRIPE_SECRET_KEY") else "not_configured",
            "sentry":   "configured" if st.secrets.get("SENTRY_DSN") else "not_configured",
        },
    }

    color = "#10b981" if overall == "ok" else "#f59e0b"

    st.markdown(f"# 🛡 AI Cyber Shield — Health Check")
    st.markdown(f"""
<div style="background:#0d1117;border:1px solid {color}33;border-radius:12px;padding:24px;margin:16px 0;">
  <div style="font-size:1.5rem;font-weight:900;color:{color};margin-bottom:8px;">
    {'✅ All Systems Operational' if overall == 'ok' else '⚠️ Degraded'}
  </div>
  <div style="color:#475569;font-size:0.85rem;">Version {_VERSION} · Uptime {uptime_s // 3600}h {(uptime_s % 3600)//60}m</div>
</div>
""", unsafe_allow_html=True)

    for component, comp_status in status["components"].items():
        icon = "✅" if comp_status in ("ok", "configured") else ("⚠️" if comp_status == "degraded" else "⚫")
        st.markdown(f"**{icon} {component.capitalize()}**: `{comp_status}`")

    st.divider()
    st.code(json.dumps(status, indent=2), language="json")
    st.caption("This page is publicly accessible for monitoring tools.")


def maybe_show_health() -> bool:
    """
    Check URL query params. If ?health=1, render health page and return True.
    Call at the very top of the app before auth.
    """
    params = st.query_params
    if params.get("health") == "1" or params.get("health") == "true":
        show_health_page()
        st.stop()
        return True
    return False

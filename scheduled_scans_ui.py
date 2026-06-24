"""
Scheduled Scans UI — Streamlit panel for managing recurring scans.
Stores schedules in Supabase so they persist across app restarts.
"""
from __future__ import annotations
import logging
import streamlit as st

_log = logging.getLogger(__name__)

_CRON_PRESETS = {
    "Every hour":       "0 * * * *",
    "Daily at 6am UTC": "0 6 * * *",
    "Weekly (Monday)":  "0 8 * * 1",
    "Monthly (1st)":    "0 9 1 * *",
    "Custom":           "",
}


def _client():
    from auth.streamlit_auth import _client as auth_client
    return auth_client()


def _ensure_table() -> bool:
    """Create scheduled_scans table if missing. Returns True on success."""
    c = _client()
    if c is None:
        return False
    try:
        c.table("scheduled_scans").select("id").limit(1).execute()
        return True
    except Exception:
        return False


def load_schedules(user_id: str) -> list[dict]:
    c = _client()
    if c is None:
        return []
    try:
        resp = (c.table("scheduled_scans")
                .select("*")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .execute())
        return resp.data or []
    except Exception as exc:
        _log.debug("load_schedules: %s", exc)
        return []


def save_schedule(user_id: str, url: str, cron: str, label: str) -> bool:
    c = _client()
    if c is None:
        return False
    try:
        c.table("scheduled_scans").insert({
            "user_id": user_id,
            "target_url": url,
            "cron_expression": cron,
            "label": label or url,
            "enabled": True,
        }).execute()
        return True
    except Exception as exc:
        _log.debug("save_schedule: %s", exc)
        return False


def delete_schedule(schedule_id: str, user_id: str) -> bool:
    c = _client()
    if c is None:
        return False
    try:
        c.table("scheduled_scans").delete().eq("id", schedule_id).eq("user_id", user_id).execute()
        return True
    except Exception as exc:
        _log.debug("delete_schedule: %s", exc)
        return False


def toggle_schedule(schedule_id: str, user_id: str, enabled: bool) -> bool:
    c = _client()
    if c is None:
        return False
    try:
        c.table("scheduled_scans").update({"enabled": enabled}).eq("id", schedule_id).eq("user_id", user_id).execute()
        return True
    except Exception as exc:
        _log.debug("toggle_schedule: %s", exc)
        return False


def show_scheduled_scans_panel(user, is_paid: bool = False) -> None:
    """Full Streamlit panel for managing scheduled scans."""
    st.markdown("## 🕐 Scheduled Scans")

    if not is_paid:
        st.info(
            "⚡ Scheduled scans are available on **Starter ($29/mo)** and above. "
            "Upgrade to automate recurring security checks."
        )
        if st.button("Upgrade to Starter →", type="primary", key="sched_upgrade_btn"):
            st.session_state["_show_pricing"] = True
            st.rerun()
        return

    st.caption("Automated scans run on a schedule and notify you of new findings.")

    schedules = load_schedules(user.user_id)

    # ── Existing schedules ────────────────────────────────────────────────────
    if schedules:
        st.markdown(f"**{len(schedules)} active schedule(s)**")
        for sched in schedules:
            sid     = sched.get("id", "")
            url     = sched.get("target_url", "")
            cron    = sched.get("cron_expression", "")
            label   = sched.get("label", url)
            enabled = sched.get("enabled", True)
            last_run = (sched.get("last_run_at") or "Never")[:16]

            with st.expander(f"{'🟢' if enabled else '⚫'} {label} — `{cron}`"):
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    st.caption(f"URL: {url}")
                    st.caption(f"Last run: {last_run}")
                with col2:
                    if st.button("⏸ Pause" if enabled else "▶ Resume",
                                 key=f"toggle_{sid}", use_container_width=True):
                        if toggle_schedule(sid, user.user_id, not enabled):
                            st.rerun()
                with col3:
                    if st.button("🗑 Delete", key=f"del_{sid}", use_container_width=True):
                        if delete_schedule(sid, user.user_id):
                            st.success("Schedule deleted.")
                            st.rerun()
    else:
        st.info("No schedules configured yet.")

    st.divider()

    # ── Add new schedule ──────────────────────────────────────────────────────
    st.markdown("### ➕ Add New Schedule")

    with st.form("new_schedule_form", clear_on_submit=True):
        new_url   = st.text_input("Target URL", placeholder="https://your-site.com")
        new_label = st.text_input("Label (optional)", placeholder="Production weekly check")
        preset    = st.selectbox("Frequency", list(_CRON_PRESETS.keys()), key="sched_preset")

        cron_val = _CRON_PRESETS[preset]
        if preset == "Custom":
            cron_val = st.text_input(
                "Cron expression (UTC)",
                placeholder="0 6 * * *  ← daily at 6am UTC",
                help="Standard 5-field cron: min hour day month weekday",
            )
        else:
            st.caption(f"Cron: `{cron_val}` (UTC)")

        submitted = st.form_submit_button("Add Schedule", type="primary")
        if submitted:
            errors = []
            if not new_url or not new_url.startswith("https://"):
                errors.append("URL must start with https://")
            if not cron_val.strip():
                errors.append("Choose or enter a cron expression.")
            if errors:
                for e in errors:
                    st.error(e)
            else:
                if save_schedule(user.user_id, new_url.strip(), cron_val.strip(), new_label.strip()):
                    st.success(f"Schedule added: {new_url}")
                    st.rerun()
                else:
                    st.error("Failed to save schedule — check Supabase connection.")

    st.caption("⚠️ Note: Scheduled scans run via Supabase Edge Functions or a background worker. "
               "Contact support to enable automated execution for your account.")

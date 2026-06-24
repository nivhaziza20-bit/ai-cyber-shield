"""Team Management UI — invite, list, remove team members."""
from __future__ import annotations
import logging
import secrets
import streamlit as st

_log = logging.getLogger(__name__)

_ROLES = {
    "viewer":  "Can view scan results and history",
    "analyst": "Can run scans and view results",
    "admin":   "Full access including team management",
}


def _client():
    from auth.streamlit_auth import _client as auth_client
    return auth_client()


def load_team(owner_id: str) -> list[dict]:
    c = _client()
    if c is None:
        return []
    try:
        resp = (c.table("team_members")
                .select("*")
                .eq("owner_id", owner_id)
                .order("created_at", desc=True)
                .execute())
        return resp.data or []
    except Exception as exc:
        _log.debug("load_team: %s", exc)
        return []


def invite_member(owner_id: str, email: str, role: str) -> dict:
    c = _client()
    if c is None:
        return {"error": "Database not available"}
    token = secrets.token_urlsafe(24)
    try:
        c.table("team_members").insert({
            "owner_id":     owner_id,
            "member_email": email.lower().strip(),
            "role":         role,
            "invite_token": token,
        }).execute()
        return {"ok": True, "token": token}
    except Exception as exc:
        msg = str(exc)
        if "duplicate" in msg.lower() or "unique" in msg.lower():
            return {"error": f"{email} is already a team member"}
        return {"error": msg}


def remove_member(member_id: str, owner_id: str) -> bool:
    c = _client()
    if c is None:
        return False
    try:
        c.table("team_members").delete().eq("id", member_id).eq("owner_id", owner_id).execute()
        return True
    except Exception as exc:
        _log.debug("remove_member: %s", exc)
        return False


def update_role(member_id: str, owner_id: str, new_role: str) -> bool:
    c = _client()
    if c is None:
        return False
    try:
        c.table("team_members").update({"role": new_role}).eq("id", member_id).eq("owner_id", owner_id).execute()
        return True
    except Exception as exc:
        _log.debug("update_role: %s", exc)
        return False


def show_team_panel(user, is_enterprise: bool = False) -> None:
    """Full team management UI."""
    st.markdown("## 👥 Team Management")

    if not is_enterprise:
        st.info(
            "👥 Team management is available on **Enterprise ($299/mo)**. "
            "Upgrade to invite colleagues and share scan access."
        )
        if st.button("Upgrade to Enterprise →", type="primary", key="team_upgrade_btn"):
            st.session_state["_show_pricing"] = True
            st.rerun()
        return

    members = load_team(user.user_id)

    # ── Current members ───────────────────────────────────────────────────────
    st.markdown(f"**Team members: {len(members)}**")
    st.caption("Members can access your scan history and run scans on your quota.")

    if members:
        for m in members:
            mid    = m.get("id", "")
            email  = m.get("member_email", "")
            role   = m.get("role", "viewer")
            accepted = m.get("invite_accepted", False)
            status   = "✅ Active" if accepted else "⏳ Invited"

            with st.expander(f"{email}  —  {role.capitalize()}  |  {status}"):
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.caption(f"Joined: {(m.get('created_at') or '')[:10]}")
                with col2:
                    new_role = st.selectbox(
                        "Role", list(_ROLES.keys()),
                        index=list(_ROLES.keys()).index(role),
                        key=f"role_{mid}",
                        label_visibility="collapsed",
                    )
                    if new_role != role:
                        if st.button("Save", key=f"save_role_{mid}"):
                            if update_role(mid, user.user_id, new_role):
                                st.success("Role updated.")
                                st.rerun()
                with col3:
                    if st.button("Remove", key=f"rm_{mid}", use_container_width=True):
                        if remove_member(mid, user.user_id):
                            st.warning(f"{email} removed from team.")
                            st.rerun()

                for role_name, desc in _ROLES.items():
                    st.caption(f"**{role_name.capitalize()}**: {desc}")
    else:
        st.info("No team members yet. Invite your first colleague below.")

    st.divider()

    # ── Invite ────────────────────────────────────────────────────────────────
    st.markdown("### ➕ Invite Team Member")
    with st.form("invite_form", clear_on_submit=True):
        inv_email = st.text_input("Email address", placeholder="colleague@company.com")
        inv_role  = st.selectbox("Role", list(_ROLES.keys()), format_func=lambda r: f"{r.capitalize()} — {_ROLES[r]}")
        submitted = st.form_submit_button("Send Invitation", type="primary")

        if submitted:
            if not inv_email or "@" not in inv_email:
                st.error("Enter a valid email address.")
            else:
                result = invite_member(user.user_id, inv_email, inv_role)
                if result.get("ok"):
                    st.success(
                        f"✅ Invitation sent to **{inv_email}** as **{inv_role}**.\n\n"
                        f"They will receive an email with a link to join your team."
                    )
                    st.rerun()
                else:
                    st.error(result.get("error", "Failed to send invitation"))

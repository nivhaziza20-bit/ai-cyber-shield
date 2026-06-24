"""Beautiful login / register / admin pages for AI Cyber Shield."""
from __future__ import annotations

import re
import streamlit as st

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PW_MIN = 8

_AUTH_CSS = """
<style>
.auth-wrap {
    max-width: 440px;
    margin: 48px auto 0;
}
.auth-header {
    text-align: center;
    margin-bottom: 32px;
}
.auth-icon { font-size: 3.2rem; line-height: 1; }
.auth-brand {
    font-size: 2rem;
    font-weight: 900;
    color: #10b981;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    letter-spacing: -0.04em;
    margin: 8px 0 4px;
}
.auth-sub {
    color: #475569;
    font-size: 0.72rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
}
.auth-card {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 16px;
    padding: 36px 40px;
    margin-top: 8px;
}
.auth-notice {
    background: #0f2027;
    border: 1px solid #10b981;
    border-radius: 8px;
    padding: 12px 16px;
    font-size: 0.82rem;
    color: #86efac;
    margin-bottom: 20px;
    line-height: 1.5;
}
.auth-footer {
    text-align: center;
    color: #475569;
    font-size: 0.75rem;
    margin-top: 28px;
    line-height: 1.7;
}
</style>
"""

# ── Validation helpers ────────────────────────────────────────────────────────

def _valid_email(e: str) -> bool:
    return bool(_EMAIL_RE.match(e.strip()))


def _valid_password(p: str) -> tuple[bool, str]:
    if len(p) < _PW_MIN:
        return False, f"Minimum {_PW_MIN} characters"
    if not any(c.isdigit() or not c.isalpha() for c in p):
        return False, "Must contain at least one number or symbol"
    return True, ""


# ── Main auth page ────────────────────────────────────────────────────────────

def show_auth_page() -> None:
    """Full-screen login / register page. Call then st.stop()."""
    from auth.streamlit_auth import sign_in, sign_up, request_password_reset

    st.markdown(_AUTH_CSS, unsafe_allow_html=True)
    st.markdown(
        """
        <div class="auth-wrap">
            <div class="auth-header">
                <div class="auth-icon">🛡</div>
                <div class="auth-brand">AI Cyber Shield</div>
                <div class="auth-sub">Authorized Access Only</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_l, col_c, col_r = st.columns([1, 4, 1])
    with col_c:
        tab_login, tab_register, tab_reset = st.tabs(["Login", "Create Account", "Forgot Password"])

        # ── Login ─────────────────────────────────────────────────────────────
        with tab_login:
            st.markdown("")
            email = st.text_input("Email address", key="li_email", placeholder="you@example.com")
            password = st.text_input("Password", type="password", key="li_pass", placeholder="••••••••")
            st.markdown("")

            if st.button("Login →", use_container_width=True, key="li_btn", type="primary"):
                if not email or not password:
                    st.error("Please enter email and password.")
                elif not _valid_email(email):
                    st.error("Enter a valid email address.")
                else:
                    with st.spinner("Authenticating…"):
                        result = sign_in(email.strip().lower(), password)
                    if result.get("ok"):
                        from audit_log import log_action
                        log_action("login", details={"method": "password"})
                        st.success("Welcome back!")
                        st.rerun()
                    else:
                        st.error(result.get("error", "Login failed"))

        # ── Register ──────────────────────────────────────────────────────────
        with tab_register:
            st.markdown("")
            st.markdown(
                """
                <div class="auth-notice">
                🔒 By creating an account you agree to scan only targets you own
                or have written permission to test.
                </div>
                """,
                unsafe_allow_html=True,
            )
            r_email = st.text_input("Email address", key="reg_email", placeholder="you@example.com")
            r_pass = st.text_input("Password", type="password", key="reg_pass",
                                   placeholder="Min 8 chars + 1 number/symbol",
                                   help="Minimum 8 characters including at least one number or symbol")
            r_pass2 = st.text_input("Confirm password", type="password", key="reg_pass2",
                                    placeholder="Repeat password")
            st.markdown("")

            if st.button("Create Account →", use_container_width=True, key="reg_btn", type="primary"):
                errors = []
                if not r_email or not _valid_email(r_email):
                    errors.append("Enter a valid email address.")
                ok_pw, pw_msg = _valid_password(r_pass)
                if not ok_pw:
                    errors.append(f"Password: {pw_msg}")
                if r_pass != r_pass2:
                    errors.append("Passwords do not match.")

                if errors:
                    for e in errors:
                        st.error(e)
                else:
                    with st.spinner("Creating account…"):
                        result = sign_up(r_email.strip().lower(), r_pass)
                    if result.get("ok"):
                        if result.get("confirm_required"):
                            st.success(
                                "Account created! Check your inbox for a confirmation email, "
                                "then return here to log in."
                            )
                        else:
                            st.success("Account created! You can now log in.")
                    else:
                        st.error(result.get("error", "Registration failed"))

        # ── Reset password ────────────────────────────────────────────────────
        with tab_reset:
            st.markdown("")
            st.info("Enter your email and we'll send a password reset link.")
            rst_email = st.text_input("Email address", key="rst_email", placeholder="you@example.com")
            st.markdown("")

            if st.button("Send Reset Link →", use_container_width=True, key="rst_btn"):
                if not rst_email or not _valid_email(rst_email):
                    st.error("Enter a valid email address.")
                else:
                    with st.spinner("Sending…"):
                        result = request_password_reset(rst_email.strip().lower())
                    if result.get("ok"):
                        st.success("Reset link sent — check your inbox.")
                    else:
                        st.error(result.get("error", "Failed to send reset email"))

        st.markdown(
            """
            <div class="auth-footer">
                🛡 AI Cyber Shield — Authorized use only<br>
                Unauthorized scanning is illegal and against our Terms of Service
            </div>
            """,
            unsafe_allow_html=True,
        )


# ── Admin panel ───────────────────────────────────────────────────────────────

def show_admin_panel() -> None:
    """Admin-only panel rendered inside the main app sidebar or page."""
    from auth.streamlit_auth import (
        get_current_user, fetch_audit_logs, fetch_all_users,
        approve_pt_mode, revoke_pt_mode,
    )
    import pandas as pd

    user = get_current_user()
    if not user or not user.is_admin:
        st.error("Admin access required.")
        return

    st.markdown("## 🔐 Admin Panel")

    tab_logs, tab_users = st.tabs(["Audit Logs", "Users & PT Approval"])

    with tab_logs:
        st.caption("Last 200 actions across all users")
        logs = fetch_audit_logs(200)
        if not logs:
            st.info("No logs yet.")
        else:
            rows = []
            for l in logs:
                ts = l.get("created_at", "")[:19].replace("T", " ")
                rows.append({
                    "Time (UTC)": ts,
                    "User": l.get("user_email", "—"),
                    "Action": l.get("action", ""),
                    "Target": (l.get("target") or "")[:60],
                    "Severity": l.get("severity", "info"),
                })
            df = pd.DataFrame(rows)

            sev_filter = st.multiselect(
                "Filter by severity",
                ["info", "warning", "error"],
                default=["info", "warning", "error"],
                key="log_sev_filter",
            )
            df = df[df["Severity"].isin(sev_filter)]

            def _color(val: str) -> str:
                return {
                    "error": "background-color:#4a1111;color:#fca5a5",
                    "warning": "background-color:#3d2a00;color:#fcd34d",
                }.get(val, "")

            st.dataframe(
                df.style.map(_color, subset=["Severity"]),
                use_container_width=True,
                hide_index=True,
            )
            st.caption(f"{len(df)} entries shown")

    with tab_users:
        users = fetch_all_users()
        if not users:
            st.info("No users yet.")
            return

        st.caption(f"{len(users)} registered users")
        for u in users:
            uid = u.get("id", "")
            uemail = u.get("email", "unknown")
            urole = u.get("role", "user")
            pt = u.get("pt_approved", False)
            created = (u.get("created_at") or "")[:10]

            badge = "🟢 Admin" if urole == "admin" else "⚪ User"
            pt_badge = "✅ PT Approved" if pt else "🔒 PT Restricted"

            with st.expander(f"{uemail}  —  {badge}  |  {pt_badge}  |  Joined {created}"):
                col1, col2 = st.columns(2)
                with col1:
                    if not pt:
                        if st.button(f"Approve PT Mode", key=f"pt_approve_{uid}"):
                            if approve_pt_mode(uid, user):
                                st.success(f"PT mode granted to {uemail}")
                                from audit_log import log_action
                                log_action("pt_approved", target=uemail,
                                           details={"approved_by": user.email}, severity="warning")
                                st.rerun()
                            else:
                                st.error("Failed to approve")
                    else:
                        if st.button(f"Revoke PT Mode", key=f"pt_revoke_{uid}"):
                            if revoke_pt_mode(uid, user):
                                st.warning(f"PT mode revoked for {uemail}")
                                from audit_log import log_action
                                log_action("pt_revoked", target=uemail,
                                           details={"revoked_by": user.email}, severity="warning")
                                st.rerun()
                            else:
                                st.error("Failed to revoke")
                with col2:
                    st.caption(f"User ID: `{uid[:8]}…`")
                    approved_by = u.get("pt_approved_by")
                    if approved_by:
                        st.caption(f"Approved by: {approved_by}")

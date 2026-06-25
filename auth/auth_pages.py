"""
auth/auth_pages.py — AI Cyber Shield v6

Landing page + Auth pages.

Layout: Split-hero — left column = product marketing, right column = auth form.
Both panels are visible simultaneously so returning users log in immediately
while new visitors understand the product before signing up.
"""
from __future__ import annotations

import re
import streamlit as st

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PW_MIN = 8

# ─────────────────────────────────────────────────────────────────────────────
# CSS — landing page + auth card
# ─────────────────────────────────────────────────────────────────────────────

_LANDING_CSS = """
<style>
/* ── Page chrome ─────────────────────────────────────────────────── */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 2rem !important; padding-bottom: 0 !important; }

/* ── Brand mark ──────────────────────────────────────────────────── */
.lp-brand {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 36px;
}
.lp-brand-icon { font-size: 2.6rem; line-height: 1; }
.lp-brand-name {
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 1.75rem;
    font-weight: 900;
    color: #10b981;
    letter-spacing: -0.04em;
    line-height: 1.1;
}
.lp-brand-sub {
    color: #475569;
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-top: 2px;
}

/* ── Hero headline ───────────────────────────────────────────────── */
.lp-headline {
    font-size: 2.6rem;
    font-weight: 800;
    color: #f8fafc;
    line-height: 1.15;
    margin: 0 0 16px;
}
.lp-headline em { color: #10b981; font-style: normal; }
.lp-desc {
    color: #94a3b8;
    font-size: 1.05rem;
    line-height: 1.65;
    max-width: 500px;
    margin: 0 0 32px;
}

/* ── Stats bar ───────────────────────────────────────────────────── */
.lp-stats {
    display: flex;
    gap: 28px;
    margin-bottom: 40px;
    padding-bottom: 32px;
    border-bottom: 1px solid #1f2d3d;
}
.lp-stat-val {
    font-size: 1.9rem;
    font-weight: 800;
    color: #10b981;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
}
.lp-stat-lbl {
    color: #64748b;
    font-size: 0.72rem;
    margin-top: 3px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* ── Features grid ───────────────────────────────────────────────── */
.lp-features-title {
    color: #94a3b8;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    margin-bottom: 14px;
}
.lp-features {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 40px;
}
.lp-feat {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 10px;
    padding: 14px 16px;
    transition: border-color 0.2s;
}
.lp-feat:hover { border-color: #10b981; }
.lp-feat-icon { font-size: 1.3rem; margin-bottom: 6px; }
.lp-feat-name {
    font-size: 0.82rem;
    font-weight: 700;
    color: #e2e8f0;
    margin-bottom: 3px;
}
.lp-feat-desc { font-size: 0.72rem; color: #64748b; line-height: 1.45; }

/* ── Free tier badge ─────────────────────────────────────────────── */
.lp-free-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: #0a2018;
    border: 1px solid #10b981;
    border-radius: 8px;
    padding: 10px 16px;
    font-size: 0.82rem;
    color: #86efac;
    margin-bottom: 40px;
}
.lp-free-badge strong { color: #34d399; }

/* ── Pricing ─────────────────────────────────────────────────────── */
.lp-pricing-title {
    text-align: center;
    color: #94a3b8;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    margin-bottom: 6px;
}
.lp-pricing-h {
    text-align: center;
    font-size: 1.7rem;
    font-weight: 800;
    color: #f8fafc;
    margin-bottom: 28px;
}
.lp-plans {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 40px;
}
.lp-plan {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 14px;
    padding: 22px 20px 20px;
    position: relative;
}
.lp-plan-pro {
    border-color: #10b981;
    background: linear-gradient(135deg, #0a1e16, #0d1117);
    box-shadow: 0 0 24px rgba(16,185,129,0.12);
}
.lp-plan-badge {
    position: absolute;
    top: -11px;
    left: 50%;
    transform: translateX(-50%);
    background: #10b981;
    color: #000;
    font-size: 0.62rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 3px 10px;
    border-radius: 99px;
    white-space: nowrap;
}
.lp-plan-name {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: #64748b;
    margin-bottom: 8px;
}
.lp-plan-price {
    font-size: 2rem;
    font-weight: 800;
    color: #f8fafc;
    line-height: 1;
    margin-bottom: 4px;
}
.lp-plan-price span { font-size: 1rem; font-weight: 400; color: #64748b; }
.lp-plan-price sub {
    font-size: 0.85rem;
    font-weight: 400;
    color: #64748b;
    vertical-align: baseline;
}
.lp-plan-tagline {
    font-size: 0.72rem;
    color: #475569;
    margin-bottom: 16px;
    min-height: 28px;
}
.lp-plan-features { list-style: none; padding: 0; margin: 0; }
.lp-plan-features li {
    font-size: 0.75rem;
    color: #94a3b8;
    padding: 4px 0;
    display: flex;
    gap: 8px;
    align-items: flex-start;
}
.lp-plan-features li::before { content: "✓"; color: #10b981; font-weight: 700; flex-shrink: 0; }
.lp-plan-features li.locked { color: #334155; }
.lp-plan-features li.locked::before { content: "–"; color: #334155; }

/* ── Auth card ───────────────────────────────────────────────────── */
.auth-card-top {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-bottom: none;
    border-radius: 16px 16px 0 0;
    padding: 24px 28px 18px;
}
.auth-card-brand { font-size: 1.5rem; margin-bottom: 2px; }
.auth-card-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 2px;
}
.auth-card-sub { font-size: 0.75rem; color: #64748b; }
.auth-notice {
    background: #0f2027;
    border: 1px solid #10b981;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 0.78rem;
    color: #86efac;
    margin-bottom: 16px;
    line-height: 1.5;
}
.auth-card-footer {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-top: none;
    border-radius: 0 0 16px 16px;
    padding: 14px 28px 22px;
    text-align: center;
    color: #334155;
    font-size: 0.7rem;
    line-height: 1.7;
}

/* ── Footer ──────────────────────────────────────────────────────── */
.lp-footer {
    text-align: center;
    color: #334155;
    font-size: 0.72rem;
    padding: 20px 0 40px;
    border-top: 1px solid #1f2d3d;
    line-height: 2;
}
.lp-footer a { color: #475569; text-decoration: none; }
.lp-footer a:hover { color: #10b981; }
</style>
"""

# ─────────────────────────────────────────────────────────────────────────────
# HTML blocks
# ─────────────────────────────────────────────────────────────────────────────

_HERO_HTML = """
<div class="lp-brand">
    <div class="lp-brand-icon">🛡</div>
    <div>
        <div class="lp-brand-name">AI Cyber Shield</div>
        <div class="lp-brand-sub">Web Application Security Intelligence</div>
    </div>
</div>

<h1 class="lp-headline">Scan. Detect.<br><em>Defend.</em></h1>

<p class="lp-desc">
    AI-powered web security scanning built for developers and security teams.
    Runs 17 tools in parallel — TLS analysis, CVE detection, technology
    fingerprinting, and active vulnerability verification. Full report in under 90 seconds.
</p>

<div class="lp-stats">
    <div>
        <div class="lp-stat-val">17</div>
        <div class="lp-stat-lbl">Scan tools</div>
    </div>
    <div>
        <div class="lp-stat-val">7,537</div>
        <div class="lp-stat-lbl">Tech signatures</div>
    </div>
    <div>
        <div class="lp-stat-val">8</div>
        <div class="lp-stat-lbl">Vuln classes</div>
    </div>
    <div>
        <div class="lp-stat-val">&lt;90s</div>
        <div class="lp-stat-lbl">Scan time</div>
    </div>
</div>
"""

_FEATURES_HTML = """
<div class="lp-features-title">What we scan</div>
<div class="lp-features">
    <div class="lp-feat">
        <div class="lp-feat-icon">🔐</div>
        <div class="lp-feat-name">TLS / SSL</div>
        <div class="lp-feat-desc">Protocol version, cipher suites, certificate validity &amp; HSTS preload status</div>
    </div>
    <div class="lp-feat">
        <div class="lp-feat-icon">🕵️</div>
        <div class="lp-feat-name">Technology Stack</div>
        <div class="lp-feat-desc">7,537 Wappalyzer signatures with version extraction and CVE mapping</div>
    </div>
    <div class="lp-feat">
        <div class="lp-feat-icon">🐛</div>
        <div class="lp-feat-name">CVE Detection</div>
        <div class="lp-feat-desc">NVD + GitHub + OSV multi-source feed with EPSS exploit probability scoring</div>
    </div>
    <div class="lp-feat">
        <div class="lp-feat-icon">⚡</div>
        <div class="lp-feat-name">Active Verification</div>
        <div class="lp-feat-desc">Non-destructive canary probes confirm Open Redirect, XSS, CORS, SSTI &amp; more</div>
    </div>
    <div class="lp-feat">
        <div class="lp-feat-icon">🌐</div>
        <div class="lp-feat-name">Deep JS Crawling</div>
        <div class="lp-feat-desc">Headless Chromium intercepts XHR, discovers hidden API endpoints &amp; secrets</div>
    </div>
    <div class="lp-feat">
        <div class="lp-feat-icon">📋</div>
        <div class="lp-feat-name">API &amp; DNS</div>
        <div class="lp-feat-desc">Swagger / GraphQL exposure, SPF / DMARC records, subdomain takeover detection</div>
    </div>
</div>

<div class="lp-free-badge">
    ✅ <strong>Free tier included</strong> — Passive OSINT scan (15 tools), no credit card required.
    Upgrade for active scanning and PT mode.
</div>
"""

_PRICING_HTML = """
<div style="margin-top: 20px; padding-top: 32px; border-top: 1px solid #1f2d3d;">
    <div class="lp-pricing-title">Simple pricing</div>
    <div class="lp-pricing-h">Start free. Scale when ready.</div>

    <div class="lp-plans">
        <div class="lp-plan">
            <div class="lp-plan-name">Free</div>
            <div class="lp-plan-price">€0</div>
            <div class="lp-plan-tagline">Always free, no card needed</div>
            <ul class="lp-plan-features">
                <li>Passive scan — 15 OSINT tools</li>
                <li>2 scans / day</li>
                <li>Overall security score A–F</li>
                <li class="locked">Active scanning</li>
                <li class="locked">CVE feed + EPSS</li>
                <li class="locked">Scan history</li>
            </ul>
        </div>

        <div class="lp-plan">
            <div class="lp-plan-name">Starter</div>
            <div class="lp-plan-price">€20<sub>/mo</sub></div>
            <div class="lp-plan-tagline">Full scan suite for developers</div>
            <ul class="lp-plan-features">
                <li>Full scan — all 17 tools</li>
                <li>20 scans / day</li>
                <li>CVE feed + EPSS scoring</li>
                <li>Scan history &amp; comparison</li>
                <li>Scheduled scans</li>
                <li class="locked">PT mode &amp; active probes</li>
            </ul>
        </div>

        <div class="lp-plan lp-plan-pro">
            <div class="lp-plan-badge">Most popular</div>
            <div class="lp-plan-name" style="color:#86efac">Professional</div>
            <div class="lp-plan-price" style="color:#34d399">€50<sub>/mo</sub></div>
            <div class="lp-plan-tagline">For security engineers &amp; consultants</div>
            <ul class="lp-plan-features">
                <li>Everything in Starter</li>
                <li>50 scans / day</li>
                <li>PT mode + Nuclei templates</li>
                <li>Active verification (8 vuln classes)</li>
                <li>REST API access</li>
                <li>GitHub Actions integration</li>
            </ul>
        </div>

        <div class="lp-plan">
            <div class="lp-plan-name">Enterprise</div>
            <div class="lp-plan-price">€120<sub>/mo</sub></div>
            <div class="lp-plan-tagline">For teams &amp; security departments</div>
            <ul class="lp-plan-features">
                <li>Unlimited scans</li>
                <li>Team management + roles</li>
                <li>Priority support</li>
                <li>Custom scan schedules</li>
                <li>JIRA / Teams / Slack export</li>
                <li>SARIF + PDF reports</li>
            </ul>
        </div>
    </div>
</div>
"""

_FOOTER_HTML = """
<div class="lp-footer">
    <a href="/?legal=tos">Terms of Service</a> &nbsp;·&nbsp;
    <a href="/?legal=privacy">Privacy Policy</a> &nbsp;·&nbsp;
    <a href="mailto:support@aicybershield.com">Contact</a>
    <br>
    🛡 AI Cyber Shield — Authorized use only.
    Unauthorized scanning is illegal and against our Terms of Service.
</div>
"""

_AUTH_CARD_TOP = """
<div class="auth-card-top">
    <div class="auth-card-brand">🔐</div>
    <div class="auth-card-title">Sign in to your account</div>
    <div class="auth-card-sub">New here? Use the <strong>Create Account</strong> tab below.</div>
</div>
"""

_AUTH_CARD_FOOTER = """
<div class="auth-card-footer">
    🛡 Authorized use only<br>
    Unauthorized scanning violates our Terms of Service
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _valid_email(e: str) -> bool:
    return bool(_EMAIL_RE.match(e.strip()))


def _valid_password(p: str) -> tuple[bool, str]:
    if len(p) < _PW_MIN:
        return False, f"Minimum {_PW_MIN} characters"
    if not any(c.isdigit() or not c.isalpha() for c in p):
        return False, "Must contain at least one number or symbol"
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# Landing + Auth page
# ─────────────────────────────────────────────────────────────────────────────

def show_auth_page() -> None:
    """Full landing page with embedded auth form. Call then st.stop()."""
    from auth.streamlit_auth import sign_in, sign_up, request_password_reset

    st.markdown(_LANDING_CSS, unsafe_allow_html=True)

    # ── Two-column split: marketing left, auth right ──────────────────────────
    col_left, col_right = st.columns([3, 2], gap="large")

    # ── LEFT: product marketing ───────────────────────────────────────────────
    with col_left:
        st.markdown(_HERO_HTML, unsafe_allow_html=True)
        st.markdown(_FEATURES_HTML, unsafe_allow_html=True)

    # ── RIGHT: auth form ──────────────────────────────────────────────────────
    with col_right:
        st.markdown(_AUTH_CARD_TOP, unsafe_allow_html=True)

        tab_login, tab_register, tab_reset = st.tabs(
            ["Sign In", "Create Account", "Reset Password"]
        )

        # ── Sign In ───────────────────────────────────────────────────────────
        with tab_login:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            email = st.text_input(
                "Email address", key="li_email",
                placeholder="you@example.com",
            )
            password = st.text_input(
                "Password", type="password", key="li_pass",
                placeholder="Your password",
            )
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

            if st.button("Sign In →", use_container_width=True, key="li_btn", type="primary"):
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

        # ── Create Account ────────────────────────────────────────────────────
        with tab_register:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            st.markdown(
                '<div class="auth-notice">'
                "🔒 By creating an account you agree to scan only targets "
                "you own or have written permission to test."
                "</div>",
                unsafe_allow_html=True,
            )
            r_email = st.text_input(
                "Email address", key="reg_email",
                placeholder="you@example.com",
            )
            r_pass = st.text_input(
                "Password", type="password", key="reg_pass",
                placeholder="Min 8 chars + 1 number/symbol",
                help="Minimum 8 characters including at least one number or symbol",
            )
            r_pass2 = st.text_input(
                "Confirm password", type="password", key="reg_pass2",
                placeholder="Repeat password",
            )
            r_tos = st.checkbox(
                "I agree to the [Terms of Service](/?legal=tos) "
                "and [Privacy Policy](/?legal=privacy)",
                key="reg_tos",
            )
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

            if st.button("Create Free Account →", use_container_width=True,
                         key="reg_btn", type="primary"):
                errors = []
                if not r_email or not _valid_email(r_email):
                    errors.append("Enter a valid email address.")
                ok_pw, pw_msg = _valid_password(r_pass)
                if not ok_pw:
                    errors.append(f"Password: {pw_msg}")
                if r_pass != r_pass2:
                    errors.append("Passwords do not match.")
                if not r_tos:
                    errors.append("You must agree to the Terms of Service.")

                if errors:
                    for e in errors:
                        st.error(e)
                else:
                    with st.spinner("Creating account…"):
                        result = sign_up(r_email.strip().lower(), r_pass)
                    if result.get("ok"):
                        if result.get("confirm_required"):
                            st.success(
                                "Account created! Check your inbox for a "
                                "confirmation email, then return here to log in."
                            )
                        else:
                            st.success("Account created! You can now log in.")
                    else:
                        st.error(result.get("error", "Registration failed"))

        # ── Reset Password ────────────────────────────────────────────────────
        with tab_reset:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            st.info("Enter your email and we'll send a reset link.")
            rst_email = st.text_input(
                "Email address", key="rst_email",
                placeholder="you@example.com",
            )
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

            if st.button("Send Reset Link →", use_container_width=True,
                         key="rst_btn"):
                if not rst_email or not _valid_email(rst_email):
                    st.error("Enter a valid email address.")
                else:
                    with st.spinner("Sending…"):
                        result = request_password_reset(rst_email.strip().lower())
                    if result.get("ok"):
                        st.success("Reset link sent — check your inbox.")
                    else:
                        st.error(result.get("error", "Failed to send reset email"))

        st.markdown(_AUTH_CARD_FOOTER, unsafe_allow_html=True)

    # ── FULL WIDTH: pricing + footer ──────────────────────────────────────────
    st.markdown(_PRICING_HTML, unsafe_allow_html=True)
    st.markdown(_FOOTER_HTML, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Admin panel (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def show_admin_panel() -> None:
    """Admin-only panel rendered inside the main app."""
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

            with st.expander(
                f"{uemail}  —  {badge}  |  {pt_badge}  |  Joined {created}"
            ):
                col1, col2 = st.columns(2)
                with col1:
                    if not pt:
                        if st.button(f"Approve PT Mode", key=f"pt_approve_{uid}"):
                            if approve_pt_mode(uid, user):
                                st.success(f"PT mode granted to {uemail}")
                                from audit_log import log_action
                                log_action(
                                    "pt_approved", target=uemail,
                                    details={"approved_by": user.email},
                                    severity="warning",
                                )
                                st.rerun()
                            else:
                                st.error("Failed to approve")
                    else:
                        if st.button(f"Revoke PT Mode", key=f"pt_revoke_{uid}"):
                            if revoke_pt_mode(uid, user):
                                st.warning(f"PT mode revoked for {uemail}")
                                from audit_log import log_action
                                log_action(
                                    "pt_revoked", target=uemail,
                                    details={"revoked_by": user.email},
                                    severity="warning",
                                )
                                st.rerun()
                            else:
                                st.error("Failed to revoke")
                with col2:
                    st.caption(f"User ID: `{uid[:8]}…`")
                    approved_by = u.get("pt_approved_by")
                    if approved_by:
                        st.caption(f"Approved by: {approved_by}")

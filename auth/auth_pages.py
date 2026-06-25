"""
auth/auth_pages.py — AI Cyber Shield v7

Landing page + Auth pages.

Layout: Nav bar → split-hero (60/40) → social proof → pricing → footer.
Auth form lives in the right column so returning users can log in immediately
while new visitors absorb the product before signing up.
"""
from __future__ import annotations

import re
import streamlit as st

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PW_MIN = 8

# ─────────────────────────────────────────────────────────────────────────────
# CSS — injected once via st.markdown, applies to all columns
# ─────────────────────────────────────────────────────────────────────────────

_LANDING_CSS = """
<style>
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stAppViewContainer"] { background: #060b14; }
[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 0 !important; padding-bottom: 0 !important; background: #060b14; }

/* ── Brand ──────────────────────────────────────────────── */
.lp-brand { display:flex; align-items:center; gap:14px; margin-bottom:24px; margin-top:8px; }
.lp-brand-icon { font-size:1.8rem; line-height:1; }
.lp-brand-name { font-family:'JetBrains Mono','Courier New',monospace; font-size:1.3rem; font-weight:900; color:#10b981; letter-spacing:-0.04em; line-height:1.1; }
.lp-brand-sub { color:#334155; font-size:0.58rem; letter-spacing:0.2em; text-transform:uppercase; margin-top:2px; }

/* ── Hero ───────────────────────────────────────────────── */
.lp-headline { font-size:3.2rem; font-weight:900; color:#f1f5f9; line-height:1.08; margin:0 0 18px; letter-spacing:-0.03em; }
.lp-headline em { color:#10b981; font-style:normal; background:linear-gradient(90deg,#10b981,#34d399); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }
.lp-desc { color:#94a3b8; font-size:0.97rem; line-height:1.72; max-width:520px; margin:0 0 22px; }
.lp-cta-row { display:flex; align-items:center; gap:16px; margin-bottom:28px; }
.lp-cta-btn { display:inline-flex; align-items:center; gap:8px; background:#10b981; color:#000; font-weight:800; font-size:0.88rem; padding:11px 24px; border-radius:9px; letter-spacing:-0.01em; }
.lp-cta-note { color:#475569; font-size:0.75rem; }

/* ── Stats ──────────────────────────────────────────────── */
.lp-stats { display:flex; gap:28px; margin-bottom:32px; padding-bottom:28px; border-bottom:1px solid #1e2d3d; }
.lp-stat-val { font-size:1.9rem; font-weight:900; color:#10b981; font-family:'JetBrains Mono',monospace; line-height:1; }
.lp-stat-lbl { color:#475569; font-size:0.68rem; margin-top:4px; text-transform:uppercase; letter-spacing:0.07em; }

/* ── Features grid ──────────────────────────────────────── */
.lp-features-label { color:#64748b; font-size:0.65rem; text-transform:uppercase; letter-spacing:0.22em; margin-bottom:12px; }
.lp-features { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:24px; }
.lp-feat { background:#0d1421; border:1px solid #1e2d3d; border-radius:10px; padding:15px 15px 14px; transition:border-color 0.18s,background 0.18s; }
.lp-feat:hover { border-color:#10b981; background:#0a1e16; }
.lp-feat-icon { color:#10b981; margin-bottom:8px; display:block; line-height:0; }
.lp-feat-name { font-size:0.86rem; font-weight:700; color:#e2e8f0; margin-bottom:4px; }
.lp-feat-desc { font-size:0.8rem; color:#64748b; line-height:1.55; }

/* ── Free badge ─────────────────────────────────────────── */
.lp-free-badge { display:inline-flex; align-items:center; gap:8px; background:#0a2018; border:1px solid #10b981; border-radius:8px; padding:9px 15px; font-size:0.8rem; color:#86efac; margin-bottom:8px; }
.lp-free-badge strong { color:#34d399; }

/* ── Auth card (floating card effect) ───────────────────── */
.auth-card-top { background:#0d1421; border:1px solid #2a3d52; border-bottom:none; border-radius:16px 16px 0 0; padding:26px 28px 20px; box-shadow:0 4px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(16,185,129,0.06); }
.auth-card-brand { font-size:1.5rem; margin-bottom:2px; }
.auth-card-title { font-size:1.1rem; font-weight:700; color:#f1f5f9; margin-bottom:3px; }
.auth-card-sub { font-size:0.75rem; color:#64748b; }
.auth-notice { background:#0f2027; border:1px solid #10b981; border-radius:8px; padding:10px 14px; font-size:0.79rem; color:#86efac; margin-bottom:16px; line-height:1.55; }
.auth-card-footer { background:#0d1421; border:1px solid #2a3d52; border-top:none; border-radius:0 0 16px 16px; padding:12px 28px 22px; text-align:center; color:#334155; font-size:0.69rem; line-height:1.75; box-shadow:0 8px 32px rgba(0,0,0,0.5); }
</style>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Navigation bar  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_NAV_HTML = """
<div style="display:flex;align-items:center;justify-content:space-between;padding:13px 4px 13px;border-bottom:1px solid #1e2d3d;margin-bottom:6px">
  <div style="display:flex;align-items:center;gap:12px">
    <span style="font-size:1.2rem">🛡</span>
    <span style="font-family:'JetBrains Mono','Courier New',monospace;font-weight:900;color:#10b981;font-size:0.95rem;letter-spacing:-0.03em">AI Cyber Shield</span>
    <span style="background:#0a2018;border:1px solid #10b981;border-radius:4px;color:#34d399;font-size:0.56rem;font-weight:800;text-transform:uppercase;letter-spacing:0.12em;padding:2px 7px;margin-left:4px">Beta</span>
  </div>
  <div style="display:flex;align-items:center;gap:24px">
    <span style="color:#64748b;font-size:0.76rem">17 scan tools</span>
    <span style="color:#64748b;font-size:0.76rem">No agent required</span>
    <span style="color:#64748b;font-size:0.76rem">Free tier available</span>
    <span style="background:#10b981;color:#000;font-weight:800;font-size:0.76rem;padding:6px 16px;border-radius:7px;white-space:nowrap">Start Free →</span>
  </div>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Hero HTML  (inside left column → st.markdown, no blank lines)
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
<p class="lp-desc">AI-powered web security scanning built for developers and security teams. Runs 17 tools in parallel — TLS analysis, CVE detection, technology fingerprinting, and active vulnerability verification. Full report in under 90 seconds.</p>
<div class="lp-cta-row">
  <span class="lp-cta-btn">→&nbsp; Create free account</span>
  <span class="lp-cta-note">No credit card &nbsp;·&nbsp; 5 free scans / day</span>
</div>
<div class="lp-stats">
  <div><div class="lp-stat-val">17</div><div class="lp-stat-lbl">Scan tools</div></div>
  <div><div class="lp-stat-val">7,537</div><div class="lp-stat-lbl">Tech signatures</div></div>
  <div><div class="lp-stat-val">8</div><div class="lp-stat-lbl">Vuln classes</div></div>
  <div><div class="lp-stat-val">&lt;90s</div><div class="lp-stat-lbl">Scan time</div></div>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Features HTML  (inside left column → st.markdown, SVG icons)
# ─────────────────────────────────────────────────────────────────────────────

_FEATURES_HTML = """
<div class="lp-features-label">What we scan</div>
<div class="lp-features">
  <div class="lp-feat">
    <span class="lp-feat-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>
    <div class="lp-feat-name">TLS / SSL</div>
    <div class="lp-feat-desc">Protocol version, cipher suites, certificate validity &amp; HSTS preload status</div>
  </div>
  <div class="lp-feat">
    <span class="lp-feat-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg></span>
    <div class="lp-feat-name">Technology Stack</div>
    <div class="lp-feat-desc">7,537 Wappalyzer signatures with version extraction and CVE mapping</div>
  </div>
  <div class="lp-feat">
    <span class="lp-feat-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></span>
    <div class="lp-feat-name">CVE Detection</div>
    <div class="lp-feat-desc">NVD + GitHub + OSV multi-source feed with EPSS exploit probability scoring</div>
  </div>
  <div class="lp-feat">
    <span class="lp-feat-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></span>
    <div class="lp-feat-name">Active Verification</div>
    <div class="lp-feat-desc">Non-destructive canary probes confirm Open Redirect, XSS, CORS, SSTI &amp; more</div>
  </div>
  <div class="lp-feat">
    <span class="lp-feat-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></span>
    <div class="lp-feat-name">Deep JS Crawling</div>
    <div class="lp-feat-desc">Headless Chromium intercepts XHR, discovers hidden API endpoints &amp; secrets</div>
  </div>
  <div class="lp-feat">
    <span class="lp-feat-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
    <div class="lp-feat-name">API &amp; DNS</div>
    <div class="lp-feat-desc">Swagger / GraphQL exposure, SPF / DMARC records, subdomain takeover detection</div>
  </div>
</div>
<div class="lp-free-badge">
  ✅ <strong>Free tier included</strong> — Passive OSINT scan (15 tools), no credit card required. Upgrade for active scanning and PT mode.
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Auth card wrappers
# ─────────────────────────────────────────────────────────────────────────────

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
# Social proof bar  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_SOCIAL_PROOF_HTML = """
<div style="text-align:center;padding:18px 0;color:#475569;font-size:0.78rem;border-top:1px solid #1e2d3d;border-bottom:1px solid #1e2d3d;background:#080d17;margin:4px 0 0">
  <span style="color:#10b981;font-weight:700">17 parallel tools</span>&nbsp;&nbsp;·&nbsp;&nbsp;
  <span style="color:#10b981;font-weight:700">No agent</span> required on target server&nbsp;&nbsp;·&nbsp;&nbsp;
  <span style="color:#10b981;font-weight:700">Passive mode</span> — zero network footprint&nbsp;&nbsp;·&nbsp;&nbsp;
  <span style="color:#10b981;font-weight:700">OWASP Top 10</span> coverage
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Pricing  (self-contained CSS + HTML → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_PRICING_HTML = """
<style>
.aics-pricing{padding:48px 0 20px;margin-top:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.aics-pricing-eye{text-align:center;color:#10b981;font-size:.7rem;text-transform:uppercase;letter-spacing:.2em;margin-bottom:8px}
.aics-pricing-h{text-align:center;font-size:1.9rem;font-weight:800;color:#f8fafc;margin-bottom:6px}
.aics-pricing-sub{text-align:center;color:#64748b;font-size:.88rem;margin-bottom:36px}
.aics-plans{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:40px}
.aics-plan{background:#0d1421;border:1px solid #1e2d3d;border-radius:14px;padding:24px 20px;position:relative}
.aics-plan-pro{border-color:#10b981;background:linear-gradient(145deg,#0a1e16,#0d1421);box-shadow:0 0 28px rgba(16,185,129,.13)}
.aics-badge{position:absolute;top:-11px;left:50%;transform:translateX(-50%);background:#10b981;color:#000;font-size:.6rem;font-weight:800;text-transform:uppercase;letter-spacing:.1em;padding:3px 12px;border-radius:99px;white-space:nowrap}
.aics-tier{font-size:.7rem;text-transform:uppercase;letter-spacing:.15em;color:#64748b;margin-bottom:10px}
.aics-price{font-size:2.1rem;font-weight:800;color:#f8fafc;line-height:1;margin-bottom:4px}
.aics-price sub{font-size:.8rem;font-weight:400;color:#64748b;vertical-align:baseline}
.aics-tagline{font-size:.72rem;color:#475569;margin-bottom:18px;min-height:30px}
.aics-features{list-style:none;padding:0;margin:0 0 20px}
.aics-features li{font-size:.74rem;color:#94a3b8;padding:4px 0;display:flex;gap:8px;align-items:flex-start}
.aics-features li::before{content:"✓";color:#10b981;font-weight:700;flex-shrink:0}
.aics-features li.off{color:#334155}
.aics-features li.off::before{content:"—";color:#334155}
.aics-cta{display:block;width:100%;padding:9px 0;border-radius:8px;font-size:.8rem;font-weight:700;text-align:center;border:1px solid #1e2d3d;background:transparent;color:#64748b;cursor:default}
.aics-cta-pro{background:#10b981;color:#000;border-color:#10b981}
</style>
<div class="aics-pricing">
  <div class="aics-pricing-eye">Simple pricing</div>
  <div class="aics-pricing-h">Start free. Scale when ready.</div>
  <div class="aics-pricing-sub">No credit card required for the free tier. Cancel anytime.</div>
  <div class="aics-plans">
    <div class="aics-plan">
      <div class="aics-tier">Free</div>
      <div class="aics-price">€0</div>
      <div class="aics-tagline">Always free, no card needed</div>
      <ul class="aics-features">
        <li>Passive scan — 15 OSINT tools</li>
        <li>5 scans / day</li>
        <li>Security score A–F</li>
        <li class="off">Active scanning</li>
        <li class="off">CVE feed + EPSS</li>
        <li class="off">Scan history</li>
      </ul>
      <span class="aics-cta">Current plan</span>
    </div>
    <div class="aics-plan">
      <div class="aics-tier">Starter</div>
      <div class="aics-price">€20<sub>/mo</sub></div>
      <div class="aics-tagline">Full scan suite for developers</div>
      <ul class="aics-features">
        <li>All 17 scan tools</li>
        <li>50 scans / day</li>
        <li>CVE feed + EPSS scoring</li>
        <li>Scan history &amp; comparison</li>
        <li>Scheduled scans</li>
        <li class="off">PT mode &amp; active probes</li>
      </ul>
      <span class="aics-cta">Upgrade</span>
    </div>
    <div class="aics-plan aics-plan-pro">
      <div class="aics-badge">Most popular</div>
      <div class="aics-tier" style="color:#86efac">Professional</div>
      <div class="aics-price" style="color:#34d399">€50<sub>/mo</sub></div>
      <div class="aics-tagline">For security engineers &amp; consultants</div>
      <ul class="aics-features">
        <li>Everything in Starter</li>
        <li>200 scans / day</li>
        <li>PT mode + Nuclei templates</li>
        <li>Active verification (8 vuln classes)</li>
        <li>REST API access</li>
        <li>GitHub Actions integration</li>
      </ul>
      <span class="aics-cta aics-cta-pro">Upgrade</span>
    </div>
    <div class="aics-plan">
      <div class="aics-tier">Enterprise</div>
      <div class="aics-price">€120<sub>/mo</sub></div>
      <div class="aics-tagline">For teams &amp; security departments</div>
      <ul class="aics-features">
        <li>Unlimited scans</li>
        <li>Team management + roles</li>
        <li>Priority support</li>
        <li>Custom scan schedules</li>
        <li>JIRA / Teams / Slack export</li>
        <li>SARIF + PDF reports</li>
      </ul>
      <span class="aics-cta">Contact us</span>
    </div>
  </div>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Footer  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_FOOTER_HTML = """
<div style="text-align:center;color:#334155;font-size:0.71rem;padding:20px 0 40px;border-top:1px solid #1e2d3d;line-height:2">
  <a href="/?legal=tos" style="color:#475569;text-decoration:none">Terms of Service</a>
  &nbsp;·&nbsp;
  <a href="/?legal=privacy" style="color:#475569;text-decoration:none">Privacy Policy</a>
  &nbsp;·&nbsp;
  <a href="mailto:support@aicybershield.com" style="color:#475569;text-decoration:none">Contact</a>
  <br>
  🛡 AI Cyber Shield — Authorized use only. Unauthorized scanning is illegal and against our Terms of Service.
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

    # ── Navigation bar ────────────────────────────────────────────────────────
    st.html(_NAV_HTML)

    # ── Two-column split: 60% marketing, 40% auth form ───────────────────────
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

    # ── FULL WIDTH: social proof → pricing → footer ───────────────────────────
    st.html(_SOCIAL_PROOF_HTML)
    st.html(_PRICING_HTML)
    st.html(_FOOTER_HTML)


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

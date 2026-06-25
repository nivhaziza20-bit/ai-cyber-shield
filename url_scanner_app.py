"""
URL Security Scanner — AI Cyber Shield v6
Streamlit UI: dark security theme, 17-category scoring, structured report.
"""

from __future__ import annotations

import json
import logging
import sys
import re
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))
load_dotenv(override=False)

# ─────────────────────────────────────────────────────────────────────────────
# Page config — must be first Streamlit call
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AI Cyber Shield",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Auth gate — Supabase if configured, else simple APP_PASSWORD fallback
# ─────────────────────────────────────────────────────────────────────────────

from monitoring import init_sentry, set_user_context
from legal_pages import show_terms_of_service, show_privacy_policy, show_legal_nav
from healthcheck import maybe_show_health
from ip_rate_limit import enforce_rate_limit
init_sentry()  # Must be before any other imports that might throw
maybe_show_health()   # ?health=1 → status page, no auth needed
enforce_rate_limit()  # Block abusive sessions before auth

from auth.streamlit_auth import (
    require_auth, get_current_user, sign_out,
    check_quota, increment_quota, supabase_available,
    TIER_DAILY_LIMITS,
)
from audit_log import log_action
from billing_ui import show_pricing_page, show_upgrade_prompt, PLANS
from scan_history import save_scan, show_scan_history_panel
from notifications import notify_scan_complete, should_notify
from scheduled_scans_ui import show_scheduled_scans_panel
from api_docs_ui import show_api_docs
from team_ui import show_team_panel
from scan_cache import get_cached_scan, set_cached_scan
from ip_rate_limit import check_scan_rate

# ── Playwright pre-download (background, one-shot at app startup) ─────────────
# Without this, the first user who triggers a deep-JS scan waits ~2 min while
# Chromium downloads (~100 MB) mid-scan.  @st.cache_resource runs exactly once
# per app instance; the background thread is non-blocking so the UI is instant.
@st.cache_resource(show_spinner=False)
def _prefetch_playwright() -> None:
    import threading
    try:
        from tools.deep_js_crawler import _ensure_playwright_browser
        t = threading.Thread(target=_ensure_playwright_browser, daemon=True, name="playwright-prefetch")
        t.start()
    except Exception:
        pass  # playwright not installed — no-op

_prefetch_playwright()

# ── Email confirmation callback handler ───────────────────────────────────────
# Supabase sends #access_token=...&refresh_token=...&type=signup in the URL hash
# after email confirmation. Browsers never send hash fragments to the server, so
# we inject JS to copy them into query params and reload — then exchange for a
# real session here.
st.html("""
<script>
(function(){
  var h = window.location.hash;
  if (!h || !h.includes('access_token')) return;
  var params = {};
  h.replace(/^#/, '').split('&').forEach(function(p){
    var kv = p.split('='); params[decodeURIComponent(kv[0])] = decodeURIComponent(kv[1]||'');
  });
  if (params.access_token) {
    var qs = '?st_at=' + encodeURIComponent(params.access_token) +
             '&st_rt=' + encodeURIComponent(params.refresh_token||'') +
             '&st_type=' + encodeURIComponent(params.type||'');
    window.location.replace(window.location.pathname + qs);
  }
})();
</script>
""")

# Exchange Supabase token from email confirmation callback
_qp = st.query_params
if _qp.get("st_at") and _qp.get("st_type") in ("signup", "recovery", "email_change"):
    try:
        from auth.streamlit_auth import _client
        _sb = _client()
        if _sb:
            _sb.auth.set_session(_qp["st_at"], _qp.get("st_rt", ""))
            _sess = _sb.auth.get_session()
            if _sess and _sess.user:
                from auth.streamlit_auth import _build_user_session
                st.session_state["_user_session"] = _build_user_session(_sess.user, _sess)
    except Exception:
        pass
    st.query_params.clear()
    st.rerun()

if supabase_available():
    _current_user = require_auth()  # shows login page + st.stop() if not authed
    if _current_user:
        set_user_context(_current_user.user_id, _current_user.email)
else:
    # Fallback: simple APP_PASSWORD
    _app_pw = st.secrets.get("APP_PASSWORD", "")
    if _app_pw and not st.session_state.get("_authenticated"):
        import hmac
        st.markdown(
            "<div style='max-width:400px;margin:80px auto 0;text-align:center'>"
            "<div style='font-size:3rem'>🛡</div>"
            "<h2 style='color:#10b981;font-family:monospace'>AI Cyber Shield</h2>"
            "<p style='color:#475569;font-size:0.8rem;letter-spacing:0.1em'>AUTHORIZED ACCESS ONLY</p>"
            "</div>",
            unsafe_allow_html=True,
        )
        _, col, _ = st.columns([1, 2, 1])
        with col:
            pw = st.text_input("Access password", type="password")
            if st.button("Enter", use_container_width=True):
                if hmac.compare_digest(pw.encode(), _app_pw.encode()):
                    st.session_state["_authenticated"] = True
                    st.rerun()
                else:
                    st.error("Incorrect password.")
        st.stop()
    _current_user = None

# ─────────────────────────────────────────────────────────────────────────────
# Dark security theme CSS
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&family=JetBrains+Mono:wght@400;500;700&display=swap');
/* ── Base ─────────────────────────────────────────────────────────────────── */
html, body, .stApp {
    background-color: #0a0e1a !important;
    color: #c9d1d9 !important;
    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
}

/* ── Sidebar ──────────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background-color: #0d1117 !important;
    border-right: 1px solid #1f2d3d !important;
}
section[data-testid="stSidebar"] * {
    color: #c9d1d9 !important;
}

/* ── Header area ──────────────────────────────────────────────────────────── */
.cs-header {
    padding: 24px 0 16px;
    border-bottom: 1px solid #1f2d3d;
    margin-bottom: 24px;
}
.cs-logo {
    font-size: 2.8rem;
    font-weight: 900;
    color: #10b981;
    letter-spacing: -0.04em;
    line-height: 1;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
}
.cs-tagline {
    color: #475569;
    font-size: 0.75rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    margin-top: 4px;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
}
.cs-badge {
    display: inline-block;
    background: #0f2027;
    border: 1px solid #10b981;
    border-radius: 4px;
    color: #10b981;
    font-size: 0.65rem;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    letter-spacing: 0.1em;
    padding: 2px 8px;
    margin-top: 6px;
}

/* ── Input ────────────────────────────────────────────────────────────────── */
.stTextInput > label { color: #64748b !important; font-size: 0.8rem !important; text-transform: uppercase; letter-spacing: 0.1em; }
.stTextInput > div > div > input {
    background-color: #0d1117 !important;
    color: #e2e8f0 !important;
    border: 1px solid #1f2d3d !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', 'Courier New', monospace !important;
    font-size: 1rem !important;
    padding: 12px 14px !important;
}
.stTextInput > div > div > input:focus {
    border-color: #10b981 !important;
    box-shadow: 0 0 0 2px rgba(16,185,129,0.15) !important;
}
.stTextInput > div > div > input::placeholder { color: #334155 !important; }

/* ── Buttons ──────────────────────────────────────────────────────────────── */
button[kind="primary"] {
    background: linear-gradient(135deg, #10b981, #059669) !important;
    color: #000 !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 6px !important;
    font-size: 0.9rem !important;
    letter-spacing: 0.05em !important;
}
button[kind="primary"]:hover {
    background: linear-gradient(135deg, #059669, #047857) !important;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(16,185,129,0.3) !important;
}
button[kind="secondary"] {
    background: #111827 !important;
    color: #94a3b8 !important;
    border: 1px solid #1f2d3d !important;
    border-radius: 6px !important;
}

/* ── Grade banner ─────────────────────────────────────────────────────────── */
.grade-banner {
    display: flex;
    align-items: center;
    gap: 24px;
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 10px;
    padding: 20px 28px;
    margin: 16px 0 24px;
}
.grade-circle {
    width: 90px; height: 90px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 2.8rem; font-weight: 900;
    flex-shrink: 0;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
}
.grade-A { background: #064e3b; color: #10b981; border: 3px solid #10b981; }
.grade-B { background: #1e3a5f; color: #3b82f6; border: 3px solid #3b82f6; }
.grade-C { background: #4a2800; color: #f59e0b; border: 3px solid #f59e0b; }
.grade-D { background: #3b0a0a; color: #ef4444; border: 3px solid #ef4444; }
.grade-F { background: #1a0000; color: #dc2626; border: 3px solid #dc2626; }

.grade-info { flex: 1; }
.grade-title { font-size: 1.5rem; font-weight: 700; color: #e2e8f0; }
.grade-subtitle { color: #64748b; font-size: 0.85rem; margin-top: 4px; }
.grade-score-bar-bg {
    background: #1f2d3d;
    border-radius: 4px;
    height: 8px;
    margin-top: 12px;
    overflow: hidden;
}
.grade-score-bar-fill {
    height: 8px;
    border-radius: 4px;
    transition: width 0.8s ease;
}

/* ── Score grid cards ─────────────────────────────────────────────────────── */
.score-card {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 8px;
    padding: 14px 16px;
    margin: 4px 0;
    transition: border-color 0.2s;
}
.score-card:hover { border-color: #2d3748; }
.score-card-label {
    color: #64748b;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 6px;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
}
.score-card-value {
    font-size: 1.5rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    line-height: 1;
}
.score-val-good  { color: #10b981; }
.score-val-ok    { color: #f59e0b; }
.score-val-bad   { color: #ef4444; }
.score-bar-bg    { background: #1f2d3d; border-radius: 3px; height: 4px; margin-top: 8px; overflow: hidden; }
.score-bar-good  { height: 4px; border-radius: 3px; background: #10b981; }
.score-bar-ok    { height: 4px; border-radius: 3px; background: #f59e0b; }
.score-bar-bad   { height: 4px; border-radius: 3px; background: #ef4444; }

/* ── Critical findings ────────────────────────────────────────────────────── */
.crit-box {
    background: #1a0000;
    border: 1px solid #7f1d1d;
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 16px 0;
}
.crit-box-title {
    color: #ef4444;
    font-weight: 700;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 10px;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
}
.crit-item {
    color: #fca5a5;
    font-size: 0.85rem;
    padding: 3px 0 3px 12px;
    border-left: 2px solid #7f1d1d;
    margin: 5px 0;
    line-height: 1.5;
}

/* ── Severity badges ──────────────────────────────────────────────────────── */
.badge {
    display: inline-block;
    border-radius: 4px;
    padding: 1px 8px;
    font-size: 0.65rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    vertical-align: middle;
    margin-right: 6px;
}
.badge-critical { background: #450a0a; color: #ef4444; border: 1px solid #7f1d1d; }
.badge-high     { background: #431407; color: #f97316; border: 1px solid #9a3412; }
.badge-medium   { background: #451a03; color: #f59e0b; border: 1px solid #92400e; }
.badge-low      { background: #1e3a5f; color: #60a5fa; border: 1px solid #1e40af; }
.badge-info     { background: #1e2d40; color: #94a3b8; border: 1px solid #334155; }

/* ── Report sections ──────────────────────────────────────────────────────── */
.report-section-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 8px 8px 0 0;
    cursor: pointer;
}
.report-section-body {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-top: none;
    border-radius: 0 0 8px 8px;
    padding: 16px;
    margin-bottom: 8px;
}

/* ── Tabs ─────────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background: #0d1117 !important;
    border-bottom: 1px solid #1f2d3d !important;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: #64748b !important;
    border-radius: 6px 6px 0 0 !important;
    font-size: 0.85rem !important;
    padding: 8px 16px !important;
    border: none !important;
}
.stTabs [aria-selected="true"] {
    background: #111827 !important;
    color: #10b981 !important;
    border-bottom: 2px solid #10b981 !important;
}

/* ── Expanders ────────────────────────────────────────────────────────────── */
.streamlit-expanderHeader {
    background: #0d1117 !important;
    border: 1px solid #1f2d3d !important;
    border-radius: 6px !important;
    color: #c9d1d9 !important;
    font-size: 0.9rem !important;
}
.streamlit-expanderContent {
    background: #0d1117 !important;
    border: 1px solid #1f2d3d !important;
    border-top: none !important;
    color: #c9d1d9 !important;
}

/* ── Metrics ──────────────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #0d1117 !important;
    border: 1px solid #1f2d3d !important;
    border-radius: 8px !important;
    padding: 12px !important;
}
[data-testid="stMetricLabel"] { color: #64748b !important; font-size: 0.75rem !important; text-transform: uppercase; }
[data-testid="stMetricValue"] { color: #e2e8f0 !important; font-family: 'JetBrains Mono', 'Courier New', monospace !important; }

/* ── Toggle ───────────────────────────────────────────────────────────────── */
.stToggle > label { color: #94a3b8 !important; font-size: 0.85rem !important; }

/* ── Divider ──────────────────────────────────────────────────────────────── */
hr { border-color: #1f2d3d !important; }

/* ── Spinner text ─────────────────────────────────────────────────────────── */
.stSpinner > div { color: #10b981 !important; }

/* ── Code / pre ───────────────────────────────────────────────────────────── */
code, pre {
    background: #111827 !important;
    color: #7dd3fc !important;
    border: 1px solid #1f2d3d !important;
    border-radius: 4px !important;
    font-family: 'JetBrains Mono', 'Courier New', monospace !important;
}

/* ── Download button ──────────────────────────────────────────────────────── */
.stDownloadButton > button {
    background: #111827 !important;
    color: #10b981 !important;
    border: 1px solid #10b981 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
}
.stDownloadButton > button:hover {
    background: #064e3b !important;
}

/* ── Scrollbar ────────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0e1a; }
::-webkit-scrollbar-thumb { background: #1f2d3d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #2d3748; }

/* ── Warning / info ───────────────────────────────────────────────────────── */
.stAlert { border-radius: 8px !important; }

/* ── Caption / small text ─────────────────────────────────────────────────── */
.stCaption, small { color: #475569 !important; }

/* ── Section dividers ─────────────────────────────────────────────────────── */
.section-label {
    color: #475569;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    padding: 6px 0 4px;
    border-bottom: 1px solid #1f2d3d;
    margin-bottom: 12px;
}

/* ── Markdown inside report ───────────────────────────────────────────────── */
.report-body h1, .report-body h2 { color: #e2e8f0; border-bottom: 1px solid #1f2d3d; padding-bottom: 6px; }
.report-body h3 { color: #94a3b8; }
.report-body h4 { color: #10b981; }
.report-body table { background: #111827; border-collapse: collapse; width: 100%; border-radius: 6px; overflow: hidden; }
.report-body th { background: #1f2d3d; color: #94a3b8; padding: 8px 12px; font-size: 0.8rem; text-align: left; }
.report-body td { color: #c9d1d9; padding: 8px 12px; border-bottom: 1px solid #1a2535; font-size: 0.85rem; }
.report-body li { color: #c9d1d9; margin: 4px 0; }
.report-body strong { color: #e2e8f0; }
.report-body blockquote { border-left: 3px solid #10b981; padding-left: 12px; color: #94a3b8; }

/* ── History / Diff cards ─────────────────────────────────────────────────── */
.hist-card {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 6px 0;
    display: flex;
    align-items: center;
    gap: 16px;
}
.hist-grade-dot {
    width: 36px; height: 36px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1rem; font-weight: 900;
    flex-shrink: 0;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
}
.delta-improved { color: #10b981; font-weight: 700; }
.delta-regressed { color: #ef4444; font-weight: 700; }
.delta-unchanged { color: #475569; }
.new-finding { color: #ef4444; }
.resolved-finding { color: #10b981; }

/* ── Verification result rows ─────────────────────────────────────────────── */
.verify-row {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-left: 4px solid #1f2d3d;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 5px 0;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.82rem;
}
.verify-confirmed { border-left-color: #ef4444; }
.verify-blocked   { border-left-color: #f59e0b; }
.verify-unknown   { border-left-color: #475569; }

/* ── TraffixNet-style inline mode selector cards ──────────────────────────── */
.mode-selector-card {
    background: #0d1117;
    border: 2px solid #1f2d3d;
    border-radius: 10px;
    padding: 18px 20px;
    transition: all .2s;
    height: 100%;
}
.mode-selector-card.msc-std { border-color: #10b981; background: #061a0d; }
.mode-selector-card.msc-pt  { border-color: #ef4444; background: #1a0606; }
.msc-tag {
    display: inline-block; border-radius: 4px; padding: 2px 7px;
    font-size: 0.6rem; font-weight: 800; font-family:'Courier New',monospace;
    letter-spacing: .08em; margin-left: 6px; vertical-align: middle;
}
.msc-tag-std { background:#0a1f0f; border:1px solid #10b981; color:#10b981; }
.msc-tag-pt  { background:#1a0606; border:1px solid #ef4444; color:#ef4444; }
.msc-tag-inactive { background:#111827; border:1px solid #374151; color:#6b7280; font-size:0.55rem; }
.msc-title { font-size:1rem; font-weight:700; color:#e2e8f0; margin:6px 0 2px; }
.msc-desc  { font-size:0.77rem; color:#64748b; line-height:1.75; }
.msc-std-color { color: #10b981; font-size:0.72rem; font-weight:800;
                  font-family:'Courier New',monospace; letter-spacing:.1em; }
.msc-pt-color  { color: #ef4444; font-size:0.72rem; font-weight:800;
                  font-family:'Courier New',monospace; letter-spacing:.1em; }

/* ── TraffixNet-style inline findings panel ───────────────────────────────── */
.tf-summary {
    background: #0d1117; border: 1px solid #1f2d3d; border-radius: 10px;
    padding: 18px 24px; margin: 16px 0;
}
.tf-counts { display:flex; align-items:center; gap:6px; flex-wrap:wrap; font-family:'Courier New',monospace; }
.tf-crit  { color:#ef4444; font-weight:800; font-size:1rem; }
.tf-worth { color:#f59e0b; font-weight:800; font-size:1rem; }
.tf-opt   { color:#94a3b8; font-weight:800; font-size:1rem; }
.tf-dot   { color:#334155; font-size:0.8rem; }
.tf-msg   { color:#64748b; font-size:0.8rem; margin-top:8px; line-height:1.5; }

.tf-group {
    background: #0d1117; border: 1px solid #1f2d3d; border-radius: 10px;
    overflow: hidden; margin: 10px 0;
}
.tf-group-header {
    background: #111827; padding: 9px 18px;
    font-size: 0.65rem; font-weight:700; text-transform:uppercase;
    letter-spacing:.14em; color:#475569; font-family:'Courier New',monospace;
    border-bottom: 1px solid #1f2d3d;
}
.tf-item {
    display:flex; align-items:flex-start; gap:14px;
    padding: 13px 18px; border-bottom: 1px solid #0f1923;
}
.tf-item:last-child { border-bottom: none; }
.tf-pri-badge {
    display:inline-block; border-radius:4px; padding:2px 8px;
    font-size:0.6rem; font-weight:800; text-transform:uppercase;
    letter-spacing:.07em; font-family:'Courier New',monospace;
    white-space:nowrap; flex-shrink:0; margin-top:2px;
}
.tf-pri-critical { background:#450a0a; color:#ef4444; border:1px solid #7f1d1d; }
.tf-pri-worth    { background:#451a03; color:#f59e0b; border:1px solid #92400e; }
.tf-pri-optional { background:#1e2d40; color:#94a3b8; border:1px solid #334155; }
.tf-item-name    { font-weight:700; color:#e2e8f0; font-size:0.9rem; line-height:1.4; }
.tf-item-what    { color:#94a3b8; font-size:0.78rem; margin-top:4px; line-height:1.6; }

/* ── Scan mode indicator ──────────────────────────────────────────────────── */
.mode-badge-standard {
    background: #0f2027;
    border: 1px solid #10b981;
    border-radius: 6px;
    padding: 10px 14px;
    color: #10b981;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    margin: 8px 0;
    line-height: 1.6;
}
.mode-badge-pt {
    background: #1a0a00;
    border: 1px solid #ef4444;
    border-radius: 6px;
    padding: 10px 14px;
    color: #ef4444;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    margin: 8px 0;
    line-height: 1.6;
}
.mode-badge-locked {
    background: #111827;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 10px 14px;
    color: #6b7280;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    margin: 8px 0;
    line-height: 1.6;
}
.mode-badge-passive {
    background: #0d1a2e;
    border: 1px solid #3b82f6;
    border-radius: 6px;
    padding: 10px 14px;
    color: #60a5fa;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    margin: 8px 0;
    line-height: 1.6;
}

/* ── Passive Recon result cards ───────────────────────────────────────────── */
.pr-section-title {
    color: #60a5fa; font-size: 0.68rem; text-transform: uppercase;
    letter-spacing: .16em; font-family: 'JetBrains Mono', 'Courier New', monospace;
    padding: 6px 0 4px; border-bottom: 1px solid #1e3a5f; margin-bottom: 14px;
    margin-top: 24px;
}
.pr-card {
    background: #0d1117; border: 1px solid #1f2d3d; border-radius: 8px;
    padding: 14px 18px; margin: 6px 0; border-left: 4px solid #1f2d3d;
    transition: border-color .2s;
}
.pr-card-critical { border-left-color: #ef4444; }
.pr-card-high     { border-left-color: #f97316; }
.pr-card-medium   { border-left-color: #f59e0b; }
.pr-card-low      { border-left-color: #60a5fa; }
.pr-card-info     { border-left-color: #334155; }
.pr-tool-name  { color: #e2e8f0; font-weight: 700; font-size: 0.88rem; margin-bottom: 4px; }
.pr-finding    { color: #94a3b8; font-size: 0.8rem; line-height: 1.6; }
.pr-meta       { color: #475569; font-size: 0.72rem; font-family:'Courier New',monospace; margin-top: 4px; }

/* ── Bug bounty contact card ───────────────────────────────────────────────── */
.bb-card {
    background: #061a0d; border: 1px solid #10b981; border-radius: 8px;
    padding: 16px 20px; margin: 8px 0;
}
.bb-card-title { color: #10b981; font-weight: 700; font-size: 0.9rem; margin-bottom: 8px; }
.bb-card-item  { color: #6ee7b7; font-size: 0.82rem; margin: 3px 0; font-family:'Courier New',monospace; }

/* ── Responsible disclosure email template ────────────────────────────────── */
.rd-email {
    background: #111827; border: 1px solid #1f2d3d; border-radius: 8px;
    padding: 16px 20px; font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.78rem; color: #c9d1d9; line-height: 1.8; white-space: pre-wrap;
}
/* inline scan-mode banner (above scan button) */
.scan-mode-banner {
    display: flex;
    align-items: center;
    gap: 10px;
    border-radius: 6px;
    padding: 8px 14px;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.8rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    margin-bottom: 12px;
}
.scan-mode-banner-std { background:#0f2027; border:1px solid #10b981; color:#10b981; }
.scan-mode-banner-pt  { background:#1a0a00; border:1px solid #ef4444; color:#ef4444; }
.poc-box {
    background: #0d0000;
    border: 1px solid #7f1d1d;
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 16px 20px;
    margin: 12px 0;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
}
.poc-box-title { color: #ef4444; font-weight: 700; font-size: 0.85rem; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.1em; }
.poc-step { color: #fca5a5; font-size: 0.8rem; margin: 4px 0; }
</style>
"""

st.markdown(_CSS, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_CATEGORY_LABELS: dict[str, str] = {
    "ssl":               "SSL/TLS",
    "headers":           "Sec Headers",
    "html":              "HTML / JS",
    "tech":              "Tech Stack",
    "crawler":           "Crawler",
    "cors_csp":          "CORS & CSP",
    "dns":               "DNS Security",
    "exposure":          "File Exposure",
    "hsts_preload":      "HSTS",
    "open_redirect":     "Open Redirect",
    "waf":               "WAF",
    "cert_transparency": "Cert. Transp.",
    "api_spec":          "API Spec",
    "subdomain_takeover":"Sub. Takeover",
    "port_scanner":      "Open Ports",
    "cookie_security":   "Cookies",
    "deep_js_crawler":   "SPA / Deep JS",
}

_CATEGORY_ICONS: dict[str, str] = {
    "ssl":               "🔒",
    "headers":           "📋",
    "html":              "🌐",
    "tech":              "⚙️",
    "crawler":           "🕷️",
    "cors_csp":          "🔀",
    "dns":               "🌍",
    "exposure":          "📂",
    "hsts_preload":      "📌",
    "open_redirect":     "↪️",
    "waf":               "🛡",
    "cert_transparency": "📜",
    "api_spec":          "🔌",
    "subdomain_takeover":"🎯",
    "port_scanner":      "🔓",
    "cookie_security":   "🍪",
    "deep_js_crawler":   "⚡",
}

_DEMO_TARGET_URL = "https://example.com"

_DEMO_URL_REPORT = """
## Web Security Report — https://example.com

### Overall Grade: C (58/100)

### Executive Summary
The target site has several notable security gaps. The SSL/TLS configuration is solid (TLS 1.3),
but missing HTTP security headers and an exposed jQuery 1.11.0 with a known prototype-pollution CVE
significantly lower the overall posture. No WAF is detected, leaving the application directly exposed
to automated attack traffic. Immediate remediation is required on the vulnerable dependency and CSP.

### Findings by Category

#### SSL/TLS — Score: 92/100
- ✅ TLS 1.3 in use with AES-256-GCM cipher — excellent
- ✅ Certificate valid for 87 days (Let's Encrypt)
- ✅ OCSP stapling enabled
- ⚠️ TLS 1.1 still listed as supported fallback — disable

#### Security Headers — Score: 33/100
- ✅ Strict-Transport-Security, X-Content-Type-Options present
- ❌ **Missing Content-Security-Policy** — allows XSS via inline scripts
- ❌ **Missing X-Frame-Options** — Clickjacking attack surface open
- ❌ Missing Referrer-Policy, Permissions-Policy, Cross-Origin headers

#### HSTS — Score: 60/100
- ✅ HSTS header present (max-age=31536000)
- ❌ Not on the HSTS preload list — first visit is still unprotected

#### CORS & CSP — Score: 40/100
- ⚠️ CORS wildcard `Access-Control-Allow-Origin: *` on /api endpoints
- ❌ No Content-Security-Policy — CSP score: 0/10
- ❌ No Subresource Integrity (SRI) on CDN scripts

#### Page Content & JavaScript — Score: 72/100
- ⚠️ **jQuery 1.11.0** — CVE-2019-11358 (Prototype Pollution, CVSS 6.1)
- ✅ No exposed API keys or secrets found in HTML source
- ✅ No mixed HTTP/HTTPS content
- ✅ 2 POST forms — CSRF tokens present

#### Open Redirects — Score: 90/100
- ✅ No confirmed open redirects detected
- ℹ️ `?next=` and `?redirect=` parameters found but blocked correctly

#### Technology Stack — Score: 50/100
- Server: nginx/1.24.0
- Framework: Next.js (detected via `__NEXT_DATA__`)
- **⚠️ jQuery 1.11.0** — update to 3.7.1+
- No server-version hiding — nginx version exposed in Server header

#### DNS Security — Score: 75/100
- ✅ SPF record configured correctly
- ✅ DMARC present (p=quarantine)
- ❌ No CAA record — any CA can issue certificates for this domain

#### Exposed Files & Methods — Score: 80/100
- ✅ No .git, .env, or source maps exposed
- ⚠️ HTTP OPTIONS returns allowed methods including PUT, DELETE

#### WAF Protection — Score: 0/100
- ❌ **No WAF detected** — all traffic reaches the application unfiltered
- No Cloudflare, AWS WAF, Akamai, or Imperva signatures detected

#### Certificate Transparency — Score: 85/100
- ℹ️ 12 subdomains found in CT logs
- ⚠️ 2 potentially sensitive: `dev.example.com`, `staging.example.com`

#### Crawler Findings — Score: 65/100
- 8 pages crawled
- ⚠️ `/api/v1/users` accessible without authentication (returns 200)
- ✅ No stack traces or debug info exposed
- 1 broken link: `/old-page` → 404

#### API Specification Exposure — Score: 95/100
- ✅ No Swagger/OpenAPI spec publicly accessible
- ✅ GraphQL introspection disabled

#### Subdomain Takeover Risk — Score: 88/100
- ✅ No dangling CNAMEs detected in checked subdomains
- ℹ️ `dev.example.com` CNAME → verify cloud resource still active

#### Open Ports — Score: 70/100
- ✅ HTTP/HTTPS ports expected and open
- ⚠️ Port 22 (SSH) open — restrict to known IP ranges via firewall
- ✅ No database ports (3306, 5432, 27017) exposed

#### Cookie Security — Score: 55/100
- ✅ Session cookie: HttpOnly ✅, Secure ✅
- ❌ `analytics_id` cookie: missing SameSite attribute — CSRF risk
- ❌ `pref` cookie: no Secure flag — transmitted over HTTP

#### Deep JS / SPA Crawler — Score: 78/100
- ✅ No hardcoded API keys or tokens found in JS bundles
- ✅ No SSRF attempts detected from SPA
- ⚠️ 3 XHR endpoints found without authentication: `/api/v1/search`, `/api/v1/stats`
- ℹ️ Next.js hydration data contains user-agent fingerprinting

### Prioritised Recommendations

1. **[CRITICAL] Update jQuery** from 1.11.0 → 3.7.1+ — CVE-2019-11358 allows attackers to
   pollute the JavaScript prototype chain, leading to XSS or denial of service.
   `npm install jquery@3.7.1`

2. **[HIGH] Deploy a WAF** — The application has no firewall layer. Add Cloudflare Free tier
   or AWS WAF to filter common attack patterns before they reach the application.

3. **[HIGH] Add Content-Security-Policy header** — Minimal starting point:
   `Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com`

4. **[HIGH] Protect `/api/v1/users`** — Endpoint returned 200 without authentication during crawl.
   Add JWT/session validation middleware on all /api routes.

5. **[MEDIUM] Add X-Frame-Options: DENY** — Prevents Clickjacking via iframe embedding.

6. **[MEDIUM] Fix cookie SameSite attributes** — Add `SameSite=Lax` to `analytics_id` cookie.

7. **[MEDIUM] Add CAA DNS record** — Limits which CAs can issue TLS certs for your domain.
   `example.com. CAA 0 issue "letsencrypt.org"`

8. **[LOW] Hide nginx version** — Remove `server_tokens on` from nginx.conf.

9. **[LOW] Restrict SSH (port 22)** — Move to non-standard port or restrict with firewall rules.

### OWASP Top 10 Mapping

| Finding | OWASP Category | Severity |
|---------|----------------|----------|
| jQuery CVE-2019-11358 | A06:2021 – Vulnerable Components | HIGH |
| No WAF | A05:2021 – Security Misconfiguration | HIGH |
| Missing CSP | A05:2021 – Security Misconfiguration | HIGH |
| Missing X-Frame-Options | A05:2021 – Security Misconfiguration | MEDIUM |
| Unauthenticated API endpoint | A01:2021 – Broken Access Control | HIGH |
| CORS wildcard on API | A05:2021 – Security Misconfiguration | MEDIUM |
| Missing Referrer-Policy | A05:2021 – Security Misconfiguration | LOW |
| Cookie SameSite missing | A07:2021 – Identification & Auth Failures | MEDIUM |

---
*Scanned by AI Cyber Shield v6 — Defensive use only · מערכת לשימוש הגנתי בלבד*
"""

_DEMO_URL_META = {
    "overall_grade": "C",
    "overall_score": 58,
    "category_scores": {
        "ssl": 92, "headers": 33, "html": 72, "tech": 50, "crawler": 65,
        "cors_csp": 40, "dns": 75, "exposure": 80, "hsts_preload": 60,
        "open_redirect": 90, "waf": 0, "cert_transparency": 85,
        "api_spec": 95, "subdomain_takeover": 88, "port_scanner": 70,
        "cookie_security": 55, "deep_js_crawler": 78,
    },
    "critical_findings": [
        "CVE-2019-11358: jQuery 1.11.0 Prototype Pollution (CVSS 6.1)",
        "No WAF detected — all traffic reaches application unfiltered",
        "Missing Content-Security-Policy — XSS attack surface open",
        "Unauthenticated /api/v1/users endpoint (HTTP 200 without auth)",
        "CORS wildcard (Access-Control-Allow-Origin: *) on API endpoints",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _score_class(score: int) -> str:
    if score >= 75: return "good"
    if score >= 40: return "ok"
    return "bad"


def _grade_color(grade: str) -> str:
    return {"A": "#10b981", "B": "#3b82f6", "C": "#f59e0b", "D": "#ef4444"}.get(grade, "#dc2626")


def _render_grade_banner(grade: str, score: int, url: str) -> None:
    color = _grade_color(grade)
    bar_width = score
    st.markdown(f"""
<div class="grade-banner">
  <div class="grade-circle grade-{grade}">{grade}</div>
  <div class="grade-info">
    <div class="grade-title">{url}</div>
    <div class="grade-subtitle">Security Score: <strong style="color:{color}">{score}/100</strong>
      &nbsp;·&nbsp; Grade: <strong style="color:{color}">{grade}</strong></div>
    <div class="grade-score-bar-bg">
      <div class="grade-score-bar-fill"
           style="width:{bar_width}%; background:{color};"></div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


def _render_score_card(key: str, score: int) -> str:
    label = _CATEGORY_LABELS.get(key, key)
    icon  = _CATEGORY_ICONS.get(key, "📊")
    cls   = _score_class(score)
    return f"""
<div class="score-card">
  <div class="score-card-label">{icon} {label}</div>
  <div class="score-card-value score-val-{cls}">{score}<span style="font-size:0.9rem;color:#475569">/100</span></div>
  <div class="score-bar-bg"><div class="score-bar-{cls}" style="width:{score}%"></div></div>
</div>"""


def _render_critical_findings(findings: list[str]) -> None:
    if not findings:
        return
    items = "".join(f'<div class="crit-item">⚡ {f}</div>' for f in findings)
    st.markdown(f"""
<div class="crit-box">
  <div class="crit-box-title">🔴 Critical Findings ({len(findings)})</div>
  {items}
</div>
""", unsafe_allow_html=True)


def _parse_report_sections(markdown: str) -> list[tuple[str, str, str]]:
    """
    Split the LLM Markdown report into (section_key, section_title, content) tuples.

    Sections are delimited by #### headers (category detail) or ### headers
    (Executive Summary, Recommendations, OWASP mapping).
    Returns a list suitable for rendering in expanders.
    """
    sections: list[tuple[str, str, str]] = []

    # Split on ### or #### headers
    pattern = re.compile(r'^(#{3,4})\s+(.+)$', re.MULTILINE)
    matches = list(pattern.finditer(markdown))

    for i, match in enumerate(matches):
        title     = match.group(2).strip()
        start     = match.end()
        end       = matches[i + 1].start() if i + 1 < len(matches) else len(markdown)
        body      = markdown[start:end].strip()
        key       = re.sub(r'[^a-z0-9_]', '_', title.lower())[:40]
        sections.append((key, title, body))

    return sections


def _severity_badge(title: str) -> str:
    t = title.lower()
    if "critical" in t or "score: 0" in t:
        return '<span class="badge badge-critical">CRITICAL</span>'
    if "high" in t or any(w in t for w in ("no waf", "exposed", "takeover")):
        return '<span class="badge badge-high">HIGH</span>'
    if "medium" in t or "warn" in t:
        return '<span class="badge badge-medium">MEDIUM</span>'
    if "low" in t:
        return '<span class="badge badge-low">LOW</span>'
    return ""


def _map_finding_priority(text: str) -> tuple[str, str]:
    """Map finding text to (css_class, label) — TraffixNet 3-level priority."""
    t = text.lower()
    if any(k in t for k in ("critical", "injection", "sql", "cve-", "rce", "remote code",
                             "no waf", "exec", "command", "takeover", "hardcoded secret",
                             "exposed", "0/100", "prototype pollution")):
        return "critical", "Critical"
    if any(k in t for k in ("high", "missing csp", "missing content-security", "cors wildcard",
                             "unauthenticated", "without authentication", "open redirect",
                             "tls 1.0", "tls 1.1", "ssrf", "xss", "csrf", "clickjack",
                             "missing x-frame", "weak cipher", "weak hash")):
        return "worth", "Worth fixing"
    return "optional", "Optional"


def _render_inline_findings(findings: list[str]) -> None:
    """Render critical findings in TraffixNet style — inline, no expanders."""
    if not findings:
        return

    classified = [(_map_finding_priority(f), f) for f in findings]
    n_crit  = sum(1 for (cls, _), _ in classified if cls == "critical")
    n_worth = sum(1 for (cls, _), _ in classified if cls == "worth")
    n_opt   = sum(1 for (cls, _), _ in classified if cls == "optional")

    readiness = (
        "Your site has critical issues actively exploited in the wild — fix immediately."
        if n_crit >= 2 else
        "Your site has important issues. Fix the high-priority items before going live."
        if n_worth >= 2 else
        "Your site is reasonably hardened — address remaining issues to reach A grade."
    )

    st.markdown(f"""
<div class="tf-summary">
  <div class="tf-counts">
    <span class="tf-crit">● {n_crit} critical</span>
    <span class="tf-dot">·</span>
    <span class="tf-worth">● {n_worth} worth fixing</span>
    <span class="tf-dot">·</span>
    <span class="tf-opt">● {n_opt} optional</span>
  </div>
  <div class="tf-msg">{readiness}</div>
</div>""", unsafe_allow_html=True)

    items_html = ""
    for (pri_cls, pri_label), f in classified:
        clean = re.sub(r'^\[.*?\]\s*', '', f).strip()
        items_html += f"""
<div class="tf-item">
  <span class="tf-pri-badge tf-pri-{pri_cls}">{pri_label}</span>
  <div><div class="tf-item-name">{clean}</div></div>
</div>"""

    st.markdown(f"""
<div class="tf-group">
  <div class="tf-group-header">Key Findings — fix in this order</div>
  {items_html}
</div>""", unsafe_allow_html=True)


def _render_mode_selector(pt_mode_active: bool) -> None:
    """Big prominent inline mode selector — TraffixNet-style two cards."""
    mc1, mc2 = st.columns(2, gap="medium")

    std_cls  = "mode-selector-card msc-std" if not pt_mode_active else "mode-selector-card"
    pt_cls   = "mode-selector-card msc-pt"  if pt_mode_active      else "mode-selector-card"
    std_tag  = '<span class="msc-tag msc-tag-std">ACTIVE</span>'  if not pt_mode_active else '<span class="msc-tag msc-tag-inactive">OFF</span>'
    pt_tag   = '<span class="msc-tag msc-tag-pt">ACTIVE</span>'   if pt_mode_active     else '<span class="msc-tag msc-tag-inactive">SELECT IN SIDEBAR</span>'

    mc1.markdown(f"""
<div class="{std_cls}">
  <div class="msc-std-color">🟢 STANDARD SCAN{std_tag}</div>
  <div class="msc-title">Deep Web Analysis + AI</div>
  <div class="msc-desc">
    ✅ 17 tools: SSL · Headers · Crawler · CORS · DNS · WAF<br>
    ✅ LLM threat-narrative report (Groq API key required)<br>
    ✅ Safe for <b style="color:#e2e8f0">any site worldwide</b><br>
    ✅ Results in ~30 seconds<br>
    <span style="color:#60a5fa;font-size:0.78rem">🔵 For OSINT-only: select Passive Recon in sidebar</span>
  </div>
</div>""", unsafe_allow_html=True)

    mc2.markdown(f"""
<div class="{pt_cls}">
  <div class="msc-pt-color">🔴 ACTIVE PT MODE{pt_tag}</div>
  <div class="msc-title">Live Verification + PoC</div>
  <div class="msc-desc">
    🔬 Passive scan + live canary probes<br>
    🔴 Auto-confirms vulnerabilities with <b style="color:#e2e8f0">curl PoC</b><br>
    ⚠️ Only authorized targets — <b style="color:#fca5a5">own site or written permission</b><br>
    📋 Enable in sidebar + check ownership box
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)


def _section_score_from_title(title: str) -> int | None:
    """Extract /100 score from a section title like 'SSL/TLS — Score: 92/100'."""
    m = re.search(r'Score:\s*(\d+)/100', title)
    return int(m.group(1)) if m else None


def _render_report_sections(report_markdown: str) -> None:
    """
    Render the LLM report as organized, collapsible sections with color-coded scores.
    """
    sections = _parse_report_sections(report_markdown)

    if not sections:
        # Fallback: render raw
        st.markdown(f'<div class="report-body">{report_markdown}</div>', unsafe_allow_html=True)
        return

    # Group: intro (before first section), category findings, and final sections
    for key, title, body in sections:
        score     = _section_score_from_title(title)
        badge     = _severity_badge(title) if score is None else ""
        score_str = f'<span style="color:{_grade_color("A" if (score or 0)>=75 else "C" if (score or 0)>=40 else "F")};font-weight:700;font-family:monospace">{score}/100</span>' if score is not None else ""

        # Determine if this is a top-level section (###) or category (####)
        is_category = bool(score is not None)

        # Choose icon for section type
        section_icon = "📁"
        tl = title.lower()
        if "executive" in tl or "summary" in tl:
            section_icon = "📋"
        elif "recommendation" in tl:
            section_icon = "🔧"
        elif "owasp" in tl:
            section_icon = "📊"
        elif "ssl" in tl or "tls" in tl:
            section_icon = "🔒"
        elif "header" in tl:
            section_icon = "📋"
        elif "redirect" in tl:
            section_icon = "↪️"
        elif "waf" in tl:
            section_icon = "🛡"
        elif "cookie" in tl:
            section_icon = "🍪"
        elif "port" in tl:
            section_icon = "🔓"
        elif "dns" in tl:
            section_icon = "🌍"
        elif "cors" in tl or "csp" in tl:
            section_icon = "🔀"
        elif "crawler" in tl or "spa" in tl or "js" in tl:
            section_icon = "⚡"
        elif "api" in tl:
            section_icon = "🔌"
        elif "subdomain" in tl or "takeover" in tl:
            section_icon = "🎯"
        elif "cert" in tl:
            section_icon = "📜"
        elif "tech" in tl:
            section_icon = "⚙️"
        elif "expos" in tl:
            section_icon = "📂"
        elif "hsts" in tl:
            section_icon = "📌"

        label_html = f"{section_icon} &nbsp; {title} &nbsp; {score_str} {badge}"

        # Default open for Executive Summary and Recommendations
        default_open = any(k in tl for k in ("executive", "summary", "recommendation", "owasp", "overall"))

        with st.expander(f"{section_icon} {title}", expanded=default_open):
            st.markdown(f'<div class="report-body">', unsafe_allow_html=True)
            st.markdown(body)
            st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar  — mode selector + demo toggle
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    # ── User info + logout ────────────────────────────────────────────────────
    if _current_user:
        # Tier badge colors
        _tier_colors = {"free":"#475569","starter":"#10b981","professional":"#6366f1","enterprise":"#f59e0b"}
        _tc = _tier_colors.get(_current_user.subscription_tier, "#475569")
        _tier_label = _current_user.subscription_tier.title()
        _admin_badge = '<span style="color:#475569;font-size:0.7rem">  🔑 Admin</span>' if _current_user.is_admin else ''
        _pt_badge    = '<span style="color:#10b981;font-size:0.7rem">  ✅ PT</span>' if _current_user.pt_approved else ''
        st.markdown(
            f"<div style='padding:10px 0 4px;'>"
            f"<span style='color:#10b981;font-size:0.78rem;font-family:monospace'>👤 {_current_user.email}</span><br>"
            f"<span style='color:{_tc};font-size:0.72rem;font-weight:700'>● {_tier_label}</span>"
            f"{_admin_badge}{_pt_badge}"
            f"</div>",
            unsafe_allow_html=True,
        )
        _quota = check_quota(_current_user)
        _limit = _quota.get("limit", 5)
        _used  = _quota.get("used", 0)
        if _quota.get("allowed"):
            if _limit > 0:
                st.progress(min(_used / _limit, 1.0), text=f"{_used}/{_limit} scans today")
            else:
                st.success("♾ Unlimited scans")
        else:
            st.error(f"⛔ Daily limit reached ({_limit}/day)")

        col_up, col_lo = st.columns(2)
        with col_up:
            if st.button("⬆ Upgrade", use_container_width=True, key="upgrade_btn"):
                st.session_state["_show_pricing"] = not st.session_state.get("_show_pricing", False)
                st.rerun()
        with col_lo:
            if st.button("Logout", use_container_width=True, key="logout_btn"):
                log_action("logout")
                sign_out()
                st.rerun()
        st.divider()

        # ── Scan history ──────────────────────────────────────────────────────
        if st.button("📊 Scan History", use_container_width=True, key="history_btn"):
            st.session_state["_show_history"] = not st.session_state.get("_show_history", False)

        # ── Scheduled scans ───────────────────────────────────────────────────
        if st.button("🕐 Schedules", use_container_width=True, key="schedule_btn"):
            st.session_state["_show_schedules"] = not st.session_state.get("_show_schedules", False)

        # ── API docs ──────────────────────────────────────────────────────────
        if st.button("📡 API Docs", use_container_width=True, key="api_docs_btn"):
            st.session_state["_show_api_docs"] = not st.session_state.get("_show_api_docs", False)

        # ── Team management ───────────────────────────────────────────────────
        if st.button("👥 Team", use_container_width=True, key="team_btn"):
            st.session_state["_show_team"] = not st.session_state.get("_show_team", False)

        # ── Admin panel ───────────────────────────────────────────────────────
        if _current_user.is_admin:
            if st.button("🔐 Admin Panel", use_container_width=True, key="admin_panel_btn"):
                st.session_state["_show_admin"] = not st.session_state.get("_show_admin", False)

    # ── Demo / Live toggle ────────────────────────────────────────────────────
    st.markdown('<div class="section-label">⚙ Configuration</div>', unsafe_allow_html=True)
    demo_mode = st.toggle("Demo Mode (no API call)", value=True, key="demo_mode_toggle")
    if demo_mode:
        st.success("✅ Demo Mode active — no real requests sent")
    else:
        st.info("🔑 Live Mode — Groq API key required in .env")

    st.divider()

    # ── Scan mode selector ────────────────────────────────────────────────────
    st.markdown('<div class="section-label">🎯 Scan Mode</div>', unsafe_allow_html=True)

    scan_mode = st.radio(
        "Scan mode",
        options=["passive", "standard", "pt"],
        format_func=lambda x: {
            "passive":  "🔵  Passive Recon (OSINT)",
            "standard": "🟢  Standard Scan",
            "pt":       "🔴  Active PT Mode",
        }.get(x, x),
        index=0,
        label_visibility="collapsed",
        key="scan_mode_radio",
        help="Passive: 10 OSINT tools, safe on any site. Standard: 17-tool full scan. PT Mode: live probes (needs permission).",
    )

    if scan_mode == "passive":
        st.markdown("""
<div class="mode-badge-passive">
🔵 PASSIVE RECON — 15 OSINT TOOLS<br>
<span style="font-weight:400;color:#93c5fd;font-size:0.72rem">
  15 OSINT tools · safe on ANY website<br>
  JS secrets · Cloud buckets · CVE match<br>
  GitHub leaks · Email spoofability · Wayback<br>
  DNS deep · CNAME takeover · Exposed files
</span>
</div>""", unsafe_allow_html=True)
        pt_mode_active = False

    elif scan_mode == "standard":
        st.markdown("""
<div class="mode-badge-standard">
🟢 STANDARD SCAN<br>
<span style="font-weight:400;color:#94a3b8;font-size:0.72rem">
  17 passive tools + AI analysis<br>
  Safe for any site worldwide<br>
  No live probes sent
</span>
</div>""", unsafe_allow_html=True)
        pt_mode_active = False

    else:
        # PT mode requires admin approval
        _pt_user_approved = _current_user.pt_approved if _current_user else False

        if not _pt_user_approved:
            st.markdown("""
<div class="mode-badge-locked">
🔒 PT MODE — ADMIN APPROVAL REQUIRED<br>
<span style="font-weight:400;font-size:0.7rem;color:#fca5a5">
  Contact admin to request PT Mode access.<br>
  Your account must be approved before use.
</span>
</div>""", unsafe_allow_html=True)
            if _current_user:
                if st.button("📩 Request PT Access", use_container_width=True, key="pt_request_btn"):
                    log_action("pt_request", severity="warning",
                               details={"email": _current_user.email})
                    st.success("Request sent — admin will review and approve your account.")
            pt_mode_active = False
        else:
            st.markdown("""
<div class="mode-badge-pt">
🔴 ACTIVE PT MODE<br>
<span style="font-weight:400;color:#fca5a5;font-size:0.72rem">
  Passive scan + live canary probes<br>
  Confirms vulnerabilities with PoC<br>
  Only for authorized targets
</span>
</div>""", unsafe_allow_html=True)
            st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
            st.markdown(
                '<span style="color:#f59e0b;font-size:0.75rem;font-weight:700;'
                'font-family:Courier New,monospace">⚠️ LEGAL CONFIRMATION REQUIRED</span>',
                unsafe_allow_html=True,
            )
            pt_owns = st.checkbox(
                "I confirm: this site is mine, or I hold explicit written permission.",
                value=False,
                key="pt_owns_confirm",
            )
            if not pt_owns:
                st.markdown("""
<div class="mode-badge-locked">
🔒 PT MODE LOCKED<br>
<span style="font-weight:400;font-size:0.7rem">Check the box above to unlock.</span>
</div>""", unsafe_allow_html=True)
                pt_mode_active = False
            elif demo_mode:
                st.warning("Switch to **Live Mode** to use PT Mode.")
                pt_mode_active = False
            else:
                st.success("✅ PT Mode active — live probes enabled")
                pt_mode_active = True

    st.divider()

    # ── About ─────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-label">ℹ About</div>', unsafe_allow_html=True)
    st.markdown("""
<small style="color:#475569;line-height:1.7">
<b style="color:#10b981">17 security tools</b> run in parallel:<br>
🔒 SSL/TLS · 📋 Headers · 🌐 HTML/JS<br>
⚙️ Tech Stack · 🕷️ Crawler · 🔀 CORS<br>
🌍 DNS · 📂 Exposure · 📌 HSTS<br>
↪️ Redirects · 🛡 WAF · 📜 Cert Transp.<br>
🔌 API Spec · 🎯 Subdomain · 🔓 Ports<br>
🍪 Cookies · ⚡ SPA/Deep JS
</small>
""", unsafe_allow_html=True)

    st.divider()

    # ── Capability badges ─────────────────────────────────────────────────────
    st.markdown('<div class="section-label">⚡ Engine Capabilities</div>', unsafe_allow_html=True)
    st.markdown("""
<small style="color:#475569;line-height:2">
<span style="color:#10b981;font-weight:700">✓</span> WAF Stealth Bypass — browser TLS fingerprint<br>
<span style="color:#10b981;font-weight:700">✓</span> SSRF guard on every redirect hop<br>
<span style="color:#10b981;font-weight:700">✓</span> IPv4-mapped IPv6 SSRF detection<br>
<span style="color:#10b981;font-weight:700">✓</span> ReDoS-safe regex patterns<br>
<span style="color:#10b981;font-weight:700">✓</span> 49 DKIM selectors · 38 exposed file probes<br>
<span style="color:#10b981;font-weight:700">✓</span> CNAME takeover · CORS cache poison check
</small>
""", unsafe_allow_html=True)

    st.divider()
    st.markdown(
        '<small style="color:#334155">AI Cyber Shield v6<br>מערכת לשימוש הגנתי בלבד</small>',
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────

_mode_badge_html = (
    '<span class="cs-badge" style="margin-left:6px;border-color:#ef4444;color:#ef4444">🔴 ACTIVE PT MODE</span>'
    if pt_mode_active else
    '<span class="cs-badge" style="margin-left:6px">🟢 STANDARD SCAN</span>'
)
st.markdown(f"""
<div class="cs-header">
  <div class="cs-logo">⬡ AI CYBER SHIELD</div>
  <div class="cs-tagline">Web Application Security Intelligence Platform</div>
  <div>
    <span class="cs-badge">v6.0</span>
    <span class="cs-badge" style="margin-left:6px">{'15 OSINT TOOLS' if scan_mode == 'passive' else '17 TOOLS'}</span>
    {_mode_badge_html}
    <span class="cs-badge" style="margin-left:6px">DEFENSIVE USE ONLY</span>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Tabs
# ─────────────────────────────────────────────────────────────────────────────

if "auth_scan_auth" not in st.session_state:
    st.session_state["auth_scan_auth"] = None

tab_url, tab_code, tab_history, tab_diff = st.tabs([
    "🌐  URL Security Scanner",
    "💻  Source Code Scanner",
    "📈  Scan History",
    "🔄  Differential View",
])


# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — URL Scanner
# ═════════════════════════════════════════════════════════════════════════════

with tab_url:
    # ── Inline mode selector (TraffixNet-style big cards) ─────────────────────
    st.markdown('<div class="section-label">SCAN MODE</div>', unsafe_allow_html=True)
    _render_mode_selector(pt_mode_active)

    # ── Target URL input ──────────────────────────────────────────────────────
    st.markdown('<div class="section-label">TARGET URL</div>', unsafe_allow_html=True)
    _demo_default = _DEMO_TARGET_URL if demo_mode else ""
    url_input = st.text_input(
        "Target URL",
        value=_demo_default,
        placeholder="https://your-site.com",
        help="Enter the full URL of a website you own or have written permission to scan.",
        label_visibility="collapsed",
    )
    if demo_mode:
        st.caption("🎮 Demo Mode: showing a pre-built report for example.com — no real requests sent.")

    # ── Authentication (Optional) ─────────────────────────────────────────────
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    with st.expander("🔐 Authenticated Scan (Optional)", expanded=False):
        st.caption("Inject session cookies or a Bearer token so the scanner can reach protected pages.")
        _auth_method = st.radio(
            "Authentication method",
            ["None", "Bearer Token", "Upload Session / Profile File"],
            horizontal=True,
            key="auth_method_radio",
            label_visibility="collapsed",
        )

        if _auth_method == "None":
            if st.session_state.get("auth_scan_auth") is not None:
                st.session_state["auth_scan_auth"] = None
                st.rerun()
            st.caption("Unauthenticated — scanner accesses public endpoints only.")

        elif _auth_method == "Bearer Token":
            _col_tok, _col_btn = st.columns([4, 1])
            _token_input = _col_tok.text_input(
                "Bearer Token",
                type="password",
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                key="auth_bearer_token",
                label_visibility="collapsed",
            )
            if _col_btn.button("Apply", key="auth_apply_bearer", use_container_width=True):
                if _token_input.strip():
                    try:
                        from auth.session_loader import from_bearer_token
                        st.session_state["auth_scan_auth"] = from_bearer_token(
                            _token_input.strip(), profile_name="quick-token"
                        )
                        st.rerun()
                    except Exception as _tok_err:
                        st.error(f"Token error: {_tok_err}")
                else:
                    st.warning("Paste a Bearer token first.")
            _cur_auth = st.session_state.get("auth_scan_auth")
            if _cur_auth and not _cur_auth.is_empty:
                st.success(f"✓ Active: {_cur_auth.summary()}")
                if st.button("Clear", key="auth_clear_token"):
                    st.session_state["auth_scan_auth"] = None
                    st.rerun()

        elif _auth_method == "Upload Session / Profile File":
            st.caption("Upload a **ScanProfile** or **LoginSession** JSON saved by `login_recorder.py`.")
            _auth_file = st.file_uploader(
                "Session file (.json)",
                type=["json"],
                key="auth_session_file",
                label_visibility="collapsed",
            )
            if _auth_file is not None:
                try:
                    import tempfile, os as _os
                    from auth.session_loader import load_from_file
                    with tempfile.NamedTemporaryFile(
                        suffix=".json", delete=False, mode="wb"
                    ) as _tf:
                        _tf.write(_auth_file.getvalue())
                        _tmp_path = _tf.name
                    try:
                        _loaded_auth = load_from_file(_tmp_path)
                        st.session_state["auth_scan_auth"] = _loaded_auth
                    finally:
                        try:
                            _os.unlink(_tmp_path)
                        except Exception:
                            pass
                except Exception as _file_err:
                    st.error(f"Failed to load session file: {_file_err}")

            _cur_auth = st.session_state.get("auth_scan_auth")
            if _cur_auth and not _cur_auth.is_empty:
                if _cur_auth.expired:
                    st.warning(
                        f"⚠ Session **'{_cur_auth.profile_name}'** appears expired. "
                        "Re-record with `login_recorder.py` before scanning."
                    )
                else:
                    st.success(f"✓ Loaded: {_cur_auth.summary()}")

                if url_input.strip() and st.button("Check session health", key="auth_health_check"):
                    try:
                        from auth.session_loader import check_session_health
                        _is_ok, _health_reason = check_session_health(
                            _cur_auth, url_input.strip(), timeout=8
                        )
                        if _is_ok:
                            st.success(f"✓ {_health_reason}")
                        else:
                            st.warning(f"⚠ {_health_reason}")
                    except Exception as _he:
                        st.error(f"Health check failed: {_he}")

                if st.button("Clear session", key="auth_clear_file"):
                    st.session_state["auth_scan_auth"] = None
                    st.rerun()

    # Resolve active scan_auth for use in scan action below
    _active_scan_auth = st.session_state.get("auth_scan_auth")

    # ── Scan button — changes label + color by mode ───────────────────────────
    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

    if pt_mode_active:
        st.markdown("""<style>
button[kind="primary"] {
    background: linear-gradient(135deg,#dc2626,#b91c1c) !important;
    color: #fff !important;
}
button[kind="primary"]:hover {
    background: linear-gradient(135deg,#b91c1c,#991b1b) !important;
    box-shadow: 0 4px 12px rgba(220,38,38,.35) !important;
}
</style>""", unsafe_allow_html=True)
        _btn_label   = "🔴  Scan + Verify (PT Mode)"
        _btn_caption = "Live canary probes will be sent automatically. Only use on authorized targets."
    elif scan_mode == "passive":
        st.markdown("""<style>
button[kind="primary"] {
    background: linear-gradient(135deg,#1d4ed8,#1e40af) !important;
    color: #fff !important;
}
button[kind="primary"]:hover {
    background: linear-gradient(135deg,#1e40af,#1e3a8a) !important;
    box-shadow: 0 4px 12px rgba(37,99,235,.35) !important;
}
</style>""", unsafe_allow_html=True)
        _btn_label   = "🔵  Run Passive Recon (15 Tools)"
        _btn_caption = "15 OSINT tools · SSL/TLS · DNS · CT Logs · Exposed files · HTTP headers · JS + source maps · CVEs (55) · ~90 s"
    else:
        _btn_label   = "🔍  Scan Now — Full Analysis"
        _btn_caption = "17 passive tools + AI report · ~30 s · no probes sent · safe for any site"

    # ── Active-scan disclosure (Standard / PT modes include TCP port probing) ──
    # Consent is per-URL: changing the target resets the gate so the user must
    # re-confirm for each new host.  Storing the consented URL (not just a bool)
    # prevents a single consent from covering unlimited future targets.
    _active_scan_consent = True   # Passive recon has no active probes
    if scan_mode in ("standard", "pt"):
        _current_url_key    = url_input.strip()
        _consented_for_url  = st.session_state.get("_active_consent_given", "")
        _already_consented  = bool(_consented_for_url) and (_consented_for_url == _current_url_key)

        with st.expander(
            "⚠️  Active Scan Disclosure — please read before scanning",
            expanded=not _already_consented,
        ):
            st.markdown("""
**This scan mode includes active TCP port probing.**

The scanner will open TCP connections to 18 common ports on the target host
(MySQL, PostgreSQL, MongoDB, Redis, RDP, SSH, FTP, SMB…) to check whether
they are reachable from the internet.

**Before running, confirm:**
- You own the target domain **or** have written authorisation to scan it.
- You understand that TCP SYN connections will appear in the target's access logs.
- You are not using this to probe infrastructure you do not control.

Scanning systems without permission may violate the Computer Fraud and Abuse Act
(CFAA), Computer Misuse Act (CMA), or local equivalent laws.
""")
            _consent_check = st.checkbox(
                "I confirm I am authorised to scan this target and accept responsibility for this scan.",
                key="active_scan_consent_cb",
                value=_already_consented,
            )
            if _consent_check and _current_url_key:
                st.session_state["_active_consent_given"] = _current_url_key
            elif not _consent_check:
                st.session_state["_active_consent_given"] = ""
        _active_scan_consent = (
            st.session_state.get("_active_consent_given", "") == _current_url_key
            and bool(_current_url_key)
        )

    col_scan, col_clear, col_cap = st.columns([2, 1, 3])
    scan_btn  = col_scan.button(
        _btn_label,
        type="primary",
        use_container_width=True,
        key="url_scan",
        disabled=(scan_mode in ("standard", "pt") and not _active_scan_consent),
    )
    clear_btn = col_clear.button("✕  Clear",  use_container_width=True, key="url_clear")
    with col_cap:
        if pt_mode_active:
            st.markdown(f'<span style="color:#fca5a5;font-size:0.75rem">🔴 {_btn_caption}</span>',
                        unsafe_allow_html=True)
        elif scan_mode in ("standard", "pt") and not _active_scan_consent:
            st.caption("Check the disclosure above to enable scanning.")
        else:
            st.caption(f"🟢 {_btn_caption}")

    if clear_btn:
        for k in ("url_report", "url_meta", "url_target", "url_tool_results",
                  "url_av_results", "url_passive_recon", "url_last_mode"):
            st.session_state.pop(k, None)
        st.rerun()

    # ── Legal pages overlay ───────────────────────────────────────────────────
    _legal = st.session_state.get("_show_legal", "")
    if _legal == "tos":
        show_terms_of_service()
        show_legal_nav()
        if st.button("← Back", key="tos_back"): st.session_state.pop("_show_legal"); st.rerun()
        st.stop()
    elif _legal == "privacy":
        show_privacy_policy()
        show_legal_nav()
        if st.button("← Back", key="privacy_back"): st.session_state.pop("_show_legal"); st.rerun()
        st.stop()

    # ── Pricing page overlay ──────────────────────────────────────────────────
    if st.session_state.get("_show_pricing"):
        show_pricing_page()
        if st.button("← Back to Scanner", key="pricing_back_btn"):
            st.session_state["_show_pricing"] = False
            st.rerun()
        st.stop()

    # ── Scan history overlay ──────────────────────────────────────────────────
    if st.session_state.get("_show_history") and _current_user:
        show_scan_history_panel(_current_user.user_id)
        st.divider()

    # ── Scheduled scans overlay ───────────────────────────────────────────────
    if st.session_state.get("_show_schedules") and _current_user:
        show_scheduled_scans_panel(_current_user, is_paid=_current_user.is_paid)
        st.divider()

    # ── API docs overlay ──────────────────────────────────────────────────────
    if st.session_state.get("_show_api_docs"):
        show_api_docs()
        if st.button("← Close API Docs", key="api_docs_close"):
            st.session_state.pop("_show_api_docs"); st.rerun()
        st.stop()

    # ── Team management overlay ───────────────────────────────────────────────
    if st.session_state.get("_show_team") and _current_user:
        is_ent = _current_user.subscription_tier == "enterprise" or _current_user.is_admin
        show_team_panel(_current_user, is_enterprise=is_ent)
        st.divider()

    # ── Admin panel overlay ───────────────────────────────────────────────────
    if st.session_state.get("_show_admin") and _current_user and _current_user.is_admin:
        from auth.auth_pages import show_admin_panel
        show_admin_panel()
        st.divider()

    # ── Scan action ───────────────────────────────────────────────────────────
    if scan_btn:
        # Prevent double-submit
        if st.session_state.get("_scanning"):
            st.warning("⏳ Scan already running — please wait.")
            st.stop()

        # Quota check before every scan
        if _current_user:
            _q = check_quota(_current_user)
            if not _q.get("allowed"):
                log_action("quota_exceeded", target=url_input.strip(), severity="warning",
                           details={"tier": _current_user.subscription_tier,
                                    "limit": _q.get("limit", 0)})
                show_upgrade_prompt(_current_user.subscription_tier, _q.get("limit", 5))
                st.stop()

        st.session_state["_scanning"] = True

        # Passive Recon: OSINT-only, no API key needed — but demo_mode shows notice
        if scan_mode == "passive":
            if demo_mode:
                st.info(
                    "ℹ️ **Demo Mode is ON** — Passive Recon always runs live (OSINT only, no payloads sent). "
                    "It does not use your Groq API key. Disable Demo Mode only affects Standard/PT scans."
                )
            if not url_input.strip():
                st.warning("Enter a target URL before running Passive Recon.")
            else:
                target = url_input.strip()
                if not target.startswith("http"):
                    target = "https://" + target
                _pr_tool_labels = {
                    "security_txt":       "📝 Security.txt",
                    "robots_sitemap":     "🤖 Robots & Sitemap",
                    "js_secrets":         "⚡ JS Secrets + Source Maps",
                    "wayback":            "🕰️ Wayback + CommonCrawl",
                    "cloud_buckets":      "☁️ Cloud Buckets",
                    "http_methods":       "🌍 HTTP Methods",
                    "email_spoofability": "📧 Email Spoofability",
                    "cve_correlation":    "🔗 CVE Correlation",
                    "meta_leakage":       "🔍 Meta Leakage",
                    "github_leaks":       "🐙 GitHub Leaks",
                    "exposed_files":      "🗂️ Exposed Files",
                    "http_headers":       "🛡️ HTTP Headers",
                    "ssl_passive":        "🔒 SSL/TLS Certificate",
                    "crt_subdomains":     "🔏 CT Log Subdomains",
                    "dns_deep":           "🌐 DNS Deep Analysis",
                }
                _sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪", "INFO": "✅"}

                log_action("scan_start", target=target, details={"mode": "passive"})
                if _current_user:
                    increment_quota(_current_user)

                with st.status("🔵 Running Passive Recon — 15 OSINT tools…", expanded=True) as _ps:
                    st.write(f"🎯 Target: **{target}** — OSINT only, no active probes")
                    try:
                        from tools.passive_recon import run_passive_recon_streaming, _build_passive_result
                        from tools.tech_fingerprinter import fingerprint_technologies
                        _tech = {}
                        try:
                            _tech = fingerprint_technologies(target)
                        except Exception:
                            pass
                        _pr_results: dict = {}
                        _sev_o = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                        for _tn, _tr in run_passive_recon_streaming(target, tech_results=_tech):
                            _pr_results[_tn] = _tr
                            _sev  = _tr.get("severity", "INFO")
                            _icon = _sev_icon.get(_sev, "✅")
                            _lbl  = _pr_tool_labels.get(_tn, _tn)
                            st.write(f"{_icon} **{_lbl}** — {_sev}")
                        _pr = _build_passive_result(target, _pr_results)
                        # Clear old 17-tool results so they don't conflict
                        for _k in ("url_report", "url_meta", "url_av_results", "url_tool_results"):
                            st.session_state.pop(_k, None)
                        st.session_state["url_passive_recon"] = _pr
                        st.session_state["url_target"]        = target
                        st.session_state["url_last_mode"]     = "passive"
                        # Save to scan history
                        try:
                            from scan_history_store import get_store as _gs
                            from scan_history_store import ScanRecord
                            _pr_score_h = max(0, 100
                                - 25 * sum(1 for r in _pr_results.values() if r.get("severity") == "CRITICAL")
                                - 15 * sum(1 for r in _pr_results.values() if r.get("severity") == "HIGH")
                                -  8 * sum(1 for r in _pr_results.values() if r.get("severity") == "MEDIUM"))
                            _pr_grade_h = ("A" if _pr_score_h >= 90 else "B" if _pr_score_h >= 75
                                           else "C" if _pr_score_h >= 60 else "D" if _pr_score_h >= 45 else "F")
                            _gs().save_scan(ScanRecord(
                                scan_id=str(__import__("uuid").uuid4()),
                                url=target,
                                scan_timestamp=_pr.get("scan_timestamp", ""),
                                overall_score=_pr_score_h,
                                overall_grade=_pr_grade_h,
                                category_scores={"passive_recon": _pr_score_h},
                                critical_findings=[
                                    f["finding"][:120] for f in _pr.get("critical_findings", [])[:5]
                                ],
                            ))
                        except Exception as _he:
                            logging.getLogger(__name__).warning("History save failed: %s", _he)
                        _crit = sum(1 for r in _pr_results.values() if r.get("severity") == "CRITICAL")
                        _high = sum(1 for r in _pr_results.values() if r.get("severity") == "HIGH")
                        st.write(f"✅ **Done — {_crit} CRITICAL · {_high} HIGH · {len(_pr_results)} tools**")
                        _ps.update(label=f"✅ Passive Recon complete — {_crit}C / {_high}H", state="complete")
                    except Exception as _exc:
                        logging.getLogger(__name__).error("Passive recon error: %s", _exc, exc_info=True)
                        _ps.update(label="❌ Passive Recon failed", state="error")
                        st.error("Passive Recon failed — check the target URL and try again. Details logged.")
                st.session_state["_scanning"] = False
                st.rerun()
        elif demo_mode:
            # Demo mode — only for Standard / PT modes, not passive
            st.session_state["url_report"]      = _DEMO_URL_REPORT
            st.session_state["url_meta"]        = _DEMO_URL_META
            st.session_state["url_target"]      = _DEMO_TARGET_URL
            st.session_state["url_last_mode"]   = "demo"
            st.session_state.pop("url_passive_recon", None)
            st.rerun()
        elif not url_input.strip():
            st.warning("Enter a target URL first.")
        else:
            from url_scanner_pipeline import run_url_security_audit
            from scan_rate_limiter import get_limiter
            from scan_history_store import get_store
            target = url_input.strip()
            _limiter = get_limiter()
            if not _limiter.acquire(target):
                st.warning(f"⏳ A scan for **{target}** is already running. Please wait.")
            else:
                with st.status("🔍 Running 17-tool security scan…", expanded=True) as status:
                    _prog = st.progress(0, text="Initialising parallel tool pipeline…")
                    st.write("⚡ Launching 17 tools in parallel…")
                    try:
                        _prog.progress(8,  text="🔒 SSL/TLS certificate analysis…")
                        st.write("🔒 SSL/TLS · 📋 Security Headers · 🌐 HTML/JS scanning…")
                        _prog.progress(22, text="🕷️ Crawling links and resources…")
                        st.write("🕷️ Web Crawler · 🔀 CORS/CSP policy · 🌍 DNS records…")
                        _prog.progress(40, text="📂 Checking exposed files and endpoints…")
                        st.write("📂 Exposed files · 📌 HSTS preload · ↪️ Open redirects…")
                        _prog.progress(58, text="🛡️ WAF detection + stealth fingerprint…")
                        st.write("🛡 WAF detection · 📜 Certificate Transparency · 🔌 API Spec…")
                        _prog.progress(72, text="🔓 Port scanning · 🍪 Cookie security…")
                        st.write("🔓 Port scan · 🍪 Cookie audit · ⚡ SPA/Deep JS crawler…")
                        _prog.progress(85, text="🤖 Running AI analysis and generating report…")
                        result = run_url_security_audit(target, scan_auth=_active_scan_auth)
                        _prog.progress(100, text="✅ Scan complete!")
                        st.write("🤖 LLM analysis complete — generating report…")
                        meta = {
                            "overall_grade":   result["overall_grade"],
                            "overall_score":   result["overall_score"],
                            "category_scores": result["category_scores"],
                            "critical_findings": result.get("critical_findings", []),
                        }
                        st.session_state["url_report"]       = result["raw_output"]
                        st.session_state["url_meta"]         = meta
                        st.session_state["url_target"]       = target
                        st.session_state["url_tool_results"] = result.get("tool_results", {})
                        st.session_state["url_last_mode"]    = "standard"
                        st.session_state["url_auth_mode"]    = result.get("auth_mode", "unauthenticated")
                        st.session_state["url_auth_profile"] = result.get("auth_profile", "")
                        st.session_state.pop("url_passive_recon", None)
                        # Auto-save to history
                        try:
                            get_store().save_scan({**meta, "url": target})
                        except Exception as _he:
                            logging.getLogger(__name__).warning("History save failed: %s", _he)

                        # ── PT Mode: auto-run active verification ─────────────
                        if pt_mode_active:
                            st.write("🔬 PT Mode: running active verification probes…")
                            from active_verification_runner import run_active_verification
                            _tool_res = result.get("tool_results", {})
                            _av = run_active_verification(target, _tool_res)
                            st.session_state["url_av_results"] = _av
                            _confirmed = sum(1 for r in _av if r.is_confirmed)
                            _blocked   = sum(1 for r in _av if not r.is_confirmed
                                             and "BLOCKED" in r.status.value)
                            if _confirmed:
                                st.write(f"🔴 {_confirmed} vulnerability(s) CONFIRMED with live probe")
                            elif _av:
                                st.write(f"⚪ {len(_av)} probe(s) sent — no confirmed vulns"
                                         f"{f', {_blocked} WAF-blocked' if _blocked else ''}")
                            else:
                                st.write("✅ No verifiable findings — no probes dispatched")

                        status.update(
                            label=("✅ Scan + Active Verification complete!" if pt_mode_active
                                   else "✅ Scan complete!"),
                            state="complete",
                        )
                    except ValueError:
                        status.update(label="❌ Invalid URL", state="error")
                        st.error("Invalid URL — enter a full URL starting with https:// or http://")
                    except Exception as exc:
                        logging.getLogger(__name__).error("URL scan error: %s", exc, exc_info=True)
                        status.update(label="❌ Scan failed", state="error")
                        _exc_str = str(exc)
                        if "GROQ_QUOTA_EXCEEDED" in _exc_str:
                            st.error(
                                "⏳ **Groq API quota reached** — the free tier allows ~30 requests/minute. "
                                "Please wait 1-2 minutes and scan again."
                            )
                        elif "GROQ_AUTH_ERROR" in _exc_str:
                            st.error(
                                "🔑 **Groq API key missing or invalid** — add a valid `GROQ_API_KEY` "
                                "in Streamlit → Settings → Secrets, then reboot the app."
                            )
                        else:
                            st.error(f"❌ Scan failed — {_exc_str[:200] if _exc_str else 'Unknown error'}. "
                                     "Check the target URL and try again.")
                    finally:
                        _limiter.release(target)
                        st.session_state["_scanning"] = False
                if "url_report" in st.session_state:
                    st.rerun()

    # ── Results ───────────────────────────────────────────────────────────────
    if "url_report" in st.session_state:
        meta   = st.session_state["url_meta"]
        grade  = meta["overall_grade"]
        score  = meta["overall_score"]
        target = st.session_state.get("url_target", "")
        cats   = meta.get("category_scores", {})

        # ── Grade banner ──────────────────────────────────────────────────────
        _render_grade_banner(grade, score, target)

        # ── 17-category score grid ────────────────────────────────────────────
        st.markdown('<div class="section-label">SECURITY SCORES — ALL 17 CATEGORIES</div>',
                    unsafe_allow_html=True)

        # 3-column layout, 6 cards each row
        all_keys = list(_CATEGORY_LABELS.keys())
        rows = [all_keys[i:i+3] for i in range(0, len(all_keys), 3)]
        for row in rows:
            cols = st.columns(3)
            for col, key in zip(cols, row):
                val = cats.get(key, 0)
                col.markdown(_render_score_card(key, val), unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── WAF stealth indicator (shown only when stealth was used) ─────────
        _tool_res = st.session_state.get("url_tool_results", {})
        _waf_res  = _tool_res.get("waf", {})
        if isinstance(_waf_res, dict):
            try:
                _waf_data = json.loads(_waf_res) if isinstance(_waf_res, str) else _waf_res
            except Exception:
                _waf_data = {}
            if _waf_data.get("stealth_used"):
                st.markdown("""
<div style="background:#071a10;border:1px solid #10b981;border-left:4px solid #10b981;
            border-radius:6px;padding:10px 16px;margin:12px 0;display:flex;
            align-items:center;gap:10px">
  <span style="font-size:1.1rem">🕵️</span>
  <div>
    <span style="color:#10b981;font-weight:700;font-size:0.8rem;
                 font-family:'Courier New',monospace;letter-spacing:.08em">
      STEALTH MODE ACTIVATED
    </span>
    <span style="color:#475569;font-size:0.78rem;margin-left:8px">
      — WAF blocked standard scanner UA · browser TLS fingerprint used for WAF fingerprinting
    </span>
  </div>
</div>""", unsafe_allow_html=True)

        # ── TraffixNet-style inline priority findings ─────────────────────────
        st.markdown('<div class="section-label" style="margin-top:8px">FINDINGS</div>',
                    unsafe_allow_html=True)
        _render_inline_findings(meta.get("critical_findings", []))

        # ── Full report — organized by section ────────────────────────────────
        st.markdown('<div class="section-label" style="margin-top:12px">FULL REPORT — BY CATEGORY</div>',
                    unsafe_allow_html=True)
        _render_report_sections(st.session_state["url_report"])

        st.divider()

        # ── Active Verification results ────────────────────────────────────────
        st.divider()
        st.markdown('<div class="section-label">ACTIVE VERIFICATION — LIVE PROBE RESULTS</div>',
                    unsafe_allow_html=True)

        if demo_mode:
            st.markdown("""
<div class="mode-badge-locked">
🔒 ACTIVE VERIFICATION UNAVAILABLE IN DEMO MODE<br>
<span style="font-weight:400;font-size:0.72rem">Switch to Live Mode and enable PT Mode in the sidebar to get Confirmed PoC results.</span>
</div>""", unsafe_allow_html=True)

        elif not pt_mode_active:
            st.markdown("""
<div class="mode-badge-standard">
🟢 STANDARD SCAN MODE — No live probes sent<br>
<span style="font-weight:400;color:#94a3b8;font-size:0.72rem">
Enable <b>Active PT Mode</b> in the sidebar (after confirming target ownership) to automatically
confirm vulnerabilities with non-destructive canary probes and get curl PoC reproduction steps.
</span>
</div>""", unsafe_allow_html=True)

        else:
            # PT mode — show auto-run results (or a spinner if not yet run)
            _av = st.session_state.get("url_av_results")
            if _av is None:
                st.info("Active verification will run automatically after the next scan.")
            elif not _av:
                st.success("✅ No verifiable findings detected — no probes dispatched.")
            else:
                _confirmed = [r for r in _av if r.is_confirmed]
                _blocked   = [r for r in _av if not r.is_confirmed
                               and "BLOCKED" in r.status.value]
                _unknown   = [r for r in _av
                               if r not in _confirmed and r not in _blocked]
                _mc1, _mc2, _mc3 = st.columns(3)
                _mc1.metric("🔴 Confirmed PoC",  len(_confirmed))
                _mc2.metric("🟡 WAF Blocked",    len(_blocked))
                _mc3.metric("⚪ Inconclusive",   len(_unknown))

                for r in _av:
                    _cls = ("verify-confirmed" if r.is_confirmed else
                            "verify-blocked" if "BLOCKED" in r.status.value
                            else "verify-unknown")
                    _icon = "🔴" if r.is_confirmed else "🟡" if "BLOCKED" in r.status.value else "⚪"
                    st.markdown(
                        f'<div class="verify-row {_cls}">'
                        f'{_icon} <b>{r.vuln_type.value}</b>'
                        f'&nbsp; · &nbsp;Confidence: <b>{int(r.confidence_score * 100)}%</b>'
                        f'&nbsp; · &nbsp;{r.status.value}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    if r.is_confirmed and r.reproduction_steps:
                        with st.expander(f"🔗 Confirmed PoC — {r.vuln_type.value}"):
                            st.markdown('<div class="poc-box">', unsafe_allow_html=True)
                            st.markdown(
                                f'<div class="poc-box-title">🔴 Confirmed — {r.vuln_type.value}'
                                f' ({int(r.confidence_score * 100)}% confidence)</div>',
                                unsafe_allow_html=True,
                            )
                            for step in r.reproduction_steps:
                                st.markdown(f'<div class="poc-step">→ {step}</div>',
                                            unsafe_allow_html=True)
                            st.markdown('</div>', unsafe_allow_html=True)
                            if r.raw_poc_request:
                                st.code(r.raw_poc_request.to_curl(), language="bash")

        # ── PDF download ──────────────────────────────────────────────────────
        st.divider()
        st.markdown('<div class="section-label">EXPORT</div>', unsafe_allow_html=True)
        try:
            from cyber_shield_pdf_app import create_pdf
            pdf_bytes = create_pdf(st.session_state["url_report"])
            st.download_button(
                label="📥  Download Full Report as PDF",
                data=pdf_bytes,
                file_name=f"cyber_shield_report_{grade}_{score}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception:
            st.warning("PDF export unavailable — the report above is the full output.")

    # ── Passive Recon Results (shown when passive mode was used) ─────────────
    _pr_data = st.session_state.get("url_passive_recon")
    if _pr_data:
        _pr_target  = st.session_state.get("url_target", "")
        _pr_tools   = _pr_data.get("tools", {})
        _pr_overall = _pr_data.get("overall_severity", "INFO")
        _pr_crits   = _pr_data.get("critical_findings", [])

        _sev_colors = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#f59e0b",
                       "LOW":"#60a5fa","INFO":"#475569"}
        _sev_cls    = {"CRITICAL":"pr-card-critical","HIGH":"pr-card-high",
                       "MEDIUM":"pr-card-medium","LOW":"pr-card-low","INFO":"pr-card-info"}
        _sev_order  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

        # Calculate numeric score based on severities found
        _sev_penalty = {"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":0}
        _pr_score = 100
        for _tk, _tv in _pr_tools.items():
            _pr_score -= _sev_penalty.get(_tv.get("severity","INFO"), 0)
        _pr_score = max(0, _pr_score)
        _pr_grade = ("A" if _pr_score>=90 else "B" if _pr_score>=75 else
                     "C" if _pr_score>=60 else "D" if _pr_score>=45 else "F")
        _grade_color = {"A":"#10b981","B":"#60a5fa","C":"#f59e0b","D":"#f97316","F":"#ef4444"}
        _gc = _grade_color.get(_pr_grade,"#60a5fa")
        _ov_color = _sev_colors.get(_pr_overall, "#60a5fa")

        _n_crit = sum(1 for t in _pr_tools.values() if t.get("severity")=="CRITICAL")
        _n_high = sum(1 for t in _pr_tools.values() if t.get("severity")=="HIGH")
        _n_med  = sum(1 for t in _pr_tools.values() if t.get("severity")=="MEDIUM")

        st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e3a5f;border-left:4px solid {_ov_color};
            border-radius:10px;padding:18px 24px;margin:20px 0 8px">
  <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
    <div style="text-align:center;min-width:70px">
      <div style="font-size:2.2rem;font-weight:900;color:{_gc};line-height:1">{_pr_score}</div>
      <div style="font-size:0.7rem;color:#475569;letter-spacing:.05em">SECURITY SCORE</div>
      <div style="font-size:1.1rem;font-weight:700;color:{_gc}">Grade {_pr_grade}</div>
    </div>
    <div style="flex:1">
      <div style="color:#e2e8f0;font-size:1.1rem;font-weight:700">
        Passive Recon Results — {_pr_target}
      </div>
      <div style="color:#475569;font-size:0.75rem;margin-top:4px;font-family:'JetBrains Mono',monospace">15 OSINT tools · Overall severity: <span style="color:{_ov_color};font-weight:700">{_pr_overall}</span> · <span style="color:#64748b">{_pr_data.get('scan_timestamp','')[:16].replace('T',' ')} UTC</span></div>
      <div style="color:#64748b;font-size:0.7rem;margin-top:3px">📊 100{f' − {_n_crit}×25(C)' if _n_crit else ''}{f' − {_n_high}×15(H)' if _n_high else ''}{f' − {_n_med}×8(M)' if _n_med else ''} = <b style="color:{_gc}">{_pr_score}/100</b></div>
      <div style="display:flex;gap:12px;margin-top:8px;flex-wrap:wrap">
        <span style="background:#3f0000;color:#ef4444;border:1px solid #ef444440;
                     padding:2px 10px;border-radius:4px;font-size:0.75rem;font-weight:700">
          🔴 {_n_crit} CRITICAL
        </span>
        <span style="background:#3f1f00;color:#f97316;border:1px solid #f9731640;
                     padding:2px 10px;border-radius:4px;font-size:0.75rem;font-weight:700">
          🟠 {_n_high} HIGH
        </span>
        <span style="background:#3f2f00;color:#f59e0b;border:1px solid #f59e0b40;
                     padding:2px 10px;border-radius:4px;font-size:0.75rem;font-weight:700">
          🟡 {_n_med} MEDIUM
        </span>
      </div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

        # ── Export / Download ──────────────────────────────────────────────
        def _build_html_report(pr_data: dict, target: str, score: int, grade: str) -> str:
            _ts  = pr_data.get("scan_timestamp", "")[:16].replace("T", " ")
            _tools = pr_data.get("tools", {})
            _sev_col = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b",
                        "LOW": "#3b82f6", "INFO": "#475569"}
            rows = ""
            _so = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            for _tn, _tr in sorted(_tools.items(), key=lambda kv: _so.get(kv[1].get("severity","INFO"), 4)):
                _sv  = _tr.get("severity", "INFO")
                _clr = _sev_col.get(_sv, "#475569")
                _fi  = (_tr.get("finding") or "No issues detected.").replace("<","&lt;").replace(">","&gt;")
                rows += (f"<tr><td><b>{_tn.replace('_',' ').title()}</b></td>"
                         f"<td style='color:{_clr};font-weight:700'>{_sv}</td>"
                         f"<td>{_fi}</td></tr>")
            return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>AI Cyber Shield — Passive Recon Report: {target}</title>
<style>body{{font-family:Inter,Segoe UI,sans-serif;background:#0d1117;color:#e2e8f0;margin:40px}}
h1{{color:#60a5fa}}h2{{color:#94a3b8;font-size:.9rem;margin:0 0 20px}}
.score{{font-size:3rem;font-weight:900;color:{'#22c55e' if score>=75 else '#f59e0b' if score>=50 else '#ef4444'}}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th{{background:#1e293b;padding:10px;text-align:left;font-size:.8rem;color:#94a3b8}}
td{{padding:9px 10px;border-bottom:1px solid #1e293b;font-size:.82rem;vertical-align:top}}
</style></head><body>
<h1>⬡ AI Cyber Shield — Passive Recon Report</h1>
<h2>Target: {target} &nbsp;|&nbsp; Scan: {_ts} UTC &nbsp;|&nbsp; Tools: 15 OSINT</h2>
<div class="score">{score}/100</div>
<div style="font-size:1.5rem;color:#94a3b8">Grade {grade}</div>
<table><thead><tr><th>Tool</th><th>Severity</th><th>Finding</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="color:#475569;font-size:.75rem;margin-top:30px">
Generated by AI Cyber Shield v6 — For authorized security testing only
</p></body></html>"""

        _html_report = _build_html_report(_pr_data, _pr_target, _pr_score, _pr_grade)
        _dl_col1, _dl_col2 = st.columns([2, 1])
        _dl_col2.download_button(
            label="📥 Download Report (HTML)",
            data=_html_report.encode("utf-8"),
            file_name=f"passive_recon_{_pr_target.replace('https://','').replace('/','_')}.html",
            mime="text/html",
            use_container_width=True,
        )

        # ── Bug bounty contact (security.txt) ─────────────────────────────
        _sec_txt = _pr_tools.get("security_txt", {})
        if _sec_txt.get("has_security_txt"):
            _contacts = _sec_txt.get("contacts", [])
            _bb_urls  = _sec_txt.get("bug_bounty_urls", [])
            _has_bb   = _sec_txt.get("has_bug_bounty", False)
            st.markdown(f"""
<div class="bb-card">
  <div class="bb-card-title">
    {"🎯 BUG BOUNTY PROGRAM DETECTED!" if _has_bb else "📝 security.txt FOUND"}
  </div>
  {"".join(f'<div class="bb-card-item">📧 {c}</div>' for c in _contacts[:3])}
  {"".join(f'<div class="bb-card-item">🔗 {u}</div>' for u in _bb_urls[:2])}
</div>""", unsafe_allow_html=True)

        # ── Tool-by-tool results ───────────────────────────────────────────
        _TOOL_META = {
            "security_txt":       ("📝", "Security.txt / Bug Bounty"),
            "exposed_files":      ("🗂️", "Exposed Sensitive Files"),
            "http_headers":       ("🛡️", "HTTP Security Headers"),
            "robots_sitemap":     ("🤖", "robots.txt / Sitemap Analysis"),
            "js_secrets":         ("⚡", "JavaScript Secrets + Source Maps"),
            "wayback":            ("🕰️", "Wayback Machine Exposure"),
            "cloud_buckets":      ("☁️", "Cloud Bucket Detection"),
            "http_methods":       ("🔧", "HTTP Methods Check"),
            "email_spoofability": ("📧", "Email Spoofability (DMARC/SPF)"),
            "cve_correlation":    ("🔗", "CVE Correlation (55 CVEs)"),
            "meta_leakage":       ("🔍", "Error Page Info Leakage"),
            "github_leaks":       ("🐙", "GitHub Public Code Leaks"),
            "crt_subdomains":     ("🔏", "CT Logs — Subdomain Enumeration"),
            "ssl_passive":        ("🔒", "SSL/TLS Certificate Analysis"),
            "dns_deep":           ("🌐", "DNS Deep Analysis"),
        }

        # Plain-language "what it means / what to report" per tool
        _TOOL_EXPLAIN = {
            "cloud_buckets": {
                "what": "נמצא Storage Bucket ציבורי — כל אחד ברשת יכול לגשת לקבצים שם. "
                        "אם ה-bucket מאפשר Directory Listing, ניתן לראות ולהוריד את כל הקבצים.",
                "report": "Cloud storage bucket is publicly accessible — potential unauthorized "
                          "data exposure or directory listing vulnerability.",
            },
            "js_secrets": {
                "what": "נמצאו מפתחות API, סיסמאות, או tokens בתוך קוד JavaScript ציבורי. "
                        "כל מי שביקר באתר יכול לראות ולנצל אותם.",
                "report": "Hardcoded secrets (API keys / credentials) found in publicly accessible "
                          "JavaScript files — immediate rotation required.",
            },
            "email_spoofability": {
                "what": "הגדרות SPF/DMARC חלשות מאפשרות לתוקף לשלוח מיילים כאילו הם מגיעים "
                        "מהדומיין הרשמי של האתר — מצוין לפישינג.",
                "report": "Domain is vulnerable to email spoofing — missing or weak "
                          "DMARC/SPF/DKIM configuration.",
            },
            "robots_sitemap": {
                "what": "קובץ robots.txt חושף נתיבים פנימיים שהמפתחים לא רצו שמנועי חיפוש יאנדקו. "
                        "לפעמים אלה עמודי ניהול, גיבויים, או ממשקי API.",
                "report": "robots.txt reveals sensitive internal paths that may expose admin "
                          "panels, backup files, or hidden API endpoints.",
            },
            "wayback": {
                "what": "ה-Wayback Machine שמר URL-ים ישנים שעוד זמינים ועשויים להכיל "
                        "נתונים רגישים, קבצי config ישנים, או גרסאות לא-מעודכנות.",
                "report": "Historical URLs found in Wayback Machine that may expose "
                          "sensitive data or outdated vulnerable software versions.",
            },
            "cve_correlation": {
                "what": "הטכנולוגיות שהתגלו באתר קשורות לפגיעויות CVE ידועות. "
                        "גרסה ישנה של ספריה או framework יכולה לאפשר מתקפה ממוקדת.",
                "report": "Detected technology versions correlate with known CVEs — "
                          "immediate patching/upgrade recommended.",
            },
            "meta_leakage": {
                "what": "דפי שגיאה או נתיבי debug חושפים מידע פנימי: גרסת PHP/Framework, "
                        "נתיבי קבצים בשרת, stack traces — מידע שעוזר לתוקף למפות את המערכת.",
                "report": "Error pages / debug endpoints expose internal server information "
                          "(stack traces, file paths, framework versions).",
            },
            "github_leaks": {
                "what": "קוד הקשור לדומיין זה נמצא ב-GitHub בצורה ציבורית. "
                        "יכול להכיל credentials, לוגים, ארכיטקטורה פנימית, או סיסמאות ישנות.",
                "report": "Source code or credentials related to this domain found "
                          "in public GitHub repositories.",
            },
            "http_methods": {
                "what": "שרת מאפשר methods מסוכנים כמו TRACE (מאפשר XST attack) "
                        "או PUT/DELETE (מאפשר שינוי תוכן בשרת).",
                "report": "Server allows dangerous HTTP methods (TRACE/PUT/DELETE) "
                          "that could be exploited for XST or unauthorized file manipulation.",
            },
            "exposed_files": {
                "what": "קבצים רגישים נגישים לכולם ברשת — קבצי config עם סיסמאות, "
                        "קוד מקור, מסדי נתונים, או קצות-קצה של ניהול.",
                "report": "Sensitive files publicly accessible (/.env, /.git, /phpinfo.php, "
                          "/swagger.json etc.) — direct credential or source code exposure.",
            },
            "http_headers": {
                "what": "כותרות HTTP חסרות או שגויות מאפשרות מתקפות כמו XSS, Clickjacking, "
                        "CSRF, גניבת session — כל אתר מקצועי חייב לכלול CSP, HSTS, X-Frame-Options.",
                "report": "HTTP security headers misconfigured — missing CSP/HSTS/X-Frame-Options "
                          "leaves site vulnerable to XSS, clickjacking, and session theft.",
            },
            "crt_subdomains": {
                "what": "Certificate Transparency logs מגלים כל subdomain שאי פעם קיבל SSL certificate. "
                        "subdomain כמו jenkins./staging./admin. = attack surface נסתר שלא רואים דרך האתר הראשי.",
                "report": "Certificate Transparency logs reveal internal/staging subdomains — "
                          "high-value targets: admin panels, development environments, internal APIs.",
            },
            "ssl_passive": {
                "what": "ניתוח תעודת SSL/TLS — גרסת TLS ישנה (1.0/1.1), תעודה פגה, cipher חלש, "
                        "או חתימה עצמית = חשיפת תעבורה או אזהרת דפדפן לכל מבקר.",
                "report": "SSL/TLS issues found — expired or soon-expiring certificate, "
                          "deprecated TLS version, or weak cipher suite. All MITM-exploitable.",
            },
            "dns_deep": {
                "what": "ניתוח DNS מעמיק חושף: ספק מייל, ספקי DNS, מדיניות CAA, "
                        "zone transfer פתוח (=כל רשומות ה-DNS זמינות לתוקף), ושירותים רשומים.",
                "report": "DNS analysis reveals mail infrastructure, nameserver provider, CAA policy gaps, "
                          "and registered third-party services. Zone transfer if open is CRITICAL.",
            },
            "security_txt": {
                "what": ("נמצא security.txt עם ערוץ דיווח — טוב לך, תוכל לשלוח ישירות."
                         if _pr_tools.get("security_txt", {}).get("has_security_txt")
                         else "לא נמצא קובץ security.txt — האתר לא פרסם ערוץ רשמי לדיווח על בעיות אבטחה. "
                              "תצטרך לחפש איש קשר ב-LinkedIn/אתר החברה."),
                "report": ("security.txt found — use the contact/Bug-Bounty URL listed."
                           if _pr_tools.get("security_txt", {}).get("has_security_txt")
                           else "No security.txt found — site has no official vulnerability "
                                "disclosure channel (RFC 9116). Recommend adding one."),
            },
        }

        st.markdown('<div class="pr-section-title">🔵 PASSIVE RECON — RESULTS (מיון לפי חומרה)</div>',
                    unsafe_allow_html=True)

        # Sort tools: CRITICAL first → HIGH → MEDIUM → LOW → INFO
        _sorted_tools = sorted(
            _TOOL_META.items(),
            key=lambda kv: _sev_order.get(_pr_tools.get(kv[0], {}).get("severity","INFO"), 99)
        )

        for tool_key, (icon, label) in _sorted_tools:
            tr = _pr_tools.get(tool_key)          # None = tool not in this scan
            _not_in_scan = tr is None
            tr = tr or {}
            sev     = tr.get("severity", "INFO")
            _raw_finding = tr.get("finding", "")
            if _not_in_scan:
                finding = "🔄 New tool — click Clear then Re-run to include this tool."
                sev     = "INFO"
            elif _raw_finding:
                finding = _raw_finding
            elif tr.get("status") == "completed":
                finding = "✅ No issues detected — tool completed successfully."
            elif tr.get("status") in ("timeout", "error"):
                finding = f"⚠️ {tr.get('status','').title()}: {tr.get('error', 'check network connection')}."
            else:
                finding = "⏳ Tool did not produce output."
            status  = tr.get("status", "—")
            cls     = _sev_cls.get(sev, "pr-card-info")
            clr     = _sev_colors.get(sev, "#475569")

            _explain    = _TOOL_EXPLAIN.get(tool_key, {})
            _what_html  = (f'<div style="color:#94a3b8;font-size:0.78rem;margin-top:6px">'
                           f'💡 <b>מה זה אומר:</b> {_explain["what"]}</div>'
                           if _explain and sev in ("CRITICAL","HIGH","MEDIUM") else "")
            _report_html= (f'<div style="color:#60a5fa;font-size:0.78rem;margin-top:4px">'
                           f'📋 <b>מה לדווח:</b> {_explain["report"]}</div>'
                           if _explain and sev in ("CRITICAL","HIGH","MEDIUM") else "")
            st.markdown(f"""
<div class="pr-card {cls}">
  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
    <span style="font-size:1.1rem">{icon}</span>
    <div class="pr-tool-name">{label}</div>
    <span class="badge badge-{'critical' if sev=='CRITICAL' else 'high' if sev=='HIGH' else 'medium' if sev=='MEDIUM' else 'low' if sev=='LOW' else 'info'}"
          style="margin-left:auto">{sev}</span>
  </div>
  <div class="pr-finding">{finding}</div>
  {_what_html}
  {_report_html}
  {f'<div class="pr-meta" style="margin-top:6px;color:#ef4444">⚠ status: {status}</div>' if status not in ("completed","—","") else ""}
</div>""", unsafe_allow_html=True)

            # Expander with details for high-value tools
            _detail_keys = {
                "js_secrets":         ("secrets_found",  "🔑 Secrets found"),
                "cloud_buckets":      ("open_buckets",   "☁️ Open buckets"),
                "wayback":            ("interesting_urls","🕰️ Historical endpoints"),
                "robots_sitemap":     ("interesting_paths","🚩 Sensitive paths"),
                "cve_correlation":    ("matched_cves",   "🔗 Matched CVEs"),
                "meta_leakage":       ("disclosures",    "🔍 Disclosures"),
                "github_leaks":       ("repos_found",    "🐙 Repositories"),
                "exposed_files":      ("exposed_files",           "🗂️ Exposed files"),
                "http_headers":       ("issues",                  "🛡️ Header issues"),
                "crt_subdomains":     ("interesting_subdomains",  "🔏 High-value subdomains"),
                "ssl_passive":        ("issues",                  "🔒 TLS issues"),
                "dns_deep":           ("issues",                  "🌐 DNS issues"),
                "email_spoofability": None,
            }
            if tool_key in _detail_keys and sev in ("CRITICAL", "HIGH", "MEDIUM"):
                detail_info = _detail_keys[tool_key]
                with st.expander(f"↳ Details — {label}"):
                    if detail_info is None:
                        # Email spoofability — full structured data + BIMI + services
                        _sp_c1, _sp_c2 = st.columns(2)
                        _sp_c1.markdown(f"""
| Field | Value |
|-------|-------|
| SPF | `{tr.get('spf_strength','?')}` |
| DMARC policy | `{tr.get('dmarc_policy','?')}` |
| DMARC pct | `{tr.get('dmarc_pct','?')}%` |
| DKIM selectors | `{', '.join(tr.get('dkim_selectors',[]) or ['none found'])}` |
| Can spoof? | **{'⚠️ YES' if tr.get('can_spoof') else '✅ NO'}** |
| BIMI record | {'✅ Yes' if tr.get('has_bimi') else '❌ No'} |
""")
                        _svcs = tr.get("registered_services", [])
                        if _svcs:
                            _sp_c2.markdown("**Services identified from TXT records:**")
                            for _svc in _svcs:
                                _sp_c2.markdown(f"- 🔍 {_svc}")
                        else:
                            _sp_c2.caption("No third-party services detected via TXT records.")
                    else:
                        items_key, items_label = detail_info
                        items = tr.get(items_key, [])
                        # Extra: source maps for JS secrets tool
                        if tool_key == "js_secrets":
                            sm = tr.get("source_maps_found", [])
                            if sm:
                                st.error(f"🗺️ **Source Maps exposed ({len(sm)}) — full original source code accessible:**")
                                for smu in sm[:5]:
                                    st.markdown(f"- 🔴 [`{smu}`]({smu})")
                        # Extra: cloud bucket details
                        if tool_key == "cloud_buckets":
                            listing = tr.get("directory_listing_buckets", [])
                            if listing:
                                st.error(f"📂 **Directory Listing ENABLED on {len(listing)} bucket(s):**")
                                for b in listing:
                                    st.markdown(f"- 🔴 [`{b['url']}`]({b['url']}) ({b['provider']})")
                            takeover = tr.get("takeover_candidates", [])
                            if takeover:
                                st.warning(f"🎯 **Bucket Takeover possible ({len(takeover)}):**")
                                for b in takeover:
                                    st.markdown(f"- 🟠 `{b['url']}` ({b['provider']}) — "
                                                "bucket name unregistered, register it to take over")
                        # Exposed files: show path, severity, why
                        if tool_key == "exposed_files" and items:
                            st.markdown(f"**{items_label} ({len(items)}):**")
                            for item in items[:20]:
                                sev_i = item.get("severity","")
                                icon_i = "🔴" if sev_i=="CRITICAL" else "🟠" if sev_i=="HIGH" else "🟡"
                                st.markdown(
                                    f"{icon_i} **[{item['path']}]({item['full_url']})** "
                                    f"`{sev_i}` — {item.get('why','')}"
                                )
                        # HTTP headers: show each issue as a table row
                        elif tool_key == "http_headers" and items:
                            st.markdown(f"**{items_label} ({len(items)}):**")
                            score = tr.get("header_score", "?")
                            grade = tr.get("header_grade", "?")
                            st.markdown(f"Header Security Grade: **{grade}** ({score}/100)")
                            for item in items:
                                sev_i = item.get("severity","")
                                icon_i = "🔴" if sev_i=="CRITICAL" else "🟠" if sev_i=="HIGH" else "🟡" if sev_i=="MEDIUM" else "⚪"
                                st.markdown(
                                    f"{icon_i} `{item['header']}` **{sev_i}** — "
                                    f"{item['issue']}  \n"
                                    f"  ✅ *Fix: {item['fix']}*"
                                )
                        # CT subdomains
                        elif tool_key == "crt_subdomains" and items:
                            total = tr.get("total_subdomains", len(items))
                            st.markdown(f"**🔏 High-value subdomains ({len(items)} of {total} total):**")
                            for sd in items[:20]:
                                icon_s = "🔴" if re.search(r'(jenkins|admin|internal|corp)', sd.get("label","")) else "🟠"
                                st.markdown(
                                    f"{icon_s} `{sd['subdomain']}` — "
                                    f"cert issued {sd.get('not_before','?')}"
                                )
                            if total > 20:
                                st.caption(f"+ {total - 20} more subdomains in CT logs")
                        # SSL/TLS issues
                        elif tool_key == "ssl_passive" and items:
                            _days = tr.get("days_until_expiry")
                            _tls  = tr.get("tls_version", "?")
                            _cipher = tr.get("cipher_suite", "?")
                            _issuer = tr.get("cert_issuer", "?")
                            st.markdown(f"**TLS {_tls}** · Cipher: `{_cipher}` · Issuer: {_issuer}"
                                        + (f" · Expires in **{_days} days**" if _days is not None else ""))
                            st.markdown(f"**{items_label} ({len(items)}):**")
                            for issue in items:
                                _si = issue.get("severity","")
                                _ii = "🔴" if _si=="CRITICAL" else "🟠" if _si=="HIGH" else "🟡"
                                st.markdown(f"{_ii} **{issue['check']}** `{_si}` — {issue['detail']}")
                            _sans = tr.get("san_domains", [])
                            if _sans:
                                st.caption(f"SANs: {', '.join(_sans[:6])}" + (" +" if len(_sans) > 6 else ""))
                        # DNS deep issues
                        elif tool_key == "dns_deep" and items:
                            _c1, _c2 = st.columns(2)
                            _mp = tr.get("mail_providers", [])
                            _ns = tr.get("ns_provider", "?")
                            _sv = tr.get("txt_services", [])
                            _c1.markdown(f"**Mail:** {', '.join(_mp) or 'Unknown'}")
                            _c1.markdown(f"**DNS Hosting:** {_ns}")
                            _c2.markdown(f"**Services:** {', '.join(_sv[:4]) or 'None found'}")
                            if tr.get("soa_email"):
                                _c2.markdown(f"**SOA Email:** `{tr['soa_email']}`")
                            if tr.get("zone_transfer_possible"):
                                st.error("⚠️ **AXFR Zone Transfer is OPEN** — ALL DNS records publicly downloadable!")
                            if not tr.get("caa_records"):
                                st.warning("No CAA records — any CA can issue SSL certs for this domain.")
                            st.markdown(f"**{items_label} ({len(items)}):**")
                            for issue in items:
                                _si = issue.get("severity","")
                                _ii = "🔴" if _si=="CRITICAL" else "🟠" if _si=="HIGH" else "🟡" if _si=="MEDIUM" else "⚪"
                                st.markdown(f"{_ii} **{issue['check']}** — {issue['detail']}")
                        # Robots accessible paths
                        elif tool_key == "robots_sitemap" and items:
                            st.markdown(f"**{items_label} ({len(items)}):**")
                            for item in items[:15]:
                                access_icon = "🔴 ACCESSIBLE" if item.get("accessible") else f"⚫ {item.get('http_status','?')}"
                                st.markdown(
                                    f"- {access_icon} `{item['path']}` "
                                    f"([{item['full_url']}]({item['full_url']})) — {item.get('source','')}"
                                )
                        elif items:
                            st.markdown(f"**{items_label} ({len(items)}):**")
                            for item in items[:15]:
                                if isinstance(item, dict):
                                    # JS secrets
                                    if "type" in item and "preview" in item:
                                        sev_i = item.get("severity", "")
                                        st.markdown(
                                            f"- `{item['type']}` — `{item['preview']}` "
                                            f"({item.get('source','')[:50]}) **{sev_i}**"
                                        )
                                    # CVEs
                                    elif "cve" in item:
                                        st.markdown(
                                            f"- **{item['cve']}** ({item['severity']}) — "
                                            f"{item['tech']} {item.get('detected_version','')} — "
                                            f"{item['desc']}  \n"
                                            f"  🔧 *{item.get('fix','')}*"
                                        )
                                    # Cloud buckets (open)
                                    elif "url" in item and "provider" in item:
                                        icon_b = "🔴 PUBLIC" if item.get("public") else "🟡 EXISTS"
                                        listing_tag = " 📂 DIRECTORY LISTING!" if item.get("listing_enabled") else ""
                                        st.markdown(
                                            f"- {icon_b} [`{item['url']}`]({item['url']}) "
                                            f"({item['provider']}){listing_tag}"
                                        )
                                    # Generic dict
                                    else:
                                        url_v = item.get("url", item.get("path", item.get("full_url", "")))
                                        st.markdown(f"- `{url_v}`")
                                else:
                                    st.markdown(f"- `{item}`")
                        else:
                            st.info("No specific items to display.")

        # ── Responsible Disclosure email template ──────────────────────────
        if _pr_crits:
            st.markdown('<div class="pr-section-title">📨 RESPONSIBLE DISCLOSURE — EMAIL TEMPLATE</div>',
                        unsafe_allow_html=True)
            st.info(
                "⚠️ **תשומת לב:** המערכת לא שולחת שום מייל אוטומטית! "
                "זוהי תבנית מוכנה בלבד — העתק אותה ושלח ידנית לאיש הקשר של האתר. "
                "לפני שליחה, ודא שיש לך ממצאים אמיתיים ומוכחים."
            )
            _domain = _pr_target.replace("https://","").replace("http://","").split("/")[0]
            _domain = re.sub(r'^www\.', '', _domain)  # strip www from contact domain
            _contact = (_sec_txt.get("contacts", ["security@" + _domain]) or ["security@" + _domain])[0]
            _findings_list = "\n".join(
                f"  {i+1}. [{f['severity']}] {f['tool'].replace('_',' ').title()}: {f['finding'][:120]}"
                for i, f in enumerate(_pr_crits[:5])
            )
            _email_template = f"""Subject: [Security Research] Responsible Disclosure — {_domain}

To: {_contact}

Dear {_domain} Security Team,

I am an independent security researcher conducting passive reconnaissance
of publicly available information about {_domain}.

During my research I discovered the following potential security issues:

{_findings_list}

All findings were discovered through passive OSINT techniques only —
no active exploitation, no intrusion, no data access.

I am reporting these findings in good faith under responsible disclosure
principles (ISO/IEC 29147). I request 90 days to address these issues
before any public disclosure.

Please confirm receipt of this report and provide a timeline for remediation.

Regards,
[Your Name]
[Your Email]
[PGP Key — optional]

---
Discovered using: AI Cyber Shield v6 — Passive Recon Module
Scan date: passive OSINT only — no active testing performed"""

            st.markdown(f'<div class="rd-email">{_email_template}</div>',
                        unsafe_allow_html=True)
            st.download_button(
                label="📥  Download Disclosure Email (.txt)",
                data=_email_template,
                file_name=f"responsible_disclosure_{_domain}.txt",
                mime="text/plain",
                use_container_width=True,
            )


# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — Code Scanner
# ═════════════════════════════════════════════════════════════════════════════

with tab_code:
    st.markdown('<div class="section-label">SOURCE CODE</div>', unsafe_allow_html=True)

    _crewai_available = True
    try:
        from cyber_shield_pdf_app import _DEMO_REPORT
        from crew_pipeline_with_alerts import run_security_audit
    except Exception as _crew_err:
        _crewai_available = False
        import logging as _logging
        _logging.getLogger(__name__).warning("crewai unavailable: %s", _crew_err)

    code_input = st.text_area(
        "Paste source code",
        height=220,
        placeholder="def get_user(uid):\n    query = 'SELECT * FROM users WHERE id=' + uid\n    ...",
        label_visibility="collapsed",
    )

    # Live input sanitiser warning
    if code_input.strip():
        from tools.input_sanitizer import sanitize_input
        pre = sanitize_input(code_input)
        if pre.is_high_risk:
            st.warning(f"⚠️ Suspicious input detected (risk {pre.risk_score}/100): "
                       f"{', '.join(pre.detections)}")
        elif pre.risk_score > 0:
            st.caption(f"ℹ️ Minor risk signals: score {pre.risk_score}/100")

    col2_run, col2_clear, _ = st.columns([3, 1, 4])
    run2_btn   = col2_run.button("🚀  Analyse Code", type="primary",
                                  use_container_width=True, key="code_run")
    clear2_btn = col2_clear.button("✕ Clear", use_container_width=True, key="code_clear")

    if clear2_btn:
        for k in ("code_report", "code_meta"):
            st.session_state.pop(k, None)
        st.rerun()

    if run2_btn:
        if not _crewai_available:
            st.error("AI code analysis unavailable on this platform (Python 3.14 / crewai incompatibility). Use URL scanning instead.")
            st.stop()
        if demo_mode:
            st.session_state["code_report"] = _DEMO_REPORT
            st.session_state["code_meta"]   = {
                "risk_score": 0, "detections": [],
                "high_sev_findings": [
                    "#### [CRITICAL] VID-1: SQL Injection",
                    "#### [HIGH] VID-2: OS Command Injection",
                ],
                "slack_alert_sent": False,
            }
            st.rerun()
        elif not code_input.strip():
            st.warning("Paste source code first.")
        else:
            with st.status("🕵️ Running static analysis…", expanded=True) as status:
                try:
                    st.write("⚡ Bandit SAST engine…")
                    st.write("🔍 Semgrep rules (OWASP Top 10)…")
                    st.write("🤖 AI vulnerability analyst…")
                    result_dict = run_security_audit(code_input)
                    st.session_state["code_report"] = result_dict["raw_output"]
                    st.session_state["code_meta"]   = {
                        "risk_score":        result_dict["risk_score"],
                        "detections":        result_dict["detections"],
                        "high_sev_findings": result_dict["high_sev_findings"],
                        "slack_alert_sent":  result_dict["slack_alert_sent"],
                    }
                    status.update(label="✅ Analysis complete!", state="complete")
                except ValueError:
                    status.update(label="❌ Invalid input", state="error")
                    st.error("Invalid input — check that the code or URL is correctly formatted.")
                except Exception as exc:
                    logging.getLogger(__name__).error("Code scan error: %s", exc, exc_info=True)
                    status.update(label="❌ Analysis failed", state="error")
                    st.error("Analysis failed — check the input and try again. Details logged.")
            if "code_report" in st.session_state:
                st.rerun()

    if "code_report" in st.session_state:
        meta = st.session_state["code_meta"] or {}

        # ── Summary metrics ───────────────────────────────────────────────────
        st.markdown('<div class="section-label">ANALYSIS SUMMARY</div>', unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        c1.metric("Input Risk Score",   f"{meta.get('risk_score', 0)}/100")
        c2.metric("Critical / High",    len(meta.get("high_sev_findings", [])))
        c3.metric("Slack Alert",        "✅ Sent" if meta.get("slack_alert_sent") else "—")

        # ── Critical findings ─────────────────────────────────────────────────
        if meta.get("high_sev_findings"):
            findings = [f.lstrip("# ").strip() for f in meta["high_sev_findings"]]
            _render_critical_findings(findings)

        # ── Report sections ───────────────────────────────────────────────────
        st.markdown('<div class="section-label" style="margin-top:8px">VULNERABILITY REPORT</div>',
                    unsafe_allow_html=True)
        _render_report_sections(st.session_state["code_report"])

        st.divider()

        # ── PDF download ──────────────────────────────────────────────────────
        try:
            from cyber_shield_pdf_app import create_pdf
            pdf_bytes = create_pdf(st.session_state["code_report"])
            st.download_button(
                label="📥  Download Report as PDF",
                data=pdf_bytes,
                file_name="code_security_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception:
            st.warning("PDF export unavailable.")


# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 — Scan History Dashboard
# ═════════════════════════════════════════════════════════════════════════════

with tab_history:
    st.markdown('<div class="section-label">HISTORICAL SCAN TIMELINE</div>',
                unsafe_allow_html=True)

    from scan_history_store import get_store as _get_store

    _store = _get_store()
    _all_urls = _store.get_all_scanned_urls()

    if not _all_urls:
        st.info("No scan history found yet. Run a live scan and results will appear here.")
    else:
        selected_url = st.selectbox(
            "Select URL to view history",
            options=_all_urls,
            format_func=lambda u: u,
            label_visibility="collapsed",
            key="hist_url_select",
        )

        if selected_url:
            history = _store.get_scan_history(selected_url, limit=20)

            if history:
                # Reverse for chart (oldest first)
                chron = list(reversed(history))

                # ── Score over time chart ─────────────────────────────────────
                st.markdown('<div class="section-label">SCORE TIMELINE</div>',
                            unsafe_allow_html=True)

                import pandas as pd
                chart_data = pd.DataFrame({
                    "Date": [h.scan_timestamp[:10] for h in chron],
                    "Score": [h.overall_score for h in chron],
                })
                # Streamlit's line_chart needs index as date
                chart_data = chart_data.set_index("Date")
                st.line_chart(chart_data["Score"], color="#10b981", height=220)

                # ── History entries ───────────────────────────────────────────
                st.markdown('<div class="section-label">SCAN HISTORY</div>',
                            unsafe_allow_html=True)

                for rec in history:
                    g = rec.overall_grade
                    g_colors = {
                        "A": ("#064e3b", "#10b981"),
                        "B": ("#1e3a5f", "#3b82f6"),
                        "C": ("#4a2800", "#f59e0b"),
                        "D": ("#3b0a0a", "#ef4444"),
                    }
                    bg, fg = g_colors.get(g, ("#1a0000", "#dc2626"))
                    ts_display = rec.scan_timestamp[:16].replace("T", " ")
                    bar_color = {"A": "#10b981", "B": "#3b82f6", "C": "#f59e0b"}.get(g, "#ef4444")
                    st.markdown(f"""
<div class="hist-card">
  <div class="hist-grade-dot" style="background:{bg};color:{fg};border:2px solid {fg}">{g}</div>
  <div style="flex:1">
    <div style="font-size:1.1rem;font-weight:700;color:#e2e8f0;font-family:'Courier New',monospace">{rec.overall_score}<span style="font-size:0.8rem;color:#475569">/100</span></div>
    <div style="font-size:0.75rem;color:#475569;margin-top:2px">{ts_display} UTC · Scan ID: {rec.scan_id[:8]}…</div>
    <div style="background:#1f2d3d;border-radius:3px;height:4px;margin-top:8px;overflow:hidden">
      <div style="width:{rec.overall_score}%;height:4px;background:{bar_color};border-radius:3px"></div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# TAB 4 — Differential View
# ═════════════════════════════════════════════════════════════════════════════

with tab_diff:
    st.markdown('<div class="section-label">DIFFERENTIAL SCAN COMPARISON</div>',
                unsafe_allow_html=True)

    from scan_history_store import get_store as _get_store2

    _store2  = _get_store2()
    _urls2   = _store2.get_all_scanned_urls()

    if not _urls2:
        st.info("No scan history yet — run scans and compare them here.")
    else:
        diff_url = st.selectbox(
            "Target URL to compare",
            options=_urls2,
            label_visibility="collapsed",
            key="diff_url_select",
        )

        if diff_url:
            _hist2 = _store2.get_scan_history(diff_url, limit=20)
            if len(_hist2) < 2:
                st.warning(f"Need at least 2 scans for {diff_url} to compare. Only {len(_hist2)} found.")
            else:
                _scan_options = {
                    f"{h.scan_timestamp[:16]} UTC — Grade {h.overall_grade} ({h.overall_score}/100)": h
                    for h in _hist2
                }
                _labels = list(_scan_options.keys())

                col_a, col_b = st.columns(2)
                _idx_a = min(1, len(_labels) - 1)  # baseline = older scan (index 1 if available)
                with col_a:
                    st.markdown('<div class="section-label">SCAN A (BASELINE)</div>', unsafe_allow_html=True)
                    label_a = st.selectbox("Scan A", options=_labels, index=_idx_a,
                                           label_visibility="collapsed", key="diff_a")
                with col_b:
                    st.markdown('<div class="section-label">SCAN B (COMPARISON)</div>', unsafe_allow_html=True)
                    label_b = st.selectbox("Scan B", options=_labels, index=0,
                                           label_visibility="collapsed", key="diff_b")

                scan_a = _scan_options[label_a]
                scan_b = _scan_options[label_b]

                # ── Overall delta ─────────────────────────────────────────────
                delta_score = scan_b.overall_score - scan_a.overall_score
                delta_sign  = "+" if delta_score >= 0 else ""
                delta_color = "#10b981" if delta_score > 0 else "#ef4444" if delta_score < 0 else "#475569"
                mc1, mc2, mc3 = st.columns(3)
                mc1.metric("Scan A Score", f"{scan_a.overall_score}/100 ({scan_a.overall_grade})")
                mc2.metric("Scan B Score", f"{scan_b.overall_score}/100 ({scan_b.overall_grade})")
                mc3.metric("Delta", f"{delta_sign}{delta_score} pts",
                           delta=delta_score, delta_color="normal")

                # ── Per-category deltas ───────────────────────────────────────
                st.markdown('<div class="section-label" style="margin-top:16px">CATEGORY DELTAS</div>',
                            unsafe_allow_html=True)

                all_cat_keys = list(_CATEGORY_LABELS.keys())
                rows_d = [all_cat_keys[i:i+3] for i in range(0, len(all_cat_keys), 3)]
                for row_d in rows_d:
                    cols_d = st.columns(3)
                    for col_d, key_d in zip(cols_d, row_d):
                        val_a = scan_a.category_scores.get(key_d, 0)
                        val_b = scan_b.category_scores.get(key_d, 0)
                        diff  = val_b - val_a
                        diff_str  = f"+{diff}" if diff > 0 else str(diff)
                        diff_cls  = "delta-improved" if diff > 0 else "delta-regressed" if diff < 0 else "delta-unchanged"
                        bar_cls   = _score_class(val_b)
                        label_d   = _CATEGORY_LABELS.get(key_d, key_d)
                        icon_d    = _CATEGORY_ICONS.get(key_d, "📊")
                        col_d.markdown(f"""
<div class="score-card">
  <div class="score-card-label">{icon_d} {label_d}</div>
  <div style="display:flex;align-items:baseline;gap:8px">
    <div class="score-card-value score-val-{bar_cls}">{val_b}<span style="font-size:0.9rem;color:#475569">/100</span></div>
    <div class="{diff_cls}" style="font-size:0.85rem;font-family:'Courier New',monospace">{diff_str}</div>
  </div>
  <div class="score-bar-bg"><div class="score-bar-{bar_cls}" style="width:{val_b}%"></div></div>
</div>""", unsafe_allow_html=True)

                # ── New vs resolved critical findings ─────────────────────────
                set_a = set(scan_a.critical_findings)
                set_b = set(scan_b.critical_findings)
                new_findings      = set_b - set_a
                resolved_findings = set_a - set_b
                unchanged         = set_a & set_b

                st.markdown('<div class="section-label" style="margin-top:16px">CRITICAL FINDINGS DELTA</div>',
                            unsafe_allow_html=True)
                fd_c1, fd_c2, fd_c3 = st.columns(3)
                fd_c1.metric("New Findings",      len(new_findings),      delta=len(new_findings) or None,
                             delta_color="inverse")
                fd_c2.metric("Resolved",          len(resolved_findings), delta=len(resolved_findings) or None,
                             delta_color="normal")
                fd_c3.metric("Unchanged",         len(unchanged))

                if new_findings:
                    st.markdown("**New findings in Scan B:**")
                    for f in new_findings:
                        st.markdown(f'<div class="verify-row verify-confirmed">🔴 NEW: {f}</div>',
                                    unsafe_allow_html=True)
                if resolved_findings:
                    st.markdown("**Resolved since Scan A:**")
                    for f in resolved_findings:
                        st.markdown(f'<div class="verify-row verify-unknown" style="border-left-color:#10b981">✅ RESOLVED: {f}</div>',
                                    unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="text-align:center;padding:24px 0 8px;color:#334155;font-size:0.75rem;
            font-family:'Courier New',monospace;letter-spacing:0.1em;">
  AI CYBER SHIELD v6 &nbsp;·&nbsp; DEFENSIVE USE ONLY &nbsp;·&nbsp;
  מערכת לשימוש הגנתי בלבד &nbsp;·&nbsp; SCAN ONLY YOUR OWN SITES
</div>
""", unsafe_allow_html=True)

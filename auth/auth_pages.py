"""
auth/auth_pages.py — AI Cyber Shield v7

Landing page + Auth pages.

Layout: Nav bar → split-hero (60/40) → social proof → pricing → footer.
Auth form lives in the right column so returning users can log in immediately
while new visitors absorb the product before signing up.
"""
from __future__ import annotations

import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
try:
    from config import CONTACT_PHONE, CONTACT_PHONE_RAW, CONTACT_EMAIL
except ImportError:
    CONTACT_PHONE     = "054-696-2565"
    CONTACT_PHONE_RAW = "0546962565"
    CONTACT_EMAIL     = "nivhaziza20@gmail.com"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PW_MIN = 8

# ─────────────────────────────────────────────────────────────────────────────
# CSS — injected once via st.markdown, applies to all columns
# ─────────────────────────────────────────────────────────────────────────────

_LANDING_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Heebo:wght@300;400;500;700;800;900&family=Inter:wght@400;600;700;900&display=swap');

#MainMenu, footer, header { visibility: hidden; }
[data-testid="stAppViewContainer"] { background: #060b14; }
[data-testid="stHeader"] { background: transparent; }

/* Hebrew font */
body, .block-container, button, label, p, span, div, input {
  font-family: 'Heebo', 'Inter', 'Segoe UI', sans-serif !important;
}

/* Glow animation on primary accent */
@keyframes cyanGlow {
  0%,100% { text-shadow: 0 0 18px rgba(34,211,238,0.3); }
  50%      { text-shadow: 0 0 38px rgba(34,211,238,0.7), 0 0 6px #22d3ee; }
}
@keyframes borderPulse {
  0%,100% { box-shadow: 0 0 0 1px rgba(34,211,238,0.15), 0 24px 80px rgba(0,0,0,0.55); }
  50%      { box-shadow: 0 0 0 1px rgba(34,211,238,0.45), 0 24px 80px rgba(0,0,0,0.55), 0 0 30px rgba(34,211,238,0.1); }
}
.block-container { padding-top: 0 !important; padding-bottom: 0 !important; padding-left: 1rem !important; padding-right: 1rem !important; background: #060b14; }

/* ── Brand ──────────────────────────────────────────────── */
.lp-brand { display:flex; align-items:center; gap:14px; margin-bottom:24px; margin-top:8px; }
.lp-brand-icon { font-size:1.8rem; line-height:1; }
.lp-brand-name { font-family:'JetBrains Mono','Courier New',monospace; font-size:1.3rem; font-weight:900; background:linear-gradient(90deg,#22d3ee,#818cf8); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; letter-spacing:-0.04em; line-height:1.1; filter:drop-shadow(0 0 12px rgba(34,211,238,0.35)); }
.lp-brand-sub { color:#475569; font-size:0.58rem; letter-spacing:0.2em; text-transform:uppercase; margin-top:2px; }

/* ── Hero ───────────────────────────────────────────────── */
.lp-headline { font-size:3.2rem; font-weight:900; color:#f1f5f9; line-height:1.08; margin:0 0 18px; letter-spacing:-0.03em; font-family:'Heebo','Inter',sans-serif; }
.lp-headline em { font-style:normal; background:linear-gradient(90deg,#22d3ee,#818cf8,#c084fc); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; filter:drop-shadow(0 0 20px rgba(34,211,238,0.40)); animation:cyanGlow 3s ease-in-out infinite; }
.lp-desc { color:#94a3b8; font-size:0.97rem; line-height:1.72; max-width:520px; margin:0 0 22px; }
.lp-cta-row { display:flex; align-items:center; gap:16px; margin-bottom:28px; flex-wrap:wrap; }
.lp-cta-btn { display:inline-flex; align-items:center; gap:8px; background:#22d3ee; color:#000; font-weight:800; font-size:0.88rem; padding:11px 24px; border-radius:9px; letter-spacing:-0.01em; }
.lp-cta-note { color:#475569; font-size:0.75rem; }

/* ── Stats ──────────────────────────────────────────────── */
.lp-stats { display:flex; gap:20px; flex-wrap:wrap; margin-bottom:32px; padding-bottom:28px; border-bottom:1px solid #1e2d3d; }
.lp-stat-val { font-size:1.9rem; font-weight:900; color:#22d3ee; font-family:'JetBrains Mono',monospace; line-height:1; }
.lp-stat-lbl { color:#475569; font-size:0.68rem; margin-top:4px; text-transform:uppercase; letter-spacing:0.07em; }

/* ── Features grid ──────────────────────────────────────── */
.lp-features-label { color:#64748b; font-size:0.65rem; text-transform:uppercase; letter-spacing:0.22em; margin-bottom:12px; }
.lp-features { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:24px; }
.lp-feat { background:#0d1421; border:1px solid #1e2d3d; border-radius:10px; padding:15px 15px 14px; transition:border-color 0.18s,background 0.18s; }
.lp-feat:hover { border-color:#22d3ee; background:#061828; }
.lp-feat-icon { color:#22d3ee; margin-bottom:8px; display:block; line-height:0; }
.lp-feat-name { font-size:0.86rem; font-weight:700; color:#e2e8f0; margin-bottom:4px; }
.lp-feat-desc { font-size:0.8rem; color:#64748b; line-height:1.55; }

/* ── Free badge ─────────────────────────────────────────── */
.lp-free-badge { display:inline-flex; align-items:center; gap:8px; background:#061a2e; border:1px solid #22d3ee; border-radius:8px; padding:9px 15px; font-size:0.8rem; color:#a5f3fc; margin-bottom:8px; flex-wrap:wrap; }
.lp-free-badge strong { color:#67e8f9; }

/* ── Auth card (floating card effect) ───────────────────── */
.auth-card-top { background:#0d1421; border:1px solid #22d3ee33; border-bottom:none; border-radius:16px 16px 0 0; padding:26px 28px 20px; box-shadow:0 4px 32px rgba(0,0,0,0.5), 0 0 30px rgba(34,211,238,0.06); animation:borderPulse 4s ease-in-out infinite; }
.auth-card-brand { display:flex; align-items:center; justify-content:center; margin-bottom:10px; }
.auth-card-title { font-size:1.25rem; font-weight:800; color:#f1f5f9; margin-bottom:4px; letter-spacing:-0.02em; font-family:'Heebo','Inter',sans-serif; }
.auth-card-sub { font-size:0.73rem; color:#475569; }
.auth-notice { background:#0c2835; border:1px solid #22d3ee; border-radius:8px; padding:10px 14px; font-size:0.79rem; color:#a5f3fc; margin-bottom:16px; line-height:1.55; }
.auth-card-footer { background:#0d1421; border:1px solid #2a3d52; border-top:none; border-radius:0 0 16px 16px; padding:12px 28px 22px; text-align:center; color:#334155; font-size:0.69rem; line-height:1.75; box-shadow:0 8px 32px rgba(0,0,0,0.5); }

/* ── Auth column card (JS-injected .aics-auth-col on the right column) ── */
.aics-auth-col {
    background: #0b1220 !important;
    border-radius: 18px !important;
    overflow: hidden !important;
    box-shadow:
        0 1px 0 rgba(255,255,255,0.04) inset,
        0 24px 80px rgba(0,0,0,0.55),
        0 0 0 1px rgba(34,211,238,0.10) !important;
}
.aics-auth-col .auth-card-top {
    border: none !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    border-bottom: 1px solid #1a2a3d !important;
}
.aics-auth-col .auth-card-footer {
    border: none !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    border-top: 1px solid #1a2a3d !important;
    background: #080f1a !important;
}

/* ── Streamlit input overrides inside auth card ─────────── */
[data-testid="stTextInput"] input {
    background: #060e1e !important;
    border: 1px solid #243347 !important;
    color: #e2e8f0 !important;
    border-radius: 9px !important;
    font-size: 0.88rem !important;
    transition: border-color 0.18s, box-shadow 0.18s !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #22d3ee !important;
    box-shadow: 0 0 0 3px rgba(34,211,238,0.12) !important;
    outline: none !important;
}
[data-testid="stTextInput"] input::placeholder { color: #2a3d52 !important; }
[data-testid="stTextInput"] label {
    color: #64748b !important;
    font-size: 0.73rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.09em !important;
    text-transform: uppercase !important;
    margin-bottom: 3px !important;
}

/* ── Google link_button (OAuth) ─────────────────────────── */
[data-testid="stLinkButton"] a {
    background: #ffffff !important;
    color: #1f1f1f !important;
    border: 1px solid #dadce0 !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    text-decoration: none !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    min-height: 44px !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12) !important;
    transition: background 0.15s, box-shadow 0.15s !important;
}
[data-testid="stLinkButton"] a:hover {
    background: #f8f8f8 !important;
    border-color: #bbb !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.18) !important;
    text-decoration: none !important;
}
[data-testid="stLinkButton"] a:active {
    background: #f1f1f1 !important;
    transform: scale(0.98) !important;
}

/* ── Toggle link buttons ─────────────────────────────────── */
.auth-toggle-row [data-testid="stButton"] button {
    background: transparent !important;
    color: #22d3ee !important;
    border: none !important;
    box-shadow: none !important;
    padding: 0 2px !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    min-height: 26px !important;
    letter-spacing: 0 !important;
    text-decoration: underline !important;
    text-underline-offset: 2px !important;
    text-decoration-color: rgba(34,211,238,0.4) !important;
}
.auth-toggle-row [data-testid="stButton"] button:hover {
    color: #67e8f9 !important;
    transform: none !important;
    text-decoration-color: rgba(52,211,153,0.85) !important;
}

/* ── Security tool check pills ─────────────────────────── */
.lp-checks {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 7px;
  margin: 0 0 14px;
}
.lp-check {
  background: #0d1421;
  border: 1px solid #1e2d3d;
  border-radius: 7px;
  padding: 7px 10px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #64748b;
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.lp-check-warn {
  border-color: rgba(239,68,68,0.22);
  color: #fca5a5;
  background: #130505;
}
.lp-check-ok {
  border-color: rgba(34,211,238,0.18);
  color: #a5f3fc;
  background: #03101a;
}
.lp-trust {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 14px;
  margin-bottom: 16px;
}
.lp-trust span {
  color: #64748b;
  font-size: 0.72rem;
  display: flex;
  align-items: center;
  gap: 4px;
}
.lp-trust span::before {
  content: "✓";
  color: #22d3ee;
  font-weight: 800;
  font-size: 0.68rem;
}

/* ── Hero scan URL label ────────────────────────────────── */
.lp-scan-label {
  color: #22d3ee;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  margin: 18px 0 8px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.lp-scan-label::before {
  content: "";
  display: inline-block;
  width: 18px;
  height: 2px;
  background: #22d3ee;
  border-radius: 1px;
}

/* ── Auth buttons (Sign In / Create Account) ────────────── */
button[kind="primary"] {
  background: linear-gradient(135deg, #22d3ee 0%, #0891b2 100%) !important;
  color: #000 !important;
  font-weight: 800 !important;
  border: none !important;
  border-radius: 10px !important;
  font-size: 0.9rem !important;
  letter-spacing: 0.03em !important;
  box-shadow: 0 2px 12px rgba(34,211,238,0.25) !important;
  transition: all 0.18s ease !important;
}
button[kind="primary"]:hover {
  background: linear-gradient(135deg, #0891b2 0%, #0e7490 100%) !important;
  box-shadow: 0 4px 20px rgba(34,211,238,0.40) !important;
  transform: translateY(-1px) !important;
}
button[kind="primary"]:active {
  transform: translateY(0) !important;
  box-shadow: 0 1px 8px rgba(34,211,238,0.20) !important;
}
/* Secondary buttons on landing page are always toggle/link actions */
button[kind="secondary"] {
  background: transparent !important;
  color: #22d3ee !important;
  border: none !important;
  box-shadow: none !important;
  padding: 0 2px !important;
  font-size: 0.81rem !important;
  font-weight: 600 !important;
  min-height: 26px !important;
  line-height: 1 !important;
  text-decoration: underline !important;
  text-underline-offset: 2px !important;
  text-decoration-color: rgba(34,211,238,0.4) !important;
}
button[kind="secondary"]:hover {
  color: #67e8f9 !important;
  transform: none !important;
  text-decoration-color: rgba(52,211,153,0.85) !important;
}

/* ── Dual scanner panel ─────────────────────────────── */
.dp-wrap{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:22px 0 20px}
@media(max-width:640px){.dp-wrap{grid-template-columns:1fr}}
.dp-panel{border-radius:11px;padding:16px 14px}
.dp-sec{background:#040d19;border:1px solid rgba(34,211,238,0.2)}
.dp-leg{background:#05040f;border:1px solid rgba(129,140,248,0.2)}
.dp-title{font-size:0.72rem;font-weight:800;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:3px;display:flex;align-items:center;gap:6px}
.dp-subtitle{font-size:0.63rem;color:#334155;margin-bottom:11px;letter-spacing:0.03em}
.dp-sec .dp-title{color:#22d3ee}
.dp-leg .dp-title{color:#818cf8}
.dp-item{font-size:0.77rem;color:#64748b;padding:2.5px 0;display:flex;align-items:baseline;gap:5px;line-height:1.4}
.dp-item::before{content:"›";font-weight:900;flex-shrink:0;font-size:0.85rem}
.dp-sec .dp-item::before{color:#22d3ee}
.dp-leg .dp-item::before{color:#818cf8}

/* ── Eyebrow tag ────────────────────────────────────── */
.lp-eyebrow{display:inline-flex;align-items:center;gap:8px;background:rgba(34,211,238,0.07);border:1px solid rgba(34,211,238,0.2);border-radius:99px;padding:5px 14px;margin-bottom:20px;margin-top:8px}
.lp-eyebrow-dot{width:6px;height:6px;border-radius:50%;background:#22d3ee;display:inline-block;animation:eyebrowPulse 1.6s ease-in-out infinite}
@keyframes eyebrowPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
.lp-eyebrow-txt{color:#22d3ee;font-size:0.64rem;letter-spacing:0.16em;text-transform:uppercase;font-weight:700}

/* ── Hero headline — larger ─────────────────────────── */
.lp-headline{font-size:3.6rem;font-weight:900;color:#f1f5f9;line-height:1.05;margin:0 0 0;letter-spacing:-0.04em;font-family:'Heebo','Inter',sans-serif}
.lp-headline em{font-style:normal;background:linear-gradient(90deg,#22d3ee,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;filter:drop-shadow(0 0 20px rgba(34,211,238,0.40));animation:cyanGlow 3s ease-in-out infinite}

/* ── Trust bar ──────────────────────────────────────── */
.lp-trust{display:flex;flex-wrap:wrap;gap:6px 16px;margin:18px 0 8px}
.lp-trust span{color:#475569;font-size:0.72rem;display:inline-flex;align-items:center;gap:5px}
.lp-trust span::before{content:"✓";color:#22d3ee;font-weight:900}
.lp-scan-label{color:#334155;font-size:0.69rem;letter-spacing:0.04em;margin-top:4px;padding-bottom:20px;border-bottom:1px solid #0f1e2d}

/* ── Nav dual badge ─────────────────────────────────── */
.nav-dual{display:inline-flex;align-items:center;gap:6px;background:#080e1a;border:1px solid #1a2a3d;border-radius:7px;padding:3px 10px;font-size:0.64rem}
.nav-dual-sec{color:#22d3ee;font-weight:700}
.nav-dual-leg{color:#818cf8;font-weight:700}
.nav-dual-sep{color:#1e2d3d;font-size:0.7rem}

/* ── Feature dual panel ─────────────────────────────── */
.feat-section{margin:24px 0 8px}
.feat-section-label{color:#475569;font-size:0.63rem;text-transform:uppercase;letter-spacing:0.22em;margin-bottom:14px;display:flex;align-items:center;gap:10px}
.feat-section-label::after{content:"";flex:1;height:1px;background:#0f1e2d}
.feat-duo{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
@media(max-width:600px){.feat-duo{grid-template-columns:1fr}}
.feat-panel{border-radius:12px;padding:18px 16px}
.feat-panel-sec{background:#040d19;border:1px solid rgba(34,211,238,0.15)}
.feat-panel-leg{background:#05040f;border:1px solid rgba(129,140,248,0.15)}
.feat-panel-head{font-size:0.72rem;font-weight:800;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:3px}
.feat-panel-sec .feat-panel-head{color:#22d3ee}
.feat-panel-leg .feat-panel-head{color:#818cf8}
.feat-panel-sub{font-size:0.63rem;color:#334155;margin-bottom:12px;letter-spacing:0.03em}
.feat-panel-item{font-size:0.77rem;color:#64748b;padding:3px 0;display:flex;gap:7px;align-items:flex-start;line-height:1.4}
.feat-panel-item-icon{flex-shrink:0}
.feat-panel-item strong{color:#94a3b8}

/* ── MOBILE — tablet (≤768px) ───────────────────────────── */
@media (max-width: 768px) {
  .lp-headline { font-size: 2.2rem; }
  .lp-desc { font-size: 0.9rem; }
  .lp-features { grid-template-columns: 1fr; }
  .lp-stats { gap: 16px; }
  .lp-stat-val { font-size: 1.5rem; }
  .auth-card-top { padding: 18px 16px 14px; border-radius: 12px 12px 0 0; }
  .auth-card-footer { padding: 10px 16px 16px; border-radius: 0 0 12px 12px; }
  .lp-free-badge { font-size: 0.74rem; }
  /* Streamlit column layout — force single column on tablet */
  [data-testid="stHorizontalBlock"] { flex-wrap: wrap !important; }
  [data-testid="stColumn"]          { min-width: 100% !important; flex: 1 1 100% !important; }
  /* Link button (Google) — ensure full width & touch-friendly */
  [data-testid="stLinkButton"] a    { min-height: 48px !important; font-size: 1rem !important; }
  /* Primary buttons — touch target */
  button[kind="primary"] { min-height: 48px !important; font-size: 0.95rem !important; }
  /* Inputs — prevent iOS zoom (font-size ≥16px) */
  [data-testid="stTextInput"] input { font-size: 16px !important; }
}

/* ── MOBILE — phone (≤480px) ────────────────────────────── */
@media (max-width: 480px) {
  .lp-headline { font-size: 1.8rem; letter-spacing: -0.02em; }
  .lp-desc { font-size: 0.85rem; max-width: 100%; }
  .lp-cta-btn { padding: 10px 18px; font-size: 0.82rem; width: 100%; justify-content: center; }
  .lp-cta-note { font-size: 0.7rem; }
  .lp-stats { gap: 12px; }
  .lp-stat-val { font-size: 1.3rem; }
  .lp-stat-lbl { font-size: 0.6rem; }
  .lp-brand-name { font-size: 1.1rem; }
  .auth-card-top { padding: 14px 12px; }
  .auth-card-footer { padding: 8px 12px 14px; }
  .dp-wrap { grid-template-columns: 1fr !important; }
  .feat-duo { grid-template-columns: 1fr !important; }
  .lp-checks { grid-template-columns: repeat(2,1fr) !important; }
  .aics-plans { grid-template-columns: 1fr !important; }
  /* Full-width inputs on phone */
  [data-testid="stTextInput"] { width: 100% !important; }
  [data-testid="stLinkButton"] a { min-height: 52px !important; font-size: 1rem !important; }
}
</style>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Navigation bar  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_NAV_HTML = """
<style>
.aics-nav{display:flex;align-items:center;justify-content:space-between;padding:13px 4px;border-bottom:1px solid #0f1e2d;margin-bottom:4px;flex-wrap:wrap;gap:10px}
.aics-nav-brand{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.aics-nav-links{display:flex;align-items:center;gap:18px}
.aics-nav-link{color:#334155;font-size:0.73rem;white-space:nowrap}
.aics-nav-cta{background:#22d3ee;color:#000;font-weight:800;font-size:0.73rem;padding:6px 15px;border-radius:7px;white-space:nowrap;letter-spacing:-0.01em}
@media(max-width:768px){.aics-nav-links .aics-nav-link{display:none}.aics-nav{padding:10px 4px}}
@media(max-width:480px){.aics-nav-cta{font-size:0.68rem;padding:5px 11px}}
</style>
<div class="aics-nav">
  <div class="aics-nav-brand">
    <span style="font-size:1.25rem;line-height:1">🛡</span>
    <span style="font-family:'JetBrains Mono','Courier New',monospace;font-weight:900;color:#22d3ee;font-size:0.97rem;letter-spacing:-0.03em">AI Cyber Shield</span>
    <div class="nav-dual">
      <span class="nav-dual-sec">🔒 Security</span>
      <span class="nav-dual-sep">+</span>
      <span class="nav-dual-leg">⚖️ Legal</span>
    </div>
  </div>
  <div class="aics-nav-links">
    <span class="aics-nav-link">18 tools</span>
    <span class="aics-nav-link">IL · GDPR · US</span>
    <span class="aics-nav-link">Free tier</span>
    <span class="aics-nav-cta">Start Free →</span>
  </div>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Hero HTML  (inside left column → st.markdown, no blank lines)
# ─────────────────────────────────────────────────────────────────────────────

def _get_hero_html(lang: str = "he") -> str:
    direction = "rtl" if lang == "he" else "ltr"

    _h = {
        "he": ("האתר שלך", "מוגן וחוקי?"),
        "en": ("Is your site", "secure & compliant?"),
    }
    h, em = _h.get(lang, _h["en"])

    _eyebrow = "פלטפורמת AI · אבטחה + ציות משפטי" if lang == "he" else "AI Platform · Security + Legal Compliance"

    _sec = {
        "he": [
            "SSL/TLS · מפתחות וחתימות",
            "CVE · פגיעויות ידועות + EPSS",
            "DNS · SPF/DMARC · זיוף מייל",
            "GitHub · דליפות קוד וסודות",
            "HTTP Headers · הגדרות שגויות",
            "Cloud Buckets · חשיפה ציבורית",
        ],
        "en": [
            "SSL/TLS · Keys & Certificates",
            "CVE · Known vulns + EPSS scoring",
            "DNS · SPF/DMARC · Email spoof",
            "GitHub · Code & secret leaks",
            "HTTP Headers · Misconfigurations",
            "Cloud Buckets · Public exposure",
        ],
    }
    _leg = {
        "he": [
            "חוק הגנת הפרטיות הישראלי",
            "GDPR · תקנות האיחוד האירופי",
            "CCPA · FTC · חוק פדרלי אמריקאי",
            "עוגיות · הסכמה וגילוי נאות",
            "נגישות · WCAG 2.1 AA",
            "דפוסים כהים · dark patterns",
        ],
        "en": [
            "Israeli Privacy Protection Law",
            "GDPR · EU Regulation 2016/679",
            "CCPA / FTC · US Federal Law",
            "Cookies · Consent & Disclosure",
            "Accessibility · WCAG 2.1 AA",
            "Dark Patterns Detection",
        ],
    }

    sec_html = "".join(f'<div class="dp-item">{i}</div>' for i in _sec.get(lang, _sec["en"]))
    leg_html = "".join(f'<div class="dp-item">{i}</div>' for i in _leg.get(lang, _leg["en"]))

    _trust = {
        "he": ["ללא agent בשרת שלך", "Zero network footprint", "תוצאות תוך 60 שניות"],
        "en": ["No agent on your server", "Zero network footprint", "Results in 60 seconds"],
    }.get(lang, ["No agent on your server", "Zero network footprint", "Results in 60 seconds"])

    _scan_label  = "הכנס את כתובת האתר שלך לסריקה מיידית" if lang == "he" else "Enter your website URL to start your free scan"
    _sec_sub     = "18 כלי OSINT · OWASP Top 10" if lang == "he" else "18 OSINT Tools · OWASP Top 10"
    _leg_sub     = "3 מערכות חוק · ניקוד אוטומטי" if lang == "he" else "3 Jurisdictions · Auto-Scoring"
    _sec_title   = "אבטחת סייבר" if lang == "he" else "Cybersecurity"
    _leg_title   = "ציות משפטי" if lang == "he" else "Legal Compliance"

    trust_html = "".join(f"<span>{s}</span>" for s in _trust)

    return f"""
<div class="lp-eyebrow">
  <span class="lp-eyebrow-dot"></span>
  <span class="lp-eyebrow-txt">{_eyebrow}</span>
</div>
<h1 class="lp-headline" dir="{direction}">{h}<br><em>{em}</em></h1>
<div class="dp-wrap">
  <div class="dp-panel dp-sec">
    <div class="dp-title">🛡 {_sec_title}</div>
    <div class="dp-subtitle">{_sec_sub}</div>
    {sec_html}
  </div>
  <div class="dp-panel dp-leg">
    <div class="dp-title">⚖️ {_leg_title}</div>
    <div class="dp-subtitle">{_leg_sub}</div>
    {leg_html}
  </div>
</div>
<div class="lp-trust">{trust_html}</div>
<div class="lp-scan-label">{_scan_label}</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Stats bar  (self-contained → st.html so count-up script runs)
# ─────────────────────────────────────────────────────────────────────────────

_STATS_HTML = """
<style>
.aics-stats {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
  padding: 22px 0 24px;
  border-bottom: 1px solid #1e2d3d;
  margin-bottom: 4px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
.aics-stat-val {
  font-size: 2rem;
  font-weight: 900;
  color: #22d3ee;
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  line-height: 1;
  letter-spacing: -0.03em;
}
.aics-stat-lbl {
  color: #475569;
  font-size: 0.67rem;
  margin-top: 5px;
  text-transform: uppercase;
  letter-spacing: 0.09em;
}
@media (max-width: 480px) {
  .aics-stat-val { font-size: 1.5rem; }
  .aics-stats    { gap: 14px; }
}
</style>
<div class="aics-stats">
  <div>
    <div class="aics-stat-val" id="st-tools">0</div>
    <div class="aics-stat-lbl">OSINT tools</div>
  </div>
  <div>
    <div class="aics-stat-val" id="st-sigs">0</div>
    <div class="aics-stat-lbl">Tech signatures</div>
  </div>
  <div>
    <div class="aics-stat-val" id="st-classes">0</div>
    <div class="aics-stat-lbl">Vuln classes</div>
  </div>
  <div>
    <div class="aics-stat-val">&lt;90s</div>
    <div class="aics-stat-lbl">Scan time</div>
  </div>
</div>
<script>
function aicsCU(id, target, dur) {
  var el = document.getElementById(id);
  if (!el) return;
  var t0 = performance.now();
  function step(ts) {
    var p  = Math.min((ts - t0) / dur, 1);
    var e  = 1 - Math.pow(1 - p, 3);          /* ease-out cubic */
    var v  = Math.round(target * e);
    el.textContent = target > 100 ? v.toLocaleString() : v;
    if (p < 1) requestAnimationFrame(step);
    else el.textContent = target > 100 ? target.toLocaleString() : target;
  }
  requestAnimationFrame(step);
}
aicsCU('st-tools',   18,   800);
aicsCU('st-sigs',   7537, 1600);
aicsCU('st-classes',   8,  500);
</script>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Features HTML  (inside left column → st.markdown, SVG icons)
# ─────────────────────────────────────────────────────────────────────────────

_FEATURES_HTML = """
<div class="feat-section">
  <div class="feat-section-label">מה בסריקה שלנו &nbsp;·&nbsp; What's in your scan</div>
  <div class="feat-duo">
    <div class="feat-panel feat-panel-sec">
      <div class="feat-panel-head">🛡 Security Scan</div>
      <div class="feat-panel-sub">18 OSINT tools · OWASP Top 10 · Active probes</div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🔒</span><span><strong>TLS / SSL</strong> — Protocol, ciphers, HSTS</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🏗</span><span><strong>Tech Stack</strong> — 7,537 Wappalyzer signatures + CVE</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🔗</span><span><strong>CVE Detection</strong> — NVD · GitHub · OSV + EPSS</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">📧</span><span><strong>Email Spoof</strong> — SPF · DKIM · DMARC records</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🐙</span><span><strong>GitHub Leaks</strong> — Secrets in public repos</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">☁️</span><span><strong>Cloud Buckets</strong> — AWS · GCP · Azure exposure</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🌐</span><span><strong>API &amp; DNS</strong> — Swagger/GraphQL · subdomain takeover</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">✅</span><span><strong>Active Probes</strong> — XSS · CORS · Open Redirect · SSTI</span></div>
    </div>
    <div class="feat-panel feat-panel-leg">
      <div class="feat-panel-head">⚖️ Legal Compliance</div>
      <div class="feat-panel-sub">3 jurisdictions · Auto-scoring · Fine estimates</div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🇮🇱</span><span><strong>Israeli Law</strong> — Privacy Protection · ILPA 2024</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🇪🇺</span><span><strong>GDPR</strong> — EU Regulation 2016/679</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🇺🇸</span><span><strong>US Federal</strong> — CCPA · FTC Act · CAN-SPAM</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🍪</span><span><strong>Cookies</strong> — Consent banner · Disclosure</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">♿</span><span><strong>Accessibility</strong> — WCAG 2.1 AA compliance</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">⚠️</span><span><strong>Dark Patterns</strong> — Deceptive UI detection</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">🔐</span><span><strong>Privacy Policy</strong> — Required disclosures check</span></div>
      <div class="feat-panel-item"><span class="feat-panel-item-icon">💰</span><span><strong>Fine Estimates</strong> — Potential penalty ranges</span></div>
    </div>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px">
    <div class="lp-free-badge">✅ <strong>Free tier</strong> — 18 OSINT tools, no card needed</div>
    <div class="lp-free-badge" style="border-color:#818cf8;background:#0a0818;color:#c7d2fe">⚖️ <strong>Legal Scanner</strong> — IL · GDPR · US compliance</div>
  </div>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Auth card wrappers
# ─────────────────────────────────────────────────────────────────────────────

_SVG_SHIELD = """<svg width="26" height="29" viewBox="0 0 28 31" fill="none">
  <path d="M14 1L2 6V16C2 23.2 7.6 29.8 14 31.4C20.4 29.8 26 23.2 26 16V6L14 1Z"
        fill="#071a10" stroke="#22d3ee" stroke-width="1.5"/>
  <path d="M9 15.5L12.5 19L19 12" stroke="#22d3ee" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

def _auth_card_top(headline: str, sub: str) -> str:
    return f"""
<div class="auth-card-top">
  <div class="auth-card-brand">{_SVG_SHIELD}</div>
  <div class="auth-card-title">{headline}</div>
  <div class="auth-card-sub">{sub}</div>
</div>"""

def _get_auth_card_footer(lang: str = "he") -> str:
    from translations import t as _t2
    return f'<div class="auth-card-footer">{_t2("auth_card_footer_legal")}</div>'

# ─────────────────────────────────────────────────────────────────────────────
# Social proof bar  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_SOCIAL_PROOF_HTML = """
<style>
.sp-bar{text-align:center;padding:14px 8px;color:#475569;font-size:0.78rem;border-top:1px solid #1e2d3d;border-bottom:1px solid #1e2d3d;background:#080d17;display:flex;justify-content:center;align-items:center;flex-wrap:wrap;gap:6px 16px}
.sp-item{white-space:nowrap}
.sp-hl{color:#22d3ee;font-weight:700}
@media(max-width:480px){.sp-bar{font-size:0.7rem;padding:10px 6px}.sp-sep{display:none}}
</style>
<div class="sp-bar">
  <span class="sp-item"><span class="sp-hl">18 parallel tools</span></span>
  <span class="sp-sep">·</span>
  <span class="sp-item"><span class="sp-hl">No agent</span> on target server</span>
  <span class="sp-sep">·</span>
  <span class="sp-item"><span class="sp-hl">Passive mode</span> — zero footprint</span>
  <span class="sp-sep">·</span>
  <span class="sp-item"><span class="sp-hl">OWASP Top 10</span> coverage</span>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Pricing  (self-contained CSS + HTML → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_PRICING_HTML = """
<style>
.aics-pricing{padding:48px 0 20px;margin-top:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.aics-pricing-eye{text-align:center;color:#22d3ee;font-size:.7rem;text-transform:uppercase;letter-spacing:.2em;margin-bottom:8px}
.aics-pricing-h{text-align:center;font-size:1.9rem;font-weight:800;color:#f8fafc;margin-bottom:6px}
.aics-pricing-sub{text-align:center;color:#64748b;font-size:.88rem;margin-bottom:36px}
.aics-plans{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:40px;align-items:start}
@media(max-width:900px){.aics-plans{grid-template-columns:repeat(2,1fr)}}
@media(max-width:500px){.aics-plans{grid-template-columns:1fr}.aics-pricing-h{font-size:1.4rem}.aics-price{font-size:1.7rem}}
.aics-plan{background:#0d1421;border:1px solid #1e2d3d;border-radius:14px;padding:24px 20px;position:relative;transition:border-color 0.2s}
.aics-plan:hover{border-color:#2a3d52}
.aics-plan-pro{
  border-color:#22d3ee;
  border-width:2px;
  background:linear-gradient(160deg,#081a10 0%,#0d1421 50%);
  box-shadow:0 0 50px rgba(34,211,238,0.22),0 8px 40px rgba(0,0,0,0.55),0 0 0 1px rgba(34,211,238,0.12);
  transform:translateY(-10px) scale(1.035);
  z-index:2;
  padding:28px 22px;
}
.aics-plan-pro:hover{border-color:#67e8f9;box-shadow:0 0 60px rgba(34,211,238,0.30),0 12px 50px rgba(0,0,0,0.6)}
.aics-badge{position:absolute;top:-14px;left:50%;transform:translateX(-50%);
  background:linear-gradient(90deg,#22d3ee,#67e8f9);
  color:#000;font-size:.6rem;font-weight:900;text-transform:uppercase;
  letter-spacing:.12em;padding:4px 16px;border-radius:99px;white-space:nowrap;
  box-shadow:0 2px 12px rgba(34,211,238,0.45)}
.aics-tier{font-size:.7rem;text-transform:uppercase;letter-spacing:.15em;color:#64748b;margin-bottom:10px}
.aics-price{font-size:2.1rem;font-weight:800;color:#f8fafc;line-height:1;margin-bottom:4px}
.aics-price sub{font-size:.8rem;font-weight:400;color:#64748b;vertical-align:baseline}
.aics-tagline{font-size:.72rem;color:#475569;margin-bottom:18px;min-height:30px}
.aics-features{list-style:none;padding:0;margin:0 0 20px}
.aics-features li{font-size:.74rem;color:#94a3b8;padding:4px 0;display:flex;gap:8px;align-items:flex-start}
.aics-features li::before{content:"✓";color:#22d3ee;font-weight:700;flex-shrink:0}
.aics-features li.off{color:#334155}
.aics-features li.off::before{content:"—";color:#334155}
.aics-cta{display:block;width:100%;padding:9px 0;border-radius:8px;font-size:.8rem;font-weight:700;text-align:center;border:1px solid #1e2d3d;background:transparent;color:#64748b;cursor:default}
.aics-cta-pro{background:#22d3ee;color:#000;border-color:#22d3ee}
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
        <li>Passive scan — 18 OSINT tools</li>
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
        <li>All 18 scan tools</li>
        <li>50 scans / day</li>
        <li>CVE feed + EPSS scoring</li>
        <li>Scan history &amp; comparison</li>
        <li>Scheduled scans</li>
        <li class="off">PT mode &amp; active probes</li>
      </ul>
      <span class="aics-cta">Upgrade</span>
    </div>
    <div class="aics-plan aics-plan-pro">
      <div class="aics-badge">⭐ Most popular</div>
      <div class="aics-tier" style="color:#22d3ee;font-weight:900;letter-spacing:.2em">Professional</div>
      <div class="aics-price" style="color:#67e8f9;font-size:2.6rem">€50<sub>/mo</sub></div>
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
# Scan Showcase  — cinematic, WOW-level design
# ─────────────────────────────────────────────────────────────────────────────

_SHOWCASE_HTML = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');

/* ── Section wrapper ── */
.sw{padding:60px 0 32px;font-family:'Inter','Segoe UI',sans-serif}
.sw-eyebrow{display:inline-flex;align-items:center;gap:8px;background:rgba(34,211,238,.08);
  border:1px solid rgba(34,211,238,.2);border-radius:99px;
  padding:5px 14px;margin-bottom:18px}
.sw-eyebrow-dot{width:6px;height:6px;border-radius:50%;background:#22d3ee;
  animation:swpulse 1.6s ease-in-out infinite}
@keyframes swpulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
.sw-eyebrow-txt{color:#22d3ee;font-size:.68rem;letter-spacing:.14em;text-transform:uppercase;font-weight:700}
.sw-h{font-size:1.7rem;font-weight:900;color:#f1f5f9;line-height:1.25;margin:0 0 8px}
.sw-h span{background:linear-gradient(90deg,#22d3ee,#67e8f9);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sw-sub{color:#475569;font-size:.88rem;margin:0 0 32px;line-height:1.6}

/* ── Grid ── */
.sw-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:700px){.sw-grid{grid-template-columns:1fr}}

/* ── Card base ── */
.sw-card{
  position:relative;border-radius:18px;padding:22px 22px 18px;overflow:hidden;
  background:linear-gradient(135deg,rgba(13,20,33,.98) 0%,rgba(9,14,24,.98) 100%);
  border:1px solid rgba(255,255,255,.06);
  transition:transform .22s ease,box-shadow .22s ease;
}
.sw-card:hover{transform:translateY(-3px)}

/* noise grain overlay */
.sw-card::before{
  content:'';position:absolute;inset:0;border-radius:18px;pointer-events:none;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.04'/%3E%3C/svg%3E");
  opacity:.5;z-index:0;
}
.sw-card>*{position:relative;z-index:1}

/* severity tints */
.sw-card-crit{
  border-color:rgba(239,68,68,.18);
  box-shadow:0 0 0 1px rgba(239,68,68,.08),0 24px 48px rgba(0,0,0,.5),inset 0 1px 0 rgba(239,68,68,.06);
}
.sw-card-crit::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:18px 18px 0 0;
  background:linear-gradient(90deg,#ef4444,#dc2626,transparent);
}
.sw-card-good{
  border-color:rgba(34,211,238,.18);
  box-shadow:0 0 0 1px rgba(34,211,238,.08),0 24px 48px rgba(0,0,0,.5),inset 0 1px 0 rgba(34,211,238,.06);
}
.sw-card-good::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:18px 18px 0 0;
  background:linear-gradient(90deg,#22d3ee,#67e8f9,transparent);
}
.sw-card-warn{
  border-color:rgba(245,158,11,.14);
  box-shadow:0 0 0 1px rgba(245,158,11,.07),0 24px 48px rgba(0,0,0,.5),inset 0 1px 0 rgba(245,158,11,.05);
}
.sw-card-warn::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:18px 18px 0 0;
  background:linear-gradient(90deg,#f59e0b,#fbbf24,transparent);
}
.sw-card-ai{
  border-color:rgba(139,92,246,.2);
  box-shadow:0 0 0 1px rgba(139,92,246,.08),0 24px 48px rgba(0,0,0,.5),inset 0 1px 0 rgba(139,92,246,.06);
}
.sw-card-ai::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:18px 18px 0 0;
  background:linear-gradient(90deg,#8b5cf6,#a78bfa,#22d3ee);
}

/* ── Browser chrome bar ── */
.sw-chrome{
  display:flex;align-items:center;gap:8px;
  background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05);
  border-radius:8px;padding:7px 12px;margin-bottom:16px;
}
.sw-chrome-dots{display:flex;gap:5px}
.sw-chrome-dot{width:9px;height:9px;border-radius:50%}
.sw-chrome-url{
  flex:1;font-family:'JetBrains Mono',monospace;font-size:.72rem;
  color:#334155;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}
.sw-chrome-lock{font-size:.72rem;margin-right:6px}

/* ── Score ring ── */
.sw-header{display:flex;align-items:center;gap:16px;margin-bottom:16px}
.sw-ring-wrap{flex-shrink:0;position:relative;width:68px;height:68px}
.sw-ring-wrap svg{transform:rotate(-90deg)}
.sw-ring-bg{fill:none;stroke:rgba(255,255,255,.06);stroke-width:7}
.sw-ring-fill{fill:none;stroke-width:7;stroke-linecap:round;transition:stroke-dashoffset 1.4s ease}
.sw-ring-label{
  position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;line-height:1;
}
.sw-score-num{font-size:1.15rem;font-weight:900;line-height:1}
.sw-score-grade{font-size:.6rem;font-weight:700;letter-spacing:.06em;margin-top:1px;opacity:.7}
.sw-meta{flex:1;min-width:0}
.sw-site-name{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:#94a3b8;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:4px}
.sw-scan-stats{display:flex;flex-wrap:wrap;gap:6px}
.sw-stat{
  font-size:.65rem;font-family:'JetBrains Mono',monospace;font-weight:700;
  padding:2px 8px;border-radius:5px;
}
.sw-stat-c{background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.2)}
.sw-stat-h{background:rgba(251,146,60,.1);color:#fb923c;border:1px solid rgba(251,146,60,.18)}
.sw-stat-m{background:rgba(251,191,36,.1);color:#fbbf24;border:1px solid rgba(251,191,36,.18)}
.sw-stat-ok{background:rgba(34,211,238,.1);color:#67e8f9;border:1px solid rgba(34,211,238,.2)}

/* ── Findings ── */
.sw-findings{display:flex;flex-direction:column;gap:7px;margin-bottom:14px}
.sw-finding{
  display:flex;align-items:flex-start;gap:9px;
  background:rgba(255,255,255,.02);border-radius:8px;
  padding:8px 10px;border:1px solid rgba(255,255,255,.04);
}
.sw-sev{
  font-family:'JetBrains Mono',monospace;font-size:.6rem;font-weight:700;
  padding:2px 6px;border-radius:4px;white-space:nowrap;margin-top:1px;flex-shrink:0;
}
.sw-sev-c{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.25)}
.sw-sev-h{background:rgba(251,146,60,.12);color:#fb923c;border:1px solid rgba(251,146,60,.2)}
.sw-sev-m{background:rgba(251,191,36,.1);color:#fbbf24;border:1px solid rgba(251,191,36,.18)}
.sw-sev-l{background:rgba(34,211,238,.08);color:#67e8f9;border:1px solid rgba(34,211,238,.15)}
.sw-finding-txt{color:#7a8fa6;font-size:.75rem;line-height:1.45}
.sw-finding-txt strong{color:#cbd5e1;font-weight:600}
.sw-finding-txt code{
  font-family:'JetBrains Mono',monospace;font-size:.68rem;
  background:rgba(255,255,255,.06);padding:1px 5px;border-radius:4px;
}
/* critical pulse on critical finding row */
.sw-finding-crit{border-color:rgba(239,68,68,.15);animation:critglow 2.5s ease-in-out infinite}
@keyframes critglow{0%,100%{box-shadow:none}50%{box-shadow:0 0 12px rgba(239,68,68,.12)}}

/* ── Tool pills ── */
.sw-tools{display:flex;flex-wrap:wrap;gap:5px}
.sw-tool{
  font-family:'JetBrains Mono',monospace;font-size:.6rem;font-weight:600;
  padding:3px 8px;border-radius:6px;display:flex;align-items:center;gap:4px;
}
.sw-tool-ok{background:rgba(34,211,238,.08);color:#22d3ee;border:1px solid rgba(34,211,238,.18)}
.sw-tool-warn{background:rgba(245,158,11,.07);color:#f59e0b;border:1px solid rgba(245,158,11,.16)}
.sw-tool-err{background:rgba(239,68,68,.08);color:#ef4444;border:1px solid rgba(239,68,68,.18)}

/* ── AI card ── */
.sw-ai-header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.sw-ai-icon{
  width:38px;height:38px;border-radius:10px;flex-shrink:0;
  background:linear-gradient(135deg,#7c3aed,#4f46e5);
  display:flex;align-items:center;justify-content:center;font-size:1.1rem;
}
.sw-ai-label{color:#a78bfa;font-size:.78rem;font-weight:700;letter-spacing:.04em}
.sw-ai-sub{color:#475569;font-size:.67rem;margin-top:1px}
.sw-ai-prompt{
  font-family:'JetBrains Mono',monospace;font-size:.7rem;
  color:#334155;background:rgba(255,255,255,.02);
  border:1px solid rgba(255,255,255,.05);border-radius:8px;
  padding:8px 12px;margin-bottom:12px;
}
.sw-ai-prompt span{color:#22d3ee}
.sw-rec{display:flex;gap:10px;padding:9px 11px;border-radius:9px;margin-bottom:6px;
  background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.04)}
.sw-rec-num{
  width:20px;height:20px;border-radius:50%;flex-shrink:0;margin-top:1px;
  background:linear-gradient(135deg,#7c3aed,#4f46e5);
  display:flex;align-items:center;justify-content:center;
  font-size:.65rem;font-weight:900;color:#fff;
}
.sw-rec-txt{color:#7a8fa6;font-size:.74rem;line-height:1.45}
.sw-rec-txt strong{color:#c4b5fd;font-weight:600}
.sw-rec-txt code{
  font-family:'JetBrains Mono',monospace;font-size:.67rem;
  background:rgba(139,92,246,.1);color:#a78bfa;padding:1px 5px;border-radius:4px;
}
.sw-rec-txt em{color:#22d3ee;font-style:normal;font-weight:600}

/* ── Section CTA ── */
.sw-cta-row{display:flex;align-items:center;justify-content:center;gap:16px;
  margin-top:28px;padding:20px;
  border:1px solid rgba(34,211,238,.12);border-radius:14px;
  background:linear-gradient(135deg,rgba(34,211,238,.04),rgba(34,211,238,.01));
}
.sw-cta-txt{color:#475569;font-size:.84rem}
.sw-cta-txt strong{color:#22d3ee}
.sw-cta-badge{
  background:linear-gradient(135deg,#22d3ee,#0891b2);
  color:#fff;font-size:.72rem;font-weight:700;
  padding:6px 16px;border-radius:8px;white-space:nowrap;letter-spacing:.02em;
}
</style>

<div class="sw">
  <div class="sw-eyebrow">
    <div class="sw-eyebrow-dot"></div>
    <span class="sw-eyebrow-txt">Live scan previews</span>
  </div>
  <h2 class="sw-h">What we find in <span>under 60 seconds</span></h2>
  <p class="sw-sub">Real findings. Real sites. Your site probably has several of these right now.</p>

  <div class="sw-grid">

    <!-- ═══ Card 1 — CRITICAL site ═══ -->
    <div class="sw-card sw-card-crit">
      <div class="sw-chrome">
        <div class="sw-chrome-dots">
          <div class="sw-chrome-dot" style="background:#ff5f57"></div>
          <div class="sw-chrome-dot" style="background:#febc2e"></div>
          <div class="sw-chrome-dot" style="background:#28c840"></div>
        </div>
        <span class="sw-chrome-lock">🔴</span>
        <span class="sw-chrome-url">http://example-shop.com/checkout</span>
      </div>
      <div class="sw-header">
        <div class="sw-ring-wrap">
          <svg width="68" height="68" viewBox="0 0 68 68">
            <circle class="sw-ring-bg" cx="34" cy="34" r="28"/>
            <circle class="sw-ring-fill" cx="34" cy="34" r="28"
              stroke="#ef4444"
              stroke-dasharray="175.9"
              stroke-dashoffset="137"/>
          </svg>
          <div class="sw-ring-label">
            <span class="sw-score-num" style="color:#ef4444">22</span>
            <span class="sw-score-grade" style="color:#ef4444">F</span>
          </div>
        </div>
        <div class="sw-meta">
          <div class="sw-site-name">example-shop.com</div>
          <div class="sw-scan-stats">
            <span class="sw-stat sw-stat-c">3 CRITICAL</span>
            <span class="sw-stat sw-stat-h">5 HIGH</span>
            <span class="sw-stat sw-stat-m">4 MEDIUM</span>
          </div>
        </div>
      </div>
      <div class="sw-findings">
        <div class="sw-finding sw-finding-crit">
          <span class="sw-sev sw-sev-c">CRIT</span>
          <span class="sw-finding-txt">SSL certificate <strong>expired 47 days ago</strong> — every visitor sees a red "Not Secure" warning</span>
        </div>
        <div class="sw-finding sw-finding-crit">
          <span class="sw-sev sw-sev-c">CRIT</span>
          <span class="sw-finding-txt">AWS S3 bucket <strong>publicly readable</strong> — 847 customer files exposed, no auth required</span>
        </div>
        <div class="sw-finding">
          <span class="sw-sev sw-sev-h">HIGH</span>
          <span class="sw-finding-txt">Live API key in JS: <code>sk_live_4Kx9...</code> — anyone can read your source and steal it</span>
        </div>
        <div class="sw-finding">
          <span class="sw-sev sw-sev-h">HIGH</span>
          <span class="sw-finding-txt"><strong>Email spoofable</strong> — no SPF/DMARC, attackers can send mail as you@example-shop.com</span>
        </div>
      </div>
      <div class="sw-tools">
        <span class="sw-tool sw-tool-err">🔒 TLS ✗</span>
        <span class="sw-tool sw-tool-err">☁️ S3 ✗</span>
        <span class="sw-tool sw-tool-err">⚡ JS Keys ✗</span>
        <span class="sw-tool sw-tool-err">📧 SPF ✗</span>
        <span class="sw-tool sw-tool-warn">📋 Headers ⚠</span>
        <span class="sw-tool sw-tool-ok">🌍 DNS ✓</span>
      </div>
    </div>

    <!-- ═══ Card 2 — GOOD site ═══ -->
    <div class="sw-card sw-card-good">
      <div class="sw-chrome">
        <div class="sw-chrome-dots">
          <div class="sw-chrome-dot" style="background:#ff5f57"></div>
          <div class="sw-chrome-dot" style="background:#febc2e"></div>
          <div class="sw-chrome-dot" style="background:#28c840"></div>
        </div>
        <span class="sw-chrome-lock">🔒</span>
        <span class="sw-chrome-url">https://secure-startup.io</span>
      </div>
      <div class="sw-header">
        <div class="sw-ring-wrap">
          <svg width="68" height="68" viewBox="0 0 68 68">
            <circle class="sw-ring-bg" cx="34" cy="34" r="28"/>
            <circle class="sw-ring-fill" cx="34" cy="34" r="28"
              stroke="#22d3ee"
              stroke-dasharray="175.9"
              stroke-dashoffset="16"/>
          </svg>
          <div class="sw-ring-label">
            <span class="sw-score-num" style="color:#22d3ee">91</span>
            <span class="sw-score-grade" style="color:#22d3ee">A</span>
          </div>
        </div>
        <div class="sw-meta">
          <div class="sw-site-name">secure-startup.io</div>
          <div class="sw-scan-stats">
            <span class="sw-stat sw-stat-ok">0 CRITICAL</span>
            <span class="sw-stat sw-stat-m">1 MEDIUM</span>
            <span class="sw-stat sw-stat-ok">15 PASSED</span>
          </div>
        </div>
      </div>
      <div class="sw-findings">
        <div class="sw-finding">
          <span class="sw-sev sw-sev-m">MED</span>
          <span class="sw-finding-txt"><strong>Permissions-Policy</strong> header missing — camera/microphone access not restricted</span>
        </div>
        <div class="sw-finding">
          <span class="sw-sev sw-sev-l">LOW</span>
          <span class="sw-finding-txt">Server version disclosed: <code>Apache/2.4.54</code> — consider hiding for stealth</span>
        </div>
        <div class="sw-finding">
          <span class="sw-sev sw-sev-l">INFO</span>
          <span class="sw-finding-txt">Wayback Machine shows 3 old endpoints still cached — verify they're intentional</span>
        </div>
      </div>
      <div class="sw-tools">
        <span class="sw-tool sw-tool-ok">🔒 TLS ✓</span>
        <span class="sw-tool sw-tool-ok">📧 SPF ✓</span>
        <span class="sw-tool sw-tool-ok">📋 Headers ✓</span>
        <span class="sw-tool sw-tool-ok">🌍 DNSSEC ✓</span>
        <span class="sw-tool sw-tool-ok">🍪 Cookies ✓</span>
        <span class="sw-tool sw-tool-ok">🔀 CORS ✓</span>
        <span class="sw-tool sw-tool-warn">🛡 Perms ⚠</span>
      </div>
    </div>

    <!-- ═══ Card 3 — MEDIUM WordPress ═══ -->
    <div class="sw-card sw-card-warn">
      <div class="sw-chrome">
        <div class="sw-chrome-dots">
          <div class="sw-chrome-dot" style="background:#ff5f57"></div>
          <div class="sw-chrome-dot" style="background:#febc2e"></div>
          <div class="sw-chrome-dot" style="background:#28c840"></div>
        </div>
        <span class="sw-chrome-lock">🔒</span>
        <span class="sw-chrome-url">https://mybusiness.co.il</span>
      </div>
      <div class="sw-header">
        <div class="sw-ring-wrap">
          <svg width="68" height="68" viewBox="0 0 68 68">
            <circle class="sw-ring-bg" cx="34" cy="34" r="28"/>
            <circle class="sw-ring-fill" cx="34" cy="34" r="28"
              stroke="#f59e0b"
              stroke-dasharray="175.9"
              stroke-dashoffset="45"/>
          </svg>
          <div class="sw-ring-label">
            <span class="sw-score-num" style="color:#f59e0b">74</span>
            <span class="sw-score-grade" style="color:#f59e0b">B</span>
          </div>
        </div>
        <div class="sw-meta">
          <div class="sw-site-name">mybusiness.co.il</div>
          <div class="sw-scan-stats">
            <span class="sw-stat sw-stat-h">2 HIGH</span>
            <span class="sw-stat sw-stat-m">3 MEDIUM</span>
            <span class="sw-stat sw-stat-ok">12 PASSED</span>
          </div>
        </div>
      </div>
      <div class="sw-findings">
        <div class="sw-finding">
          <span class="sw-sev sw-sev-h">HIGH</span>
          <span class="sw-finding-txt"><strong>WordPress 6.1.3</strong> — 12 known CVEs (CVSS up to 8.8). Latest is 6.5.4</span>
        </div>
        <div class="sw-finding">
          <span class="sw-sev sw-sev-h">HIGH</span>
          <span class="sw-finding-txt"><strong>/wp-admin exposed</strong> — no rate limiting, brute-force attack possible in minutes</span>
        </div>
        <div class="sw-finding">
          <span class="sw-sev sw-sev-m">MED</span>
          <span class="sw-finding-txt">CORS: <code>Access-Control-Allow-Origin: *</code> — any website can read your API responses</span>
        </div>
        <div class="sw-finding">
          <span class="sw-sev sw-sev-m">MED</span>
          <span class="sw-finding-txt">HSTS <code>max-age=2592000</code> (30 days) — too short, attackers can downgrade to HTTP</span>
        </div>
      </div>
      <div class="sw-tools">
        <span class="sw-tool sw-tool-ok">🔒 TLS ✓</span>
        <span class="sw-tool sw-tool-err">🛡 CVE ✗</span>
        <span class="sw-tool sw-tool-err">🔑 Admin ✗</span>
        <span class="sw-tool sw-tool-warn">🔀 CORS ⚠</span>
        <span class="sw-tool sw-tool-warn">📌 HSTS ⚠</span>
        <span class="sw-tool sw-tool-ok">📧 Email ✓</span>
      </div>
    </div>

    <!-- ═══ Card 4 — AI Recommendations ═══ -->
    <div class="sw-card sw-card-ai">
      <div class="sw-ai-header">
        <div class="sw-ai-icon">✨</div>
        <div>
          <div class="sw-ai-label">AI Security Report</div>
          <div class="sw-ai-sub">Generated in 9 seconds · mybusiness.co.il</div>
        </div>
      </div>
      <div class="sw-ai-prompt">
        <span style="color:#475569">$ </span><span>Analyzing 18 tool results · generating priority fix plan…</span><span style="color:#22d3ee"> ▋</span>
      </div>
      <div class="sw-rec">
        <div class="sw-rec-num">1</div>
        <div class="sw-rec-txt">
          <strong>Update WordPress NOW.</strong> Run <code>wp core update && wp plugin update --all</code>
          — patches 12 CVEs including one rated <em>CVSS 8.8</em>
        </div>
      </div>
      <div class="sw-rec">
        <div class="sw-rec-num">2</div>
        <div class="sw-rec-txt">
          <strong>Lock down /wp-admin.</strong> Install Wordfence, enable 2FA, whitelist your IP.
          Default config allows unlimited login attempts — trivially brute-forceable.
        </div>
      </div>
      <div class="sw-rec">
        <div class="sw-rec-num">3</div>
        <div class="sw-rec-txt">
          <strong>Fix CORS header:</strong> replace <code>Allow-Origin: *</code> with
          <code>Allow-Origin: https://mybusiness.co.il</code> — takes 2 minutes in nginx/Apache.
        </div>
      </div>
      <div class="sw-rec">
        <div class="sw-rec-num">4</div>
        <div class="sw-rec-txt">
          <strong>Extend HSTS:</strong> set <code>max-age=31536000; includeSubDomains; preload</code>
          then submit to Chrome's <em>HSTS preload list</em> for permanent protection.
        </div>
      </div>
    </div>

  </div>

  <div class="sw-cta-row">
    <div class="sw-cta-txt">
      <strong>Is your site on this list?</strong> Create a free account and scan it in 60 seconds.
    </div>
    <div class="sw-cta-badge">↑ Sign up free above</div>
  </div>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Footer  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

def _get_footer_html(lang: str = "he") -> str:
    from translations import t as _t2
    tos     = _t2("tos_link")
    privacy = _t2("privacy_link")
    contact = _t2("contact_link")
    disc    = _t2("footer_disclaimer")
    return f"""<div style="text-align:center;color:#334155;font-size:0.71rem;padding:20px 0 40px;border-top:1px solid #1e2d3d;line-height:2">
  <a href="/?legal=tos" style="color:#475569;text-decoration:none">{tos}</a>
  &nbsp;·&nbsp;
  <a href="/?legal=privacy" style="color:#475569;text-decoration:none">{privacy}</a>
  &nbsp;·&nbsp;
  <a href="mailto:{CONTACT_EMAIL}" style="color:#475569;text-decoration:none">{contact}</a>
  <br>
  <a href="tel:{CONTACT_PHONE_RAW}" style="color:#475569;text-decoration:none">📞 {CONTACT_PHONE}</a>
  &nbsp;·&nbsp;
  <a href="mailto:{CONTACT_EMAIL}" style="color:#475569;text-decoration:none">✉️ {CONTACT_EMAIL}</a>
  <br>{disc}
</div>"""

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
    from legal_pages import (
        show_terms_of_service, show_privacy_policy,
        show_cookie_policy, show_accessibility_statement,
    )

    # Handle ?legal= query param — all 4 legal docs accessible WITHOUT login
    _legal_qp = st.query_params.get("legal", "")
    _legal_map = {
        "tos":           show_terms_of_service,
        "privacy":       show_privacy_policy,
        "cookies":       show_cookie_policy,
        "accessibility": show_accessibility_statement,
    }
    if _legal_qp in _legal_map:
        st.query_params.clear()
        st.markdown(_LANDING_CSS, unsafe_allow_html=True)
        _legal_map[_legal_qp]()
        st.markdown("---")
        if st.button("← Back to AI Cyber Shield", key="legal_lp_back", type="primary"):
            st.rerun()
        st.stop()

    st.markdown(_LANDING_CSS, unsafe_allow_html=True)

    # ── Translations / RTL ────────────────────────────────────────────────────
    from translations import lang_switcher, inject_rtl_css, get_lang as _get_lang, t as _t
    inject_rtl_css()

    # ── Navigation bar ────────────────────────────────────────────────────────
    st.html(_NAV_HTML)

    # ── Two-column split: 60% marketing, 40% auth form ───────────────────────
    col_left, col_right = st.columns([3, 2], gap="large")

    # ── LEFT: product marketing ───────────────────────────────────────────────
    with col_left:
        st.markdown(_get_hero_html(_get_lang()), unsafe_allow_html=True)
        st.html(_STATS_HTML)
        st.markdown(_FEATURES_HTML, unsafe_allow_html=True)
        st.html(_SHOWCASE_HTML)

    # ── RIGHT: language toggle + auth card ───────────────────────────────────
    with col_right:
        # Language switcher sits neatly above the auth card
        lang_switcher("landing")
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        # ── View state ────────────────────────────────────────────────────────
        if "_auth_view" not in st.session_state:
            st.session_state["_auth_view"] = "signin"
        _view = st.session_state["_auth_view"]

        _card_meta = {
            "signin":         (_t("auth_signin_title"), _t("auth_signin_sub")),
            "signup":         (_t("auth_signup_title"), _t("auth_signup_sub")),
            "reset":          (_t("auth_reset_title"),  _t("auth_reset_sub")),
            "signup_confirm": ("Check your inbox 📧",   "One more step"),
        }
        _hl, _sub = _card_meta.get(_view, _card_meta["signin"])

        # ── Dynamic card header ───────────────────────────────────────────────
        st.markdown(_auth_card_top(_hl, _sub), unsafe_allow_html=True)

        # ── Google OAuth (shown for signin + signup) ──────────────────────────
        if _view in ("signin", "signup"):
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
            # CSS: style the link_button to look like a Google button
            st.markdown("""
<style>
/* st.link_button renders as <a> inside [data-testid="stLinkButton"] */
[data-testid="stLinkButton"] a {
  background:#ffffff!important;color:#1f1f1f!important;
  border:1px solid #dadce0!important;border-radius:10px!important;
  font-weight:600!important;font-size:0.9rem!important;
  text-decoration:none!important;
  display:flex!important;align-items:center!important;justify-content:center!important;
  transition:background 0.15s,border-color 0.15s!important;
  box-shadow:0 1px 4px rgba(0,0,0,0.14)!important;
}
[data-testid="stLinkButton"] a:hover{
  background:#f8f8f8!important;border-color:#bbb!important;
  box-shadow:0 2px 8px rgba(0,0,0,0.18)!important;
}
</style>""", unsafe_allow_html=True)
            from auth.streamlit_auth import sign_in_with_google as _sig
            _gg = _sig()
            if "url" in _gg:
                # st.link_button renders a real <a href> — no JavaScript needed,
                # works in all browsers including Streamlit Cloud iframes.
                st.link_button(
                    f"G  {_t('auth_google')}",
                    url=_gg["url"],
                    use_container_width=True,
                )
            else:
                st.button(
                    f"G  {_t('auth_google')}",
                    use_container_width=True,
                    disabled=True,
                    key=f"google_disabled_{_view}",
                )
                st.error(_gg.get("error", "Google OAuth is not configured. Enable it in Supabase → Auth → Providers → Google."))

            st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;margin:14px 0 10px">
  <div style="flex:1;height:1px;background:#1a2a3d"></div>
  <span style="color:#2d4056;font-size:0.7rem;white-space:nowrap;letter-spacing:0.06em">{_t('auth_or_email')}</span>
  <div style="flex:1;height:1px;background:#1a2a3d"></div>
</div>""", unsafe_allow_html=True)

        # ── Form content ──────────────────────────name="auth-body"──────────
        st.markdown("<div style='height:2px'></div>", unsafe_allow_html=True)

        # ── Sign In ───────────────────────────────────────────────────────────
        if _view == "signin":
            _li_email = st.text_input(
                _t("auth_email"), key="li_email", placeholder="you@example.com",
            )
            _li_pass = st.text_input(
                _t("auth_password"), type="password", key="li_pass", placeholder="••••••••",
            )
            st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

            if st.button(_t("auth_signin_btn"), use_container_width=True, key="li_btn", type="primary"):
                if not _li_email or not _li_pass:
                    st.error(_t("auth_fill_both"))
                elif not _valid_email(_li_email):
                    st.error(_t("auth_valid_email"))
                else:
                    with st.spinner("Authenticating…"):
                        result = sign_in(_li_email.strip().lower(), _li_pass)
                    if result.get("ok"):
                        from audit_log import log_action
                        log_action("login", details={"method": "password"})
                        st.rerun()
                    else:
                        st.error(result.get("error", "Login failed"))

            # Toggle row
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
            _tc1, _tc2 = st.columns([1, 1])
            with _tc1:
                st.markdown(
                    f'<div style="color:#334155;font-size:0.79rem;padding-top:6px">{_t("auth_new_here")}</div>',
                    unsafe_allow_html=True,
                )
                st.markdown('<div class="auth-toggle-row">', unsafe_allow_html=True)
                if st.button(_t("auth_create_free"), key="go_signup"):
                    st.session_state["_auth_view"] = "signup"
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)
            with _tc2:
                st.markdown(
                    f'<div style="text-align:right;color:#334155;font-size:0.79rem;padding-top:6px">{_t("auth_trouble")}</div>',
                    unsafe_allow_html=True,
                )
                st.markdown('<div class="auth-toggle-row" style="text-align:right">', unsafe_allow_html=True)
                if st.button(_t("auth_reset_pw"), key="go_reset"):
                    st.session_state["_auth_view"] = "reset"
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)

        # ── Sign Up ───────────────────────────────────────────────────────────
        elif _view == "signup":
            st.markdown(
                '<div class="auth-notice">🔒 Only scan targets you own or have written permission to test.</div>',
                unsafe_allow_html=True,
            )
            _r_email = st.text_input(
                _t("auth_email"), key="reg_email", placeholder="you@example.com",
            )
            _r_pass = st.text_input(
                _t("auth_password"), type="password", key="reg_pass",
                placeholder="Min 8 chars + 1 number/symbol",
            )
            if _r_pass:
                _pw_score = sum([
                    len(_r_pass) >= 8,
                    len(_r_pass) >= 12,
                    any(c.isdigit() for c in _r_pass),
                    any(not c.isalnum() for c in _r_pass),
                    any(c.isupper() for c in _r_pass),
                ])
                _pwl = ["Too short", "Weak", "Fair", "Good", "Strong"][min(_pw_score, 4)]
                _pwc = ["#ef4444", "#f97316", "#f59e0b", "#60a5fa", "#22d3ee"][min(_pw_score, 4)]
                _pww = [16, 32, 52, 75, 100][min(_pw_score, 4)]
                st.markdown(
                    f'<div style="margin:-4px 0 10px">'
                    f'<div style="height:3px;background:#1e2d3d;border-radius:2px;overflow:hidden">'
                    f'<div style="width:{_pww}%;height:100%;background:{_pwc};border-radius:2px;transition:width 0.2s"></div>'
                    f'</div><div style="color:{_pwc};font-size:0.7rem;margin-top:3px">{_pwl}</div></div>',
                    unsafe_allow_html=True,
                )
            _r_pass2 = st.text_input(
                "Confirm password", type="password", key="reg_pass2",
                placeholder="Repeat your password",
            )
            if _r_pass and _r_pass2 and _r_pass != _r_pass2:
                st.markdown(
                    '<div style="color:#ef4444;font-size:0.72rem;margin:-4px 0 6px">Passwords do not match</div>',
                    unsafe_allow_html=True,
                )
            st.markdown(
                '<div style="color:#334155;font-size:0.71rem;margin-bottom:10px;line-height:1.6">'
                'By signing up you agree to our '
                '<a href="/?legal=tos" style="color:#475569;text-decoration:underline">Terms</a>'
                ' and <a href="/?legal=privacy" style="color:#475569;text-decoration:underline">Privacy Policy</a>.'
                '</div>',
                unsafe_allow_html=True,
            )
            if st.button(_t("auth_signup_btn"), use_container_width=True, key="reg_btn", type="primary"):
                _errors = []
                if not _r_email or not _valid_email(_r_email):
                    _errors.append("Enter a valid email address.")
                _ok_pw, _pw_msg = _valid_password(_r_pass)
                if not _ok_pw:
                    _errors.append(f"Password: {_pw_msg}")
                if _r_pass and _r_pass2 and _r_pass != _r_pass2:
                    _errors.append("Passwords do not match.")
                if _errors:
                    for _e in _errors:
                        st.error(_e)
                else:
                    with st.spinner("Creating account…"):
                        result = sign_up(_r_email.strip().lower(), _r_pass)
                    if result.get("ok"):
                        from audit_log import log_action
                        log_action("signup", target=_r_email.strip().lower(), details={"confirm_required": result.get("confirm_required", False)})
                        if result.get("confirm_required"):
                            # Switch to dedicated confirmation screen
                            st.session_state["_signup_email"] = _r_email.strip().lower()
                            st.session_state["_auth_view"] = "signup_confirm"
                            st.rerun()
                        else:
                            st.success(_t("auth_confirmed_ok"))
                    else:
                        st.error(result.get("error", "Registration failed"))

            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            st.markdown('<div class="auth-toggle-row">', unsafe_allow_html=True)
            if st.button(_t("auth_have_account"), key="go_signin_from_reg"):
                st.session_state["_auth_view"] = "signin"
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Reset Password ────────────────────────────────────────────────────
        elif _view == "reset":
            st.markdown(
                '<div style="color:#64748b;font-size:0.82rem;line-height:1.6;margin-bottom:14px">'
                'Enter your email and we\'ll send a link to reset your password.'
                '</div>',
                unsafe_allow_html=True,
            )
            _rst_email = st.text_input(
                _t("auth_email"), key="rst_email", placeholder="you@example.com",
            )
            st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
            if st.button(_t("auth_reset_btn"), use_container_width=True, key="rst_btn", type="primary"):
                if not _rst_email or not _valid_email(_rst_email):
                    st.error(_t("auth_valid_email"))
                else:
                    with st.spinner("Sending…"):
                        result = request_password_reset(_rst_email.strip().lower())
                    if result.get("ok"):
                        st.success(_t("auth_reset_sent"))
                        st.info("📧 Spam folder  ·  🔒 Link expires 24 h  ·  Return here to sign in")
                    else:
                        st.error(result.get("error", "Failed to send reset email"))

            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            st.markdown('<div class="auth-toggle-row">', unsafe_allow_html=True)
            if st.button(_t("auth_back_signin"), key="go_signin_from_reset"):
                st.session_state["_auth_view"] = "signin"
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Email confirmation pending screen ─────────────────────────────────
        elif _view == "signup_confirm":
            _conf_email = st.session_state.get("_signup_email", "your email")
            st.markdown(f"""
<div style="text-align:center;padding:18px 0 8px">
  <div style="font-size:2.6rem;margin-bottom:14px">📧</div>
  <div style="color:#f1f5f9;font-weight:700;font-size:1.05rem;margin-bottom:8px">
    Confirmation email sent!
  </div>
  <div style="color:#64748b;font-size:0.82rem;line-height:1.65;margin-bottom:20px">
    We sent a link to <strong style="color:#22d3ee">{_conf_email}</strong>.<br>
    Click the link in the email to activate your account.
  </div>
  <div style="background:#0c2030;border:1px solid #1a3a50;border-radius:10px;padding:12px 16px;font-size:0.77rem;color:#475569;line-height:1.75;text-align:left">
    📂 Check spam/junk folder<br>
    🔒 Link expires in 24 hours<br>
    🔄 Once confirmed, sign in below
  </div>
</div>""", unsafe_allow_html=True)
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
            if st.button("Sign in after confirming →", use_container_width=True, key="go_signin_after_confirm", type="primary"):
                st.session_state["_auth_view"] = "signin"
                st.rerun()
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            st.markdown('<div class="auth-toggle-row">', unsafe_allow_html=True)
            if st.button("← Start over", key="go_signup_from_confirm"):
                st.session_state["_auth_view"] = "signup"
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Card footer + JS column marker ────────────────────────────────────
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        st.markdown(_get_auth_card_footer(_get_lang()), unsafe_allow_html=True)

        # JS: mark auth column + apply Google button white styling
        st.html("""<script>
(function(){
  function markCol(){
    var t=document.querySelector('.auth-card-top');
    if(!t){setTimeout(markCol,120);return;}
    for(var n=t,i=0;i<16;i++){
      n=n.parentElement;
      if(!n)break;
      var td=n.getAttribute&&n.getAttribute('data-testid');
      if(td==='column'||td==='stColumn'){
        n.classList.add('aics-auth-col');
        var btns=n.querySelectorAll('button');
        btns.forEach(function(b){
          if(b.textContent.includes('Google')){
            b.style.cssText='background:#fff!important;color:#1f1f1f!important;border:1px solid #dadce0!important;border-radius:10px!important;font-weight:600!important;';
          }
        });
        return;
      }
    }
  }
  markCol();
})();
</script>""")

    # ── FULL WIDTH: social proof → pricing → footer ───────────────────────────
    st.html(_SOCIAL_PROOF_HTML)
    st.html(_PRICING_HTML)
    st.html(_get_footer_html(_get_lang()))


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

    tab_analytics, tab_logs, tab_users = st.tabs(["📊 Analytics", "Audit Logs", "Users & PT Approval"])

    with tab_analytics:
        from datetime import datetime, timezone, timedelta
        _now = datetime.now(timezone.utc)
        _week_ago = (_now - timedelta(days=7)).isoformat()
        _today_str = _now.date().isoformat()

        _all_users = fetch_all_users()
        _all_logs  = fetch_audit_logs(500)

        _new_this_week = sum(
            1 for u in _all_users
            if (u.get("created_at") or "") >= _week_ago
        )
        _paid_users = sum(
            1 for u in _all_users
            if u.get("subscription_tier", "free") != "free"
        )
        _scans_today = sum(
            1 for l in _all_logs
            if l.get("action") == "scan_complete"
            and (l.get("created_at") or "")[:10] == _today_str
        )
        _scans_week = sum(
            1 for l in _all_logs
            if l.get("action") == "scan_complete"
            and (l.get("created_at") or "") >= _week_ago
        )
        _logins_today = sum(
            1 for l in _all_logs
            if l.get("action") == "login"
            and (l.get("created_at") or "")[:10] == _today_str
        )
        _signups_week = sum(
            1 for l in _all_logs
            if l.get("action") == "signup"
            and (l.get("created_at") or "") >= _week_ago
        )

        # Summary metric cards
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Total Users", len(_all_users), delta=f"+{_new_this_week} this week")
        mc2.metric("Paid Users", _paid_users)
        mc3.metric("Scans Today", _scans_today, delta=f"+{_scans_week} this week")
        mc4.metric("Logins Today", _logins_today)

        st.markdown("---")

        # Daily scans chart — last 7 days
        _day_counts: dict[str, int] = {}
        for _i in range(7):
            _d = (_now - timedelta(days=6 - _i)).date().isoformat()
            _day_counts[_d] = 0
        for _l in _all_logs:
            if _l.get("action") == "scan_complete":
                _d = (_l.get("created_at") or "")[:10]
                if _d in _day_counts:
                    _day_counts[_d] += 1
        _chart_df = pd.DataFrame({"Date": list(_day_counts.keys()), "Scans": list(_day_counts.values())})
        _chart_df = _chart_df.set_index("Date")
        st.subheader("Scans per day (last 7 days)")
        st.bar_chart(_chart_df)

        st.markdown("---")

        # Action breakdown table
        _action_counts: dict[str, int] = {}
        for _l in _all_logs:
            _a = _l.get("action", "unknown")
            _action_counts[_a] = _action_counts.get(_a, 0) + 1
        _action_rows = [{"Action": k, "Count": v} for k, v in sorted(_action_counts.items(), key=lambda x: -x[1])]
        col_act, col_recent = st.columns([1, 2])
        with col_act:
            st.subheader("Event types")
            st.dataframe(pd.DataFrame(_action_rows), hide_index=True, use_container_width=True)
        with col_recent:
            st.subheader("Recent signups")
            _recent_signups = [
                {"Email": u.get("email", "—"), "Tier": u.get("subscription_tier", "free"), "Joined": (u.get("created_at") or "")[:10]}
                for u in _all_users[:10]
            ]
            st.dataframe(pd.DataFrame(_recent_signups), hide_index=True, use_container_width=True)

        st.markdown("---")
        st.caption(f"Data from last 500 audit log entries · refreshes on page reload")

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

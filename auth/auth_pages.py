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
.block-container { padding-top: 0 !important; padding-bottom: 0 !important; padding-left: 1rem !important; padding-right: 1rem !important; background: #060b14; }

/* ── Brand ──────────────────────────────────────────────── */
.lp-brand { display:flex; align-items:center; gap:14px; margin-bottom:24px; margin-top:8px; }
.lp-brand-icon { font-size:1.8rem; line-height:1; }
.lp-brand-name { font-family:'JetBrains Mono','Courier New',monospace; font-size:1.3rem; font-weight:900; color:#10b981; letter-spacing:-0.04em; line-height:1.1; }
.lp-brand-sub { color:#334155; font-size:0.58rem; letter-spacing:0.2em; text-transform:uppercase; margin-top:2px; }

/* ── Hero ───────────────────────────────────────────────── */
.lp-headline { font-size:3.2rem; font-weight:900; color:#f1f5f9; line-height:1.08; margin:0 0 18px; letter-spacing:-0.03em; }
.lp-headline em { color:#10b981; font-style:normal; background:linear-gradient(90deg,#10b981,#34d399); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }
.lp-desc { color:#94a3b8; font-size:0.97rem; line-height:1.72; max-width:520px; margin:0 0 22px; }
.lp-cta-row { display:flex; align-items:center; gap:16px; margin-bottom:28px; flex-wrap:wrap; }
.lp-cta-btn { display:inline-flex; align-items:center; gap:8px; background:#10b981; color:#000; font-weight:800; font-size:0.88rem; padding:11px 24px; border-radius:9px; letter-spacing:-0.01em; }
.lp-cta-note { color:#475569; font-size:0.75rem; }

/* ── Stats ──────────────────────────────────────────────── */
.lp-stats { display:flex; gap:20px; flex-wrap:wrap; margin-bottom:32px; padding-bottom:28px; border-bottom:1px solid #1e2d3d; }
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
.lp-free-badge { display:inline-flex; align-items:center; gap:8px; background:#0a2018; border:1px solid #10b981; border-radius:8px; padding:9px 15px; font-size:0.8rem; color:#86efac; margin-bottom:8px; flex-wrap:wrap; }
.lp-free-badge strong { color:#34d399; }

/* ── Auth card (floating card effect) ───────────────────── */
.auth-card-top { background:#0d1421; border:1px solid #2a3d52; border-bottom:none; border-radius:16px 16px 0 0; padding:26px 28px 20px; box-shadow:0 4px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(16,185,129,0.06); }
.auth-card-brand { display:flex; align-items:center; justify-content:center; margin-bottom:10px; }
.auth-card-title { font-size:1.25rem; font-weight:800; color:#f1f5f9; margin-bottom:4px; letter-spacing:-0.02em; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; }
.auth-card-sub { font-size:0.73rem; color:#475569; }
.auth-notice { background:#0f2027; border:1px solid #10b981; border-radius:8px; padding:10px 14px; font-size:0.79rem; color:#86efac; margin-bottom:16px; line-height:1.55; }
.auth-card-footer { background:#0d1421; border:1px solid #2a3d52; border-top:none; border-radius:0 0 16px 16px; padding:12px 28px 22px; text-align:center; color:#334155; font-size:0.69rem; line-height:1.75; box-shadow:0 8px 32px rgba(0,0,0,0.5); }

/* ── Auth column card (JS-injected .aics-auth-col on the right column) ── */
.aics-auth-col {
    background: #0b1220 !important;
    border-radius: 18px !important;
    overflow: hidden !important;
    box-shadow:
        0 1px 0 rgba(255,255,255,0.04) inset,
        0 24px 80px rgba(0,0,0,0.55),
        0 0 0 1px rgba(16,185,129,0.10) !important;
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
    border-color: #10b981 !important;
    box-shadow: 0 0 0 3px rgba(16,185,129,0.12) !important;
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

/* ── GitHub button ───────────────────────────────────────── */
.auth-github-row [data-testid="stButton"] button {
    background: #21262d !important;
    color: #e6edf3 !important;
    border: 1px solid #30363d !important;
    border-radius: 10px !important;
    font-weight: 700 !important;
    font-size: 0.88rem !important;
    box-shadow: none !important;
    letter-spacing: 0.01em !important;
    transition: background 0.15s, border-color 0.15s, transform 0.15s !important;
}
.auth-github-row [data-testid="stButton"] button:hover {
    background: #2d333b !important;
    border-color: #8b949e !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 3px 14px rgba(0,0,0,0.35) !important;
}

/* ── Toggle link buttons ─────────────────────────────────── */
.auth-toggle-row [data-testid="stButton"] button {
    background: transparent !important;
    color: #10b981 !important;
    border: none !important;
    box-shadow: none !important;
    padding: 0 2px !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    min-height: 26px !important;
    letter-spacing: 0 !important;
    text-decoration: underline !important;
    text-underline-offset: 2px !important;
    text-decoration-color: rgba(16,185,129,0.4) !important;
}
.auth-toggle-row [data-testid="stButton"] button:hover {
    color: #34d399 !important;
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
  border-color: rgba(16,185,129,0.18);
  color: #6ee7b7;
  background: #030f09;
}
.lp-trust {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 14px;
  margin-bottom: 16px;
}
.lp-trust span {
  color: #2d4056;
  font-size: 0.7rem;
  display: flex;
  align-items: center;
  gap: 4px;
}
.lp-trust span::before {
  content: "✓";
  color: #10b981;
  font-weight: 800;
  font-size: 0.68rem;
}

/* ── GitHub button CSS marker trick (:has selector) ─────── */
[data-testid="stMarkdownContainer"]:has(.lp-gh-marker) + [data-testid="stButton"] button {
  background: #21262d !important;
  color: #e6edf3 !important;
  border: 1px solid #30363d !important;
  box-shadow: none !important;
  text-decoration: none !important;
  font-weight: 700 !important;
  letter-spacing: 0.01em !important;
}
[data-testid="stMarkdownContainer"]:has(.lp-gh-marker) + [data-testid="stButton"] button:hover {
  background: #2d333b !important;
  border-color: #8b949e !important;
  transform: translateY(-1px) !important;
  box-shadow: 0 3px 14px rgba(0,0,0,0.35) !important;
}

/* ── Hero scan URL label ────────────────────────────────── */
.lp-scan-label {
  color: #10b981;
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
  background: #10b981;
  border-radius: 1px;
}

/* ── Auth buttons (Sign In / Create Account) ────────────── */
button[kind="primary"] {
  background: linear-gradient(135deg, #10b981 0%, #059669 100%) !important;
  color: #000 !important;
  font-weight: 800 !important;
  border: none !important;
  border-radius: 10px !important;
  font-size: 0.9rem !important;
  letter-spacing: 0.03em !important;
  box-shadow: 0 2px 12px rgba(16,185,129,0.25) !important;
  transition: all 0.18s ease !important;
}
button[kind="primary"]:hover {
  background: linear-gradient(135deg, #059669 0%, #047857 100%) !important;
  box-shadow: 0 4px 20px rgba(16,185,129,0.40) !important;
  transform: translateY(-1px) !important;
}
button[kind="primary"]:active {
  transform: translateY(0) !important;
  box-shadow: 0 1px 8px rgba(16,185,129,0.20) !important;
}
/* Secondary buttons on landing page are always toggle/link actions */
button[kind="secondary"] {
  background: transparent !important;
  color: #10b981 !important;
  border: none !important;
  box-shadow: none !important;
  padding: 0 2px !important;
  font-size: 0.81rem !important;
  font-weight: 600 !important;
  min-height: 26px !important;
  line-height: 1 !important;
  text-decoration: underline !important;
  text-underline-offset: 2px !important;
  text-decoration-color: rgba(16,185,129,0.4) !important;
}
button[kind="secondary"]:hover {
  color: #34d399 !important;
  transform: none !important;
  text-decoration-color: rgba(52,211,153,0.85) !important;
}

/* ── MOBILE — tablet (≤768px) ───────────────────────────── */
@media (max-width: 768px) {
  .lp-headline { font-size: 2.1rem; }
  .lp-desc { font-size: 0.9rem; }
  .lp-features { grid-template-columns: 1fr; }
  .lp-stats { gap: 16px; }
  .lp-stat-val { font-size: 1.5rem; }
  .auth-card-top { padding: 18px 16px 14px; border-radius: 12px 12px 0 0; }
  .auth-card-footer { padding: 10px 16px 16px; border-radius: 0 0 12px 12px; }
  .lp-free-badge { font-size: 0.74rem; }
}

/* ── MOBILE — phone (≤480px) ────────────────────────────── */
@media (max-width: 480px) {
  .lp-headline { font-size: 1.7rem; letter-spacing: -0.01em; }
  .lp-desc { font-size: 0.85rem; max-width: 100%; }
  .lp-cta-btn { padding: 10px 18px; font-size: 0.82rem; width: 100%; justify-content: center; }
  .lp-cta-note { font-size: 0.7rem; }
  .lp-stats { gap: 12px; }
  .lp-stat-val { font-size: 1.3rem; }
  .lp-stat-lbl { font-size: 0.6rem; }
  .lp-brand-name { font-size: 1.1rem; }
  .auth-card-top { padding: 14px 12px; }
  .auth-card-footer { padding: 8px 12px 14px; }
}
</style>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Navigation bar  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_NAV_HTML = """
<style>
.aics-nav{display:flex;align-items:center;justify-content:space-between;padding:13px 4px;border-bottom:1px solid #1e2d3d;margin-bottom:6px;flex-wrap:wrap;gap:10px}
.aics-nav-brand{display:flex;align-items:center;gap:10px}
.aics-nav-links{display:flex;align-items:center;gap:20px}
.aics-nav-link{color:#64748b;font-size:0.76rem;white-space:nowrap}
.aics-nav-cta{background:#10b981;color:#000;font-weight:800;font-size:0.76rem;padding:6px 16px;border-radius:7px;white-space:nowrap}
@media(max-width:768px){
  .aics-nav-links .aics-nav-link{display:none}
  .aics-nav{padding:10px 4px}
}
@media(max-width:480px){
  .aics-nav-cta{font-size:0.7rem;padding:5px 12px}
}
</style>
<div class="aics-nav">
  <div class="aics-nav-brand">
    <span style="font-size:1.2rem">🛡</span>
    <span style="font-family:'JetBrains Mono','Courier New',monospace;font-weight:900;color:#10b981;font-size:0.95rem;letter-spacing:-0.03em">AI Cyber Shield</span>
    <span style="background:#0a2018;border:1px solid #10b981;border-radius:4px;color:#34d399;font-size:0.56rem;font-weight:800;text-transform:uppercase;letter-spacing:0.12em;padding:2px 7px">Beta</span>
  </div>
  <div class="aics-nav-links">
    <span class="aics-nav-link">18 scan tools</span>
    <span class="aics-nav-link">No agent required</span>
    <span class="aics-nav-link">Free tier available</span>
    <span class="aics-nav-cta">Start Free →</span>
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
<h1 class="lp-headline">Is your website<br>secure right now? <em>Find out.</em></h1>
<div class="lp-checks">
  <div class="lp-check lp-check-warn">🔒 TLS / SSL</div>
  <div class="lp-check lp-check-warn">📧 Email Spoofability</div>
  <div class="lp-check lp-check-warn">🔗 CVE Detection</div>
  <div class="lp-check lp-check-ok">🌐 DNS Deep Scan</div>
  <div class="lp-check lp-check-ok">🛡 HTTP Headers</div>
  <div class="lp-check lp-check-ok">☁️ Cloud Buckets</div>
  <div class="lp-check">🐙 GitHub Leaks</div>
  <div class="lp-check">📡 IP / Shodan</div>
  <div class="lp-check">🗂 Exposed Files</div>
</div>
<div class="lp-trust">
  <span>No agent installed on your server</span>
  <span>Zero network footprint</span>
  <span>18 tools · results in &lt;90 sec</span>
</div>
<div class="lp-scan-label">Enter your website to get started</div>
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
  color: #10b981;
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
  ✅ <strong>Free tier included</strong> — 18-tool OSINT scan, no credit card required. Upgrade for active scanning and PT mode.
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Auth card wrappers
# ─────────────────────────────────────────────────────────────────────────────

_SVG_SHIELD = """<svg width="26" height="29" viewBox="0 0 28 31" fill="none">
  <path d="M14 1L2 6V16C2 23.2 7.6 29.8 14 31.4C20.4 29.8 26 23.2 26 16V6L14 1Z"
        fill="#071a10" stroke="#10b981" stroke-width="1.5"/>
  <path d="M9 15.5L12.5 19L19 12" stroke="#10b981" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

def _auth_card_top(headline: str, sub: str) -> str:
    return f"""
<div class="auth-card-top">
  <div class="auth-card-brand">{_SVG_SHIELD}</div>
  <div class="auth-card-title">{headline}</div>
  <div class="auth-card-sub">{sub}</div>
</div>"""

_AUTH_CARD_FOOTER = """
<div class="auth-card-footer">
    🛡 Authorized use only &nbsp;·&nbsp; Scanning targets without permission violates our <a href="/?legal=tos" style="color:#334155;text-decoration:underline">Terms</a>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Social proof bar  (self-contained inline styles → st.html)
# ─────────────────────────────────────────────────────────────────────────────

_SOCIAL_PROOF_HTML = """
<style>
.sp-bar{text-align:center;padding:14px 8px;color:#475569;font-size:0.78rem;border-top:1px solid #1e2d3d;border-bottom:1px solid #1e2d3d;background:#080d17;display:flex;justify-content:center;align-items:center;flex-wrap:wrap;gap:6px 16px}
.sp-item{white-space:nowrap}
.sp-hl{color:#10b981;font-weight:700}
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
.aics-pricing-eye{text-align:center;color:#10b981;font-size:.7rem;text-transform:uppercase;letter-spacing:.2em;margin-bottom:8px}
.aics-pricing-h{text-align:center;font-size:1.9rem;font-weight:800;color:#f8fafc;margin-bottom:6px}
.aics-pricing-sub{text-align:center;color:#64748b;font-size:.88rem;margin-bottom:36px}
.aics-plans{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:40px;align-items:start}
@media(max-width:900px){.aics-plans{grid-template-columns:repeat(2,1fr)}}
@media(max-width:500px){.aics-plans{grid-template-columns:1fr}.aics-pricing-h{font-size:1.4rem}.aics-price{font-size:1.7rem}}
.aics-plan{background:#0d1421;border:1px solid #1e2d3d;border-radius:14px;padding:24px 20px;position:relative;transition:border-color 0.2s}
.aics-plan:hover{border-color:#2a3d52}
.aics-plan-pro{
  border-color:#10b981;
  border-width:2px;
  background:linear-gradient(160deg,#081a10 0%,#0d1421 50%);
  box-shadow:0 0 50px rgba(16,185,129,0.22),0 8px 40px rgba(0,0,0,0.55),0 0 0 1px rgba(16,185,129,0.12);
  transform:translateY(-10px) scale(1.035);
  z-index:2;
  padding:28px 22px;
}
.aics-plan-pro:hover{border-color:#34d399;box-shadow:0 0 60px rgba(16,185,129,0.30),0 12px 50px rgba(0,0,0,0.6)}
.aics-badge{position:absolute;top:-14px;left:50%;transform:translateX(-50%);
  background:linear-gradient(90deg,#10b981,#34d399);
  color:#000;font-size:.6rem;font-weight:900;text-transform:uppercase;
  letter-spacing:.12em;padding:4px 16px;border-radius:99px;white-space:nowrap;
  box-shadow:0 2px 12px rgba(16,185,129,0.45)}
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
      <div class="aics-tier" style="color:#10b981;font-weight:900;letter-spacing:.2em">Professional</div>
      <div class="aics-price" style="color:#34d399;font-size:2.6rem">€50<sub>/mo</sub></div>
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
    from legal_pages import show_terms_of_service, show_privacy_policy

    # Handle ?legal= query param — show legal pages without requiring login
    _legal_qp = st.query_params.get("legal", "")
    if _legal_qp in ("tos", "privacy"):
        st.query_params.clear()
        st.markdown(_LANDING_CSS, unsafe_allow_html=True)
        if _legal_qp == "tos":
            show_terms_of_service()
        else:
            show_privacy_policy()
        st.markdown("---")
        if st.button("← Back", key="legal_lp_back", type="primary"):
            st.rerun()
        st.stop()

    st.markdown(_LANDING_CSS, unsafe_allow_html=True)

    # ── Navigation bar ────────────────────────────────────────────────────────
    st.html(_NAV_HTML)

    # ── Two-column split: 60% marketing, 40% auth form ───────────────────────
    col_left, col_right = st.columns([3, 2], gap="large")

    # ── LEFT: product marketing ───────────────────────────────────────────────
    with col_left:
        st.markdown(_HERO_HTML, unsafe_allow_html=True)

        # ── Hero URL input — stores URL for post-login auto-fill ──────────────
        _hero_url = st.text_input(
            "hero_label",
            placeholder="https://yourwebsite.com",
            key="hero_scan_url",
            label_visibility="collapsed",
        )
        if st.button(
            "→  Get your free security score",
            key="hero_get_score_btn",
            type="primary",
            use_container_width=True,
        ):
            if _hero_url.strip():
                st.session_state["hero_target_url"] = _hero_url.strip()
                st.session_state["_run_guest_scan"]  = True
                st.rerun()
            else:
                st.warning("Enter a URL to get started.")

        # ── Animated stats ────────────────────────────────────────────────────
        st.html(_STATS_HTML)

        st.markdown(_FEATURES_HTML, unsafe_allow_html=True)

    # ── RIGHT: auth card (no tabs — session-state view switching) ────────────
    with col_right:
        # ── View state ────────────────────────────────────────────────────────
        if "_auth_view" not in st.session_state:
            st.session_state["_auth_view"] = "signin"
        _view = st.session_state["_auth_view"]

        _card_meta = {
            "signin": ("Welcome back.",        "Sign in to AI Cyber Shield"),
            "signup": ("Create your account.", "Free forever · No credit card required"),
            "reset":  ("Forgot your password?","We'll send a reset link to your inbox"),
        }
        _hl, _sub = _card_meta.get(_view, _card_meta["signin"])

        # ── Dynamic card header ───────────────────────────────────────────────
        st.markdown(_auth_card_top(_hl, _sub), unsafe_allow_html=True)

        # ── GitHub OAuth (shown for signin + signup) ──────────────────────────
        if _view in ("signin", "signup"):
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
            st.markdown('<div class="lp-gh-marker"></div>', unsafe_allow_html=True)
            if st.button(
                "⬡  Continue with GitHub",
                use_container_width=True,
                key=f"gh_{_view}",
            ):
                from auth.streamlit_auth import sign_in_with_github
                _gh = sign_in_with_github()
                if "url" in _gh:
                    st.html(f'<script>window.location.href="{_gh["url"]}";</script>')
                else:
                    st.error(_gh.get("error", "GitHub login is not configured yet."))

            st.markdown("""
<div style="display:flex;align-items:center;gap:10px;margin:14px 0 10px">
  <div style="flex:1;height:1px;background:#1a2a3d"></div>
  <span style="color:#2d4056;font-size:0.7rem;white-space:nowrap;letter-spacing:0.06em">or continue with email</span>
  <div style="flex:1;height:1px;background:#1a2a3d"></div>
</div>""", unsafe_allow_html=True)

        # ── Form content ──────────────────────────name="auth-body"──────────
        st.markdown("<div style='height:2px'></div>", unsafe_allow_html=True)

        # ── Sign In ───────────────────────────────────────────────────────────
        if _view == "signin":
            _li_email = st.text_input(
                "Email address", key="li_email", placeholder="you@example.com",
            )
            _li_pass = st.text_input(
                "Password", type="password", key="li_pass", placeholder="••••••••",
            )
            st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

            if st.button("Sign In →", use_container_width=True, key="li_btn", type="primary"):
                if not _li_email or not _li_pass:
                    st.error("Please enter email and password.")
                elif not _valid_email(_li_email):
                    st.error("Enter a valid email address.")
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
                    '<div style="color:#334155;font-size:0.79rem;padding-top:6px">New here?</div>',
                    unsafe_allow_html=True,
                )
                st.markdown('<div class="auth-toggle-row">', unsafe_allow_html=True)
                if st.button("Create free account", key="go_signup"):
                    st.session_state["_auth_view"] = "signup"
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)
            with _tc2:
                st.markdown(
                    '<div style="text-align:right;color:#334155;font-size:0.79rem;padding-top:6px">Trouble signing in?</div>',
                    unsafe_allow_html=True,
                )
                st.markdown('<div class="auth-toggle-row" style="text-align:right">', unsafe_allow_html=True)
                if st.button("Reset password", key="go_reset"):
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
                "Email address", key="reg_email", placeholder="you@example.com",
            )
            _r_pass = st.text_input(
                "Password", type="password", key="reg_pass",
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
                _pwc = ["#ef4444", "#f97316", "#f59e0b", "#60a5fa", "#10b981"][min(_pw_score, 4)]
                _pww = [16, 32, 52, 75, 100][min(_pw_score, 4)]
                st.markdown(
                    f'<div style="margin:-4px 0 10px">'
                    f'<div style="height:3px;background:#1e2d3d;border-radius:2px;overflow:hidden">'
                    f'<div style="width:{_pww}%;height:100%;background:{_pwc};border-radius:2px;transition:width 0.2s"></div>'
                    f'</div><div style="color:{_pwc};font-size:0.7rem;margin-top:3px">{_pwl}</div></div>',
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
            if st.button("Create Free Account →", use_container_width=True, key="reg_btn", type="primary"):
                _errors = []
                if not _r_email or not _valid_email(_r_email):
                    _errors.append("Enter a valid email address.")
                _ok_pw, _pw_msg = _valid_password(_r_pass)
                if not _ok_pw:
                    _errors.append(f"Password: {_pw_msg}")
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
                            st.success("Account created! Check your inbox for a confirmation email.")
                        else:
                            st.success("Account created! You can now sign in.")
                    else:
                        st.error(result.get("error", "Registration failed"))

            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            st.markdown('<div class="auth-toggle-row">', unsafe_allow_html=True)
            if st.button("← Already have an account? Sign in", key="go_signin_from_reg"):
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
                "Email address", key="rst_email", placeholder="you@example.com",
            )
            st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
            if st.button("Send Reset Link →", use_container_width=True, key="rst_btn", type="primary"):
                if not _rst_email or not _valid_email(_rst_email):
                    st.error("Enter a valid email address.")
                else:
                    with st.spinner("Sending…"):
                        result = request_password_reset(_rst_email.strip().lower())
                    if result.get("ok"):
                        st.success("Reset link sent! Check your inbox — also check spam.")
                        st.info("📧 Spam folder  ·  🔒 Link expires 24 h  ·  Return here to sign in")
                    else:
                        st.error(result.get("error", "Failed to send reset email"))

            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            st.markdown('<div class="auth-toggle-row">', unsafe_allow_html=True)
            if st.button("← Back to Sign In", key="go_signin_from_reset"):
                st.session_state["_auth_view"] = "signin"
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Card footer + JS column marker ────────────────────────────────────
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        st.markdown(_AUTH_CARD_FOOTER, unsafe_allow_html=True)

        # JS: mark auth column + apply GitHub button dark styling
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
        /* Also style GitHub button dark */
        var btns=n.querySelectorAll('button');
        btns.forEach(function(b){
          if(b.textContent.includes('GitHub')){
            b.style.cssText='background:#21262d!important;color:#e6edf3!important;border:1px solid #30363d!important;border-radius:10px!important;font-weight:700!important;';
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

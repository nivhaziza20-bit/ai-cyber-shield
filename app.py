"""
app.py — AI Cyber Shield · Code Security Analyser
Dark security theme, professional finding cards, plain-English explanations.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dotenv import load_dotenv
load_dotenv(override=False)

# ─────────────────────────────────────────────────────────────────────────────
# Page config — must be first Streamlit call
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Cyber Shield — Code Analyser",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Session state defaults
# ─────────────────────────────────────────────────────────────────────────────
if "result"       not in st.session_state: st.session_state.result       = None
if "running"      not in st.session_state: st.session_state.running      = False
if "scan_target"  not in st.session_state: st.session_state.scan_target  = ""
if "scan_is_demo" not in st.session_state: st.session_state.scan_is_demo = False

# ─────────────────────────────────────────────────────────────────────────────
# Dark security theme CSS
# ─────────────────────────────────────────────────────────────────────────────
_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&family=JetBrains+Mono:wght@400;600;700&display=swap');

html, body, .stApp {
    background-color: #060b14 !important;
    color: #c9d1d9 !important;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
}
section[data-testid="stSidebar"] {
    background-color: #0d1117 !important;
    border-right: 1px solid #1f2d3d !important;
}
section[data-testid="stSidebar"] * { color: #c9d1d9 !important; }

/* ── Header ── */
.cs-header { padding: 20px 0 14px; border-bottom: 1px solid #1f2d3d; margin-bottom: 20px; }
.cs-logo   { font-size: 2.2rem; font-weight: 900; color: #10b981; letter-spacing: -0.04em;
             font-family: 'JetBrains Mono', 'Fira Code', monospace; line-height: 1; }
.cs-tagline{ color: #475569; font-size: 0.72rem; letter-spacing: 0.18em;
             text-transform: uppercase; margin-top: 4px; font-family: 'JetBrains Mono', monospace; }
.cs-badge  { display: inline-block; background: #0f2027; border: 1px solid #10b981;
             border-radius: 4px; color: #10b981; font-size: 0.62rem;
             font-family: 'JetBrains Mono', monospace; letter-spacing: 0.1em;
             padding: 2px 8px; margin-top: 6px; }

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: #0d1117 !important; border: 1px solid #1f2d3d !important;
    border-radius: 8px !important; padding: 14px !important;
}
[data-testid="stMetricLabel"] { color: #64748b !important; font-size: 0.72rem !important; text-transform: uppercase; }
[data-testid="stMetricValue"] { color: #e2e8f0 !important; font-family: 'JetBrains Mono', monospace !important; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] { background: #0d1117 !important; border-bottom: 1px solid #1f2d3d !important; gap: 4px; }
.stTabs [data-baseweb="tab"]      { background: transparent !important; color: #64748b !important;
                                    border-radius: 6px 6px 0 0 !important; font-size: 0.85rem !important;
                                    padding: 8px 16px !important; border: none !important; }
.stTabs [aria-selected="true"]    { background: #111827 !important; color: #10b981 !important;
                                    border-bottom: 2px solid #10b981 !important; }

/* ── Buttons ── */
button[kind="primary"] {
    background: linear-gradient(135deg,#10b981,#059669) !important;
    color: #000 !important; font-weight: 700 !important; border: none !important;
    border-radius: 6px !important;
}
button[kind="primary"]:hover { background: linear-gradient(135deg,#059669,#047857) !important;
    transform: translateY(-1px); box-shadow: 0 4px 12px rgba(16,185,129,.3) !important; }
button[kind="secondary"] {
    background: #111827 !important; color: #94a3b8 !important;
    border: 1px solid #1f2d3d !important; border-radius: 6px !important;
}

/* ── Inputs ── */
.stTextInput > div > div > input, .stTextArea textarea {
    background-color: #0d1117 !important; color: #e2e8f0 !important;
    border: 1px solid #1f2d3d !important; border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.stTextInput > div > div > input:focus, .stTextArea textarea:focus {
    border-color: #10b981 !important; box-shadow: 0 0 0 2px rgba(16,185,129,.15) !important;
}

/* ── Code ── */
code, pre { background: #111827 !important; color: #7dd3fc !important;
    border: 1px solid #1f2d3d !important; border-radius: 4px !important;
    font-family: 'JetBrains Mono', monospace !important; }

/* ── Expanders ── */
.streamlit-expanderHeader { background: #0d1117 !important; border: 1px solid #1f2d3d !important;
    border-radius: 6px !important; color: #c9d1d9 !important; font-size: 0.88rem !important; }
.streamlit-expanderContent { background: #0d1117 !important; border: 1px solid #1f2d3d !important;
    border-top: none !important; color: #c9d1d9 !important; }

/* ── Download ── */
.stDownloadButton > button {
    background: #111827 !important; color: #10b981 !important;
    border: 1px solid #10b981 !important; border-radius: 6px !important; font-weight: 600 !important;
}

/* ── Divider / misc ── */
hr { border-color: #1f2d3d !important; }
.stSpinner > div { color: #10b981 !important; }
.stAlert { border-radius: 8px !important; }
.stCaption, small { color: #475569 !important; }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0e1a; }
::-webkit-scrollbar-thumb { background: #1f2d3d; border-radius: 3px; }
section[data-testid="stSidebar"] .stToggle > label { color: #94a3b8 !important; font-size: 0.85rem !important; }

/* ── Section label ── */
.section-label {
    color: #475569; font-size: 0.63rem; text-transform: uppercase; letter-spacing: 0.18em;
    font-family: 'JetBrains Mono', monospace; padding: 6px 0 4px; border-bottom: 1px solid #1f2d3d; margin-bottom: 12px;
}

/* ── Finding card ── */
.finding-card {
    background: #0d1117; border: 1px solid #1f2d3d; border-radius: 8px;
    padding: 16px 20px; margin: 8px 0; transition: border-color .2s;
}
.finding-card:hover { border-color: #2d3748; }
.finding-title { font-size: 1rem; font-weight: 700; color: #e2e8f0; }
.finding-meta  { color: #475569; font-size: 0.75rem; font-family:'JetBrains Mono',monospace; margin-top: 3px; }
.finding-impact{ color: #94a3b8; font-size: 0.82rem; margin: 8px 0; line-height: 1.6; }
.finding-owasp { color: #475569; font-size: 0.72rem; font-family:'JetBrains Mono',monospace; }

/* ── Severity badge ── */
.badge {
    display: inline-block; border-radius: 4px; padding: 2px 9px;
    font-size: 0.65rem; font-weight: 800; letter-spacing: 0.08em;
    text-transform: uppercase; font-family: 'JetBrains Mono', monospace; vertical-align: middle; margin-right: 8px;
}
.badge-critical { background:#450a0a; color:#ef4444; border:1px solid #7f1d1d; }
.badge-high     { background:#431407; color:#f97316; border:1px solid #9a3412; }
.badge-medium   { background:#451a03; color:#f59e0b; border:1px solid #92400e; }
.badge-low      { background:#1e3a5f; color:#60a5fa; border:1px solid #1e40af; }
.badge-info     { background:#1e2d40; color:#94a3b8; border:1px solid #334155; }

/* ── Risk score bar ── */
.risk-bar-bg   { background:#1f2d3d; border-radius:4px; height:10px; margin:8px 0; overflow:hidden; }
.risk-bar-fill { height:10px; border-radius:4px; transition:width .6s ease; }

/* ── Capability card — Snyk-style ── */
.cap-card {
    background: #0d1117; border: 1px solid #1f2d3d; border-radius: 8px;
    padding: 18px 16px; display: flex; gap: 14px; align-items: flex-start;
    transition: border-color .2s;
}
.cap-card:hover { border-color: #10b981; }
.cap-num {
    min-width: 28px; height: 28px; border-radius: 50%;
    background: #0f2027; border: 1px solid #10b981;
    color: #10b981; font-family:'JetBrains Mono',monospace; font-size: 0.75rem;
    font-weight: 800; display: flex; align-items:center; justify-content:center; flex-shrink:0;
}
.cap-body {}
.cap-title { color: #e2e8f0; font-weight: 700; font-size: 0.88rem; margin-bottom: 3px; }
.cap-owasp { color: #10b981; font-size: 0.68rem; font-family:'JetBrains Mono',monospace; letter-spacing:.05em; margin-bottom:4px; }
.cap-desc  { color: #475569; font-size: 0.75rem; line-height: 1.5; }

/* ── Upload zone ── */
.upload-zone {
    background: #0d1117; border: 2px dashed #1f2d3d; border-radius: 10px;
    padding: 28px; text-align: center; cursor: pointer; transition: border-color .2s;
}
.upload-zone:hover { border-color: #10b981; }

/* ── Pipeline step badges ── */
.pipeline-step {
    display: inline-flex; align-items: center; gap: 6px;
    background: #0d1117; border: 1px solid #1f2d3d; border-radius: 6px;
    padding: 6px 12px; font-size: 0.75rem; color: #94a3b8;
    font-family: 'JetBrains Mono', monospace;
}
.pipeline-step b { color: #10b981; }
.pipeline-arrow { color: #1f2d3d; font-size: 1rem; margin: 0 2px; }

/* ── Demo mode warning banner ── */
.demo-banner {
    background: linear-gradient(90deg, #1a1000, #1c1400);
    border: 1px solid #92400e; border-left: 4px solid #f59e0b;
    border-radius: 8px; padding: 12px 18px; margin-bottom: 16px;
    display: flex; align-items: center; gap: 12px;
}
.demo-banner-icon { font-size: 1.1rem; }
.demo-banner-text { color: #fbbf24; font-size: 0.82rem; font-weight: 600; }
.demo-banner-sub  { color: #92400e; font-size: 0.74rem; margin-top: 2px; }

/* ── Scan target banner ── */
.scan-target-banner {
    background: #0d1117; border: 1px solid #1f2d3d; border-left: 4px solid #10b981;
    border-radius: 8px; padding: 12px 18px; margin-bottom: 16px;
    display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
}
.scan-target-label { color: #475569; font-size: 0.68rem; text-transform: uppercase;
                     letter-spacing: .14em; font-family:'JetBrains Mono',monospace; }
.scan-target-value { color: #e2e8f0; font-size: 0.88rem; font-weight: 700;
                     font-family:'JetBrains Mono',monospace; word-break: break-all; }
.scan-target-meta  { color: #475569; font-size: 0.72rem; margin-top: 2px; }

/* ── Report sections ── */
.report-body h1, .report-body h2 { color:#e2e8f0; border-bottom:1px solid #1f2d3d; padding-bottom:6px; }
.report-body h3 { color:#94a3b8; }
.report-body h4 { color:#10b981; }
.report-body table { background:#111827; border-collapse:collapse; width:100%; border-radius:6px; overflow:hidden; }
.report-body th { background:#1f2d3d; color:#94a3b8; padding:8px 12px; font-size:0.8rem; text-align:left; }
.report-body td { color:#c9d1d9; padding:8px 12px; border-bottom:1px solid #1a2535; font-size:0.85rem; }
.report-body li { color:#c9d1d9; margin:4px 0; }
.report-body strong { color:#e2e8f0; }
.report-body blockquote { border-left:3px solid #10b981; padding-left:12px; color:#94a3b8; }
.report-body code { background:#111827 !important; color:#7dd3fc !important; padding:1px 5px; border-radius:3px; }
</style>
"""
st.markdown(_CSS, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Plain-English translations for Bandit rule IDs
# ─────────────────────────────────────────────────────────────────────────────

_BANDIT_LABELS: dict[str, tuple[str, str, str]] = {
    # (Plain name, attacker-can, owasp)
    "B101": ("Assert Statement Bypass",   "Disable your security assertions at runtime with Python -O flag, bypassing access controls.", "A05:2021 – Security Misconfiguration"),
    "B102": ("Exec() Code Execution",     "Execute any arbitrary Python code they inject into your application.", "A03:2021 – Injection"),
    "B105": ("Hardcoded Password",        "Read your source code (e.g. via git) and steal the embedded credential.", "A07:2021 – Identification & Auth Failures"),
    "B106": ("Hardcoded Password in Call","Extract the plaintext credential from your binary or repository.", "A07:2021 – Identification & Auth Failures"),
    "B107": ("Hardcoded Default Argument","Use the default password to authenticate without authorization.", "A07:2021 – Identification & Auth Failures"),
    "B108": ("Predictable Temp File",     "Race-condition (TOCTOU) the temp file and redirect writes to sensitive paths.", "A01:2021 – Broken Access Control"),
    "B201": ("Flask Debug Mode Exposed",  "Access the interactive Python debugger console — full remote code execution.", "A05:2021 – Security Misconfiguration"),
    "B301": ("Pickle Deserialization",    "Craft a malicious pickle payload and gain arbitrary code execution.", "A08:2021 – Software and Data Integrity Failures"),
    "B303": ("Broken Hash (MD5/SHA1)",    "Crack password hashes offline in seconds using GPU hash-cracking.", "A02:2021 – Cryptographic Failures"),
    "B304": ("Broken Cipher (DES/RC4)",   "Decrypt your data — DES and RC4 are fully broken algorithms.", "A02:2021 – Cryptographic Failures"),
    "B307": ("eval() Code Execution",     "Inject Python expressions that execute as code inside your application.", "A03:2021 – Injection"),
    "B310": ("Unvalidated URL Open",      "Trigger Server-Side Request Forgery (SSRF) to access internal services.", "A10:2021 – Server-Side Request Forgery"),
    "B311": ("Weak Random Number",        "Predict your 'random' values — session tokens, OTPs, UUIDs become guessable.", "A02:2021 – Cryptographic Failures"),
    "B324": ("Broken Hash (MD5/SHA1)",    "Crack hashes in seconds — MD5/SHA1 are no longer collision-resistant.", "A02:2021 – Cryptographic Failures"),
    "B501": ("TLS Verification Disabled", "Intercept your HTTPS traffic with a self-signed certificate (MITM attack).", "A02:2021 – Cryptographic Failures"),
    "B502": ("Insecure SSL Version",      "Exploit SSLv2/SSLv3 POODLE/DROWN vulnerabilities to decrypt traffic.", "A02:2021 – Cryptographic Failures"),
    "B506": ("YAML Unsafe Load",          "Embed Python objects in YAML to execute arbitrary code on deserialisation.", "A08:2021 – Software and Data Integrity Failures"),
    "B601": ("Shell Injection (Paramiko)","Chain OS commands to the SSH exec_command call.", "A03:2021 – Injection"),
    "B602": ("OS Command Injection",      "Append `;id`, `;rm -rf /` or any shell command to your subprocess call.", "A03:2021 – Injection"),
    "B603": ("Subprocess User Input",     "Pass crafted arguments that alter the subprocess behaviour.", "A03:2021 – Injection"),
    "B604": ("Shell=True Injection",      "Inject shell metacharacters to run arbitrary OS commands.", "A03:2021 – Injection"),
    "B607": ("Partial Path Binary",       "Hijack PATH to execute a malicious binary instead of the intended one.", "A03:2021 – Injection"),
    "B608": ("SQL Injection",             "Access, modify, or exfiltrate your entire database with one crafted input.", "A03:2021 – Injection"),
    "B609": ("Shell Wildcard Injection",  "Expand shell wildcards to match files outside the intended scope.", "A03:2021 – Injection"),
    "B701": ("Jinja2 Autoescape Off",     "Inject HTML/JavaScript into your pages (XSS / SSTI attack chain).", "A03:2021 – Injection"),
    "B703": ("Django mark_safe XSS",      "Inject unsanitised HTML that executes in other users' browsers.", "A03:2021 – Injection"),
}

_SEV_COLORS = {
    "CRITICAL": ("#450a0a", "#ef4444", "#7f1d1d"),
    "HIGH":     ("#431407", "#f97316", "#9a3412"),
    "MEDIUM":   ("#451a03", "#f59e0b", "#92400e"),
    "LOW":      ("#1e3a5f", "#60a5fa", "#1e40af"),
    "ERROR":    ("#431407", "#f97316", "#9a3412"),
    "WARNING":  ("#451a03", "#f59e0b", "#92400e"),
    "INFO":     ("#1e3a5f", "#60a5fa", "#1e40af"),
}
_SEV_BADGE = {
    "CRITICAL": "badge-critical", "HIGH": "badge-high",
    "MEDIUM": "badge-medium", "ERROR": "badge-high",
    "WARNING": "badge-medium", "LOW": "badge-low", "INFO": "badge-info",
}
_SEV_BORDER = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316",
    "MEDIUM": "#f59e0b", "ERROR": "#f97316",
    "WARNING": "#f59e0b", "LOW": "#60a5fa", "INFO": "#475569",
}


def _sev_norm(raw: str) -> str:
    return raw.upper().strip()


def _render_bandit_card(f: dict, index: int) -> None:
    sev   = _sev_norm(f.get("severity", "LOW"))
    rid   = f.get("id", "")
    line  = f.get("line_number", "?")
    conf  = f.get("confidence", "")

    name, attacker_can, owasp = _BANDIT_LABELS.get(
        rid,
        (f.get("name", rid), f.get("description", ""), "")
    )
    border = _SEV_BORDER.get(sev, "#475569")
    badge  = _SEV_BADGE.get(sev, "badge-info")

    st.markdown(f"""
<div class="finding-card" style="border-left:4px solid {border}">
  <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap">
    <span class="badge {badge}">{sev}</span>
    <span class="finding-title">{name}</span>
    <span class="finding-meta" style="margin-left:auto">Line {line} &nbsp;·&nbsp; {rid}
      {f'&nbsp;·&nbsp; Confidence: {conf}' if conf else ''}</span>
  </div>
  <div class="finding-impact">⚠️ An attacker could: <b style="color:#e2e8f0">{attacker_can}</b></div>
  {f'<div class="finding-owasp">📋 OWASP {owasp}</div>' if owasp else ''}
</div>""", unsafe_allow_html=True)

    with st.expander(f"↳ Code snippet & details — {name}"):
        snippet = f.get("code_snippet", "")
        if snippet:
            st.code(snippet.strip(), language="python")
        desc = f.get("description", "")
        if desc:
            st.markdown(f"**What Bandit detected:** {desc}")
        cwe = f.get("cwe", {})
        if cwe:
            st.markdown(
                f'`CWE-{cwe.get("id","")}` — {cwe.get("name","")}  \n'
                f'[Read CWE reference →]({cwe.get("link","")})'
                if cwe.get("link") else f'`CWE-{cwe.get("id","")}` — {cwe.get("name","")}'
            )
        if f.get("more_info"):
            st.caption(f"🔗 {f['more_info']}")


def _render_semgrep_card(f: dict, index: int) -> None:
    raw_sev = f.get("severity", "WARNING")
    sev     = _sev_norm(raw_sev)
    rid     = f.get("rule_id", "")
    line    = f.get("line_start", "?")
    msg     = f.get("message", "")

    # Human-readable title from rule_id
    parts = rid.split(".")
    title = parts[-1].replace("-", " ").replace("_", " ").title() if parts else rid

    border = _SEV_BORDER.get(sev, "#f59e0b")
    badge  = _SEV_BADGE.get(sev, "badge-medium")

    owasp_list = f.get("owasp", [])
    cwe_list   = f.get("cwe", [])

    st.markdown(f"""
<div class="finding-card" style="border-left:4px solid {border}">
  <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap">
    <span class="badge {badge}">{sev}</span>
    <span class="finding-title">{title}</span>
    <span class="finding-meta" style="margin-left:auto">Line {line}</span>
  </div>
  <div class="finding-impact" style="margin-top:8px">{msg}</div>
  {f'<div class="finding-owasp">📋 {" · ".join(owasp_list)}</div>' if owasp_list else ''}
</div>""", unsafe_allow_html=True)

    with st.expander(f"↳ Code snippet & details — {title}"):
        snippet = f.get("code_snippet", "")
        if snippet:
            st.code(snippet.strip(), language="python")
        if cwe_list:
            st.markdown("**CWE:** " + ", ".join(f"`{c}`" for c in cwe_list))
        st.caption(f"Rule: `{rid}`")


def _count_findings(scanner_json: str) -> dict:
    try:
        data  = json.loads(scanner_json)
        b_sum = (data.get("bandit_results") or {}).get("severity_summary", {})
        s_sum = (data.get("semgrep_results") or {}).get("severity_summary", {})
        high  = b_sum.get("high", 0) + s_sum.get("error", 0)
        med   = b_sum.get("medium", 0) + s_sum.get("warning", 0)
        low   = b_sum.get("low", 0) + s_sum.get("info", 0)
        return {
            "HIGH": high, "MEDIUM": med, "LOW": low,
            "total": (data.get("bandit_results") or {}).get("total_findings", 0)
                   + (data.get("semgrep_results") or {}).get("total_findings", 0),
        }
    except Exception:
        return {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="section-label">⚙ Configuration</div>', unsafe_allow_html=True)
    demo_mode    = st.toggle("🎭 Demo Mode (תוצאות סטטיות)", value=True,
                             help="כאשר פעיל — מחזיר תמיד את אותן תוצאות קבועות ללא סריקה אמיתית. כבה לסריקה חיה.")
    scanner_only = st.toggle("Scanner Only",            value=False,
                             help="Run Bandit + Semgrep but skip the LLM analysis stages.")
    save_reports = st.toggle("Save reports to ./reports/", value=False)

    if demo_mode:
        st.warning("⚠️ **Demo Mode ON** — תוצאות סטטיות קבועות.\nכבה כדי לסרוק אתר/קוד אמיתי.")
    else:
        import os
        key_ok = bool(os.getenv("ANTHROPIC_API_KEY"))
        if key_ok:
            st.success("✅ Live Mode — ANTHROPIC_API_KEY detected")
        else:
            st.error("❌ Set ANTHROPIC_API_KEY in .env for live mode")

    st.divider()
    st.markdown('<div class="section-label">🔬 Detection Engines</div>', unsafe_allow_html=True)
    st.markdown("""
<small style="color:#475569;line-height:1.8">
🔍 <b style="color:#10b981">Bandit</b> — Python SAST (30+ rules)<br>
🔍 <b style="color:#10b981">Semgrep</b> — OWASP Top 10 patterns<br>
🤖 <b style="color:#10b981">AI Analyst</b> — LangChain + Claude<br>
🔧 <b style="color:#10b981">AI Remediation</b> — patch playbook
</small>""", unsafe_allow_html=True)
    st.divider()
    st.markdown('<small style="color:#334155">AI Cyber Shield v6<br>מערכת לשימוש הגנתי בלבד</small>',
                unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="cs-header">
  <div class="cs-logo">⬡ CODE SECURITY ANALYSER</div>
  <div class="cs-tagline">Scanner Agent → AI Analyst → Remediation Playbook</div>
  <div>
    <span class="cs-badge">v6.0</span>
    <span class="cs-badge" style="margin-left:6px">BANDIT · SEMGREP · CLAUDE</span>
    <span class="cs-badge" style="margin-left:6px">DEFENSIVE USE ONLY</span>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Scan target + Demo Mode banners (shown once results exist)
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.result:
    scan_tgt  = st.session_state.get("scan_target", "")
    is_demo   = st.session_state.get("scan_is_demo", False)

    if is_demo:
        st.markdown(f"""
<div class="demo-banner">
  <span class="demo-banner-icon">🎭</span>
  <div>
    <div class="demo-banner-text">DEMO MODE — תוצאות אלו הן דוגמה סטטית קבועה ואינן מבוססות על סריקה אמיתית</div>
    <div class="demo-banner-sub">כבה את "Demo Mode" בתפריט הצד כדי לסרוק קוד או אתר אמיתי</div>
  </div>
</div>""", unsafe_allow_html=True)

    if scan_tgt:
        icon = "🌐" if scan_tgt.startswith("http") else "📄"
        st.markdown(f"""
<div class="scan-target-banner">
  <span style="font-size:1.4rem">{icon}</span>
  <div>
    <div class="scan-target-label">יעד הסריקה</div>
    <div class="scan-target-value">{scan_tgt}</div>
    <div class="scan-target-meta">{"🎭 Demo — תוצאות סטטיות" if is_demo else "🔍 Live Scan — תוצאות אמיתיות"}</div>
  </div>
</div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Risk summary row (after a scan)
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.result and st.session_state.result.scanner.status == "success":
    counts  = _count_findings(st.session_state.result.scanner.output)
    total   = counts["total"]
    risk_score = min(100, counts["HIGH"] * 20 + counts["MEDIUM"] * 8 + counts["LOW"] * 2)
    risk_label = ("🔴 CRITICAL RISK" if risk_score >= 60 else
                  "🟡 MEDIUM RISK"   if risk_score >= 25 else "🟢 LOW RISK")
    bar_color  = "#ef4444" if risk_score >= 60 else "#f59e0b" if risk_score >= 25 else "#10b981"

    st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1f2d3d;border-radius:10px;padding:18px 24px;margin-bottom:20px">
  <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap">
    <div>
      <div style="color:#475569;font-size:0.65rem;text-transform:uppercase;letter-spacing:.12em;font-family:'JetBrains Mono',monospace">Risk Score</div>
      <div style="font-size:2rem;font-weight:900;color:{bar_color};font-family:'JetBrains Mono',monospace">{risk_score}<span style="font-size:1rem;color:#475569">/100</span></div>
      <div style="font-size:0.78rem;font-weight:700;color:{bar_color}">{risk_label}</div>
      <div class="risk-bar-bg" style="width:160px">
        <div class="risk-bar-fill" style="width:{risk_score}%;background:{bar_color}"></div>
      </div>
    </div>
    <div style="display:flex;gap:32px;flex-wrap:wrap">
      <div style="text-align:center">
        <div style="font-size:1.8rem;font-weight:900;color:#ef4444;font-family:'JetBrains Mono',monospace">{counts['HIGH']}</div>
        <div style="font-size:0.7rem;color:#7f1d1d;text-transform:uppercase;letter-spacing:.1em">High / Critical</div>
      </div>
      <div style="text-align:center">
        <div style="font-size:1.8rem;font-weight:900;color:#f59e0b;font-family:'JetBrains Mono',monospace">{counts['MEDIUM']}</div>
        <div style="font-size:0.7rem;color:#92400e;text-transform:uppercase;letter-spacing:.1em">Medium</div>
      </div>
      <div style="text-align:center">
        <div style="font-size:1.8rem;font-weight:900;color:#60a5fa;font-family:'JetBrains Mono',monospace">{counts['LOW']}</div>
        <div style="font-size:0.7rem;color:#1e40af;text-transform:uppercase;letter-spacing:.1em">Low</div>
      </div>
      <div style="text-align:center">
        <div style="font-size:1.8rem;font-weight:900;color:#e2e8f0;font-family:'JetBrains Mono',monospace">{total}</div>
        <div style="font-size:0.7rem;color:#475569;text-transform:uppercase;letter-spacing:.1em">Total Findings</div>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Tabs
# ─────────────────────────────────────────────────────────────────────────────
tab_input, tab_scanner, tab_analyst, tab_remediation = st.tabs([
    "📥  Input",
    "🔍  Scanner Findings",
    "📊  Vulnerability Report",
    "🔧  Remediation Playbook",
])


# ═══════════════════════════════════════════════════════════════════════════
# TAB 1 — Input + Capability Showcase
# ═══════════════════════════════════════════════════════════════════════════
with tab_input:
    # ── Pipeline flow indicator ───────────────────────────────────────────
    st.markdown("""
<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:20px">
  <div class="pipeline-step">① <b>Bandit</b> Python SAST</div>
  <span class="pipeline-arrow">→</span>
  <div class="pipeline-step">② <b>Semgrep</b> OWASP rules</div>
  <span class="pipeline-arrow">→</span>
  <div class="pipeline-step">③ <b>AI Analyst</b> CVSS scoring</div>
  <span class="pipeline-arrow">→</span>
  <div class="pipeline-step">④ <b>AI Remediation</b> fix playbook</div>
</div>
""", unsafe_allow_html=True)

    # ── Left: code input  |  Right: capabilities ─────────────────────────
    left_col, right_col = st.columns([3, 2], gap="large")

    with left_col:
        st.markdown('<div class="section-label">SOURCE CODE</div>', unsafe_allow_html=True)
        uploaded = st.file_uploader(
            "Upload a source file",
            type=["py", "js", "ts", "java", "go", "rb", "php", "c", "cpp"],
            help="200MB per file · PY, JS, TS, JAVA, GO, RB, PHP, C, CPP",
            label_visibility="collapsed",
        )
        if uploaded:
            raw_code = uploaded.read().decode("utf-8", errors="replace")
            st.code(
                raw_code[:3000] + ("\n…(truncated)" if len(raw_code) > 3000 else ""),
                language=uploaded.name.rsplit(".", 1)[-1],
            )
        else:
            raw_code = st.text_area(
                "Or paste code directly",
                height=300,
                placeholder="# Paste Python, JS, Java, Go, PHP… source code here\n# Detects: SQL injection · RCE · hardcoded secrets · broken crypto · SSRF",
                value=(
                    Path("samples/vulnerable_app.py").read_text(encoding="utf-8")
                    if demo_mode and Path("samples/vulnerable_app.py").exists()
                    else ""
                ),
                label_visibility="collapsed",
            )

        st.markdown('<div class="section-label" style="margin-top:12px">URL AUDIT (OPTIONAL)</div>',
                    unsafe_allow_html=True)
        target_url = st.text_input(
            "Target URL",
            placeholder="https://example.com — checks VirusTotal + security headers",
            label_visibility="collapsed",
        )
        st.caption("Only public HTTPS URLs · private IPs blocked · SSRF guard active")

    with right_col:
        st.markdown('<div class="section-label">VULNERABILITY CLASSES DETECTED</div>', unsafe_allow_html=True)
        caps = [
            ("01", "SQL Injection",         "A03:2021", "String-concatenated queries let attackers dump your database."),
            ("02", "OS Command Injection",   "A03:2021", "subprocess shell=True with user input → full RCE."),
            ("03", "Hardcoded Secrets",      "A07:2021", "Passwords & API keys committed to source code."),
            ("04", "Broken Cryptography",    "A02:2021", "MD5 / SHA-1 / DES — crackable with a GPU in minutes."),
            ("05", "Arbitrary Code Execution","A03:2021", "eval() / exec() / pickle on untrusted input."),
            ("06", "SSRF / URL Injection",   "A10:2021", "Unvalidated URL open → access internal services."),
            ("07", "Weak Authentication",    "A07:2021", "random.random() tokens, disabled TLS verification."),
            ("08", "Insecure Deserialisation","A08:2021", "YAML.load() / pickle.loads() on untrusted data."),
        ]
        for num, title, owasp, desc in caps:
            st.markdown(f"""
<div class="cap-card">
  <div class="cap-num">{num}</div>
  <div class="cap-body">
    <div class="cap-title">{title}</div>
    <div class="cap-owasp">OWASP {owasp}</div>
    <div class="cap-desc">{desc}</div>
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Run / Clear buttons ───────────────────────────────────────────────
    _btn_label = "🚀  Run Full Analysis" if not scanner_only else "🔍  Run Scanners Only (skip AI)"
    run_col, clear_col, info_col = st.columns([2, 1, 3])
    run_btn   = run_col.button(_btn_label, type="primary", use_container_width=True)
    clear_btn = clear_col.button("✕  Clear",               use_container_width=True)
    with info_col:
        st.caption("Bandit + Semgrep scan takes ~3 s · AI analysis ~15 s · results stay in browser session")

    if clear_btn:
        st.session_state.result       = None
        st.session_state.running      = False
        st.session_state.scan_target  = ""
        st.session_state.scan_is_demo = False
        st.rerun()

    # ── Pipeline execution ────────────────────────────────────────────────
    if run_btn and not st.session_state.running:
        has_code = bool(raw_code.strip())
        has_url  = bool(target_url.strip())

        # Determine what label to show for the scanned target
        if has_url:
            display_target = target_url.strip()
        elif uploaded:
            display_target = uploaded.name
        elif has_code and demo_mode and not uploaded:
            display_target = "samples/vulnerable_app.py (demo)"
        elif has_code:
            display_target = "קוד שהוזן ידנית"
        else:
            display_target = "samples/vulnerable_app.py (demo)"

        if not demo_mode and not has_code and not has_url:
            st.error("⚠️ יש להזין קוד מקור או כתובת URL לפני הרצת הסריקה.")
        else:
            st.session_state.running      = True
            st.session_state.scan_target  = display_target
            st.session_state.scan_is_demo = demo_mode

            with st.status("Running pipeline…", expanded=True) as status_box:
                if demo_mode:
                    import time
                    from samples.mock_responses import (
                        ANALYST_MARKDOWN, REMEDIATION_MARKDOWN, SCANNER_JSON,
                    )
                    from orchestrator import PipelineResult, StageResult
                    from datetime import datetime, timezone

                    st.write(f"🎭 **Demo Mode** — מדמה סריקה של: `{display_target}`")
                    st.write("⚡ Stage 1 — Scanner: Bandit · Semgrep…")
                    time.sleep(1.0)
                    st.write("  ✓ Bandit: 6 findings · Semgrep: 2 findings")

                    if not scanner_only:
                        st.write("🤖 Stage 2 — AI Analyst: CVSS scoring · OWASP mapping…")
                        time.sleep(1.2)
                        st.write("  ✓ Analyst: vulnerability report ready")
                        st.write("🔧 Stage 3 — Remediation Agent: generating fix playbook…")
                        time.sleep(1.0)
                        st.write("  ✓ Playbook: patch recommendations ready")

                    now = datetime.now(timezone.utc).isoformat()
                    st.session_state.result = PipelineResult(
                        target_description=f"{display_target} [DEMO]",
                        started_at=now, completed_at=now, total_duration_seconds=3.2,
                        scanner=StageResult(status="success", output=SCANNER_JSON, duration_seconds=1.0),
                        analyst=StageResult(
                            status="success" if not scanner_only else "skipped",
                            output=ANALYST_MARKDOWN, duration_seconds=1.2,
                        ),
                        remediation=StageResult(
                            status="success" if not scanner_only else "skipped",
                            output=REMEDIATION_MARKDOWN, duration_seconds=1.0,
                        ),
                        overall_status="success" if not scanner_only else "partial",
                    )
                    status_box.update(label="✅ Pipeline complete! (Demo — תוצאות סטטיות)", state="complete")

                else:
                    parts = []
                    if has_code:
                        ext  = uploaded.name.rsplit(".", 1)[-1] if uploaded else "py"
                        lang = {"py":"python","js":"javascript","ts":"typescript",
                                "java":"java","go":"go","rb":"ruby","php":"php"}.get(ext,"python")
                        parts.append(f"Scan the following {lang} code:\n\n```{lang}\n{raw_code}\n```")
                    if has_url:
                        parts.append(f"Also audit this URL: {target_url.strip()}")
                    target = "\n\n".join(parts)

                    from orchestrator import SecurityPipeline
                    pipeline = SecurityPipeline(verbose=False)
                    st.write(f"🔍 **Live Scan** — סורק: `{display_target}`")
                    st.write("⚡ Stage 1 — Running Bandit + Semgrep…")
                    result = pipeline.run(target, scanner_only=scanner_only)
                    st.session_state.result = result
                    if result.scanner.status    == "success": st.write("  ✓ Scanner complete")
                    if result.analyst.status    == "success": st.write("  ✓ AI Analyst complete")
                    if result.remediation.status== "success": st.write("  ✓ Remediation Playbook ready")
                    lbl = "✅ Pipeline complete!" if result.is_success() else "⚠️ Pipeline finished with warnings"
                    status_box.update(label=lbl, state="complete" if result.is_success() else "error")

            if save_reports and st.session_state.result:
                saved = st.session_state.result.save_reports("./reports")
                st.success(f"Reports saved to ./reports/ ({len(saved)} files)")
            st.session_state.running = False
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# TAB 2 — Scanner Findings (professional cards)
# ═══════════════════════════════════════════════════════════════════════════
with tab_scanner:
    result = st.session_state.result

    if not result:
        st.markdown("""
<div style="background:#0d1117;border:1px solid #1f2d3d;border-radius:10px;padding:40px;text-align:center;margin-top:20px">
  <div style="font-size:2rem;margin-bottom:12px">🔍</div>
  <div style="color:#475569;font-size:0.9rem">Run an analysis on the Input tab to see findings here.</div>
</div>""", unsafe_allow_html=True)

    elif result.scanner.status != "success":
        st.error(f"Scanner did not complete: {result.scanner.error}")

    else:
        try:
            data = json.loads(result.scanner.output)
        except json.JSONDecodeError:
            st.code(result.scanner.output)
            st.stop()

        # ── Bandit ───────────────────────────────────────────────────────
        bandit = data.get("bandit_results")
        if bandit and bandit.get("status") == "completed":
            b_total = bandit.get("total_findings", 0)
            b_sev   = bandit.get("severity_summary", {})
            st.markdown(f"""
<div style="display:flex;align-items:center;gap:16px;margin:16px 0 8px">
  <div style="color:#e2e8f0;font-size:1.1rem;font-weight:700">🔍 Bandit — {b_total} finding(s)</div>
  <span class="badge badge-high">{b_sev.get("high",0)} High</span>
  <span class="badge badge-medium">{b_sev.get("medium",0)} Medium</span>
  <span class="badge badge-low">{b_sev.get("low",0)} Low</span>
</div>""", unsafe_allow_html=True)

            findings = bandit.get("findings", [])
            # Sort by severity
            _order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
            findings = sorted(findings, key=lambda f: _order.get(f.get("severity","LOW").upper(), 4))
            for i, f in enumerate(findings):
                _render_bandit_card(f, i)

        # ── Semgrep ───────────────────────────────────────────────────────
        sem = data.get("semgrep_results")
        if sem and sem.get("status") == "completed":
            s_total = sem.get("total_findings", 0)
            s_sev   = sem.get("severity_summary", {})
            st.markdown(f"""
<div style="display:flex;align-items:center;gap:16px;margin:20px 0 8px">
  <div style="color:#e2e8f0;font-size:1.1rem;font-weight:700">🔍 Semgrep — {s_total} finding(s)</div>
  <span class="badge badge-high">{s_sev.get("error",0)} Error</span>
  <span class="badge badge-medium">{s_sev.get("warning",0)} Warning</span>
  <span class="badge badge-low">{s_sev.get("info",0)} Info</span>
</div>""", unsafe_allow_html=True)

            sem_findings = sem.get("findings", [])
            for i, f in enumerate(sem_findings):
                _render_semgrep_card(f, i)

        # ── VirusTotal ─────────────────────────────────────────────────────
        vt = data.get("virustotal_results")
        if vt:
            threat     = vt.get("threat_level", "UNKNOWN").upper()
            vt_color   = _SEV_BORDER.get(threat, "#10b981")
            vt_badge   = _SEV_BADGE.get(threat, "badge-info")
            risk_score = vt.get("risk_score", 0)
            flagged    = len(vt.get("flagged_by", {}))
            engines    = vt.get("total_engines_checked", 0)
            st.markdown(f"""
<div class="finding-card" style="border-left:4px solid {vt_color};margin-top:20px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <span class="badge {vt_badge}">{threat}</span>
    <span class="finding-title">VirusTotal URL Reputation</span>
  </div>
  <div style="display:flex;gap:32px">
    <div><div style="font-size:1.4rem;font-weight:900;color:{vt_color};font-family:'JetBrains Mono',monospace">{risk_score}/100</div>
    <div style="color:#475569;font-size:0.72rem">Risk Score</div></div>
    <div><div style="font-size:1.4rem;font-weight:900;color:{vt_color};font-family:'JetBrains Mono',monospace">{flagged}/{engines}</div>
    <div style="color:#475569;font-size:0.72rem">Engines flagged</div></div>
  </div>
</div>""", unsafe_allow_html=True)

        # ── Security Headers ──────────────────────────────────────────────
        headers = data.get("headers_results")
        if headers:
            h_score   = headers.get("security_score", 0)
            h_missing = headers.get("missing_headers", [])
            h_color   = "#10b981" if h_score >= 75 else "#f59e0b" if h_score >= 40 else "#ef4444"
            st.markdown(f"""
<div class="finding-card" style="border-left:4px solid {h_color};margin-top:8px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <span class="finding-title">Security Headers Audit</span>
    <span style="margin-left:auto;font-size:1.4rem;font-weight:900;color:{h_color};font-family:'JetBrains Mono',monospace">{h_score}%</span>
  </div>
  {f'<div class="finding-impact">❌ Missing: <b style="color:#e2e8f0">{", ".join(h_missing)}</b></div>' if h_missing else '<div class="finding-impact">✅ All critical security headers present</div>'}
</div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# TAB 3 — AI Vulnerability Report
# ═══════════════════════════════════════════════════════════════════════════
with tab_analyst:
    result = st.session_state.result

    if not result:
        st.markdown("""
<div style="background:#0d1117;border:1px solid #1f2d3d;border-radius:10px;padding:40px;text-align:center;margin-top:20px">
  <div style="font-size:2rem;margin-bottom:12px">📊</div>
  <div style="color:#475569;font-size:0.9rem">The AI vulnerability report will appear here after analysis.</div>
</div>""", unsafe_allow_html=True)

    elif result.analyst.status == "skipped":
        st.info("AI Analyst was skipped — disable **Scanner Only** mode and re-run to get the full report.")
    elif result.analyst.status == "failed":
        st.error(f"Analyst stage failed: {result.analyst.error}")
    else:
        st.markdown('<div class="section-label">AI VULNERABILITY REPORT</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="report-body">', unsafe_allow_html=True)
        st.markdown(result.analyst.output)
        st.markdown("</div>", unsafe_allow_html=True)
        st.divider()
        st.download_button(
            label="📥  Download Vulnerability Report (.md)",
            data=result.analyst.output,
            file_name="vulnerability_report.md",
            mime="text/markdown",
            use_container_width=True,
            key="dl_analyst_tab3",
        )


# ═══════════════════════════════════════════════════════════════════════════
# TAB 4 — Remediation Playbook
# ═══════════════════════════════════════════════════════════════════════════
with tab_remediation:
    result = st.session_state.result

    if not result:
        st.markdown("""
<div style="background:#0d1117;border:1px solid #1f2d3d;border-radius:10px;padding:40px;text-align:center;margin-top:20px">
  <div style="font-size:2rem;margin-bottom:12px">🔧</div>
  <div style="color:#475569;font-size:0.9rem">The step-by-step fix playbook will appear here after analysis.</div>
</div>""", unsafe_allow_html=True)

    elif result.remediation.status == "skipped":
        st.info("Remediation stage was skipped — disable **Scanner Only** mode to get the fix playbook.")
    elif result.remediation.status == "failed":
        st.error(f"Remediation stage failed: {result.remediation.error}")
    else:
        st.markdown('<div class="section-label">REMEDIATION PLAYBOOK</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="report-body">', unsafe_allow_html=True)
        st.markdown(result.remediation.output)
        st.markdown("</div>", unsafe_allow_html=True)
        st.divider()
        dl1, dl2 = st.columns(2)
        dl1.download_button(
            label="📥  Download Playbook (.md)",
            data=result.remediation.output,
            file_name="remediation_playbook.md",
            mime="text/markdown",
            use_container_width=True,
            key="dl_remediation_tab4",
        )
        if result.analyst.status == "success":
            dl2.download_button(
                label="📥  Download Vulnerability Report (.md)",
                data=result.analyst.output,
                file_name="vulnerability_report.md",
                mime="text/markdown",
                use_container_width=True,
                key="dl_analyst_tab4",
            )


# ─────────────────────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center;padding:24px 0 8px;color:#334155;font-size:0.72rem;
            font-family:'JetBrains Mono',monospace;letter-spacing:0.1em;">
  AI CYBER SHIELD v6 &nbsp;·&nbsp; CODE SECURITY ANALYSER &nbsp;·&nbsp;
  DEFENSIVE USE ONLY &nbsp;·&nbsp; מערכת לשימוש הגנתי בלבד
</div>
""", unsafe_allow_html=True)

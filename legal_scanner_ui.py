"""
Legal Compliance Scanner UI — AI Cyber Shield
Renders the full legal scanner interface inside url_scanner_app.py
"""
from __future__ import annotations

import streamlit as st

from tools.legal_scanner import LegalFinding, LegalScanResult, run_legal_scan

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_DISCLAIMER_HTML = """
<div style="
  background:rgba(245,158,11,0.08);
  border:1px solid rgba(245,158,11,0.35);
  border-left:4px solid #f59e0b;
  border-radius:10px;padding:14px 18px;margin:16px 0 24px;
  font-size:0.78rem;color:#94a3b8;line-height:1.6;
">
  <strong style="color:#f59e0b">⚠️ Legal Disclaimer</strong><br>
  This tool provides <strong>informational analysis only</strong> and does not constitute legal advice.
  Results are based on automated technical scanning and may not reflect the full legal picture.
  Always review findings with a qualified legal professional before making compliance decisions.
  <strong>AI Cyber Shield Ltd. accepts no liability</strong> for compliance decisions made based on this report.
  Laws vary by jurisdiction, business type, and data processing activities.
</div>"""

_FRAMEWORK_INFO = {
    "IL": {
        "flag": "🇮🇱", "name": "Israeli Law",
        "laws": "Privacy Protection Law + Amendment 13 (Aug 2025) · Data Security Regulations 2017 · Consumer Protection Law · E-Commerce Regulations 2003 · IS 5568 Accessibility · Anti-Spam Law",
        "color": "#3b82f6",
    },
    "US": {
        "flag": "🇺🇸", "name": "US Law",
        "laws": "CCPA/CPRA (California) · ADA Web Accessibility (WCAG 2.1 AA) · CAN-SPAM Act · COPPA · FTC Act §5 (Dark Patterns)",
        "color": "#ef4444",
    },
    "GDPR": {
        "flag": "🇪🇺", "name": "GDPR (EU)",
        "laws": "Arts. 13/14 Privacy Notice · Art. 7 Cookie Consent · Art. 17 Right to Erasure · Art. 37 DPO · ePrivacy Directive · EDPB Cookie Taskforce",
        "color": "#6366f1",
    },
}

_CATEGORY_LABELS = {
    "privacy":       "🔒 Privacy Policy",
    "cookies":       "🍪 Cookie & Consent",
    "trackers":      "📡 Third-Party Trackers",
    "accessibility": "♿ Accessibility",
    "consumer":      "🛒 Consumer Law",
    "data_rights":   "📋 Data Rights",
    "dark_patterns": "⚠️ Dark Patterns",
    "security":      "🛡️ Security Headers",
}

_STATUS_COLOR  = {"PASS": "#10b981", "FAIL": "#ef4444", "WARN": "#f59e0b", "SKIP": "#475569"}
_STATUS_ICON   = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭"}
_SEV_COLOR     = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#64748b"}
_SEV_BG        = {"HIGH": "rgba(239,68,68,0.1)", "MEDIUM": "rgba(245,158,11,0.1)", "LOW": "rgba(100,116,139,0.1)"}


# ─────────────────────────────────────────────────────────────────────────────
# Score gauge
# ─────────────────────────────────────────────────────────────────────────────

def _risk_label(score: int) -> tuple[str, str]:
    if score <= 20:  return "Low Risk",    "#10b981"
    if score <= 50:  return "Medium Risk", "#f59e0b"
    if score <= 75:  return "High Risk",   "#ef4444"
    return               "Critical",      "#dc2626"


def _score_gauge_svg(score: int, label: str, color: str, size: int = 120) -> str:
    r = 44
    cx = cy = size // 2
    circumference = 2 * 3.14159 * r
    # Risk score: high score = high risk = fill red. We invert: 0 risk = green full
    # Show the actual risk level via arc fill
    fill_pct = score / 100
    dash_fill = circumference * fill_pct
    dash_empty = circumference * (1 - fill_pct)
    safe_color = "#10b981" if score <= 20 else ("#f59e0b" if score <= 50 else "#ef4444")
    return f"""<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1e293b" stroke-width="8"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{safe_color}" stroke-width="8"
    stroke-dasharray="{dash_fill:.1f} {dash_empty:.1f}"
    stroke-linecap="round"
    transform="rotate(-90 {cx} {cy})"/>
  <text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="20" font-weight="900"
    fill="{safe_color}" font-family="system-ui">{score}</text>
  <text x="{cx}" y="{cy + 14}" text-anchor="middle" font-size="8" fill="#64748b"
    font-family="system-ui">{label}</text>
</svg>"""


# ─────────────────────────────────────────────────────────────────────────────
# Render helpers
# ─────────────────────────────────────────────────────────────────────────────

def _render_score_dashboard(result: LegalScanResult) -> None:
    risk_lbl, risk_col = _risk_label(result.risk_score)

    st.markdown(f"""
<style>
.lscore-wrap{{display:flex;gap:20px;flex-wrap:wrap;margin:20px 0 8px}}
.lscore-card{{
  background:linear-gradient(135deg,#0a0f1e,#060b14);
  border:1px solid #1e293b;border-radius:16px;padding:20px;
  flex:1;min-width:160px;text-align:center;
}}
.lscore-main{{
  background:linear-gradient(135deg,#0d1829,#060b14);
  border:1px solid {risk_col}44;
  box-shadow:0 0 30px {risk_col}1a;
}}
.lscore-fw{{font-size:0.7rem;color:#475569;margin-bottom:6px;letter-spacing:0.04em}}
.lscore-lbl{{font-size:0.75rem;font-weight:700;margin-top:4px}}
</style>
<div class="lscore-wrap">
  <div class="lscore-card lscore-main">
    <div class="lscore-fw">OVERALL LEGAL RISK</div>
    {_score_gauge_svg(result.risk_score, risk_lbl, risk_col, 130)}
    <div class="lscore-lbl" style="color:{risk_col}">{risk_lbl}</div>
  </div>
  <div class="lscore-card">
    <div class="lscore-fw">🇮🇱 ISRAELI LAW</div>
    {_score_gauge_svg(result.il_score, _risk_label(result.il_score)[0], _risk_label(result.il_score)[1], 110)}
    <div class="lscore-lbl" style="color:{_risk_label(result.il_score)[1]}">{_risk_label(result.il_score)[0]}</div>
  </div>
  <div class="lscore-card">
    <div class="lscore-fw">🇺🇸 US LAW</div>
    {_score_gauge_svg(result.us_score, _risk_label(result.us_score)[0], _risk_label(result.us_score)[1], 110)}
    <div class="lscore-lbl" style="color:{_risk_label(result.us_score)[1]}">{_risk_label(result.us_score)[0]}</div>
  </div>
  <div class="lscore-card">
    <div class="lscore-fw">🇪🇺 GDPR</div>
    {_score_gauge_svg(result.gdpr_score, _risk_label(result.gdpr_score)[0], _risk_label(result.gdpr_score)[1], 110)}
    <div class="lscore-lbl" style="color:{_risk_label(result.gdpr_score)[1]}">{_risk_label(result.gdpr_score)[0]}</div>
  </div>
</div>""", unsafe_allow_html=True)

    # Stats row
    fails  = sum(1 for f in result.findings if f.status == "FAIL")
    warns  = sum(1 for f in result.findings if f.status == "WARN")
    passes = sum(1 for f in result.findings if f.status == "PASS")
    high_r = sum(1 for f in result.findings if f.status == "FAIL" and f.severity == "HIGH")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("❌ Violations",  fails)
    c2.metric("⚠️ Warnings",   warns)
    c3.metric("✅ Compliant",   passes)
    c4.metric("🔴 High Risk",   high_r)
    c5.metric("⏱ Scan time",   f"{result.scan_time}s")


def _render_tracker_summary(result: LegalScanResult) -> None:
    if not result.trackers_found and not result.consent_sdk:
        return
    st.markdown("### 📡 Third-Party Tracker Inventory")
    col_t, col_c = st.columns([3, 2])
    with col_t:
        if result.trackers_found:
            pills = " ".join(
                f'<span style="display:inline-block;background:#1e293b;border:1px solid #ef4444;'
                f'border-radius:6px;padding:3px 10px;margin:3px;font-size:0.75rem;color:#f87171">'
                f'{t}</span>' for t in result.trackers_found
            )
            st.markdown(f"**Trackers detected ({len(result.trackers_found)}):** {pills}", unsafe_allow_html=True)
            st.caption("⚠️ Under GDPR/CCPA/IL law, these must only load AFTER explicit user consent.")
        else:
            st.success("No known tracking scripts detected.")
    with col_c:
        if result.consent_sdk:
            st.success(f"✅ CMP detected: **{result.consent_sdk}**")
        else:
            st.error("❌ No cookie consent platform detected")
        if result.privacy_policy_url:
            st.markdown(f"📄 [Privacy Policy]({result.privacy_policy_url})")
        if result.tos_url:
            st.markdown(f"📜 [Terms of Service]({result.tos_url})")
        if result.accessibility_url:
            st.markdown(f"♿ [Accessibility Statement]({result.accessibility_url})")


def _render_finding_card(f: LegalFinding) -> None:
    sc = _STATUS_COLOR[f.status]
    si = _STATUS_ICON[f.status]
    sev_c = _SEV_COLOR[f.severity]
    sev_bg = _SEV_BG[f.severity]
    fw_info = _FRAMEWORK_INFO.get(f.framework, {"flag": "🌐", "color": "#475569"})
    fw_flag = fw_info["flag"] if f.framework != "ALL" else "🌐"
    fw_col  = fw_info["color"] if f.framework != "ALL" else "#475569"

    st.markdown(f"""
<div style="
  background:#0a0f1e;border:1px solid #1e293b;border-left:3px solid {sc};
  border-radius:10px;padding:14px 16px;margin:8px 0;
">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:8px">
    <div style="font-size:0.9rem;font-weight:700;color:#f1f5f9">{si} {f.title}</div>
    <div style="display:flex;gap:6px;align-items:center">
      <span style="background:{sev_bg};border:1px solid {sev_c};color:{sev_c};
        font-size:0.65rem;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:0.05em">{f.severity}</span>
      <span style="background:#1e293b;border:1px solid {fw_col}44;color:{fw_col};
        font-size:0.65rem;font-weight:700;padding:2px 8px;border-radius:4px">{fw_flag} {f.framework}</span>
    </div>
  </div>
  <div style="font-size:0.75rem;color:#64748b;margin-bottom:6px">
    ⚖️ <em>{f.legal_basis}</em>
  </div>
  <div style="font-size:0.8rem;color:#94a3b8;margin-bottom:8px;line-height:1.5">{f.description}</div>
  {'<div style="background:#0f1f0f;border:1px solid #166534;border-radius:6px;padding:8px 12px;font-size:0.78rem;color:#86efac;margin-top:4px">💡 ' + f.recommendation + '</div>' if f.status in ("FAIL", "WARN") else ''}
  {'<div style="font-size:0.7rem;color:#334155;margin-top:6px">🔍 ' + f.evidence + '</div>' if f.evidence else ''}
</div>""", unsafe_allow_html=True)


def _render_findings_by_category(findings: list[LegalFinding]) -> None:
    # Group by category
    categories: dict[str, list[LegalFinding]] = {}
    for f in findings:
        categories.setdefault(f.category, []).append(f)

    priority_order = ["privacy", "cookies", "trackers", "data_rights",
                      "consumer", "accessibility", "dark_patterns", "security"]

    for cat in priority_order:
        if cat not in categories:
            continue
        cat_findings = categories[cat]
        fails  = sum(1 for f in cat_findings if f.status == "FAIL")
        warns  = sum(1 for f in cat_findings if f.status == "WARN")
        passes = sum(1 for f in cat_findings if f.status == "PASS")
        label  = _CATEGORY_LABELS.get(cat, cat.title())

        status_summary = ""
        if fails:
            status_summary += f'<span style="color:#ef4444">❌ {fails} fail{"s" if fails>1 else ""}</span>  '
        if warns:
            status_summary += f'<span style="color:#f59e0b">⚠️ {warns} warning{"s" if warns>1 else ""}</span>  '
        if passes:
            status_summary += f'<span style="color:#10b981">✅ {passes} pass</span>'

        with st.expander(f"{label} — {status_summary}", expanded=(fails > 0)):
            for f in sorted(cat_findings, key=lambda x: {"FAIL": 0, "WARN": 1, "PASS": 2, "SKIP": 3}[x.status]):
                if f.status != "SKIP":
                    _render_finding_card(f)


def _render_recommendations_summary(findings: list[LegalFinding]) -> None:
    """Quick-action list of top priority recommendations."""
    high_fails = [f for f in findings if f.status == "FAIL" and f.severity == "HIGH"]
    if not high_fails:
        st.success("🎉 No critical (HIGH severity) violations found!")
        return

    st.markdown("### 🎯 Priority Action List")
    st.caption(f"These {len(high_fails)} HIGH-severity items should be addressed immediately to reduce legal exposure.")

    for i, f in enumerate(high_fails[:10], 1):
        fw_info = _FRAMEWORK_INFO.get(f.framework, {"flag": "🌐"})
        flag = fw_info["flag"] if f.framework != "ALL" else "🌐"
        st.markdown(f"""
<div style="background:#0a0f1e;border:1px solid #1e293b;border-left:3px solid #ef4444;
  border-radius:8px;padding:10px 14px;margin:5px 0">
  <div style="font-size:0.82rem;font-weight:700;color:#f87171;margin-bottom:3px">
    {i}. {f.title} {flag}
  </div>
  <div style="font-size:0.77rem;color:#86efac">💡 {f.recommendation}</div>
  <div style="font-size:0.68rem;color:#334155;margin-top:3px">⚖️ {f.legal_basis}</div>
</div>""", unsafe_allow_html=True)


def _render_framework_cards() -> None:
    """Show the 3 framework info cards."""
    cols = st.columns(3)
    for i, (fw_code, fw) in enumerate(_FRAMEWORK_INFO.items()):
        with cols[i]:
            st.markdown(f"""
<div style="background:linear-gradient(135deg,#0a0f1e,#060b14);
  border:1px solid {fw['color']}33;border-radius:12px;padding:14px 16px;height:100%">
  <div style="font-size:1.1rem;margin-bottom:6px">{fw['flag']} <strong style="color:{fw['color']}">{fw['name']}</strong></div>
  <div style="font-size:0.7rem;color:#475569;line-height:1.6">{fw['laws']}</div>
</div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point — called from url_scanner_app.py
# ─────────────────────────────────────────────────────────────────────────────

def show_legal_scanner(prefill_url: str = "") -> None:
    """Main legal scanner UI. Call from a Streamlit tab or section."""

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown("""
<style>
.legal-hero{
  background:linear-gradient(135deg,#0a0f1e 0%,#060b14 100%);
  border:1px solid #1e293b;border-radius:16px;padding:28px 32px;margin-bottom:20px;
}
.legal-hero h2{
  font-size:1.6rem;font-weight:900;
  background:linear-gradient(90deg,#3b82f6,#6366f1,#8b5cf6);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  margin:0 0 8px;
}
.legal-hero p{color:#64748b;font-size:0.88rem;margin:0}
</style>
<div class="legal-hero">
  <h2>⚖️ Legal Compliance Scanner</h2>
  <p>Automated compliance analysis across 3 legal frameworks · 40+ checks · Actionable remediation steps</p>
</div>""", unsafe_allow_html=True)

    _render_framework_cards()
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Legal disclaimer ──────────────────────────────────────────────────────
    st.markdown(_DISCLAIMER_HTML, unsafe_allow_html=True)

    # ── URL input ─────────────────────────────────────────────────────────────
    url_input = st.text_input(
        "Target URL",
        value=prefill_url or "",
        placeholder="https://yourwebsite.com",
        help="Enter the full URL of a website you own or have written permission to scan.",
        label_visibility="collapsed",
        key="legal_url_input",
    )

    # ── Framework selector ────────────────────────────────────────────────────
    fw_col1, fw_col2, fw_col3, fw_col4 = st.columns(4)
    with fw_col1:
        do_il   = st.checkbox("🇮🇱 Israeli Law", value=True, key="legal_fw_il")
    with fw_col2:
        do_us   = st.checkbox("🇺🇸 US Law",      value=True, key="legal_fw_us")
    with fw_col3:
        do_gdpr = st.checkbox("🇪🇺 GDPR",        value=True, key="legal_fw_gdpr")
    with fw_col4:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        scan_btn = st.button("⚖️ Run Legal Scan", type="primary", use_container_width=True, key="legal_scan_btn")

    active_frameworks = []
    if do_il:   active_frameworks.append("IL")
    if do_us:   active_frameworks.append("US")
    if do_gdpr: active_frameworks.append("GDPR")

    if not active_frameworks:
        st.warning("Please select at least one legal framework to scan.")
        return

    # ── Scan execution ────────────────────────────────────────────────────────
    if scan_btn:
        if not url_input or not url_input.strip():
            st.error("Please enter a target URL.")
            return

        raw_url = url_input.strip()
        if not raw_url.startswith(("http://", "https://")):
            raw_url = "https://" + raw_url

        # SSRF / self-scan guard
        from urllib.parse import urlparse
        hostname = urlparse(raw_url).hostname or ""
        if any(hostname == b or hostname.endswith("." + b)
               for b in ("streamlit.app", "localhost", "127.0.0.1", "::1")):
            st.error("⚠️ Scanning this app's own domain is disabled. Enter an external URL to scan.")
            return

        # Log the scan attempt
        try:
            from audit_log import log_action
            log_action("legal_scan_start", target=raw_url,
                       details={"frameworks": active_frameworks}, severity="info")
        except Exception:
            pass

        with st.spinner("⚖️ Analysing legal compliance… fetching pages, detecting trackers, running AI analysis…"):
            result = run_legal_scan(raw_url, active_frameworks)

        if result.error:
            st.error(f"Scan failed: {result.error}")
            return

        try:
            from audit_log import log_action
            log_action("legal_scan_complete", target=raw_url, details={
                "risk_score": result.risk_score,
                "il_score":   result.il_score,
                "us_score":   result.us_score,
                "gdpr_score": result.gdpr_score,
                "fails":      sum(1 for f in result.findings if f.status == "FAIL"),
                "trackers":   len(result.trackers_found),
                "frameworks": active_frameworks,
            }, severity="info")
        except Exception:
            pass

        # ── Results ───────────────────────────────────────────────────────────
        st.markdown("---")
        st.markdown(f"### ⚖️ Legal Compliance Report — `{raw_url}`")
        st.caption(f"Frameworks: {' · '.join(_FRAMEWORK_INFO[fw]['flag'] + ' ' + _FRAMEWORK_INFO[fw]['name'] for fw in active_frameworks if fw in _FRAMEWORK_INFO)} · Scan time: {result.scan_time}s · {len(result.findings)} checks")

        # Score dashboard
        _render_score_dashboard(result)

        # Tracker summary
        st.markdown("---")
        _render_tracker_summary(result)

        # Priority action list
        st.markdown("---")
        _render_recommendations_summary(result.findings)

        # Full findings by category
        st.markdown("---")
        st.markdown("### 📋 Full Compliance Report")

        tab_all, tab_il, tab_us, tab_gdpr = st.tabs([
            "📊 All Checks",
            "🇮🇱 Israeli Law",
            "🇺🇸 US Law",
            "🇪🇺 GDPR",
        ])

        with tab_all:
            _render_findings_by_category(result.findings)

        with tab_il:
            il_findings = [f for f in result.findings if f.framework in ("IL", "ALL")]
            _render_findings_by_category(il_findings)

        with tab_us:
            us_findings = [f for f in result.findings if f.framework in ("US", "ALL")]
            _render_findings_by_category(us_findings)

        with tab_gdpr:
            gdpr_findings = [f for f in result.findings if f.framework in ("GDPR", "ALL")]
            _render_findings_by_category(gdpr_findings)

        # Repeat disclaimer at bottom of results
        st.markdown(_DISCLAIMER_HTML, unsafe_allow_html=True)

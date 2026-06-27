"""
Compliance Shield UI — AI Cyber Shield
Renders the full Compliance Shield interface inside url_scanner_app.py
"""
from __future__ import annotations

import streamlit as st

from tools.legal_scanner import LegalFinding, LegalScanResult, CookieRecord, run_legal_scan

# ─────────────────────────────────────────────────────────────────────────────
# Language system — default Hebrew
# ─────────────────────────────────────────────────────────────────────────────

def _get_lang() -> str:
    return st.session_state.get("cs_lang", "he")


_STRINGS: dict[str, dict] = {
    # ── Hebrew ────────────────────────────────────────────────────────────────
    "he": {
        "hero": {
            "title":    "⚖️ מגן ציות",
            "subtitle": "ניתוח ציות אוטומטי ב-3 מסגרות משפטיות · 50+ בדיקות · צעדי תיקון מעשיים",
        },
        "scan": {
            "url_placeholder": "https://yourwebsite.com",
            "url_help":  "הזן כתובת מלאה של אתר שבבעלותך או שיש לך אישור בכתב לסרוק אותו.",
            "fw_il":     "🇮🇱 חוק ישראלי",
            "fw_us":     "🇺🇸 חוק אמריקאי",
            "fw_gdpr":   "🇪🇺 GDPR",
            "btn_scan":  "⚖️ הפעל סריקת ציות",
            "no_fw":     "יש לבחור לפחות מסגרת משפטית אחת לסריקה.",
            "no_url":    "אנא הזן כתובת אתר יעד.",
            "ssrf":      "⚠️ סריקת דומיין זה אינה מותרת. הזן כתובת חיצונית לסריקה.",
            "spinner":   "⚖️ מגן ציות סורק… טוען עמודים, מזהה עוקבים, מנתח…",
            "fail":      "הסריקה נכשלה",
        },
        "result": {
            "report_title": "### ⚖️ דוח מגן ציות — `{url}`",
            "caption":      "מסגרות: {fws} · זמן סריקה: {t}ש׳ · {n} בדיקות",
        },
        "score": {
            "overall":  "סיכון משפטי כולל",
            "il":       "🇮🇱 חוק ישראלי",
            "us":       "🇺🇸 חוק אמריקאי",
            "gdpr":     "🇪🇺 GDPR",
            "low":      "סיכון נמוך",
            "medium":   "סיכון בינוני",
            "high":     "סיכון גבוה",
            "critical": "קריטי",
        },
        "metrics": {
            "violations":      "❌ הפרות",
            "warnings":        "⚠️ אזהרות",
            "compliant":       "✅ תואם",
            "high_risk":       "🔴 סיכון גבוה",
            "scan_time":       "⏱ זמן סריקה",
            "pages":           "🌐 עמודים שנסרקו",
            "playwright_ok":   "🟢 נסרק עם Playwright — עיבוד JS מלא, לכידת עוגיות אמיתית",
            "playwright_warn": "🟡 סריקת HTML סטטית — עוגיות שנטענות ב-JS עלולות לא להיות מזוהות. התקן Playwright לכיסוי מלא.",
        },
        "tracker": {
            "heading":      "### 📡 מלאי עוקבים צד-שלישי",
            "detected":     "**עוקבים שזוהו ({n}):**",
            "none":         "לא זוהו סקריפטים מעקב ידועים.",
            "cmp_ok":       "✅ פלטפורמת הסכמה זוהתה: **{sdk}**",
            "cmp_fail":     "❌ לא זוהתה פלטפורמת הסכמה לעוגיות",
            "must_consent": "⚠️ לפי GDPR/CCPA/חוק ישראלי, אלה חייבים להיטען רק לאחר הסכמה מפורשת של המשתמש.",
            "privacy_link": "📄 [מדיניות פרטיות]({url})",
            "tos_link":     "📜 [תנאי שימוש]({url})",
            "access_link":  "♿ [הצהרת נגישות]({url})",
        },
        "cookie": {
            "heading":         "### 🍪 מלאי עוגיות",
            "nonconsent_warn": "⚠️ {n} עוגיות אנליטיקה/שיווק זוהו. לפי GDPR סעיף 7 + ePrivacy, אלה דורשות הסכמה מפורשת לפני ההגדרה שלהן.",
            "details_expand":  "פרטי עוגיות (נמצאו {n} עוגיות)",
            "col_name":        "שם",
            "col_cat":         "קטגוריה",
            "col_flags":       "דגלי אבטחה",
            "col_domain":      "דומיין",
            "no_flags":        "⚠️ ללא דגלים",
        },
        "cookie_cat": {
            "strictly_necessary": ("✅ הכרחי",       "#10b981"),
            "functional":         ("⚙️ פונקציונלי",  "#3b82f6"),
            "analytics":          ("📊 אנליטיקה",    "#f59e0b"),
            "marketing":          ("📢 שיווקי",       "#ef4444"),
            "unknown":            ("❓ לא ידוע",      "#475569"),
        },
        "multipage": {
            "heading":      "### 🗺️ כיסוי סריקת ריבוי עמודים",
            "ok":           "✅ קישור מדיניות הפרטיות בכותרת תחתית נמצא בכל {n} העמודים שנדגמו.",
            "warn":         "⚠️ קישור מדיניות הפרטיות לא נמצא בכל {n} העמודים שנדגמו. GDPR סעיף 12 מחייב שהקישור יהיה נגיש מכל עמוד.",
            "pages_expand": "עמודים שנבדקו ({n})",
        },
        "actions": {
            "heading": "### 🎯 רשימת פעולות עדיפות",
            "caption": "{n} פריטים ברמת חומרה גבוהה אלה צריכים להיות מטופלים מיידית להפחתת החשיפה המשפטית.",
            "none":    "🎉 לא נמצאו הפרות קריטיות (חומרה גבוהה)!",
        },
        "report": {
            "heading":   "### 📋 דוח ציות מלא",
            "tab_all":   "📊 כל הבדיקות",
            "tab_il":    "🇮🇱 חוק ישראלי",
            "tab_us":    "🇺🇸 חוק אמריקאי",
            "tab_gdpr":  "🇪🇺 GDPR",
        },
        "category": {
            "privacy":       "🔒 מדיניות פרטיות",
            "cookies":       "🍪 עוגיות והסכמה",
            "trackers":      "📡 עוקבים צד-שלישי",
            "accessibility": "♿ נגישות",
            "consumer":      "🛒 דיני צרכנות",
            "data_rights":   "📋 זכויות מידע",
            "dark_patterns": "⚠️ דפוסים מניפולטיביים",
            "security":      "🛡️ כותרות אבטחה",
        },
        "finding": {
            "fine_label": "💰 קנס פוטנציאלי",
            "fine_min":   "מינימום:",
            "fine_max":   "מקסימום:",
        },
        "status_summary": {
            "fail_s": "❌ {n} הפרה",
            "fail_p": "❌ {n} הפרות",
            "warn_s": "⚠️ {n} אזהרה",
            "warn_p": "⚠️ {n} אזהרות",
            "pass":   "✅ {n} עבר",
        },
        "disclaimer": {
            "title": "⚠️ כתב ויתור משפטי",
            "body":  (
                "כלי זה מספק <strong>ניתוח מידעי בלבד</strong> ואינו מהווה ייעוץ משפטי. "
                "התוצאות מבוססות על סריקה טכנית אוטומטית ועשויות לא לשקף את התמונה המשפטית המלאה. "
                "בדוק תמיד ממצאים עם עורך דין מוסמך לפני קבלת החלטות ציות. "
                "<strong>AI Cyber Shield Ltd. אינה אחראית</strong> להחלטות ציות שהתקבלו בהתבסס על דוח זה. "
                "החוקים משתנים לפי תחום שיפוט, סוג עסק ופעילות עיבוד נתונים."
            ),
        },
        "lang_toggle": "EN",
    },
    # ── English ───────────────────────────────────────────────────────────────
    "en": {
        "hero": {
            "title":    "⚖️ Compliance Shield",
            "subtitle": "Automated compliance analysis across 3 legal frameworks · 50+ checks · Actionable remediation steps",
        },
        "scan": {
            "url_placeholder": "https://yourwebsite.com",
            "url_help":  "Enter the full URL of a website you own or have written permission to scan.",
            "fw_il":     "🇮🇱 Israeli Law",
            "fw_us":     "🇺🇸 US Law",
            "fw_gdpr":   "🇪🇺 GDPR",
            "btn_scan":  "⚖️ Run Compliance Scan",
            "no_fw":     "Please select at least one legal framework to scan.",
            "no_url":    "Please enter a target URL.",
            "ssrf":      "⚠️ Scanning this app's own domain is disabled. Enter an external URL to scan.",
            "spinner":   "⚖️ Compliance Shield scanning… fetching pages, detecting trackers, running analysis…",
            "fail":      "Scan failed",
        },
        "result": {
            "report_title": "### ⚖️ Compliance Shield Report — `{url}`",
            "caption":      "Frameworks: {fws} · Scan time: {t}s · {n} checks",
        },
        "score": {
            "overall":  "OVERALL LEGAL RISK",
            "il":       "🇮🇱 ISRAELI LAW",
            "us":       "🇺🇸 US LAW",
            "gdpr":     "🇪🇺 GDPR",
            "low":      "Low Risk",
            "medium":   "Medium Risk",
            "high":     "High Risk",
            "critical": "Critical",
        },
        "metrics": {
            "violations":      "❌ Violations",
            "warnings":        "⚠️ Warnings",
            "compliant":       "✅ Compliant",
            "high_risk":       "🔴 High Risk",
            "scan_time":       "⏱ Scan time",
            "pages":           "🌐 Pages scanned",
            "playwright_ok":   "🟢 Scanned with Playwright — full JS rendering, real cookie capture",
            "playwright_warn": "🟡 Static HTML scan — JS-loaded cookies may not be detected. Install Playwright for full coverage.",
        },
        "tracker": {
            "heading":      "### 📡 Third-Party Tracker Inventory",
            "detected":     "**Trackers detected ({n}):**",
            "none":         "No known tracking scripts detected.",
            "cmp_ok":       "✅ CMP detected: **{sdk}**",
            "cmp_fail":     "❌ No cookie consent platform detected",
            "must_consent": "⚠️ Under GDPR/CCPA/IL law, these must only load AFTER explicit user consent.",
            "privacy_link": "📄 [Privacy Policy]({url})",
            "tos_link":     "📜 [Terms of Service]({url})",
            "access_link":  "♿ [Accessibility Statement]({url})",
        },
        "cookie": {
            "heading":         "### 🍪 Cookie Inventory",
            "nonconsent_warn": "⚠️ {n} analytics/marketing cookie(s) detected. Under GDPR Art. 7 + ePrivacy Directive, these require explicit opt-in consent BEFORE they are set.",
            "details_expand":  "Cookie details ({n} cookies found)",
            "col_name":        "Name",
            "col_cat":         "Category",
            "col_flags":       "Security Flags",
            "col_domain":      "Domain",
            "no_flags":        "⚠️ No flags",
        },
        "cookie_cat": {
            "strictly_necessary": ("✅ Strictly Necessary", "#10b981"),
            "functional":         ("⚙️ Functional",         "#3b82f6"),
            "analytics":          ("📊 Analytics",           "#f59e0b"),
            "marketing":          ("📢 Marketing",           "#ef4444"),
            "unknown":            ("❓ Unknown",             "#475569"),
        },
        "multipage": {
            "heading":      "### 🗺️ Multi-Page Scan Coverage",
            "ok":           "✅ Privacy policy footer link found on all {n} sampled pages.",
            "warn":         "⚠️ Privacy policy footer link was NOT found on all {n} sampled pages. GDPR Art. 12 requires the privacy notice link to be accessible from every page.",
            "pages_expand": "Pages checked ({n})",
        },
        "actions": {
            "heading": "### 🎯 Priority Action List",
            "caption": "These {n} HIGH-severity items should be addressed immediately to reduce legal exposure.",
            "none":    "🎉 No critical (HIGH severity) violations found!",
        },
        "report": {
            "heading":  "### 📋 Full Compliance Report",
            "tab_all":  "📊 All Checks",
            "tab_il":   "🇮🇱 Israeli Law",
            "tab_us":   "🇺🇸 US Law",
            "tab_gdpr": "🇪🇺 GDPR",
        },
        "category": {
            "privacy":       "🔒 Privacy Policy",
            "cookies":       "🍪 Cookie & Consent",
            "trackers":      "📡 Third-Party Trackers",
            "accessibility": "♿ Accessibility",
            "consumer":      "🛒 Consumer Law",
            "data_rights":   "📋 Data Rights",
            "dark_patterns": "⚠️ Dark Patterns",
            "security":      "🛡️ Security Headers",
        },
        "finding": {
            "fine_label": "💰 Potential Fine",
            "fine_min":   "Min:",
            "fine_max":   "Max:",
        },
        "status_summary": {
            "fail_s": "❌ {n} fail",
            "fail_p": "❌ {n} fails",
            "warn_s": "⚠️ {n} warning",
            "warn_p": "⚠️ {n} warnings",
            "pass":   "✅ {n} pass",
        },
        "disclaimer": {
            "title": "⚠️ Legal Disclaimer",
            "body":  (
                "This tool provides <strong>informational analysis only</strong> and does not constitute legal advice. "
                "Results are based on automated technical scanning and may not reflect the full legal picture. "
                "Always review findings with a qualified legal professional before making compliance decisions. "
                "<strong>AI Cyber Shield Ltd. accepts no liability</strong> for compliance decisions made based on this report. "
                "Laws vary by jurisdiction, business type, and data processing activities."
            ),
        },
        "lang_toggle": "עב",
    },
}


def _s(lang: str, *keys: str) -> str:
    """Get a string from the translation dict. Supports nested keys."""
    obj: dict | str = _STRINGS[lang]
    for k in keys:
        obj = obj[k]  # type: ignore[index]
    return str(obj)


# ─────────────────────────────────────────────────────────────────────────────
# Constants (language-independent)
# ─────────────────────────────────────────────────────────────────────────────

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

_STATUS_COLOR = {"PASS": "#10b981", "FAIL": "#ef4444", "WARN": "#f59e0b", "SKIP": "#475569"}
_STATUS_ICON  = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭"}
_SEV_COLOR    = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#64748b"}
_SEV_BG       = {"HIGH": "rgba(239,68,68,0.1)", "MEDIUM": "rgba(245,158,11,0.1)", "LOW": "rgba(100,116,139,0.1)"}


# ─────────────────────────────────────────────────────────────────────────────
# Score gauge helpers
# ─────────────────────────────────────────────────────────────────────────────

def _risk_label(score: int) -> tuple[str, str]:
    lang = _get_lang()
    s = _STRINGS[lang]["score"]
    if score <= 20: return s["low"],      "#10b981"
    if score <= 50: return s["medium"],   "#f59e0b"
    if score <= 75: return s["high"],     "#ef4444"
    return               s["critical"],  "#dc2626"


def _score_gauge_svg(score: int, label: str, color: str, size: int = 120) -> str:
    r = 44
    cx = cy = size // 2
    circumference = 2 * 3.14159 * r
    fill_pct   = score / 100
    dash_fill  = circumference * fill_pct
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

def _disclaimer_html() -> str:
    lang = _get_lang()
    d = _STRINGS[lang]["disclaimer"]
    return f"""
<div style="
  background:rgba(245,158,11,0.08);
  border:1px solid rgba(245,158,11,0.35);
  border-left:4px solid #f59e0b;
  border-radius:10px;padding:14px 18px;margin:16px 0 24px;
  font-size:0.78rem;color:#94a3b8;line-height:1.6;
">
  <strong style="color:#f59e0b">{d['title']}</strong><br>
  {d['body']}
</div>"""


def _render_score_dashboard(result: LegalScanResult, active_frameworks: list[str]) -> None:
    lang = _get_lang()
    s    = _STRINGS[lang]["score"]
    m    = _STRINGS[lang]["metrics"]
    risk_lbl, risk_col = _risk_label(result.risk_score)

    # Build only the selected framework gauge cards
    fw_cards_html = ""
    if "IL" in active_frameworks:
        il_lbl, il_col = _risk_label(result.il_score)
        fw_cards_html += f"""
  <div class="lscore-card">
    <div class="lscore-fw">{s["il"]}</div>
    {_score_gauge_svg(result.il_score, il_lbl, il_col, 110)}
    <div class="lscore-lbl" style="color:{il_col}">{il_lbl}</div>
  </div>"""
    if "US" in active_frameworks:
        us_lbl, us_col = _risk_label(result.us_score)
        fw_cards_html += f"""
  <div class="lscore-card">
    <div class="lscore-fw">{s["us"]}</div>
    {_score_gauge_svg(result.us_score, us_lbl, us_col, 110)}
    <div class="lscore-lbl" style="color:{us_col}">{us_lbl}</div>
  </div>"""
    if "GDPR" in active_frameworks:
        gdpr_lbl, gdpr_col = _risk_label(result.gdpr_score)
        fw_cards_html += f"""
  <div class="lscore-card">
    <div class="lscore-fw">{s["gdpr"]}</div>
    {_score_gauge_svg(result.gdpr_score, gdpr_lbl, gdpr_col, 110)}
    <div class="lscore-lbl" style="color:{gdpr_col}">{gdpr_lbl}</div>
  </div>"""

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
    <div class="lscore-fw">{s["overall"]}</div>
    {_score_gauge_svg(result.risk_score, risk_lbl, risk_col, 130)}
    <div class="lscore-lbl" style="color:{risk_col}">{risk_lbl}</div>
  </div>
  {fw_cards_html}
</div>""", unsafe_allow_html=True)

    # Stats row
    fails  = sum(1 for f in result.findings if f.status == "FAIL")
    warns  = sum(1 for f in result.findings if f.status == "WARN")
    passes = sum(1 for f in result.findings if f.status == "PASS")
    high_r = sum(1 for f in result.findings if f.status == "FAIL" and f.severity == "HIGH")
    method = getattr(result, "scan_method", "static")
    pages  = len(getattr(result, "pages_scanned", []))

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric(m["violations"], fails)
    c2.metric(m["warnings"],   warns)
    c3.metric(m["compliant"],  passes)
    c4.metric(m["high_risk"],  high_r)
    c5.metric(m["scan_time"],  f"{result.scan_time}s")
    c6.metric(m["pages"],      pages or 1,
              help=f"{'Playwright' if method == 'playwright' else 'Static HTML'}")

    badge_html = m["playwright_ok"] if method == "playwright" else m["playwright_warn"]
    badge_color = "#10b981" if method == "playwright" else "#f59e0b"
    badge_bg    = "rgba(16,185,129,0.12)" if method == "playwright" else "rgba(245,158,11,0.10)"
    badge_border= "rgba(16,185,129,0.4)"  if method == "playwright" else "rgba(245,158,11,0.35)"
    st.markdown(
        f'<div style="display:inline-block;background:{badge_bg};'
        f'border:1px solid {badge_border};border-radius:6px;padding:3px 12px;'
        f'font-size:0.7rem;color:{badge_color};margin-top:4px">'
        f'{badge_html}</div>',
        unsafe_allow_html=True,
    )


def _render_tracker_summary(result: LegalScanResult) -> None:
    if not result.trackers_found and not result.consent_sdk:
        return
    lang = _get_lang()
    t    = _STRINGS[lang]["tracker"]
    st.markdown(t["heading"])
    col_t, col_c = st.columns([3, 2])
    with col_t:
        if result.trackers_found:
            pills = " ".join(
                f'<span style="display:inline-block;background:#1e293b;border:1px solid #ef4444;'
                f'border-radius:6px;padding:3px 10px;margin:3px;font-size:0.75rem;color:#f87171">'
                f'{tr}</span>' for tr in result.trackers_found
            )
            st.markdown(
                t["detected"].format(n=len(result.trackers_found)) + " " + pills,
                unsafe_allow_html=True,
            )
            st.caption(t["must_consent"])
        else:
            st.success(t["none"])
    with col_c:
        if result.consent_sdk:
            st.success(t["cmp_ok"].format(sdk=result.consent_sdk))
        else:
            st.error(t["cmp_fail"])
        if result.privacy_policy_url:
            st.markdown(t["privacy_link"].format(url=result.privacy_policy_url))
        if result.tos_url:
            st.markdown(t["tos_link"].format(url=result.tos_url))
        if result.accessibility_url:
            st.markdown(t["access_link"].format(url=result.accessibility_url))


def _render_finding_card(f: LegalFinding) -> None:
    lang   = _get_lang()
    fs     = _STRINGS[lang]["finding"]
    sc     = _STATUS_COLOR[f.status]
    si     = _STATUS_ICON[f.status]
    sev_c  = _SEV_COLOR[f.severity]
    sev_bg = _SEV_BG[f.severity]
    fw_info = _FRAMEWORK_INFO.get(f.framework, {"flag": "🌐", "color": "#475569"})
    fw_flag = fw_info["flag"] if f.framework != "ALL" else "🌐"
    fw_col  = fw_info["color"] if f.framework != "ALL" else "#475569"

    fine_html = ""
    if f.status in ("FAIL", "WARN") and (f.fine_min or f.fine_max or f.fine_example):
        fine_min_str  = f"<strong>{fs['fine_min']}</strong> {f.fine_min}" if f.fine_min else ""
        fine_max_str  = f"<strong>{fs['fine_max']}</strong> {f.fine_max}" if f.fine_max else ""
        fine_case_str = (
            f'<span style="color:#94a3b8">📌 {f.fine_example}</span>' if f.fine_example else ""
        )
        fine_parts = " &nbsp;|&nbsp; ".join(p for p in [fine_min_str, fine_max_str] if p)
        fine_html = f"""
<div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.25);
  border-radius:6px;padding:7px 12px;margin-top:8px;font-size:0.74rem">
  <span style="color:#f87171;font-weight:700">{fs['fine_label']} &nbsp;</span>
  <span style="color:#fca5a5">{fine_parts}</span>
  {'<br><span style="font-size:0.69rem">' + fine_case_str + '</span>' if fine_case_str else ''}
</div>"""

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
  {fine_html}
  {'<div style="font-size:0.7rem;color:#334155;margin-top:6px">🔍 ' + f.evidence + '</div>' if f.evidence else ''}
</div>""", unsafe_allow_html=True)


def _render_findings_by_category(findings: list[LegalFinding]) -> None:
    lang = _get_lang()
    cat_labels = _STRINGS[lang]["category"]
    ss         = _STRINGS[lang]["status_summary"]

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
        label  = cat_labels.get(cat, cat.title())

        status_summary = ""
        if fails:
            lbl = ss["fail_s"].format(n=fails) if fails == 1 else ss["fail_p"].format(n=fails)
            status_summary += f'<span style="color:#ef4444">{lbl}</span>  '
        if warns:
            lbl = ss["warn_s"].format(n=warns) if warns == 1 else ss["warn_p"].format(n=warns)
            status_summary += f'<span style="color:#f59e0b">{lbl}</span>  '
        if passes:
            status_summary += f'<span style="color:#10b981">{ss["pass"].format(n=passes)}</span>'

        with st.expander(f"{label} — {status_summary}", expanded=(fails > 0)):
            for f in sorted(cat_findings, key=lambda x: {"FAIL": 0, "WARN": 1, "PASS": 2, "SKIP": 3}[x.status]):
                if f.status != "SKIP":
                    _render_finding_card(f)


def _render_recommendations_summary(findings: list[LegalFinding]) -> None:
    lang = _get_lang()
    a    = _STRINGS[lang]["actions"]
    high_fails = [f for f in findings if f.status == "FAIL" and f.severity == "HIGH"]
    if not high_fails:
        st.success(a["none"])
        return

    st.markdown(a["heading"])
    st.caption(a["caption"].format(n=len(high_fails)))

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


def _render_cookie_table(cookies: list[CookieRecord]) -> None:
    if not cookies:
        return
    lang = _get_lang()
    ck   = _STRINGS[lang]["cookie"]
    cc   = _STRINGS[lang]["cookie_cat"]
    st.markdown(ck["heading"])

    by_cat: dict[str, list[CookieRecord]] = {}
    for c in cookies:
        by_cat.setdefault(c.category, []).append(c)

    pills_html = ""
    for cat in ["strictly_necessary", "functional", "analytics", "marketing", "unknown"]:
        if cat not in by_cat:
            continue
        label, col = cc[cat]
        count = len(by_cat[cat])
        pills_html += (
            f'<span style="display:inline-block;background:rgba(255,255,255,0.04);'
            f'border:1px solid {col}55;border-radius:20px;padding:3px 12px;margin:3px;'
            f'font-size:0.73rem;color:{col}">{label} &nbsp;<strong>{count}</strong></span>'
        )
    st.markdown(pills_html, unsafe_allow_html=True)

    non_essential = [c for c in cookies if c.category in ("analytics", "marketing")]
    if non_essential:
        st.warning(ck["nonconsent_warn"].format(n=len(non_essential)))

    with st.expander(ck["details_expand"].format(n=len(cookies)), expanded=False):
        rows = []
        for c in sorted(cookies, key=lambda x: (x.category, x.name)):
            label, col = cc[c.category]
            cat_badge  = f'<span style="color:{col};font-size:0.7rem;font-weight:700">{label}</span>'
            flags = []
            if c.secure:    flags.append('<span style="color:#10b981">Secure</span>')
            if c.http_only: flags.append('<span style="color:#3b82f6">HttpOnly</span>')
            if c.same_site: flags.append(f'<span style="color:#64748b">SameSite={c.same_site}</span>')
            flags_html  = " ".join(flags) or f'<span style="color:#ef4444">{ck["no_flags"]}</span>'
            tracker_str = f' <em style="color:#f59e0b">({c.tracker})</em>' if c.tracker else ""
            rows.append(
                f'<tr><td style="font-family:monospace;color:#93c5fd;font-size:0.75rem">{c.name}</td>'
                f'<td>{cat_badge}{tracker_str}</td>'
                f'<td>{flags_html}</td>'
                f'<td style="color:#475569;font-size:0.7rem">{c.domain}</td></tr>'
            )
        table = (
            '<table style="width:100%;border-collapse:collapse;font-size:0.8rem">'
            f'<thead><tr style="border-bottom:1px solid #1e293b;color:#64748b">'
            f'<th style="text-align:left;padding:4px 8px">{ck["col_name"]}</th>'
            f'<th style="text-align:left;padding:4px 8px">{ck["col_cat"]}</th>'
            f'<th style="text-align:left;padding:4px 8px">{ck["col_flags"]}</th>'
            f'<th style="text-align:left;padding:4px 8px">{ck["col_domain"]}</th>'
            '</tr></thead><tbody>' + "".join(rows) + "</tbody></table>"
        )
        st.markdown(table, unsafe_allow_html=True)


def _render_multipage_summary(result: LegalScanResult) -> None:
    pages  = getattr(result, "pages_scanned", [])
    all_ok = getattr(result, "privacy_in_footer_all_pages", False)
    if not pages:
        return
    lang = _get_lang()
    mp   = _STRINGS[lang]["multipage"]
    st.markdown(mp["heading"])
    if all_ok:
        st.success(mp["ok"].format(n=len(pages)))
    else:
        st.warning(mp["warn"].format(n=len(pages)))
    with st.expander(mp["pages_expand"].format(n=len(pages)), expanded=False):
        for p in pages:
            st.markdown(f"- `{p}`")


def _render_framework_cards() -> None:
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
    """Main Compliance Shield UI. Call from a Streamlit tab or section."""

    # ── Language toggle (top-right) ───────────────────────────────────────────
    if "cs_lang" not in st.session_state:
        st.session_state.cs_lang = "he"

    lang        = _get_lang()
    toggle_lbl  = _STRINGS[lang]["lang_toggle"]
    toggle_col, _ = st.columns([1, 9])
    if toggle_col.button(toggle_lbl, key="cs_lang_toggle"):
        st.session_state.cs_lang = "en" if lang == "he" else "he"
        st.rerun()

    lang = _get_lang()   # re-read after possible toggle
    hero = _STRINGS[lang]["hero"]
    sc   = _STRINGS[lang]["scan"]
    rep  = _STRINGS[lang]["report"]

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown(f"""
<style>
.legal-hero{{
  background:linear-gradient(135deg,#0a0f1e 0%,#060b14 100%);
  border:1px solid #1e293b;border-radius:16px;padding:28px 32px;margin-bottom:20px;
}}
.legal-hero h2{{
  font-size:1.6rem;font-weight:900;
  background:linear-gradient(90deg,#3b82f6,#6366f1,#8b5cf6);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  margin:0 0 8px;
}}
.legal-hero p{{color:#64748b;font-size:0.88rem;margin:0}}
</style>
<div class="legal-hero">
  <h2>{hero["title"]}</h2>
  <p>{hero["subtitle"]}</p>
</div>""", unsafe_allow_html=True)

    _render_framework_cards()
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Legal disclaimer ──────────────────────────────────────────────────────
    st.markdown(_disclaimer_html(), unsafe_allow_html=True)

    # ── URL input ─────────────────────────────────────────────────────────────
    url_input = st.text_input(
        "URL",
        value=prefill_url or "",
        placeholder=sc["url_placeholder"],
        help=sc["url_help"],
        label_visibility="collapsed",
        key="legal_url_input",
    )

    # ── Framework selector ────────────────────────────────────────────────────
    fw_col1, fw_col2, fw_col3, fw_col4 = st.columns(4)
    with fw_col1:
        do_il   = st.checkbox(sc["fw_il"],   value=True, key="legal_fw_il")
    with fw_col2:
        do_us   = st.checkbox(sc["fw_us"],   value=True, key="legal_fw_us")
    with fw_col3:
        do_gdpr = st.checkbox(sc["fw_gdpr"], value=True, key="legal_fw_gdpr")
    with fw_col4:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        scan_btn = st.button(sc["btn_scan"], type="primary", use_container_width=True, key="legal_scan_btn")

    active_frameworks: list[str] = []
    if do_il:   active_frameworks.append("IL")
    if do_us:   active_frameworks.append("US")
    if do_gdpr: active_frameworks.append("GDPR")

    if not active_frameworks:
        st.warning(sc["no_fw"])
        return

    # ── Scan execution ────────────────────────────────────────────────────────
    if scan_btn:
        if not url_input or not url_input.strip():
            st.error(sc["no_url"])
            return

        raw_url = url_input.strip()
        if not raw_url.startswith(("http://", "https://")):
            raw_url = "https://" + raw_url

        from urllib.parse import urlparse
        hostname = urlparse(raw_url).hostname or ""
        if any(hostname == b or hostname.endswith("." + b)
               for b in ("streamlit.app", "localhost", "127.0.0.1", "::1")):
            st.error(sc["ssrf"])
            return

        # ── Quota check ───────────────────────────────────────────────────────
        from auth.streamlit_auth import get_current_user, check_quota, increment_quota
        from billing_ui import show_upgrade_prompt

        user = get_current_user()
        if user:
            quota = check_quota(user)
            if not quota["allowed"]:
                show_upgrade_prompt(user.subscription_tier, quota["limit"])
                return

        try:
            from audit_log import log_action
            log_action("legal_scan_start", target=raw_url,
                       details={"frameworks": active_frameworks}, severity="info")
        except Exception:
            pass

        with st.spinner(sc["spinner"]):
            result = run_legal_scan(raw_url, active_frameworks)

        if result.error:
            st.error(f"{sc['fail']}: {result.error}")
            return

        if user:
            try:
                increment_quota(user)
            except Exception:
                pass

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
        rs = _STRINGS[lang]["result"]
        st.markdown("---")
        st.markdown(rs["report_title"].format(url=raw_url))

        fw_labels = " · ".join(
            _FRAMEWORK_INFO[fw]["flag"] + " " + _FRAMEWORK_INFO[fw]["name"]
            for fw in active_frameworks if fw in _FRAMEWORK_INFO
        )
        st.caption(rs["caption"].format(fws=fw_labels, t=result.scan_time, n=len(result.findings)))

        # Score dashboard — only selected frameworks
        _render_score_dashboard(result, active_frameworks)

        # Cookie inventory
        if getattr(result, "cookies_found", None):
            st.markdown("---")
            _render_cookie_table(result.cookies_found)

        # Multi-page coverage
        if getattr(result, "pages_scanned", None):
            st.markdown("---")
            _render_multipage_summary(result)

        # Tracker summary
        st.markdown("---")
        _render_tracker_summary(result)

        # Priority action list
        st.markdown("---")
        _render_recommendations_summary(result.findings)

        # Full findings — dynamic tabs (only selected frameworks)
        st.markdown("---")
        st.markdown(rep["heading"])

        tab_labels = [rep["tab_all"]]
        tab_keys   = ["ALL"]
        if "IL" in active_frameworks:
            tab_labels.append(rep["tab_il"])
            tab_keys.append("IL")
        if "US" in active_frameworks:
            tab_labels.append(rep["tab_us"])
            tab_keys.append("US")
        if "GDPR" in active_frameworks:
            tab_labels.append(rep["tab_gdpr"])
            tab_keys.append("GDPR")

        tab_objects = st.tabs(tab_labels)
        fw_filter = {
            "ALL":  lambda f: True,
            "IL":   lambda f: f.framework in ("IL", "ALL"),
            "US":   lambda f: f.framework in ("US", "ALL"),
            "GDPR": lambda f: f.framework in ("GDPR", "ALL"),
        }
        for tab_obj, key in zip(tab_objects, tab_keys):
            with tab_obj:
                _render_findings_by_category(
                    [f for f in result.findings if fw_filter[key](f)]
                )

        # Repeat disclaimer at bottom
        st.markdown(_disclaimer_html(), unsafe_allow_html=True)

"""
Multi-language support for AI Cyber Shield.
Supported: Hebrew (default) and English.
Scan results stay in English (industry standard).
UI chrome, landing page, auth, and prompts are translated.
"""
from __future__ import annotations
import streamlit as st

SUPPORTED_LANGS = {
    "he": {"flag": "🇮🇱", "label": "עברית", "rtl": True},
    "en": {"flag": "🇺🇸", "label": "English", "rtl": False},
}

_T: dict[str, dict[str, str]] = {

    # ── Navigation ────────────────────────────────────────────────────────────
    "nav_pricing":   {"he": "תמחור",             "en": "Pricing"},
    "nav_docs":      {"he": "תיעוד API",          "en": "API Docs"},
    "nav_signin":    {"he": "כניסה",              "en": "Sign in"},

    # ── Landing hero ──────────────────────────────────────────────────────────
    "hero_headline": {
        "he": "האתר שלך מאובטח עכשיו?<br>בדוק תוך 60 שניות.",
        "en": "Is your website secure right now?<br>Find out.",
    },
    "hero_sub": {
        "he": "סריקת אבטחה מבוססת AI · 18 כלים · תוצאות תוך פחות מ-60 שניות",
        "en": "AI-powered security scan · 18 tools · results in under 60 seconds",
    },

    # ── Auth card ─────────────────────────────────────────────────────────────
    "auth_signin_title": {"he": "ברוך שובך.",              "en": "Welcome back."},
    "auth_signin_sub":   {"he": "כניסה ל-AI Cyber Shield", "en": "Sign in to AI Cyber Shield"},
    "auth_signup_title": {"he": "צור חשבון.",              "en": "Create your account."},
    "auth_signup_sub":   {"he": "חינם לתמיד · ללא כרטיס אשראי", "en": "Free forever · No credit card required"},
    "auth_reset_title":  {"he": "שכחת סיסמה?",            "en": "Forgot your password?"},
    "auth_reset_sub":    {"he": "נשלח קישור לאיפוס למייל שלך", "en": "We'll send a reset link to your inbox"},

    "auth_google":       {"he": "המשך עם Google",          "en": "Continue with Google"},
    "auth_or_email":     {"he": "או המשך עם מייל",         "en": "or continue with email"},

    "auth_email":        {"he": "כתובת מייל",              "en": "Email address"},
    "auth_password":     {"he": "סיסמה",                   "en": "Password"},
    "auth_signin_btn":   {"he": "כניסה ←",                 "en": "Sign In →"},
    "auth_signup_btn":   {"he": "צור חשבון ←",             "en": "Create Account →"},
    "auth_reset_btn":    {"he": "שלח קישור ←",             "en": "Send Reset Link →"},
    "auth_forgot":       {"he": "שכחת סיסמה?",             "en": "Forgot password?"},

    "auth_no_account":   {"he": "אין לך חשבון? הרשם חינם", "en": "Don't have an account? Sign up free"},
    "auth_have_account": {"he": "← כבר יש לך חשבון? כנס", "en": "← Already have an account? Sign in"},
    "auth_back_signin":  {"he": "← חזור לכניסה",           "en": "← Back to sign in"},

    "auth_confirm_email":{"he": "החשבון נוצר! בדוק את תיבת הדואר שלך.", "en": "Account created! Check your inbox for a confirmation email."},
    "auth_reset_sent":   {"he": "קישור נשלח — בדוק את המייל שלך (גם ספאם).", "en": "Reset link sent — check your inbox (and spam folder)."},

    # ── Scan page ─────────────────────────────────────────────────────────────
    "scan_input_label":  {"he": "הכנס כתובת אתר לסריקה",  "en": "Enter target URL"},
    "scan_input_ph":     {"he": "https://האתר-שלך.com",    "en": "https://yourwebsite.com"},
    "scan_btn_passive":  {"he": "🔵  הרץ סריקה פסיבית (18 כלים)", "en": "🔵  Run Passive Recon (18 Tools)"},
    "scan_btn_standard": {"he": "🔍  הרץ סריקת אבטחה",    "en": "🔍  Run Security Scan"},

    "scan_empty_headline":{"he": "האתר שלך דולף מידע עכשיו?", "en": "Is your website leaking secrets right now?"},

    # ── Sidebar ───────────────────────────────────────────────────────────────
    "sidebar_logout":    {"he": "התנתק",                   "en": "Sign out"},
    "sidebar_history":   {"he": "היסטוריית סריקות",        "en": "Scan History"},
    "sidebar_schedule":  {"he": "סריקות מתוזמנות",         "en": "Scheduled Scans"},
    "sidebar_upgrade":   {"he": "שדרג תוכנית",             "en": "Upgrade Plan"},

    # ── Upgrade wall ──────────────────────────────────────────────────────────
    "quota_title":       {"he": "השתמשת ב-{n} סריקות החינמיות שלך להיום", "en": "You've used your {n} free scan{s} today"},
    "quota_sub":         {"he": "פתח סריקה בלתי מוגבלת והגן על האתר שלך 24/7.", "en": "Unlock unlimited scanning and keep your site protected 24/7."},
    "quota_upgrade_btn": {"he": "🚀  שדרג — {price}/חודש", "en": "🚀  Upgrade — {price}/mo"},
    "quota_wait_btn":    {"he": "⏳  חכה למחר (חינם)",     "en": "⏳  Wait until tomorrow (free)"},
    "quota_wait_msg":    {"he": "הסריקות החינמיות מתאפסות בחצות UTC. להתראות מחר! 👋", "en": "Your free scans reset at midnight UTC. See you tomorrow! 👋"},

    # ── Auth status messages ──────────────────────────────────────────────────
    "auth_new_here":     {"he": "חדש כאן?",                "en": "New here?"},
    "auth_trouble":      {"he": "בעיה בכניסה?",            "en": "Trouble signing in?"},
    "auth_create_free":  {"he": "צור חשבון חינם",          "en": "Create free account"},
    "auth_reset_pw":     {"he": "אפס סיסמה",               "en": "Reset password"},
    "auth_confirmed_ok": {"he": "החשבון נוצר! תוכל להיכנס עכשיו.", "en": "Account created! You can now sign in."},
    "auth_fill_both":    {"he": "אנא הכנס מייל וסיסמה.",   "en": "Please enter email and password."},
    "auth_valid_email":  {"he": "הכנס כתובת מייל תקינה.",  "en": "Enter a valid email address."},

    # ── Upgrade wall (billing_ui.py) ─────────────────────────────────────────
    "wall_title":        {"he": "השתמשת ב-{n} סריקות החינמיות שלך להיום", "en": "You've used your {n} free scan{s} today"},
    "wall_sub":          {"he": "תוכנית חינם כוללת <b>{n} סריקות ביום</b>. מצאת פגיעויות אמיתיות —<br>פתח סריקה בלתי מוגבלת והגן על האתר שלך 24/7.", "en": "Free plan includes <b>{n} scans per day</b>. You found real vulnerabilities —<br>unlock unlimited scanning and keep your site protected 24/7."},
    "wall_upgrade_btn":  {"he": "🚀  שדרג ל-{plan} — {price}/חודש", "en": "🚀  Upgrade to {plan} — {price}/mo"},
    "wall_wait_btn":     {"he": "⏳  חכה למחר (חינם)",     "en": "⏳  Wait until tomorrow (free)"},
    "wall_wait_msg":     {"he": "הסריקות החינמיות מתאפסות בחצות UTC. להתראות מחר! 👋", "en": "Your free scans reset at midnight UTC. See you tomorrow! 👋"},
    "wall_cancel":       {"he": "ביטול בכל עת · אחריות 7 ימים", "en": "Cancel anytime · 7-day money-back guarantee"},
    "wall_per_month":    {"he": "/חודש",                   "en": "/month"},

    # ── Legal ─────────────────────────────────────────────────────────────────
    "tos_link":          {"he": "תנאי שימוש",              "en": "Terms of Service"},
    "privacy_link":      {"he": "מדיניות פרטיות",          "en": "Privacy Policy"},
    "back_btn":          {"he": "← חזרה לאפליקציה",        "en": "← Back to app"},
}


def get_lang() -> str:
    return st.session_state.get("_lang", "he")


def t(key: str, **kwargs) -> str:
    """Translate key to current language. Falls back to English."""
    lang = get_lang()
    row  = _T.get(key, {})
    text = row.get(lang) or row.get("en") or key
    if kwargs:
        text = text.format(**kwargs)
    return text


def is_rtl() -> bool:
    return SUPPORTED_LANGS.get(get_lang(), {}).get("rtl", False)


def inject_rtl_css() -> None:
    """Call once per page when RTL language is active."""
    if is_rtl():
        st.markdown("""
<style>
html, body, [data-testid="stAppViewContainer"], .block-container,
[data-testid="stSidebar"] { direction: rtl !important; text-align: right !important; }
[data-testid="stButton"] button { direction: rtl !important; }
.stTextInput input, .stTextArea textarea { direction: rtl !important; text-align: right !important; }
/* Hebrew font override */
html, body, .block-container, [data-testid="stSidebar"],
.stTextInput input, .stTextArea textarea, .stMarkdown,
button, label, p, span, div { font-family: 'Heebo', 'Segoe UI', sans-serif !important; }
/* Keep scan results LTR (English technical content) */
.finding-card, .result-block, pre, code,
[data-testid="stExpander"] { direction: ltr !important; text-align: left !important;
  font-family: 'JetBrains Mono', 'Courier New', monospace !important; }
</style>""", unsafe_allow_html=True)


def lang_switcher(location: str = "sidebar") -> None:
    """Render HE / EN language toggle. Default position: sidebar."""
    current = get_lang()

    if location == "sidebar":
        st.sidebar.markdown(
            "<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;"
            "letter-spacing:0.14em;margin-bottom:6px'>שפה / Language</div>",
            unsafe_allow_html=True,
        )
        col_he, col_en = st.sidebar.columns(2)
        with col_he:
            if st.button(
                "🇮🇱 עב",
                key="lang_he_sidebar",
                type="primary" if current == "he" else "secondary",
                use_container_width=True,
            ):
                st.session_state["_lang"] = "he"
                st.rerun()
        with col_en:
            if st.button(
                "🇺🇸 EN",
                key="lang_en_sidebar",
                type="primary" if current == "en" else "secondary",
                use_container_width=True,
            ):
                st.session_state["_lang"] = "en"
                st.rerun()
    else:
        # Inline (top navbar)
        col_he, col_en, *_ = st.columns([1, 1, 8])
        with col_he:
            if st.button(
                "🇮🇱 עב",
                key="lang_he_inline",
                type="primary" if current == "he" else "secondary",
            ):
                st.session_state["_lang"] = "he"
                st.rerun()
        with col_en:
            if st.button(
                "🇺🇸 EN",
                key="lang_en_inline",
                type="primary" if current == "en" else "secondary",
            ):
                st.session_state["_lang"] = "en"
                st.rerun()

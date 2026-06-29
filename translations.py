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
    "contact_link":      {"he": "צור קשר",                 "en": "Contact"},
    "back_btn":          {"he": "← חזרה לאפליקציה",        "en": "← Back to app"},
    "back_to_scanner":   {"he": "← חזרה לסורק",            "en": "← Back to Scanner"},
    "close_api_docs":    {"he": "סגור מסמכי API ←",        "en": "← Close API Docs"},

    # ── Tab names ─────────────────────────────────────────────────────────────
    "tab_url_scanner":   {"he": "🌐  סורק אבטחה",          "en": "🌐  URL Security Scanner"},
    "tab_legal":         {"he": "⚖️  סורק משפטי",          "en": "⚖️  Legal Scanner"},
    "tab_legal_docs":    {"he": "📋  מסמכים משפטיים",      "en": "📋  Legal Docs"},
    "tab_code_scanner":  {"he": "💻  סורק קוד מקור",       "en": "💻  Source Code Scanner"},
    "tab_scan_history":  {"he": "📈  היסטוריית סריקות",    "en": "📈  Scan History"},
    "tab_compare_scans": {"he": "🔄  השוואת סריקות",       "en": "🔄  Compare Scans"},

    # ── Sidebar secondary ─────────────────────────────────────────────────────
    "sidebar_more_tools":    {"he": "⋯ כלים נוספים",       "en": "⋯ More tools"},
    "sidebar_api_docs":      {"he": "📡 תיעוד API",         "en": "📡 API Docs"},
    "sidebar_team":          {"he": "👥 צוות",              "en": "👥 Team"},
    "sidebar_admin_panel":   {"he": "🔐 לוח ניהול",        "en": "🔐 Admin Panel"},
    "sidebar_dev_tools":     {"he": "⚙ כלי פיתוח",         "en": "⚙ Dev Tools"},

    # ── Scan input ────────────────────────────────────────────────────────────
    "scan_input_help":   {
        "he": "הכנס את הכתובת המלאה של האתר שאתה מחזיק בו או קיבלת אישור לסרוק.",
        "en": "Enter the full URL of a website you own or have written permission to scan.",
    },
    "demo_mode_caption": {
        "he": "🎮 מצב הדגמה: מציג דו\"ח מוכן מראש עבור example.com — לא נשלחות בקשות אמיתיות.",
        "en": "🎮 Demo Mode: showing a pre-built report for example.com — no real requests sent.",
    },
    "demo_mode_toggle":    {"he": "מצב הדגמה (ללא קריאת API)",  "en": "Demo Mode (no API call)"},
    "demo_mode_active_msg":{"he": "✅ מצב הדגמה פעיל — לא נשלחות בקשות אמיתיות", "en": "✅ Demo Mode active — no real requests sent"},
    "live_mode_caption":   {"he": "🔑 מצב חי — נדרש מפתח Groq API",             "en": "🔑 Live Mode — Groq API key required"},

    # ── Authenticated scan ────────────────────────────────────────────────────
    "auth_scan_label":   {"he": "🔐 סריקה מאומתת (אופציונלי)",  "en": "🔐 Authenticated Scan (Optional)"},
    "auth_scan_help":    {
        "he": "הזן עוגיות סשן או Bearer token כדי שהסורק יגיע לדפים מוגנים.",
        "en": "Inject session cookies or a Bearer token so the scanner can reach protected pages.",
    },
    "auth_method_label": {"he": "שיטת אימות",                   "en": "Authentication method"},
    "auth_opt_none":     {"he": "ללא",                           "en": "None"},
    "auth_opt_bearer":   {"he": "Bearer Token",                  "en": "Bearer Token"},
    "auth_opt_upload":   {"he": "העלאת קובץ סשן / פרופיל",      "en": "Upload Session / Profile File"},
    "auth_unauthenticated_caption": {
        "he": "לא מאומת — הסורק ניגש לנקודות קצה ציבוריות בלבד.",
        "en": "Unauthenticated — scanner accesses public endpoints only.",
    },

    # ── Scan mode ─────────────────────────────────────────────────────────────
    "scan_mode_passive":  {"he": "🔵  סריקה פסיבית (OSINT)",    "en": "🔵  Passive Recon (OSINT)"},
    "scan_mode_standard": {"he": "🟡  סריקה רגילה",              "en": "🟡  Standard Scan"},
    "scan_mode_pt":       {"he": "🔴  מצב PT פעיל",              "en": "🔴  Active PT Mode"},
    "scan_mode_help":     {
        "he": "פסיבית: 10 כלי OSINT, בטוחה לכל אתר. רגילה: 17 כלים. PT: בדיקות חיות (דורש אישור).",
        "en": "Passive: 10 OSINT tools, safe on any site. Standard: 17-tool full scan. PT Mode: live probes (needs permission).",
    },

    # ── Auth page (password fallback) ─────────────────────────────────────────
    "auth_only_heading":  {"he": "גישה מורשית בלבד",             "en": "AUTHORIZED ACCESS ONLY"},
    "password_label":     {"he": "סיסמת גישה",                   "en": "Access password"},
    "auth_enter_btn":     {"he": "כניסה",                         "en": "Enter"},
    "auth_incorrect_pw":  {"he": "סיסמה שגויה.",                  "en": "Incorrect password."},

    # ── Scan result section headers ───────────────────────────────────────────
    "res_findings":         {"he": "ממצאים",                        "en": "FINDINGS"},
    "res_full_report":      {"he": "דוח מלא — לפי קטגוריה",        "en": "FULL REPORT — BY CATEGORY"},
    "res_active_verify":    {"he": "אימות פעיל — תוצאות בדיקות",   "en": "ACTIVE VERIFICATION — LIVE PROBE RESULTS"},
    "res_passive_title":    {"he": "🔵 PASSIVE RECON — תוצאות (מיון לפי חומרה)", "en": "🔵 PASSIVE RECON — RESULTS (by severity)"},
    "fix_snippet_label":    {"he": "תקן את זה",                      "en": "Fix this"},
    "tab_portfolio":        {"he": "🏢 פורטפוליו",                   "en": "🏢 Portfolio"},
    "badge_title":          {"he": "SECURITY BADGE — הטמע באתר שלך", "en": "SECURITY BADGE — Embed on your site"},
    "badge_subtitle":       {
        "he": "שתף את התג הזה באתר שלך — מבקרים יידעו שאתה לוקח אבטחה ברצינות.",
        "en": "Share this badge on your site — visitors will know you take security seriously.",
    },
    "res_export":           {"he": "ייצוא",                         "en": "EXPORT"},
    "res_download_pdf":     {"he": "הורד דוח PDF",                  "en": "Download PDF Report"},
    "res_export_json":      {"he": "ייצוא JSON",                    "en": "Export JSON"},
    "res_download_html":    {"he": "📥  הורד דוח (HTML)",           "en": "📥  Download Report (HTML)"},
    "res_pdf_unavailable":  {"he": "ייצוא PDF אינו זמין — הדוח לעיל הוא הפלט המלא.", "en": "PDF export unavailable — the report above is the full output."},

    # ── Severity group labels ─────────────────────────────────────────────────
    "sev_critical":     {"he": "🔴 קריטי — נדרשת פעולה מיידית",    "en": "🔴 CRITICAL — Immediate Action Required"},
    "sev_high":         {"he": "🟠 גבוה — תקן לפני הגרסה הבאה",    "en": "🟠 HIGH — Fix Before Next Release"},
    "sev_medium":       {"he": "🟡 בינוני — יש לטפל בזה",          "en": "🟡 MEDIUM — Should Be Addressed"},
    "sev_low":          {"he": "⚪ נמוך — בעיות קלות",              "en": "⚪ LOW — Minor Issues"},
    "sev_info":         {"he": "✅ מידע — לא נמצאו בעיות",          "en": "✅ INFORMATIONAL — No Issues Found"},

    # ── Scan result status messages ───────────────────────────────────────────
    "res_no_issues":        {"he": "✅ לא נמצאו בעיות.",             "en": "✅ No issues detected."},
    "res_not_found":        {"he": "ℹ️ לא נמצא ביעד זה.",           "en": "ℹ️ Not found on this target."},
    "res_no_data":          {"he": "ℹ️ לא הוחזרו נתונים ליעד זה.", "en": "ℹ️ No data returned for this target."},
    "res_no_verify":        {"he": "✅ לא נמצאו ממצאים לאימות — לא נשלחו בדיקות.", "en": "✅ No verifiable findings detected — no probes dispatched."},
    "res_no_critical":      {"he": "לא נמצאו ממצאים קריטיים/גבוהים — האתר עבר את הבדיקות הפסיביות. 🎉", "en": "No critical/high findings — your site passed passive checks. 🎉"},
    "res_av_auto":          {"he": "האימות הפעיל ירוץ אוטומטית לאחר הסריקה הבאה.", "en": "Active verification will run automatically after the next scan."},

    # ── Scan mode messages ────────────────────────────────────────────────────
    "res_demo_locked":      {
        "he": "🔒 אימות פעיל אינו זמין במצב הדגמה<br><span style='font-weight:400;font-size:0.72rem'>עבור למצב חי והפעל PT Mode בסרגל הצד לקבלת תוצאות PoC מאומתות.</span>",
        "en": "🔒 ACTIVE VERIFICATION UNAVAILABLE IN DEMO MODE<br><span style='font-weight:400;font-size:0.72rem'>Switch to Live Mode and enable PT Mode in the sidebar to get Confirmed PoC results.</span>",
    },
    "res_standard_mode":    {
        "he": "🟢 מצב סריקה רגיל — לא נשלחו בדיקות חיות<br><span style='font-weight:400;color:#94a3b8;font-size:0.72rem'>הפעל <b>Active PT Mode</b> בסרגל הצד (לאחר אישור בעלות על היעד) לאימות פגיעויות ויצירת curl PoC.</span>",
        "en": "🟢 STANDARD SCAN MODE — No live probes sent<br><span style='font-weight:400;color:#94a3b8;font-size:0.72rem'>Enable <b>Active PT Mode</b> in the sidebar (after confirming target ownership) to automatically confirm vulnerabilities with non-destructive canary probes and get curl PoC reproduction steps.</span>",
    },

    # ── Tool section titles ───────────────────────────────────────────────────
    "tool_security_txt":       {"he": "Security.txt / Bug Bounty",      "en": "Security.txt / Bug Bounty"},
    "tool_exposed_files":      {"he": "קבצים רגישים חשופים",            "en": "Exposed Sensitive Files"},
    "tool_http_headers":       {"he": "כותרות HTTP אבטחה",              "en": "HTTP Security Headers"},
    "tool_robots_sitemap":     {"he": "robots.txt / מפת אתר",           "en": "robots.txt / Sitemap Analysis"},
    "tool_js_secrets":         {"he": "סודות JavaScript + Source Maps", "en": "JavaScript Secrets + Source Maps"},
    "tool_wayback":            {"he": "חשיפת Wayback Machine",          "en": "Wayback Machine Exposure"},
    "tool_cloud_buckets":      {"he": "גילוי Cloud Buckets",            "en": "Cloud Bucket Detection"},
    "tool_http_methods":       {"he": "בדיקת HTTP Methods",             "en": "HTTP Methods Check"},
    "tool_email_spoofability": {"he": "זיוף מייל (DMARC/SPF)",         "en": "Email Spoofability (DMARC/SPF)"},
    "tool_cve_correlation":    {"he": "קורלציית CVE (55 CVEs)",         "en": "CVE Correlation (55 CVEs)"},
    "tool_meta_leakage":       {"he": "דליפת מידע בדפי שגיאה",         "en": "Error Page Info Leakage"},
    "tool_github_leaks":       {"he": "דליפות קוד ציבורי GitHub",      "en": "GitHub Public Code Leaks"},
    "tool_crt_subdomains":     {"he": "CT Logs — תת-דומיינים",         "en": "CT Logs — Subdomain Enumeration"},
    "tool_ssl_passive":        {"he": "ניתוח אישור SSL/TLS",            "en": "SSL/TLS Certificate Analysis"},
    "tool_dns_deep":           {"he": "ניתוח DNS מעמיק",               "en": "DNS Deep Analysis"},
    "tool_whois":              {"he": "WHOIS וגיל הדומיין",            "en": "WHOIS & Domain Age"},
    "tool_urlscan":            {"he": "טביעת אצבע URLScan.io",         "en": "URLScan.io Fingerprint"},
    "tool_ip_intelligence":    {"he": "מודיעין IP (Shodan InternetDB)", "en": "IP Intelligence (Shodan InternetDB)"},

    # ── What to do next / CTA ─────────────────────────────────────────────────
    "res_what_next":        {"he": "מה לעשות עכשיו",                   "en": "What to do next"},
    "res_quick_wins":       {"he": "{n} תיקונים מהירים זוהו",          "en": "{n} quick wins identified"},
    "res_upgrade_fixes":    {"he": "🔍 שדרג ל-Pro לקבלת מדריכי תיקון שלב-אחר-שלב", "en": "🔍 Upgrade to Pro for step-by-step fix guides"},
    "res_tools_no_data":    {"he": "⚙️ {n} כלים — אין נתונים ליעד זה", "en": "⚙️ {n} tools — no data for this target"},

    # ── Scan buttons ─────────────────────────────────────────────────────────
    "scan_btn_pt":          {"he": "🔴  סריקה + אימות (PT Mode)",    "en": "🔴  Scan + Verify (PT Mode)"},
    "scan_btn_pt_caption":  {
        "he": "בדיקות חיות יישלחו אוטומטית. השתמש על יעדים מורשים בלבד.",
        "en": "Live canary probes will be sent automatically. Only use on authorized targets.",
    },
    "scan_btn_passive":     {"he": "🔵  הרץ סריקה פסיבית (18 כלים)", "en": "🔵  Run Passive Recon (18 Tools)"},
    "scan_btn_passive_caption": {
        "he": "18 כלי OSINT · SSL/TLS · DNS · CT Logs · כותרות HTTP · IP Intelligence · WHOIS · URLScan · ~90 שניות",
        "en": "18 OSINT tools · SSL/TLS · DNS · CT Logs · HTTP headers · IP Intelligence (Shodan) · WHOIS · URLScan · ~90 s",
    },
    "scan_btn_standard":    {"he": "🔍  סרוק עכשיו — ניתוח מלא",   "en": "🔍  Scan Now — Full Analysis"},
    "scan_btn_standard_caption": {
        "he": "17 כלים פסיביים + דוח AI · ~30 שניות · ללא בדיקות חיות · בטוח לכל אתר",
        "en": "17 passive tools + AI report · ~30 s · no probes sent · safe for any site",
    },
    "scan_btn_clear":       {"he": "✕  נקה",                         "en": "✕  Clear"},

    # ── Mode badges (sidebar descriptions) ───────────────────────────────────
    "mode_passive_title":   {"he": "🔵 PASSIVE RECON — 18 OSINT TOOLS", "en": "🔵 PASSIVE RECON — 18 OSINT TOOLS"},
    "mode_passive_desc":    {
        "he": "18 כלי OSINT · בטוח לכל אתר · ללא בדיקות חיות<br>  JS secrets · Cloud Buckets · CVE · GitHub Leaks<br>  Email Spoofability · Wayback · DNS · CNAME Takeover",
        "en": "18 OSINT tools · safe on ANY website · no active probes<br>  JS secrets · Cloud buckets · CVE match<br>  GitHub leaks · Email spoofability · Wayback<br>  DNS deep · CNAME takeover · Exposed files",
    },
    "mode_standard_title":  {"he": "🟢 STANDARD SCAN",                "en": "🟢 STANDARD SCAN"},
    "mode_standard_desc":   {
        "he": "17 כלים פסיביים + ניתוח AI<br>  בטוח לכל אתר בעולם<br>  ללא בדיקות חיות",
        "en": "17 passive tools + AI analysis<br>  Safe for any site worldwide<br>  No live probes sent",
    },

    # ── Active scan disclosure ────────────────────────────────────────────────
    "disclosure_expander":  {"he": "⚠️  גילוי סריקה פעילה — נא לקרוא לפני הסריקה", "en": "⚠️  Active Scan Disclosure — please read before scanning"},
    "disclosure_body":      {
        "he": """**מצב סריקה זה כולל בדיקת פורטים TCP פעילה.**

הסורק יפתח חיבורי TCP ל-18 פורטים נפוצים ביעד
(MySQL, PostgreSQL, MongoDB, Redis, RDP, SSH, FTP, SMB…) כדי לבדוק
אם הם נגישים מהאינטרנט.

**לפני הסריקה, אשר:**
- הנך הבעלים של הדומיין היעד **או** קיבלת אישור כתוב לסרוק אותו.
- חיבורי TCP SYN יופיעו ביומני הגישה של היעד.
- אינך משתמש בזה לסריקת תשתית שאינה בשליטתך.

סריקת מערכות ללא אישור עלולה להפר את חוק המחשבים הישראלי (1995),
ה-CFAA האמריקאי, או חוקים מקומים שקולים.""",
        "en": """**This scan mode includes active TCP port probing.**

The scanner will open TCP connections to 18 common ports on the target host
(MySQL, PostgreSQL, MongoDB, Redis, RDP, SSH, FTP, SMB…) to check whether
they are reachable from the internet.

**Before running, confirm:**
- You own the target domain **or** have written authorisation to scan it.
- You understand that TCP SYN connections will appear in the target's access logs.
- You are not using this to probe infrastructure you do not control.

Scanning systems without permission may violate the Computer Fraud and Abuse Act
(CFAA), Computer Misuse Act (CMA), or local equivalent laws.""",
    },
    "disclosure_check":     {
        "he": "אני מאשר שאני מורשה לסרוק יעד זה ומקבל אחריות לסריקה זו.",
        "en": "I confirm I am authorised to scan this target and accept responsibility for this scan.",
    },
    "disclosure_required":  {"he": "אמת את הגילוי לעיל כדי לאפשר סריקה.", "en": "Check the disclosure above to enable scanning."},

    # ── PT mode UI ───────────────────────────────────────────────────────────
    "pt_request_btn":       {"he": "📩 בקש גישה ל-PT Mode",          "en": "📩 Request PT Access"},
    "pt_request_success":   {
        "he": "הבקשה נרשמה — ניצור איתך קשר להשלמת האישור.",
        "en": "Request logged — we will contact you to complete approval.",
    },
    "pt_legal_confirm":     {
        "he": "✅ אני מאשר שאני הבעלים של הדומיין הזה או מחזיק אישור כתוב חתום מבעל הדומיין.",
        "en": "✅ I confirm I own this domain OR hold signed written permission from the domain owner.",
    },
    "pt_mode_unlocked":     {"he": "✅ PT Mode פעיל — אישור משפטי נרשם, בדיקות חיות מופעלות", "en": "✅ PT Mode active — legal confirmation recorded, live probes enabled"},

    # ── Key section labels ────────────────────────────────────────────────────
    "section_scores":       {"he": "ציוני אבטחה — כל 17 הקטגוריות",  "en": "SECURITY SCORES — ALL 17 CATEGORIES"},
    "section_code_summary": {"he": "סיכום ניתוח",                     "en": "ANALYSIS SUMMARY"},
    "section_vuln_report":  {"he": "דוח פגיעויות",                    "en": "VULNERABILITY REPORT"},
    "section_hist_timeline":{"he": "ציר זמן סריקות היסטוריות",       "en": "HISTORICAL SCAN TIMELINE"},
    "section_score_timeline":{"he": "ציר ציונים",                     "en": "SCORE TIMELINE"},
    "section_scan_history": {"he": "היסטוריית סריקות",               "en": "SCAN HISTORY"},
    "section_diff_compare": {"he": "השוואת סריקות — מצב דיפרנציאלי", "en": "DIFFERENTIAL SCAN COMPARISON"},
    "section_contact":      {"he": "📞 צור קשר",                      "en": "📞 Contact"},

    # ── Scan status messages ─────────────────────────────────────────────────
    "status_passive_running":  {"he": "🔵 מריץ Passive Recon…",        "en": "🔵 Running Passive Recon…"},
    "status_url_required":     {"he": "הכנס כתובת URL יעד לפני הסריקה הפסיבית.", "en": "Enter a target URL before running Passive Recon."},
    "status_url_required_gen": {"he": "הכנס קודם את כתובת ה-URL.",     "en": "Enter a target URL first."},
    "status_passive_failed":   {"he": "הסריקה הפסיבית נכשלה — בדוק את כתובת ה-URL ונסה שוב.", "en": "Passive Recon failed — check the target URL and try again."},
    "status_code_no_input":    {"he": "הדבק קוד מקור קודם.",           "en": "Paste source code first."},
    "status_code_invalid":     {"he": "קלט לא חוקי — בדוק שהקוד או ה-URL תקינים ונסה שוב.", "en": "Invalid input — check that the code or URL is valid and try again."},
    "status_code_failed":      {"he": "הניתוח נכשל — בדוק את הקלט ונסה שוב. פרטים מוקלדים.", "en": "Analysis failed — check the input and try again. Details logged."},

    # ── Code scanner ─────────────────────────────────────────────────────────
    "code_input_label":     {"he": "הדבק קוד מקור",                   "en": "Paste source code"},
    "code_analyse_btn":     {"he": "🚀  נתח קוד",                     "en": "🚀  Analyse Code"},
    "code_clear_btn":       {"he": "✕  נקה",                          "en": "✕  Clear"},

    # ── Scan history / compare ────────────────────────────────────────────────
    "hist_no_history":      {"he": "לא נמצאה היסטוריית סריקות עדיין…", "en": "No scan history found yet…"},
    "hist_select_url":      {"he": "בחר URL לצפייה בהיסטוריה",        "en": "Select URL to view history"},
    "diff_no_history":      {"he": "אין היסטוריית סריקות עדיין…",     "en": "No scan history yet…"},
    "diff_select_url":      {"he": "URL יעד להשוואה",                  "en": "Target URL to compare"},
    "diff_scan_a":          {"he": "סריקה A (בסיס)",                   "en": "SCAN A (BASELINE)"},
    "diff_scan_b":          {"he": "סריקה B (השוואה)",                 "en": "SCAN B (COMPARISON)"},
    "stealth_activated":    {"he": "🕵️ מצב STEALTH הופעל — WAF חסם UA רגיל · TLS fingerprint של דפדפן בשימוש", "en": "STEALTH MODE ACTIVATED"},
    "stealth_detail":       {"he": "", "en": " — WAF blocked standard scanner UA · browser TLS fingerprint used for WAF fingerprinting"},
    "passive_recon_header": {"he": "PASSIVE RECON — תוצאות · 18 כלים · {ts} UTC", "en": "Passive OSINT Recon · 18 Tools · {ts} UTC"},

    # ── Empty state ───────────────────────────────────────────────────────────
    "empty_headline_passive": {"he": "האתר שלך דולף מידע עכשיו?",     "en": "Is your website leaking secrets right now?"},
    "empty_headline_standard":{"he": "מה הפגיעויות שהאתר שלך חושף?",  "en": "What vulnerabilities is your site exposing?"},
    "empty_headline_pt":      {"he": "מוכן לאמת ממצאים בזמן אמת?",    "en": "Ready to verify these findings live?"},

    # ── Sidebar labels ────────────────────────────────────────────────────────
    "sidebar_about":           {"he": "ℹ מידע",                         "en": "ℹ About"},
    "sidebar_engine":          {"he": "⚡ יכולות המנוע",                  "en": "⚡ Engine Capabilities"},
    "sidebar_change_hint":     {"he": "→ שנה בסרגל הצד",                 "en": "← Change in sidebar"},

    # ── Tab diff section labels ───────────────────────────────────────────────
    "diff_category_deltas":    {"he": "שינויים לפי קטגוריה",            "en": "CATEGORY DELTAS"},
    "diff_findings_delta":     {"he": "שינויים בממצאים קריטיים",        "en": "CRITICAL FINDINGS DELTA"},
    "diff_new_findings":       {"he": "**ממצאים חדשים בסריקה B:**",      "en": "**New findings in Scan B:**"},
    "diff_resolved":           {"he": "**ממצאים שנפתרו מאז סריקה A:**", "en": "**Resolved since Scan A:**"},
    "diff_score_a":            {"he": "ציון — סריקה A",                  "en": "Scan A Score"},
    "diff_score_b":            {"he": "ציון — סריקה B",                  "en": "Scan B Score"},
    "diff_delta":              {"he": "שינוי",                           "en": "Delta"},

    # ── Disclosure email template ─────────────────────────────────────────────
    "disclosure_email_tpl":    {"he": "📨 גילוי אחראי — תבנית מייל",    "en": "📨 RESPONSIBLE DISCLOSURE — EMAIL TEMPLATE"},

    # ── Footer / legal disclaimer ─────────────────────────────────────────────
    "auth_card_footer_legal": {
        "he": "🛡 לשימוש מורשה בלבד · סריקת יעדים ללא אישור מפרה את <a href='/?legal=tos' style='color:#334155;text-decoration:underline'>התנאים שלנו</a>",
        "en": "🛡 Authorized use only · Scanning targets without permission violates our <a href='/?legal=tos' style='color:#334155;text-decoration:underline'>Terms</a>",
    },
    "footer_disclaimer":  {
        "he": "🛡 AI Cyber Shield — לשימוש מורשה בלבד. סריקה לא מורשית אסורה ומפרה את תנאי השירות שלנו.",
        "en": "🛡 AI Cyber Shield — Authorized use only. Unauthorized scanning is illegal and against our Terms of Service.",
    },
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
/* RTL: text direction only — do NOT flip Streamlit layout containers */
.block-container p, .block-container span, .block-container label,
.block-container h1, .block-container h2, .block-container h3,
.block-container li, .stMarkdown, .stMarkdown p {
    direction: rtl !important;
    text-align: right !important;
}
/* Input fields — RTL text entry */
.stTextInput input, .stTextArea textarea {
    direction: rtl !important;
    text-align: right !important;
}
/* Buttons — text alignment only */
[data-testid="stButton"] button {
    text-align: center !important;
}
/* Hebrew font for UI text */
.block-container, [data-testid="stSidebar"],
.stTextInput input, .stTextArea textarea,
.stMarkdown, button, label {
    font-family: 'Heebo', 'Segoe UI', sans-serif !important;
}
/* Keep scan result cards LTR — technical English content */
.finding-card, .result-block, pre, code,
[data-testid="stExpander"] .stMarkdown {
    direction: ltr !important;
    text-align: left !important;
    font-family: 'JetBrains Mono', 'Courier New', monospace !important;
}
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

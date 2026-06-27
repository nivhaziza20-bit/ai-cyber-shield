"""
Multi-language support for AI Cyber Shield.
Scan results stay in English (industry standard).
UI chrome, landing page, auth, and prompts are translated.
"""
from __future__ import annotations
import streamlit as st

SUPPORTED_LANGS = {
    "en": {"flag": "🇺🇸", "label": "English", "rtl": False},
    "he": {"flag": "🇮🇱", "label": "עברית",   "rtl": True},
    "ru": {"flag": "🇷🇺", "label": "Русский",  "rtl": False},
    "ar": {"flag": "🇸🇦", "label": "العربية",  "rtl": True},
}

_T: dict[str, dict[str, str]] = {

    # ── Navigation ────────────────────────────────────────────────────────────
    "nav_pricing":   {"en": "Pricing",      "he": "תמחור",       "ru": "Цены",        "ar": "الأسعار"},
    "nav_docs":      {"en": "API Docs",     "he": "תיעוד API",   "ru": "API",         "ar": "التوثيق"},
    "nav_signin":    {"en": "Sign in",      "he": "כניסה",       "ru": "Войти",       "ar": "تسجيل الدخول"},

    # ── Landing hero ──────────────────────────────────────────────────────────
    "hero_headline": {
        "en": "Is your website secure right now?<br>Find out.",
        "he": "האתר שלך מאובטח עכשיו?<br>בדוק תוך 60 שניות.",
        "ru": "Ваш сайт защищён прямо сейчас?<br>Проверьте.",
        "ar": "هل موقعك آمن الآن؟<br>اكتشف ذلك.",
    },
    "hero_sub": {
        "en": "AI-powered security scan · 18 tools · results in under 60 seconds",
        "he": "סריקת אבטחה מבוססת AI · 18 כלים · תוצאות תוך פחות מ-60 שניות",
        "ru": "Сканирование безопасности на базе ИИ · 18 инструментов · результаты за 60 секунд",
        "ar": "فحص أمني بالذكاء الاصطناعي · 18 أداة · نتائج في أقل من 60 ثانية",
    },

    # ── Auth card ─────────────────────────────────────────────────────────────
    "auth_signin_title": {"en": "Welcome back.",        "he": "ברוך שובך.",           "ru": "Добро пожаловать.", "ar": "مرحباً بعودتك."},
    "auth_signin_sub":   {"en": "Sign in to AI Cyber Shield", "he": "כניסה ל-AI Cyber Shield", "ru": "Войдите в AI Cyber Shield", "ar": "سجل دخولك إلى AI Cyber Shield"},
    "auth_signup_title": {"en": "Create your account.", "he": "צור חשבון.",            "ru": "Создайте аккаунт.", "ar": "أنشئ حسابك."},
    "auth_signup_sub":   {"en": "Free forever · No credit card required", "he": "חינם לתמיד · ללא כרטיס אשראי", "ru": "Бесплатно · Без карты", "ar": "مجاني · بدون بطاقة ائتمان"},
    "auth_reset_title":  {"en": "Forgot your password?", "he": "שכחת סיסמה?",         "ru": "Забыли пароль?",   "ar": "نسيت كلمة المرور؟"},
    "auth_reset_sub":    {"en": "We'll send a reset link to your inbox", "he": "נשלח קישור לאיפוס למייל שלך", "ru": "Отправим ссылку на сброс", "ar": "سنرسل رابط إعادة تعيين إلى بريدك"},

    "auth_google":       {"en": "Continue with Google", "he": "המשך עם Google",       "ru": "Войти через Google", "ar": "المتابعة مع Google"},
    "auth_or_email":     {"en": "or continue with email", "he": "או המשך עם מייל",    "ru": "или через email",   "ar": "أو تابع بالبريد الإلكتروني"},

    "auth_email":        {"en": "Email address",        "he": "כתובת מייל",           "ru": "Email",             "ar": "البريد الإلكتروني"},
    "auth_password":     {"en": "Password",             "he": "סיסמה",                "ru": "Пароль",            "ar": "كلمة المرور"},
    "auth_signin_btn":   {"en": "Sign In →",            "he": "כניסה ←",              "ru": "Войти →",           "ar": "دخول →"},
    "auth_signup_btn":   {"en": "Create Account →",     "he": "צור חשבון ←",          "ru": "Создать →",         "ar": "إنشاء حساب →"},
    "auth_reset_btn":    {"en": "Send Reset Link →",    "he": "שלח קישור ←",          "ru": "Отправить →",       "ar": "إرسال رابط →"},
    "auth_forgot":       {"en": "Forgot password?",     "he": "שכחת סיסמה?",          "ru": "Забыли пароль?",    "ar": "نسيت كلمة المرور؟"},

    "auth_no_account":   {"en": "Don't have an account? Sign up free", "he": "אין לך חשבון? הרשם חינם", "ru": "Нет аккаунта? Зарегистрируйтесь", "ar": "ليس لديك حساب؟ سجل مجاناً"},
    "auth_have_account": {"en": "← Already have an account? Sign in", "he": "← כבר יש לך חשבון? כנס", "ru": "← Уже есть аккаунт? Войти", "ar": "← لديك حساب؟ سجل دخولك"},
    "auth_back_signin":  {"en": "← Back to sign in",   "he": "← חזור לכניסה",        "ru": "← Назад",           "ar": "← العودة"},

    "auth_confirm_email":{"en": "Account created! Check your inbox for a confirmation email.", "he": "החשבון נוצר! בדוק את תיבת הדואר שלך.", "ru": "Аккаунт создан! Проверьте email.", "ar": "تم إنشاء الحساب! تحقق من بريدك."},
    "auth_reset_sent":   {"en": "Reset link sent — check your inbox.", "he": "קישור נשלח — בדוק את המייל שלך.", "ru": "Ссылка отправлена.", "ar": "تم إرسال الرابط."},

    # ── Scan page ─────────────────────────────────────────────────────────────
    "scan_input_label":  {"en": "Enter target URL",     "he": "הכנס כתובת אתר לסריקה","ru": "Введите URL сайта", "ar": "أدخل عنوان الموقع"},
    "scan_input_ph":     {"en": "https://yourwebsite.com","he": "https://האתר-שלך.com","ru": "https://ваш-сайт.com","ar": "https://موقعك.com"},
    "scan_btn_passive":  {"en": "🔵  Run Passive Recon (18 Tools)", "he": "🔵  הרץ סריקה פסיבית (18 כלים)", "ru": "🔵  Пассивный разведка", "ar": "🔵  فحص مراقبة"},
    "scan_btn_standard": {"en": "🔍  Run Security Scan", "he": "🔍  הרץ סריקת אבטחה", "ru": "🔍  Сканировать",   "ar": "🔍  فحص أمني"},

    "scan_empty_headline":{"en": "Is your website leaking secrets right now?", "he": "האתר שלך דולף מידע עכשיו?", "ru": "Ваш сайт утечёт секреты?", "ar": "هل يسرب موقعك بيانات الآن؟"},

    # ── Sidebar ───────────────────────────────────────────────────────────────
    "sidebar_logout":    {"en": "Sign out",             "he": "התנתק",               "ru": "Выйти",             "ar": "تسجيل الخروج"},
    "sidebar_history":   {"en": "Scan History",         "he": "היסטוריית סריקות",    "ru": "История сканов",    "ar": "سجل الفحوصات"},
    "sidebar_schedule":  {"en": "Scheduled Scans",      "he": "סריקות מתוזמנות",     "ru": "Расписание",        "ar": "الفحوصات المجدولة"},
    "sidebar_upgrade":   {"en": "Upgrade Plan",         "he": "שדרג תוכנית",         "ru": "Улучшить план",     "ar": "ترقية الخطة"},

    # ── Upgrade wall ──────────────────────────────────────────────────────────
    "quota_title":       {"en": "You've used your {n} free scan{s} today", "he": "השתמשת ב-{n} סריקות החינמיות שלך להיום", "ru": "Вы использовали {n} бесплатных сканов", "ar": "لقد استخدمت {n} فحوصاتك المجانية اليوم"},
    "quota_sub":         {"en": "Unlock unlimited scanning and keep your site protected 24/7.", "he": "פתח סריקה בלתי מוגבלת והגן על האתר שלך 24/7.", "ru": "Разблокируйте неограниченное сканирование.", "ar": "افتح الفحص غير المحدود."},
    "quota_upgrade_btn": {"en": "🚀  Upgrade — {price}/mo", "he": "🚀  שדרג — {price}/חודש", "ru": "🚀  Улучшить — {price}/мес", "ar": "🚀  ترقية — {price}/شهر"},
    "quota_wait_btn":    {"en": "⏳  Wait until tomorrow (free)", "he": "⏳  חכה למחר (חינם)", "ru": "⏳  Подождать до завтра", "ar": "⏳  انتظر حتى الغد"},
    "quota_wait_msg":    {"en": "Your free scans reset at midnight UTC. See you tomorrow! 👋", "he": "הסריקות החינמיות מתאפסות בחצות UTC. להתראות מחר! 👋", "ru": "Сканы сбрасываются в полночь UTC.", "ar": "تتجدد فحوصاتك عند منتصف الليل."},

    # ── Auth status messages ──────────────────────────────────────────────────
    "auth_new_here":     {"en": "New here?",              "he": "חדש כאן?",            "ru": "Новый здесь?",      "ar": "جديد هنا؟"},
    "auth_trouble":      {"en": "Trouble signing in?",    "he": "בעיה בכניסה?",        "ru": "Проблема со входом?","ar": "مشكلة في الدخول؟"},
    "auth_create_free":  {"en": "Create free account",    "he": "צור חשבון חינם",      "ru": "Создать аккаунт",   "ar": "إنشاء حساب مجاني"},
    "auth_reset_pw":     {"en": "Reset password",         "he": "אפס סיסמה",           "ru": "Сбросить пароль",   "ar": "إعادة تعيين كلمة المرور"},
    "auth_confirm_email":{"en": "Account created! Check your inbox for a confirmation email.", "he": "החשבון נוצר! בדוק את תיבת הדואר שלך.", "ru": "Аккаунт создан! Проверьте email.", "ar": "تم إنشاء الحساب! تحقق من بريدك."},
    "auth_confirmed_ok": {"en": "Account created! You can now sign in.", "he": "החשבון נוצר! תוכל להיכנס עכשיו.", "ru": "Готово! Теперь войдите.", "ar": "تم! يمكنك تسجيل الدخول الآن."},
    "auth_reset_sent":   {"en": "Reset link sent — check your inbox (and spam folder).", "he": "קישור נשלח — בדוק את המייל שלך (גם ספאם).", "ru": "Ссылка отправлена — проверьте email.", "ar": "تم إرسال الرابط — تحقق من بريدك."},
    "auth_fill_both":    {"en": "Please enter email and password.", "he": "אנא הכנס מייל וסיסמה.", "ru": "Введите email и пароль.", "ar": "أدخل البريد وكلمة المرور."},
    "auth_valid_email":  {"en": "Enter a valid email address.", "he": "הכנס כתובת מייל תקינה.", "ru": "Введите корректный email.", "ar": "أدخل بريدًا إلكترونيًا صحيحًا."},

    # ── Upgrade wall (billing_ui.py) ─────────────────────────────────────────
    "wall_title":        {"en": "You've used your {n} free scan{s} today", "he": "השתמשת ב-{n} סריקות החינמיות שלך להיום", "ru": "Вы использовали {n} бесплатных сканов", "ar": "لقد استخدمت {n} فحوصاتك المجانية اليوم"},
    "wall_sub":          {"en": "Free plan includes <b>{n} scans per day</b>. You found real vulnerabilities —<br>unlock unlimited scanning and keep your site protected 24/7.", "he": "תוכנית חינם כוללת <b>{n} סריקות ביום</b>. מצאת פגיעויות אמיתיות —<br>פתח סריקה בלתי מוגבלת והגן על האתר שלך 24/7.", "ru": "Бесплатный план включает <b>{n} сканов/день</b>. Вы нашли уязвимости —<br>разблокируйте неограниченное сканирование.", "ar": "الخطة المجانية تشمل <b>{n} فحوصات/يوم</b>. وجدت ثغرات حقيقية —<br>افتح الفحص غير المحدود."},
    "wall_upgrade_btn":  {"en": "🚀  Upgrade to {plan} — {price}/mo", "he": "🚀  שדרג ל-{plan} — {price}/חודש", "ru": "🚀  Улучшить до {plan} — {price}/мес", "ar": "🚀  ترقية إلى {plan} — {price}/شهر"},
    "wall_wait_btn":     {"en": "⏳  Wait until tomorrow (free)", "he": "⏳  חכה למחר (חינם)", "ru": "⏳  Подождать до завтра", "ar": "⏳  انتظر حتى الغد"},
    "wall_wait_msg":     {"en": "Your free scans reset at midnight UTC. See you tomorrow! 👋", "he": "הסריקות החינמיות מתאפסות בחצות UTC. להתראות מחר! 👋", "ru": "Сканы сбрасываются в полночь UTC. До завтра!", "ar": "تتجدد فحوصاتك عند منتصف الليل. إلى اللقاء غدًا!"},
    "wall_cancel":       {"en": "Cancel anytime · 7-day money-back guarantee", "he": "ביטול בכל עת · אחריות 7 ימים", "ru": "Отмена в любое время · Возврат 7 дней", "ar": "إلغاء في أي وقت · ضمان 7 أيام"},
    "wall_per_month":    {"en": "/month", "he": "/חודש", "ru": "/мес", "ar": "/شهر"},

    # ── Legal ─────────────────────────────────────────────────────────────────
    "tos_link":          {"en": "Terms of Service",     "he": "תנאי שימוש",          "ru": "Условия",           "ar": "شروط الخدمة"},
    "privacy_link":      {"en": "Privacy Policy",       "he": "מדיניות פרטיות",      "ru": "Конфиденциальность","ar": "سياسة الخصوصية"},
    "back_btn":          {"en": "← Back to app",        "he": "← חזרה לאפליקציה",    "ru": "← Назад",           "ar": "← العودة"},
}


def get_lang() -> str:
    return st.session_state.get("_lang", "en")


def t(key: str, **kwargs) -> str:
    """Translate key to current language. Falls back to English."""
    lang = get_lang()
    row = _T.get(key, {})
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
/* Keep scan results LTR (English technical content) */
.finding-card, .result-block, pre, code,
[data-testid="stExpander"] { direction: ltr !important; text-align: left !important; }
</style>""", unsafe_allow_html=True)


def lang_switcher(location: str = "sidebar") -> None:
    """Render language toggle buttons. Caller is responsible for any preceding separator."""
    if location == "sidebar":
        cols = st.sidebar.columns(len(SUPPORTED_LANGS))
        for i, (code, info) in enumerate(SUPPORTED_LANGS.items()):
            with cols[i]:
                active = get_lang() == code
                if st.button(
                    info["flag"],
                    key=f"lang_{code}_{location}",
                    help=info["label"],
                    type="primary" if active else "secondary",
                    use_container_width=True,
                ):
                    st.session_state["_lang"] = code
                    st.rerun()
    else:
        # Inline horizontal — for navbar injection via HTML
        current = get_lang()
        cols = st.columns(len(SUPPORTED_LANGS) + 4)
        for i, (code, info) in enumerate(SUPPORTED_LANGS.items()):
            with cols[i]:
                active = current == code
                label = f"{info['flag']} {info['label']}" if active else info["flag"]
                if st.button(
                    label,
                    key=f"lang_{code}_{location}",
                    help=info["label"],
                    type="primary" if active else "secondary",
                ):
                    st.session_state["_lang"] = code
                    st.rerun()

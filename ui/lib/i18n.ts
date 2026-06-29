export type Lang = "en" | "he";

export const t = {
  /* ── Navigation ─────────────────────────────────────────────────────────── */
  nav_dashboard:   { en: "Dashboard",          he: "לוח בקרה" },
  nav_history:     { en: "Scan History",       he: "היסטוריית סריקות" },
  nav_scheduled:   { en: "Scheduled Scans",    he: "סריקות מתוזמנות" },
  nav_compliance:  { en: "Legal Scanner",       he: "סורק משפטי" },
  nav_settings:    { en: "Settings",           he: "הגדרות" },

  /* ── Header ─────────────────────────────────────────────────────────────── */
  new_scan:        { en: "New Scan",           he: "סריקה חדשה" },
  search:          { en: "Search...",          he: "חיפוש..." },

  /* ── Scan input ──────────────────────────────────────────────────────────── */
  scan_title:      { en: "Security Intelligence",   he: "מודיעין אבטחה" },
  scan_subtitle:   { en: "Analyze any domain or IP with 18 OSINT tools", he: "ניתוח כל דומיין או IP עם 18 כלי OSINT" },
  scan_placeholder:{ en: "https://example.com",     he: "https://example.com" },
  scan_label:      { en: "Target URL or domain",    he: "כתובת URL או דומיין" },
  scan_button:     { en: "Start Scan",              he: "התחל סריקה" },
  scanning:        { en: "Scanning...",             he: "סורק..." },
  scan_mode_std:   { en: "Standard",               he: "רגיל" },
  scan_mode_pt:    { en: "Pen Test",               he: "בדיקת חדירות" },
  scan_mode_passive:{ en: "Passive OSINT",         he: "OSINT פסיבי" },

  /* ── Grade banner ────────────────────────────────────────────────────────── */
  grade_excellent: { en: "Excellent",          he: "מצוין" },
  grade_good:      { en: "Good",               he: "טוב" },
  grade_fair:      { en: "Fair",               he: "סביר" },
  grade_poor:      { en: "Poor",               he: "גרוע" },
  grade_critical:  { en: "Critical Risk",      he: "סיכון קריטי" },
  report_title:    { en: "Security Report",    he: "דוח אבטחה" },
  security_posture:{ en: "security posture",   he: "רמת אבטחה" },
  defensive_only:  { en: "Defensive use only", he: "לשימוש הגנתי בלבד" },
  critical_badge:  { en: "critical",           he: "קריטי" },
  no_critical:     { en: "0 critical",         he: "0 קריטי" },

  /* ── Score grid ──────────────────────────────────────────────────────────── */
  scores_title:    { en: "Category Scores",    he: "ציוני קטגוריות" },

  /* ── Findings ────────────────────────────────────────────────────────────── */
  findings_title:  { en: "Findings",           he: "ממצאים" },
  critical_findings:{ en: "Critical Findings", he: "ממצאים קריטיים" },
  no_findings:     { en: "No findings",        he: "אין ממצאים" },

  /* ── History ─────────────────────────────────────────────────────────────── */
  history_title:   { en: "Scan History",       he: "היסטוריה" },
  rescan:          { en: "Re-scan",            he: "סרוק מחדש" },
  last_scan:       { en: "Last scan",          he: "סריקה אחרונה" },

  /* ── Scheduled ───────────────────────────────────────────────────────────── */
  scheduled_title: { en: "Scheduled Scans",    he: "סריקות מתוזמנות" },
  add_schedule:    { en: "Add Schedule",        he: "הוסף תזמון" },
  next_run:        { en: "Next run",            he: "ריצה הבאה" },

  /* ── Compliance ──────────────────────────────────────────────────────────── */
  compliance_title:{ en: "Legal Scanner",       he: "סורק משפטי" },
  compliance_sub:  { en: "IL · GDPR · US Law — automated legal compliance analysis", he: "ניתוח ציות אוטומטי — חוק ישראלי · GDPR · חוק אמריקאי" },
  export_pdf:      { en: "Export PDF",         he: "ייצוא PDF" },
  framework_il:    { en: "Israeli Law",        he: "חוק ישראלי" },
  framework_gdpr:  { en: "GDPR (EU)",          he: "GDPR (אירופה)" },
  framework_us:    { en: "US Federal & State", he: "חוק אמריקאי" },
  framework_all:   { en: "All Frameworks",     he: "כל המסגרות" },

  /* ── Empty state ─────────────────────────────────────────────────────────── */
  empty_title:     { en: "Enter a URL to begin",     he: "הכנס כתובת URL להתחלה" },
  empty_sub:       { en: "We'll analyze security across 18 dimensions in under 60 seconds", he: "נבצע ניתוח אבטחה ב-18 ממדים תוך פחות מ-60 שניות" },
  tip_1:           { en: "Works with any domain — no installation required", he: "עובד עם כל דומיין — ללא התקנה" },
  tip_2:           { en: "Completely passive by default — no payload injection", he: "פסיבי לחלוטין כברירת מחדל — ללא הזרקת payload" },
  tip_3:           { en: "Results saved to your history automatically", he: "תוצאות נשמרות להיסטוריה שלך אוטומטית" },

  /* ── Sidebar footer ──────────────────────────────────────────────────────── */
  sidebar_tools:   { en: "18 OSINT Tools",     he: "18 כלי OSINT" },
  sidebar_version: { en: "v6.0",               he: "v6.0" },
  toggle_lang:     { en: "עברית",              he: "English" },
} as const;

export type TranslationKey = keyof typeof t;

export function tr(key: TranslationKey, lang: Lang): string {
  return t[key][lang] ?? t[key].en;
}

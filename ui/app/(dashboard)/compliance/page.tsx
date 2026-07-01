"use client";

import { useState } from "react";
import { Header } from "@/components/layout/header";
import { useLang } from "@/contexts/language-context";
import type { TranslationKey } from "@/lib/i18n";

type Framework = "IL" | "GDPR" | "US" | "ALL";

const FRAMEWORK_LABEL: Record<Framework, TranslationKey> = {
  IL:   "framework_il",
  GDPR: "framework_gdpr",
  US:   "framework_us",
  ALL:  "framework_all",
};

const FRAMEWORKS: { id: Framework; flag: string; color: string }[] = [
  { id: "IL",   flag: "🇮🇱", color: "#22d3ee" },
  { id: "GDPR", flag: "🇪🇺", color: "#3b82f6" },
  { id: "US",   flag: "🇺🇸", color: "#f59e0b" },
  { id: "ALL",  flag: "🌐",  color: "#10b981" },
];

/* ── Israeli regulatory indicator rows (demo / indicative) ─────────────────── */
const IL_DEMO_INDICATORS = [
  {
    finding_title:      "Exposed .env File",
    regulation_name:    "Privacy Protection Regulations (Data Security), 5777-2017",
    regulation_section: "Regulation 2 — Information Security Requirements",
    confidence:         "direct_indicator",
    description_he:     "חשיפת קבצי .env עשויה להוות הפרה של חובת אבטחת מידע במאגרי מידע",
    description_en:     "Exposed .env files may indicate a failure to implement required data security measures",
  },
  {
    finding_title:      "Weak TLS Protocol (TLS 1.0)",
    regulation_name:    "Privacy Protection Regulations (Data Security), 5777-2017",
    regulation_section: "Regulation 4 — Encryption Requirements",
    confidence:         "direct_indicator",
    description_he:     "שימוש בפרוטוקולי הצפנה חלשים עלול להפר את דרישות ההצפנה בתקנות",
    description_en:     "Weak TLS protocols may violate the encryption requirements under the Privacy Protection Regulations",
  },
  {
    finding_title:      "Missing SPF Record",
    regulation_name:    "Privacy Protection Law (Amendment 13), 5783-2023",
    regulation_section: "Section 13D — Notification of Security Breach",
    confidence:         "related_context",
    description_he:     "היעדר SPF מאפשר זיוף כתובת שולח ועלול להוביל לחובת דיווח לרשות הגנת הפרטיות",
    description_en:     "Missing SPF may enable impersonation attacks triggering breach notification obligations",
  },
  {
    finding_title:      "CORS Wildcard Origin",
    regulation_name:    "Privacy Protection Regulations (Data Security), 5777-2017",
    regulation_section: "Regulation 3 — Access Control",
    confidence:         "related_context",
    description_he:     "הגדרות CORS שגויות עלולות לאפשר גישה ממקורות לא מורשים למידע אישי",
    description_en:     "Misconfigured CORS may allow unauthorized cross-origin access to personal data",
  },
  {
    finding_title:      "Exposed Database Port (3306)",
    regulation_name:    "Privacy Protection Regulations (Data Security), 5777-2017",
    regulation_section: "Regulation 3 — Access Control & Regulation 5 — Logical Security",
    confidence:         "direct_indicator",
    description_he:     "פורטים של מסדי נתונים הנגישים לציבור מהווים הפרה ברורה של חובת הגנת מסדי מידע",
    description_en:     "Publicly accessible database ports represent a clear violation of data protection requirements",
  },
];

const CONFIDENCE_COLOR: Record<string, string> = {
  direct_indicator: "#ef4444",
  related_context:  "#f59e0b",
};
const CONFIDENCE_LABEL_HE: Record<string, string> = {
  direct_indicator: "אינדיקטור ישיר",
  related_context:  "קשור להקשר",
};

const IL_DISCLAIMER_HE =
  "⚠️ המיפוי שלהלן הוא אינדיקטיבי בלבד ואינו ייעוץ משפטי. לבדיקת חשיפה רגולטורית בפועל יש להיוועץ ביועץ משפטי המתמחה בדיני הגנת פרטיות ישראליים.";
const IL_DISCLAIMER_EN =
  "⚠️ The mapping below is INDICATIVE ONLY and does NOT constitute legal advice. For actual regulatory exposure assessment, consult a qualified attorney specializing in Israeli privacy law.";

/* ── Toggle switch ──────────────────────────────────────────────────────────── */
function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
      <div
        onClick={() => onChange(!checked)}
        style={{
          width: "42px", height: "22px",
          borderRadius: "11px",
          background: checked ? "#22d3ee" : "#1a2236",
          position: "relative",
          transition: "background 200ms ease",
          border: checked ? "1px solid #22d3ee88" : "1px solid #2a3a52",
          flexShrink: 0,
        }}
      >
        <div style={{
          width: "16px", height: "16px",
          borderRadius: "50%",
          background: "#fff",
          position: "absolute",
          top: "2px",
          left: checked ? "22px" : "2px",
          transition: "left 200ms ease",
          boxShadow: "0 1px 4px rgba(0,0,0,0.4)",
        }} />
      </div>
      <span style={{ color: "#94a3b8", fontSize: "0.82rem" }}>{label}</span>
    </label>
  );
}

/* ── Israeli Regulatory Mapping section ─────────────────────────────────────── */
function ILRegulatoryMapping({ isHe }: { isHe: boolean }) {
  const disclaimer = isHe ? IL_DISCLAIMER_HE : IL_DISCLAIMER_EN;
  const directCount  = IL_DEMO_INDICATORS.filter((i) => i.confidence === "direct_indicator").length;
  const relatedCount = IL_DEMO_INDICATORS.filter((i) => i.confidence === "related_context").length;

  return (
    <div style={{ marginTop: "20px" }}>
      {/* Disclaimer */}
      <div style={{
        padding: "12px 16px",
        borderRadius: "10px",
        background: "rgba(239,68,68,0.07)",
        border: "1px solid rgba(239,68,68,0.2)",
        color: "#fca5a5",
        fontSize: "0.78rem",
        lineHeight: 1.65,
        marginBottom: "16px",
        direction: isHe ? "rtl" : "ltr",
        textAlign: isHe ? "right" : "left",
      }}>
        {disclaimer}
      </div>

      {/* Summary counts */}
      <div style={{ display: "flex", gap: "12px", marginBottom: "16px", flexWrap: "wrap" }}>
        {[
          { label: isHe ? "אינדיקטורים ישירים" : "Direct Indicators", count: directCount,  color: "#ef4444" },
          { label: isHe ? "קשורים להקשר"      : "Related Context",   count: relatedCount, color: "#f59e0b" },
        ].map((item) => (
          <div key={item.label} style={{
            padding: "8px 16px", borderRadius: "8px",
            background: `${item.color}10`,
            border: `1px solid ${item.color}30`,
            display: "flex", alignItems: "center", gap: "10px",
          }}>
            <span style={{ fontSize: "1.2rem", fontWeight: 800, color: item.color }}>{item.count}</span>
            <span style={{ fontSize: "0.78rem", color: "#94a3b8" }}>{item.label}</span>
          </div>
        ))}
      </div>

      {/* Indicator rows */}
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {IL_DEMO_INDICATORS.map((ind, i) => {
          const confColor = CONFIDENCE_COLOR[ind.confidence] ?? "#64748b";
          const confLabel = isHe
            ? CONFIDENCE_LABEL_HE[ind.confidence] ?? ind.confidence
            : ind.confidence.replace("_", " ");
          const description = isHe ? ind.description_he : ind.description_en;

          return (
            <div key={i} style={{
              padding: "12px 16px",
              borderRadius: "10px",
              background: "rgba(13,20,33,0.8)",
              border: "1px solid #1a2236",
              direction: isHe ? "rtl" : "ltr",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px", flexWrap: "wrap" }}>
                <span style={{ color: "#f1f5f9", fontWeight: 600, fontSize: "0.85rem" }}>
                  {ind.finding_title}
                </span>
                <span style={{
                  padding: "2px 8px", borderRadius: "4px",
                  background: `${confColor}15`,
                  border: `1px solid ${confColor}30`,
                  color: confColor,
                  fontSize: "0.68rem", fontWeight: 700,
                  whiteSpace: "nowrap",
                }}>
                  {confLabel}
                </span>
              </div>
              <div style={{ color: "#22d3ee", fontSize: "0.76rem", marginBottom: "3px" }}>
                {ind.regulation_name}
              </div>
              <div style={{ color: "#64748b", fontSize: "0.73rem", marginBottom: "6px" }}>
                {ind.regulation_section}
              </div>
              <div style={{ color: "#94a3b8", fontSize: "0.76rem", lineHeight: 1.6 }}>
                {description}
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer note */}
      <div style={{
        marginTop: "14px",
        padding: "10px 14px",
        borderRadius: "8px",
        background: "rgba(34,211,238,0.05)",
        border: "1px solid rgba(34,211,238,0.15)",
        color: "#64748b",
        fontSize: "0.73rem",
        lineHeight: 1.6,
        direction: isHe ? "rtl" : "ltr",
        textAlign: isHe ? "right" : "left",
      }}>
        {isHe
          ? "מיפוי זה מוצג לצרכי המחשה על בסיס ממצאי סריקה לדוגמה. לחץ על 'ייצוא PDF' לדוח התאמה מלא."
          : "This mapping is shown for illustration purposes based on demo scan findings. Click 'Export PDF' for a full compliance report."
        }
      </div>
    </div>
  );
}

/* ── Page ───────────────────────────────────────────────────────────────────── */
export default function CompliancePage() {
  const { t, lang } = useLang();
  const isHe = lang === "he";
  const [activeFramework, setActiveFramework] = useState<Framework>("IL");
  const [url, setUrl]                         = useState("");
  const [ilMappingEnabled, setIlMappingEnabled] = useState(false);

  const fw = FRAMEWORKS.find((f) => f.id === activeFramework)!;

  return (
    <>
      <Header title={t("nav_compliance")} />
      <main style={{ flex: 1, padding: "28px 32px", maxWidth: "900px", margin: "0 auto", width: "100%" }}>

        {/* Hero */}
        <div style={{
          background: "rgba(12,17,32,0.8)",
          border: "1px solid #1a2236",
          borderRadius: "16px",
          padding: "24px 28px",
          marginBottom: "24px",
          backdropFilter: "blur(12px)",
        }}>
          <div style={{ display: "flex", alignItems: "flex-start", gap: "16px", marginBottom: "20px" }}>
            <svg width="40" height="46" viewBox="0 0 28 32" fill="none" style={{ flexShrink: 0 }}>
              <path d="M14 1.5L2 6.5V15.5C2 23.2 7.4 30.1 14 32C20.6 30.1 26 23.2 26 15.5V6.5L14 1.5Z"
                    fill="#090d1a" stroke="#22d3ee" strokeWidth="1.2"/>
              <path d="M9 16l4 4 7-7" stroke="#22d3ee" strokeWidth="1.8"
                    strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <div>
              <h1 style={{ margin: 0, fontSize: "1.2rem", fontWeight: 700, color: "#f1f5f9" }}>
                {t("compliance_title")}
              </h1>
              <p style={{ margin: "4px 0 0", color: "#64748b", fontSize: "0.82rem" }}>
                {t("compliance_sub")}
              </p>
            </div>
          </div>

          {/* Framework selector */}
          <div style={{ display: "flex", gap: "8px", marginBottom: "18px", flexWrap: "wrap" }}>
            {FRAMEWORKS.map((f) => (
              <button
                key={f.id}
                onClick={() => setActiveFramework(f.id)}
                style={{
                  display: "flex", alignItems: "center", gap: "7px",
                  padding: "7px 16px", borderRadius: "8px",
                  border: `1px solid ${activeFramework === f.id ? f.color + "44" : "#1a2236"}`,
                  background: activeFramework === f.id ? `${f.color}10` : "transparent",
                  color: activeFramework === f.id ? f.color : "#64748b",
                  fontSize: "0.82rem",
                  fontWeight: activeFramework === f.id ? 700 : 400,
                  cursor: "pointer",
                  transition: "all 150ms ease",
                }}
              >
                <span>{f.flag}</span>
                {t(FRAMEWORK_LABEL[f.id])}
              </button>
            ))}
          </div>

          {/* URL input */}
          <div style={{ display: "flex", gap: "10px" }}>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              style={{
                flex: 1, padding: "11px 14px",
                background: "#080c18", border: "1px solid #1a2236",
                borderRadius: "8px", color: "#f1f5f9",
                fontSize: "0.95rem", fontFamily: "JetBrains Mono, monospace",
                outline: "none",
              }}
              onFocus={(e) => { e.target.style.borderColor = fw.color; e.target.style.boxShadow = `0 0 0 3px ${fw.color}15`; }}
              onBlur={(e)  => { e.target.style.borderColor = "#1a2236"; e.target.style.boxShadow = ""; }}
            />
            <button style={{
              padding: "11px 22px", borderRadius: "8px", border: "none",
              background: `linear-gradient(135deg, ${fw.color} 0%, ${fw.color}90 100%)`,
              color: "#000d1a", fontWeight: 800, fontSize: "0.88rem",
              cursor: "pointer", transition: "all 200ms ease",
              boxShadow: `0 0 16px ${fw.color}30`,
            }}>
              {t("scan_button")}
            </button>
          </div>

          {/* Israeli regulatory mapping toggle — shown only on IL framework */}
          {activeFramework === "IL" && (
            <div style={{
              marginTop: "18px",
              padding: "14px 16px",
              borderRadius: "10px",
              background: "rgba(34,211,238,0.04)",
              border: "1px solid rgba(34,211,238,0.18)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "12px",
              flexWrap: "wrap",
            }}>
              <div>
                <div style={{ color: "#22d3ee", fontWeight: 700, fontSize: "0.85rem", marginBottom: "3px" }}>
                  {isHe ? "🇮🇱 כלול מיפוי רגולטורי ישראלי" : "🇮🇱 Include Israeli regulatory mapping"}
                </div>
                <div style={{ color: "#64748b", fontSize: "0.75rem" }}>
                  {isHe
                    ? "מיפוי אינדיקטיבי לחוק הגנת הפרטיות ותיקון 13 — אינו ייעוץ משפטי"
                    : "Indicative mapping to Privacy Protection Law & Amendment 13 — not legal advice"
                  }
                </div>
              </div>
              <Toggle
                checked={ilMappingEnabled}
                onChange={setIlMappingEnabled}
                label={ilMappingEnabled
                  ? (isHe ? "מופעל" : "Enabled")
                  : (isHe ? "כבוי"  : "Disabled")
                }
              />
            </div>
          )}
        </div>

        {/* Israeli regulatory mapping table */}
        {activeFramework === "IL" && ilMappingEnabled && (
          <div style={{
            background: "rgba(12,17,32,0.8)",
            border: "1px solid #1a2236",
            borderRadius: "14px",
            padding: "20px 24px",
            marginBottom: "24px",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
              <span style={{ fontSize: "1.1rem" }}>🇮🇱</span>
              <h2 style={{ margin: 0, fontSize: "1rem", fontWeight: 700, color: "#f1f5f9" }}>
                {isHe ? "מיפוי רגולטורי ישראלי (אינדיקטיבי בלבד)" : "Israeli Regulatory Mapping (Indicative Only)"}
              </h2>
            </div>
            <p style={{ margin: "0 0 0 0", color: "#64748b", fontSize: "0.76rem" }}>
              {isHe
                ? "מבוסס על חוק הגנת הפרטיות תשמ\"א-1981, תקנות הגנת הפרטיות (אבטחת מידע) תשע\"ז-2017, ותיקון 13 (אוגוסט 2025)"
                : "Based on Privacy Protection Law 5741-1981, Privacy Protection Regulations (Data Security) 5777-2017, and Amendment 13 (August 2025)"
              }
            </p>
            <ILRegulatoryMapping isHe={isHe} />
          </div>
        )}

        {/* Framework detail cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: "12px" }}>
          {[
            { flag: "🇮🇱", color: "#22d3ee", title: t("framework_il"), desc: "Privacy Protection Law (1981) · Computer Law (1995) · Information Security Regulations (2017)" },
            { flag: "🇪🇺", color: "#3b82f6", title: t("framework_gdpr"), desc: "Regulation (EU) 2016/679 · ePrivacy Directive · Right to be Forgotten · Data Protection" },
            { flag: "🇺🇸", color: "#f59e0b", title: t("framework_us"), desc: "CCPA / CPRA · COPPA · CAN-SPAM Act · WCAG 2.1 AA (ADA / Section 508)" },
          ].map((item) => (
            <div
              key={item.flag}
              className="glass-card animate-fade-up"
              style={{ padding: "16px 18px", transition: "transform 200ms cubic-bezier(0.16,1,0.3,1), border-color 200ms ease" }}
              onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.borderColor = item.color + "44"; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.borderColor = ""; }}
            >
              <div style={{ fontSize: "1.4rem", marginBottom: "8px" }}>{item.flag}</div>
              <div style={{ color: item.color, fontWeight: 700, fontSize: "0.9rem", marginBottom: "6px" }}>
                {item.title}
              </div>
              <div style={{ color: "#64748b", fontSize: "0.76rem", lineHeight: 1.65 }}>
                {item.desc}
              </div>
              <button style={{
                marginTop: "14px", padding: "6px 14px", borderRadius: "6px",
                border: `1px solid ${item.color}33`, background: `${item.color}0a`,
                color: item.color, fontSize: "0.75rem", fontWeight: 700, cursor: "pointer",
                transition: "all 150ms ease",
              }}>
                {t("export_pdf")} →
              </button>
            </div>
          ))}
        </div>
      </main>
    </>
  );
}

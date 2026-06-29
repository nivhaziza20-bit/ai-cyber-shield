"use client";

import { Header } from "@/components/layout/header";
import { useLang } from "@/contexts/language-context";

function SettingRow({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      gap: "16px",
      padding: "16px 0",
      borderBottom: "1px solid #1a2236",
    }}>
      <div style={{ flex: 1 }}>
        <div style={{ color: "#f1f5f9", fontSize: "0.88rem", fontWeight: 600 }}>{label}</div>
        {desc && <div style={{ color: "#64748b", fontSize: "0.76rem", marginTop: "3px" }}>{desc}</div>}
      </div>
      <div style={{ flexShrink: 0 }}>{children}</div>
    </div>
  );
}

export default function SettingsPage() {
  const { t, lang, toggle } = useLang();

  return (
    <>
      <Header title={t("nav_settings")} />
      <main style={{ flex: 1, padding: "28px 32px", maxWidth: "700px", margin: "0 auto", width: "100%" }}>

        {/* API Config */}
        <div style={{
          background: "rgba(12,17,32,0.8)",
          border: "1px solid #1a2236",
          borderRadius: "14px",
          padding: "20px 24px",
          marginBottom: "16px",
        }}>
          <div style={{
            color: "#64748b",
            fontSize: "0.65rem",
            textTransform: "uppercase",
            letterSpacing: "0.18em",
            fontFamily: "JetBrains Mono, monospace",
            marginBottom: "4px",
          }}>
            API
          </div>

          <SettingRow
            label="Backend API URL"
            desc="Python scanner endpoint. Leave blank to use mock data."
          >
            <input
              defaultValue=""
              placeholder="http://localhost:8000"
              style={{
                padding: "7px 12px",
                background: "#080c18",
                border: "1px solid #1a2236",
                borderRadius: "6px",
                color: "#f1f5f9",
                fontSize: "0.82rem",
                fontFamily: "JetBrains Mono, monospace",
                width: "220px",
                outline: "none",
              }}
            />
          </SettingRow>

          <SettingRow
            label="Mock API"
            desc="Use demo data without a real scanner backend."
          >
            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              padding: "5px 12px",
              borderRadius: "999px",
              background: "rgba(16,185,129,0.08)",
              border: "1px solid rgba(16,185,129,0.2)",
              color: "#10b981",
              fontSize: "0.72rem",
              fontWeight: 700,
              fontFamily: "JetBrains Mono, monospace",
            }}>
              ● ACTIVE
            </div>
          </SettingRow>
        </div>

        {/* UI Preferences */}
        <div style={{
          background: "rgba(12,17,32,0.8)",
          border: "1px solid #1a2236",
          borderRadius: "14px",
          padding: "20px 24px",
          marginBottom: "16px",
        }}>
          <div style={{
            color: "#64748b",
            fontSize: "0.65rem",
            textTransform: "uppercase",
            letterSpacing: "0.18em",
            fontFamily: "JetBrains Mono, monospace",
            marginBottom: "4px",
          }}>
            Interface
          </div>

          <SettingRow label="Language" desc="UI language and text direction">
            <button
              onClick={toggle}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "7px 14px",
                borderRadius: "8px",
                border: "1px solid rgba(34,211,238,0.3)",
                background: "rgba(34,211,238,0.06)",
                color: "#22d3ee",
                fontSize: "0.82rem",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              {lang === "he" ? "🇮🇱 עברית" : "🇺🇸 English"} →
              {lang === "he" ? " English" : " עברית"}
            </button>
          </SettingRow>
        </div>

        {/* Version info */}
        <div style={{
          padding: "16px 20px",
          background: "rgba(9,13,26,0.5)",
          border: "1px solid #1a2236",
          borderRadius: "10px",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "0.7rem",
          color: "#5a7084",
          lineHeight: 1.9,
        }}>
          <div>AI CYBER SHIELD · v6.0 · 18 OSINT TOOLS</div>
          <div>DEFENSIVE USE ONLY · מערכת לשימוש הגנתי בלבד</div>
        </div>
      </main>
    </>
  );
}

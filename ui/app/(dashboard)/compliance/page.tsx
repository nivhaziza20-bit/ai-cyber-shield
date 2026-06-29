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
  { id: "ALL",  flag: "🌐", color: "#10b981" },
];

export default function CompliancePage() {
  const { t } = useLang();
  const [activeFramework, setActiveFramework] = useState<Framework>("IL");
  const [url, setUrl] = useState("");

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
            {/* Shield icon */}
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
                  display: "flex",
                  alignItems: "center",
                  gap: "7px",
                  padding: "7px 16px",
                  borderRadius: "8px",
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
                flex: 1,
                padding: "11px 14px",
                background: "#080c18",
                border: "1px solid #1a2236",
                borderRadius: "8px",
                color: "#f1f5f9",
                fontSize: "0.95rem",
                fontFamily: "JetBrains Mono, monospace",
                outline: "none",
              }}
              onFocus={(e) => {
                e.target.style.borderColor = fw.color;
                e.target.style.boxShadow = `0 0 0 3px ${fw.color}15`;
              }}
              onBlur={(e) => {
                e.target.style.borderColor = "#1a2236";
                e.target.style.boxShadow = "";
              }}
            />
            <button style={{
              padding: "11px 22px",
              borderRadius: "8px",
              border: "none",
              background: `linear-gradient(135deg, ${fw.color} 0%, ${fw.color}90 100%)`,
              color: "#000d1a",
              fontWeight: 800,
              fontSize: "0.88rem",
              cursor: "pointer",
              transition: "all 200ms ease",
              boxShadow: `0 0 16px ${fw.color}30`,
            }}>
              {t("scan_button")}
            </button>
          </div>
        </div>

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
              style={{
                padding: "16px 18px",
                transition: "transform 200ms cubic-bezier(0.16,1,0.3,1), border-color 200ms ease",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = "translateY(-2px)";
                e.currentTarget.style.borderColor = item.color + "44";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = "";
                e.currentTarget.style.borderColor = "";
              }}
            >
              <div style={{ fontSize: "1.4rem", marginBottom: "8px" }}>{item.flag}</div>
              <div style={{ color: item.color, fontWeight: 700, fontSize: "0.9rem", marginBottom: "6px" }}>
                {item.title}
              </div>
              <div style={{ color: "#64748b", fontSize: "0.76rem", lineHeight: 1.65 }}>
                {item.desc}
              </div>
              <button style={{
                marginTop: "14px",
                padding: "6px 14px",
                borderRadius: "6px",
                border: `1px solid ${item.color}33`,
                background: `${item.color}0a`,
                color: item.color,
                fontSize: "0.75rem",
                fontWeight: 700,
                cursor: "pointer",
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

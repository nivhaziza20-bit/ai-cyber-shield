"use client";

import { useState } from "react";
import type { Finding, Severity } from "@/lib/api";
import { useLang } from "@/contexts/language-context";

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const SEV_STYLE: Record<Severity, { color: string; bg: string; border: string; barColor: string }> = {
  CRITICAL: { color: "#ef4444", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.25)", barColor: "#ef4444" },
  HIGH:     { color: "#f97316", bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.25)", barColor: "#f97316" },
  MEDIUM:   { color: "#f59e0b", bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.25)", barColor: "#f59e0b" },
  LOW:      { color: "#3b82f6", bg: "rgba(59,130,246,0.08)",  border: "rgba(59,130,246,0.2)",  barColor: "#3b82f6" },
  INFO:     { color: "#94a3b8", bg: "rgba(30,45,64,0.5)",     border: "#1a2236",               barColor: "#1a2236" },
};

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const sev = SEV_STYLE[finding.severity] ?? SEV_STYLE.INFO;

  return (
    <div
      style={{
        background: "rgba(12,17,32,0.75)",
        border: `1px solid ${sev.border}`,
        borderLeft: `4px solid ${sev.barColor}`,
        borderRadius: "10px",
        overflow: "hidden",
        transition: "border-color 200ms ease, transform 200ms cubic-bezier(0.16,1,0.3,1), box-shadow 200ms ease",
        backdropFilter: "blur(6px)",
        marginBottom: "6px",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = "translateX(3px)";
        e.currentTarget.style.boxShadow = "0 4px 20px rgba(0,0,0,0.35)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = "";
        e.currentTarget.style.boxShadow = "";
      }}
    >
      {/* Header row — clickable to expand */}
      <button
        onClick={() => setOpen((o) => !o)}
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "12px",
          padding: "13px 18px",
          width: "100%",
          background: "transparent",
          border: "none",
          cursor: "pointer",
          textAlign: "start",
        }}
      >
        {/* Severity badge */}
        <span
          className="badge"
          style={{
            background: sev.bg,
            color: sev.color,
            border: `1px solid ${sev.border}`,
            flexShrink: 0,
            marginTop: "2px",
          }}
        >
          {finding.severity}
        </span>

        {/* Title + tool */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: "0.88rem", lineHeight: 1.4 }}>
            {finding.title}
          </div>
          <div style={{ color: "#3d4f6e", fontSize: "0.72rem", marginTop: "3px", fontFamily: "JetBrains Mono, monospace" }}>
            {finding.tool}
          </div>
        </div>

        {/* Chevron */}
        <svg
          width="16" height="16" viewBox="0 0 16 16" fill="none"
          style={{
            flexShrink: 0,
            color: "#3d4f6e",
            transform: open ? "rotate(180deg)" : "rotate(0)",
            transition: "transform 200ms ease",
            marginTop: "2px",
          }}
        >
          <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </button>

      {/* Expanded body */}
      {open && (
        <div style={{
          padding: "0 18px 14px 18px",
          borderTop: `1px solid ${sev.border}`,
          display: "flex",
          flexDirection: "column",
          gap: "8px",
          animation: "fadeUp 0.2s ease both",
        }}>
          {/* Description */}
          <p style={{ color: "#94a3b8", fontSize: "0.82rem", lineHeight: 1.65, margin: "10px 0 0" }}>
            {finding.description}
          </p>

          {/* Recommendation */}
          {finding.recommendation && (
            <div style={{
              background: "rgba(34,211,238,0.04)",
              border: "1px solid rgba(34,211,238,0.15)",
              borderRadius: "8px",
              padding: "10px 14px",
            }}>
              <div style={{
                color: "#22d3ee",
                fontSize: "0.7rem",
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                marginBottom: "5px",
                fontFamily: "JetBrains Mono, monospace",
              }}>
                Recommendation
              </div>
              <p style={{ color: "#94a3b8", fontSize: "0.8rem", lineHeight: 1.6, margin: 0 }}>
                {finding.recommendation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface FindingsPanelProps {
  findings: Finding[];
  criticalFindings: string[];
}

export function FindingsPanel({ findings, criticalFindings }: FindingsPanelProps) {
  const { t } = useLang();
  const [activeFilter, setActiveFilter] = useState<Severity | "ALL">("ALL");

  const counts = SEV_ORDER.reduce((acc, sev) => {
    acc[sev] = findings.filter((f) => f.severity === sev).length;
    return acc;
  }, {} as Record<Severity, number>);

  const filtered = activeFilter === "ALL"
    ? [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    : findings.filter((f) => f.severity === activeFilter);

  return (
    <div>
      {/* Critical box */}
      {criticalFindings.length > 0 && (
        <div style={{
          background: "rgba(239,68,68,0.07)",
          border: "1px solid rgba(239,68,68,0.2)",
          borderLeft: "4px solid #ef4444",
          borderRadius: "10px",
          padding: "14px 18px",
          marginBottom: "16px",
        }}>
          <div style={{
            color: "#ef4444",
            fontWeight: 700,
            fontSize: "0.78rem",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            marginBottom: "8px",
            fontFamily: "JetBrains Mono, monospace",
          }}>
            ⚡ {t("critical_findings")}
          </div>
          {criticalFindings.map((c, i) => (
            <div key={i} style={{
              color: "#fca5a5",
              fontSize: "0.82rem",
              padding: "3px 0 3px 12px",
              borderLeft: "2px solid rgba(239,68,68,0.25)",
              margin: "4px 0",
              lineHeight: 1.55,
            }}>
              {c}
            </div>
          ))}
        </div>
      )}

      {/* Severity filter tabs */}
      <div style={{
        display: "flex",
        gap: "6px",
        flexWrap: "wrap",
        marginBottom: "12px",
        borderBottom: "1px solid #1a2236",
        paddingBottom: "12px",
      }}>
        {(["ALL", ...SEV_ORDER] as const).map((sev) => {
          const count = sev === "ALL" ? findings.length : counts[sev];
          if (sev !== "ALL" && count === 0) return null;
          const active = activeFilter === sev;
          const sevStyle = sev === "ALL" ? null : SEV_STYLE[sev];
          return (
            <button
              key={sev}
              onClick={() => setActiveFilter(sev)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                padding: "5px 12px",
                borderRadius: "999px",
                border: `1px solid ${active && sevStyle ? sevStyle.border : active ? "rgba(34,211,238,0.3)" : "#1a2236"}`,
                background: active && sevStyle ? sevStyle.bg : active ? "rgba(34,211,238,0.06)" : "transparent",
                color: active && sevStyle ? sevStyle.color : active ? "#22d3ee" : "#4a5568",
                fontSize: "0.72rem",
                fontWeight: active ? 700 : 400,
                cursor: "pointer",
                transition: "all 150ms ease",
                fontFamily: "JetBrains Mono, monospace",
              }}
            >
              {sev}
              <span style={{
                fontSize: "0.65rem",
                fontWeight: 800,
                opacity: 0.8,
              }}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Section title */}
      <div style={{
        color: "#3d4f6e",
        fontSize: "0.65rem",
        textTransform: "uppercase",
        letterSpacing: "0.18em",
        fontFamily: "JetBrains Mono, monospace",
        paddingBottom: "8px",
        borderBottom: "1px solid #1a2236",
        marginBottom: "10px",
      }}>
        {t("findings_title")} · {filtered.length}
      </div>

      {/* Findings list */}
      {filtered.length === 0 ? (
        <div style={{ color: "#3d4f6e", fontSize: "0.85rem", padding: "24px 0", textAlign: "center" }}>
          {t("no_findings")}
        </div>
      ) : (
        filtered.map((f) => <FindingCard key={f.id} finding={f} />)
      )}
    </div>
  );
}

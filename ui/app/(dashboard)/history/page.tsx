"use client";

import { useEffect, useState } from "react";
import { Header } from "@/components/layout/header";
import { useLang } from "@/contexts/language-context";
import { getScanHistory, gradeColor, relativeTime, type HistoryRecord, type Grade } from "@/lib/api";

function GradeDot({ grade }: { grade: Grade }) {
  const color = gradeColor(grade);
  return (
    <div style={{
      width: "38px", height: "38px",
      borderRadius: "50%",
      border: `2px solid ${color}`,
      background: `${color}15`,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "JetBrains Mono, monospace",
      fontWeight: 900,
      fontSize: "1rem",
      color,
      flexShrink: 0,
    }}>
      {grade}
    </div>
  );
}

function DeltaBadge({ current, prev }: { current: number; prev?: number }) {
  if (prev === undefined) return null;
  const diff = current - prev;
  if (diff === 0) return <span style={{ color: "#64748b", fontSize: "0.72rem" }}>—</span>;
  return (
    <span style={{
      color: diff > 0 ? "#22d3ee" : "#ef4444",
      fontSize: "0.72rem",
      fontWeight: 700,
      fontFamily: "JetBrains Mono, monospace",
    }}>
      {diff > 0 ? "▲" : "▼"} {Math.abs(diff)}
    </span>
  );
}

export default function HistoryPage() {
  const { t, isRTL } = useLang();
  const [records, setRecords]   = useState<HistoryRecord[]>([]);
  const [loading, setLoading]   = useState(true);
  const [filter,  setFilter]    = useState<Grade | "ALL">("ALL");

  useEffect(() => {
    getScanHistory().then((r) => { setRecords(r); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const filtered = filter === "ALL" ? records : records.filter((r) => r.overall_grade === filter);
  const grades = (["A","B","C","D","F"] as Grade[]).filter((g) => records.some((r) => r.overall_grade === g));

  return (
    <>
      <Header title={t("history_title")} />
      <main style={{ flex: 1, padding: "28px 32px", maxWidth: "900px", margin: "0 auto", width: "100%" }}>

        {/* Filter row */}
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "18px" }}>
          {(["ALL", ...grades] as (Grade | "ALL")[]).map((g) => (
            <button
              key={g}
              onClick={() => setFilter(g)}
              style={{
                padding: "5px 14px",
                borderRadius: "999px",
                border: `1px solid ${filter === g && g !== "ALL" ? gradeColor(g as Grade) + "44" : filter === g ? "rgba(34,211,238,0.3)" : "#1a2236"}`,
                background: filter === g && g !== "ALL" ? gradeColor(g as Grade) + "11" : filter === g ? "rgba(34,211,238,0.06)" : "transparent",
                color: filter === g && g !== "ALL" ? gradeColor(g as Grade) : filter === g ? "#22d3ee" : "#64748b",
                fontSize: "0.76rem",
                fontWeight: filter === g ? 700 : 400,
                cursor: "pointer",
                transition: "all 150ms ease",
                fontFamily: "JetBrains Mono, monospace",
              }}
            >
              {g === "ALL" ? `ALL (${records.length})` : `${g} (${records.filter((r) => r.overall_grade === g).length})`}
            </button>
          ))}
        </div>

        {loading ? (
          <div style={{ color: "#64748b", textAlign: "center", padding: "40px" }}>Loading...</div>
        ) : filtered.length === 0 ? (
          <div style={{ color: "#64748b", textAlign: "center", padding: "40px" }}>
            No scan history yet
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {filtered.map((rec) => (
              <div
                key={rec.scan_id}
                className="glass-card animate-fade-up"
                style={{
                  padding: "14px 18px",
                  display: "flex",
                  alignItems: "center",
                  gap: "16px",
                  transition: "transform 200ms cubic-bezier(0.16,1,0.3,1), border-color 200ms ease, box-shadow 200ms ease",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = "translateX(3px)";
                  e.currentTarget.style.borderColor = "#243049";
                  e.currentTarget.style.boxShadow = "0 4px 20px rgba(0,0,0,0.3)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = "";
                  e.currentTarget.style.borderColor = "";
                  e.currentTarget.style.boxShadow = "";
                }}
              >
                <GradeDot grade={rec.overall_grade} />

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    color: "#f1f5f9",
                    fontWeight: 600,
                    fontSize: "0.9rem",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}>
                    {rec.url}
                  </div>
                  <div style={{ color: "#64748b", fontSize: "0.72rem", marginTop: "3px", fontFamily: "JetBrains Mono, monospace" }}>
                    {t("last_scan")}: {relativeTime(rec.scanned_at)}
                    {rec.critical_count > 0 && (
                      <span style={{ color: "#ef4444", marginInlineStart: "10px" }}>
                        ⚡ {rec.critical_count} critical
                      </span>
                    )}
                  </div>
                </div>

                {/* Score + delta */}
                <div style={{ textAlign: isRTL ? "start" : "end", flexShrink: 0 }}>
                  <div style={{
                    color: gradeColor(rec.overall_grade),
                    fontFamily: "JetBrains Mono, monospace",
                    fontWeight: 800,
                    fontSize: "1.1rem",
                  }}>
                    {rec.overall_score}
                  </div>
                  <DeltaBadge current={rec.overall_score} prev={rec.prev_score} />
                </div>

                {/* Rescan button */}
                <button
                  style={{
                    padding: "6px 14px",
                    borderRadius: "8px",
                    border: "1px solid #1a2236",
                    background: "transparent",
                    color: "#64748b",
                    fontSize: "0.75rem",
                    cursor: "pointer",
                    transition: "all 150ms ease",
                    fontWeight: 600,
                    flexShrink: 0,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "rgba(34,211,238,0.3)";
                    e.currentTarget.style.color = "#22d3ee";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "#1a2236";
                    e.currentTarget.style.color = "#64748b";
                  }}
                >
                  {t("rescan")}
                </button>
              </div>
            ))}
          </div>
        )}
      </main>
    </>
  );
}

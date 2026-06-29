"use client";

import { useEffect, useState } from "react";
import { Header } from "@/components/layout/header";
import { useLang } from "@/contexts/language-context";
import { getSchedules, toggleSchedule, gradeColor, relativeTime, type Schedule, type Grade } from "@/lib/api";

function StatusDot({ status }: { status: Schedule["status"] }) {
  const map = { ok: "#10b981", error: "#ef4444", running: "#f59e0b" };
  const color = map[status] ?? "#4a5568";
  return (
    <span style={{
      display: "inline-block",
      width: "7px", height: "7px",
      borderRadius: "50%",
      background: color,
      boxShadow: `0 0 6px ${color}`,
      flexShrink: 0,
    }} />
  );
}

export default function ScheduledPage() {
  const { t } = useLang();
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading,   setLoading]   = useState(true);

  useEffect(() => {
    getSchedules().then((s) => { setSchedules(s); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const handleToggle = async (id: string, enabled: boolean) => {
    setSchedules((prev) => prev.map((s) => s.id === id ? { ...s, enabled } : s));
    await toggleSchedule(id, enabled).catch(() =>
      setSchedules((prev) => prev.map((s) => s.id === id ? { ...s, enabled: !enabled } : s))
    );
  };

  return (
    <>
      <Header
        title={t("scheduled_title")}
        onNewScan={() => {}}
      />
      <main style={{ flex: 1, padding: "28px 32px", maxWidth: "900px", margin: "0 auto", width: "100%" }}>

        {loading ? (
          <div style={{ color: "#3d4f6e", textAlign: "center", padding: "40px" }}>Loading...</div>
        ) : schedules.length === 0 ? (
          <div style={{ color: "#3d4f6e", textAlign: "center", padding: "40px" }}>
            No scheduled scans yet
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {schedules.map((s) => (
              <div
                key={s.id}
                className="glass-card animate-fade-up"
                style={{
                  padding: "16px 20px",
                  opacity: s.enabled ? 1 : 0.6,
                  transition: "transform 200ms cubic-bezier(0.16,1,0.3,1), border-color 200ms ease, opacity 300ms ease",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = "translateX(2px)";
                  e.currentTarget.style.borderColor = "#243049";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = "";
                  e.currentTarget.style.borderColor = "";
                }}
              >
                <div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}>
                  {/* Status dot */}
                  <div style={{ paddingTop: "4px" }}>
                    <StatusDot status={s.status} />
                  </div>

                  {/* Main info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      color: "#f1f5f9",
                      fontWeight: 600,
                      fontSize: "0.92rem",
                      marginBottom: "3px",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      {s.label ?? s.url}
                    </div>

                    <div style={{
                      color: "#3d4f6e",
                      fontSize: "0.72rem",
                      fontFamily: "JetBrains Mono, monospace",
                      marginBottom: "8px",
                    }}>
                      {s.url} · <span style={{ color: "#22d3ee" }}>{s.cron_expression}</span>
                    </div>

                    {/* Meta row */}
                    <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", fontSize: "0.72rem", color: "#4a5568" }}>
                      {s.last_grade && (
                        <span style={{ color: gradeColor(s.last_grade as Grade) }}>
                          Grade {s.last_grade} · {s.last_score}/100
                        </span>
                      )}
                      {s.next_run_at && (
                        <span>
                          {t("next_run")}: {relativeTime(s.next_run_at)}
                        </span>
                      )}
                      {s.last_run_at && (
                        <span>
                          Last: {relativeTime(s.last_run_at)}
                        </span>
                      )}
                      <span style={{ color: "#2d3a52" }}>
                        {s.run_count} runs
                      </span>
                    </div>
                  </div>

                  {/* Toggle */}
                  <button
                    onClick={() => handleToggle(s.id, !s.enabled)}
                    style={{
                      position: "relative",
                      width: "40px",
                      height: "22px",
                      borderRadius: "999px",
                      border: `1px solid ${s.enabled ? "rgba(34,211,238,0.4)" : "#1a2236"}`,
                      background: s.enabled ? "rgba(34,211,238,0.15)" : "rgba(26,34,54,0.5)",
                      cursor: "pointer",
                      transition: "all 200ms ease",
                      flexShrink: 0,
                    }}
                  >
                    <span style={{
                      position: "absolute",
                      top: "3px",
                      left: s.enabled ? "calc(100% - 19px)" : "3px",
                      width: "14px",
                      height: "14px",
                      borderRadius: "50%",
                      background: s.enabled ? "#22d3ee" : "#2d3a52",
                      transition: "left 200ms cubic-bezier(0.16,1,0.3,1), background 200ms ease",
                    }} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Add button */}
        <button
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            marginTop: "16px",
            padding: "10px 18px",
            borderRadius: "8px",
            border: "1px dashed #243049",
            background: "transparent",
            color: "#4a5568",
            fontSize: "0.84rem",
            cursor: "pointer",
            transition: "all 150ms ease",
            width: "100%",
            justifyContent: "center",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "rgba(34,211,238,0.4)";
            e.currentTarget.style.color = "#22d3ee";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "#243049";
            e.currentTarget.style.color = "#4a5568";
          }}
        >
          + {t("add_schedule")}
        </button>
      </main>
    </>
  );
}

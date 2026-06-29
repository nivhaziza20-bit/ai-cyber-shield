"use client";

import { useEffect, useId, useRef } from "react";
import type { Grade, ScanResult } from "@/lib/api";
import { gradeColor, gradeDesc, scoreColor } from "@/lib/api";
import { useLang } from "@/contexts/language-context";
import { relativeTime } from "@/lib/api";

const RING_R  = 52;
const RING_C  = +(2 * Math.PI * RING_R).toFixed(2); // 326.73

interface GradeRingProps {
  result: ScanResult;
}

export function GradeRing({ result }: GradeRingProps) {
  const { t, lang } = useLang();
  const uid   = useId().replace(/:/g, "");
  const numRef = useRef<SVGTextElement>(null);

  const grade  = result.overall_grade;
  const score  = result.overall_score;
  const color  = gradeColor(grade);
  const offset = +(RING_C * (1 - score / 100)).toFixed(2);
  const crits  = result.critical_findings.length;
  const desc   = gradeDesc(grade, lang);

  /* Animated score counter */
  useEffect(() => {
    const el = numRef.current;
    if (!el) return;
    const start  = performance.now();
    const dur    = 1300;
    const raf = (ts: number) => {
      const p    = Math.min((ts - start) / dur, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      el.textContent = String(Math.round(score * ease));
      if (p < 1) requestAnimationFrame(raf);
      else el.textContent = String(score);
    };
    const timer = setTimeout(() => requestAnimationFrame(raf), 200);
    return () => clearTimeout(timer);
  }, [score]);

  const gradeA = grade === "A";
  const gradeF = grade === "F";

  return (
    <div
      className="animate-fade-up"
      style={{
        display: "flex",
        alignItems: "center",
        gap: "24px",
        background: "rgba(12,17,32,0.82)",
        border: "1px solid #1a2236",
        borderRadius: "16px",
        padding: "20px 28px",
        margin: "0 0 20px",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        boxShadow: gradeA
          ? "0 0 40px rgba(34,211,238,0.15), 0 4px 40px rgba(0,0,0,0.5)"
          : "0 4px 40px rgba(0,0,0,0.5)",
        animation: "fadeUp 0.4s cubic-bezier(0.16,1,0.3,1) both",
      }}
    >
      {/* SVG ring */}
      <div style={{ flexShrink: 0 }}>
        <style>{`
          @keyframes ring-${uid} {
            from { stroke-dashoffset: ${RING_C}; }
            to   { stroke-dashoffset: ${offset}; }
          }
          .ring-${uid} {
            stroke-dasharray: ${RING_C};
            stroke-dashoffset: ${RING_C};
            animation: ring-${uid} 1.6s cubic-bezier(0.34,1.56,0.64,1) 0.2s forwards;
          }
          ${gradeA ? `@keyframes pulse-a-${uid} { 0%,100%{filter:drop-shadow(0 0 8px ${color})} 50%{filter:drop-shadow(0 0 20px ${color})} }` : ""}
          ${gradeF ? `@keyframes pulse-f-${uid} { 0%,100%{filter:drop-shadow(0 0 6px ${color})} 50%{filter:drop-shadow(0 0 18px ${color})} }` : ""}
        `}</style>
        <svg
          width="128" height="128" viewBox="0 0 120 120"
          style={gradeA ? { animation: `pulse-a-${uid} 3s ease-in-out infinite` }
               : gradeF ? { animation: `pulse-f-${uid} 2.5s ease-in-out infinite` }
               : undefined}
        >
          {/* Track */}
          <circle cx="60" cy="60" r={RING_R} fill="none" stroke="#1a2236" strokeWidth="8"/>
          {/* Fill */}
          <circle
            cx="60" cy="60" r={RING_R}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            transform="rotate(-90 60 60)"
            className={`ring-${uid}`}
          />
          {/* Score */}
          <text
            ref={numRef}
            x="60" y="50"
            textAnchor="middle"
            dominantBaseline="middle"
            fill={color}
            fontSize="24"
            fontWeight="900"
            fontFamily="JetBrains Mono, Courier New, monospace"
          >
            0
          </text>
          <text x="60" y="67" textAnchor="middle" dominantBaseline="middle"
                fill="#3d4f6e" fontSize="9">/ 100</text>
          <text x="60" y="83" textAnchor="middle" dominantBaseline="middle"
                fill={color} fontSize="10" fontWeight="800" letterSpacing="2">
            {grade}
          </text>
        </svg>
      </div>

      {/* Info column */}
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Label */}
        <div style={{
          color: "#3d4f6e",
          fontSize: "0.64rem",
          textTransform: "uppercase",
          letterSpacing: "0.16em",
          marginBottom: "5px",
          fontFamily: "JetBrains Mono, monospace",
        }}>
          {t("report_title")} · AI Cyber Shield v6
        </div>

        {/* URL */}
        <div style={{
          color: "#f1f5f9",
          fontSize: "1.15rem",
          fontWeight: 700,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          marginBottom: "10px",
        }}>
          {result.url}
        </div>

        {/* Badges */}
        <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: "6px", marginBottom: "12px" }}>
          {crits > 0 ? (
            <span style={{
              background: "rgba(239,68,68,0.1)",
              color: "#ef4444",
              border: "1px solid rgba(239,68,68,0.25)",
              borderRadius: "999px",
              padding: "2px 12px",
              fontSize: "0.7rem",
              fontWeight: 800,
            }}>
              ⚡ {crits} {t("critical_badge")}
            </span>
          ) : (
            <span style={{
              background: "rgba(16,185,129,0.08)",
              color: "#10b981",
              border: "1px solid rgba(16,185,129,0.2)",
              borderRadius: "999px",
              padding: "2px 12px",
              fontSize: "0.7rem",
              fontWeight: 800,
            }}>
              ✓ {t("no_critical")}
            </span>
          )}
          <span style={{ color: "#3d4f6e", fontSize: "0.7rem", fontFamily: "JetBrains Mono, monospace" }}>
            {desc} {t("security_posture")} · {relativeTime(result.scanned_at)}
          </span>
        </div>

        {/* Progress bar */}
        <div style={{
          background: "#1a2236",
          borderRadius: "3px",
          height: "4px",
          overflow: "hidden",
          maxWidth: "380px",
        }}>
          <div
            className="score-bar-fill"
            style={{
              height: "4px",
              width: `${score}%`,
              borderRadius: "3px",
              background: `linear-gradient(90deg, ${color}, ${color}70)`,
              boxShadow: `0 0 8px ${color}40`,
            }}
          />
        </div>

        {/* Footer */}
        <div style={{
          color: "#3d4f6e",
          fontSize: "0.62rem",
          marginTop: "6px",
          fontFamily: "JetBrains Mono, monospace",
          letterSpacing: "0.04em",
        }}>
          {t("defensive_only")} · {result.scan_duration_s}s · {result.findings.length} findings
        </div>
      </div>
    </div>
  );
}

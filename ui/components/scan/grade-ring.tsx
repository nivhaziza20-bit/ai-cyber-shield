"use client";

import { useEffect, useId, useRef } from "react";
import type { Grade, ScanResult } from "@/lib/api";
import { gradeColor, gradeDesc, scoreColor } from "@/lib/api";
import { useLang } from "@/contexts/language-context";
import { relativeTime } from "@/lib/api";

const RING_R = 56;
const RING_C = +(2 * Math.PI * RING_R).toFixed(2);

/* Grade metadata for full visual treatment */
const GRADE_META: Record<Grade, { glow: string; pulse: number; speed: string }> = {
  A: { glow: "rgba(34,211,238,0.45)",  pulse: 3.0, speed: "ease-in-out" },
  B: { glow: "rgba(59,130,246,0.40)",  pulse: 3.5, speed: "ease-in-out" },
  C: { glow: "rgba(245,158,11,0.35)",  pulse: 2.8, speed: "ease-in-out" },
  D: { glow: "rgba(239,68,68,0.40)",   pulse: 2.2, speed: "ease-in-out" },
  F: { glow: "rgba(220,38,38,0.50)",   pulse: 1.8, speed: "ease-in-out" },
};

interface GradeRingProps {
  result: ScanResult;
}

export function GradeRing({ result }: GradeRingProps) {
  const { t, lang } = useLang();
  const uid    = useId().replace(/:/g, "");
  const numRef = useRef<SVGTextElement>(null);

  const grade  = result.overall_grade;
  const score  = result.overall_score;
  const color  = gradeColor(grade);
  const offset = +(RING_C * (1 - score / 100)).toFixed(2);
  const crits  = result.critical_findings.length;
  const desc   = gradeDesc(grade, lang);
  const meta   = GRADE_META[grade] ?? GRADE_META.C;

  const bannerGlow = crits > 0
    ? "0 0 60px rgba(239,68,68,0.12), 0 4px 48px rgba(0,0,0,0.6)"
    : `0 0 60px ${meta.glow.replace("0.45","0.10")}, 0 4px 48px rgba(0,0,0,0.6)`;

  /* Animated score counter */
  useEffect(() => {
    const el = numRef.current;
    if (!el) return;
    const start = performance.now();
    const dur   = 1400;
    const raf = (ts: number) => {
      const p    = Math.min((ts - start) / dur, 1);
      const ease = 1 - Math.pow(1 - p, 4); // quartic ease-out for snappier feel
      el.textContent = String(Math.round(score * ease));
      if (p < 1) requestAnimationFrame(raf);
      else el.textContent = String(score);
    };
    const timer = setTimeout(() => requestAnimationFrame(raf), 250);
    return () => clearTimeout(timer);
  }, [score]);

  return (
    <div
      className="animate-fade-up"
      style={{
        display: "flex",
        alignItems: "center",
        gap: "28px",
        background: "rgba(10,15,28,0.90)",
        border: `1px solid ${color}22`,
        borderRadius: "18px",
        padding: "22px 28px",
        margin: "0 0 20px",
        backdropFilter: "blur(16px)",
        WebkitBackdropFilter: "blur(16px)",
        boxShadow: bannerGlow,
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Ambient gradient highlight */}
      <div style={{
        position: "absolute",
        top: "-40px",
        left: "60px",
        width: "160px",
        height: "160px",
        borderRadius: "50%",
        background: `radial-gradient(circle, ${meta.glow} 0%, transparent 70%)`,
        pointerEvents: "none",
        zIndex: 0,
      }} />

      {/* SVG ring */}
      <div style={{ flexShrink: 0, position: "relative", zIndex: 1 }}>
        <style>{`
          @keyframes ring-fill-${uid} {
            from { stroke-dashoffset: ${RING_C}; }
            to   { stroke-dashoffset: ${offset}; }
          }
          .ring-fill-${uid} {
            stroke-dasharray: ${RING_C};
            stroke-dashoffset: ${RING_C};
            animation: ring-fill-${uid} 1.8s cubic-bezier(0.34,1.20,0.64,1) 0.25s forwards;
          }
          @keyframes glow-pulse-${uid} {
            0%,100% { filter: drop-shadow(0 0 6px ${color}66); }
            50%     { filter: drop-shadow(0 0 22px ${color}cc); }
          }
          .ring-svg-${uid} {
            animation: glow-pulse-${uid} ${meta.pulse}s ${meta.speed} infinite;
          }
          @keyframes track-shimmer-${uid} {
            0%   { stroke: #1a2236; }
            50%  { stroke: #243050; }
            100% { stroke: #1a2236; }
          }
        `}</style>

        <svg
          width="136" height="136" viewBox="0 0 120 120"
          className={`ring-svg-${uid}`}
        >
          {/* Outer glow ring */}
          <circle cx="60" cy="60" r={RING_R + 4}
            fill="none" stroke={`${color}12`} strokeWidth="12" />
          {/* Track */}
          <circle cx="60" cy="60" r={RING_R}
            fill="none" stroke="#1e2b40" strokeWidth="9" />
          {/* Fill — animated */}
          <circle
            cx="60" cy="60" r={RING_R}
            fill="none"
            stroke={color}
            strokeWidth="9"
            strokeLinecap="round"
            transform="rotate(-90 60 60)"
            className={`ring-fill-${uid}`}
          />
          {/* Score number */}
          <text
            ref={numRef}
            x="60" y="47"
            textAnchor="middle"
            dominantBaseline="middle"
            fill={color}
            fontSize="26"
            fontWeight="900"
            fontFamily="JetBrains Mono, Courier New, monospace"
          >
            0
          </text>
          {/* /100 */}
          <text x="60" y="64" textAnchor="middle" dominantBaseline="middle"
                fill="#64748b" fontSize="8.5" fontFamily="JetBrains Mono, monospace">
            / 100
          </text>
          {/* Grade letter */}
          <text x="60" y="80" textAnchor="middle" dominantBaseline="middle"
                fill={color} fontSize="11" fontWeight="900"
                letterSpacing="3" fontFamily="JetBrains Mono, Courier New, monospace">
            {grade}
          </text>
        </svg>
      </div>

      {/* Info column */}
      <div style={{ flex: 1, minWidth: 0, position: "relative", zIndex: 1 }}>

        {/* Label row */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginBottom: "6px",
        }}>
          <span style={{
            color: "#64748b",
            fontSize: "0.62rem",
            textTransform: "uppercase",
            letterSpacing: "0.18em",
            fontFamily: "JetBrains Mono, monospace",
          }}>
            {t("report_title")} · AI Cyber Shield v6
          </span>
        </div>

        {/* URL */}
        <div style={{
          color: "#f1f5f9",
          fontSize: "1.1rem",
          fontWeight: 700,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          marginBottom: "12px",
          letterSpacing: "-0.01em",
        }}>
          {result.url}
        </div>

        {/* Badge + descriptor row */}
        <div style={{
          display: "flex",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "8px",
          marginBottom: "14px",
        }}>
          {crits > 0 ? (
            <span style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "5px",
              background: "rgba(239,68,68,0.10)",
              color: "#ef4444",
              border: "1px solid rgba(239,68,68,0.28)",
              borderRadius: "999px",
              padding: "3px 10px",
              fontSize: "0.68rem",
              fontWeight: 800,
              letterSpacing: "0.04em",
            }}>
              <span style={{
                width: "6px", height: "6px", borderRadius: "50%",
                background: "#ef4444",
                boxShadow: "0 0 6px #ef4444",
                flexShrink: 0,
                animation: "critPingRing 1.4s ease-in-out infinite",
              }} />
              {crits} {t("critical_badge")}
            </span>
          ) : (
            <span style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "5px",
              background: "rgba(16,185,129,0.08)",
              color: "#10b981",
              border: "1px solid rgba(16,185,129,0.22)",
              borderRadius: "999px",
              padding: "3px 10px",
              fontSize: "0.68rem",
              fontWeight: 800,
            }}>
              ✓ {t("no_critical")}
            </span>
          )}
          <span style={{
            color: color,
            fontSize: "0.68rem",
            fontWeight: 700,
            fontFamily: "JetBrains Mono, monospace",
          }}>
            {desc}
          </span>
          <span style={{ color: "#5a7084", fontSize: "0.66rem", fontFamily: "JetBrains Mono, monospace" }}>
            · {relativeTime(result.scanned_at)}
          </span>
        </div>

        {/* Score bar — wider, animated */}
        <div style={{
          background: "#111827",
          borderRadius: "6px",
          height: "7px",
          overflow: "hidden",
          maxWidth: "400px",
          border: "1px solid #1a2236",
        }}>
          <div
            className="score-bar-fill"
            style={{
              height: "7px",
              width: `${score}%`,
              borderRadius: "6px",
              background: `linear-gradient(90deg, ${color}cc, ${color})`,
              boxShadow: `0 0 12px ${color}60`,
            }}
          />
        </div>

        {/* Footer meta */}
        <div style={{
          display: "flex",
          gap: "12px",
          color: "#64748b",
          fontSize: "0.61rem",
          marginTop: "7px",
          fontFamily: "JetBrains Mono, monospace",
          letterSpacing: "0.04em",
        }}>
          <span>{t("defensive_only")}</span>
          <span>· {result.scan_duration_s}s</span>
          <span>· {result.findings.length} {t("findings_title").toLowerCase()}</span>
        </div>
      </div>
    </div>
  );
}

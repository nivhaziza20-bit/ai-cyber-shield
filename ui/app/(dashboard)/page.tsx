"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { Header } from "@/components/layout/header";
import { GradeRing } from "@/components/scan/grade-ring";
import { ScoreGrid } from "@/components/scan/score-grid";
import { FindingsPanel } from "@/components/scan/findings-panel";
import ScanProgressPanel from "@/components/scan/ScanProgressPanel";
import { useLang } from "@/contexts/language-context";
import { triggerScan, getScan, type ScanResult, type ScanMode } from "@/lib/api";
import { useScanProgress } from "@/lib/useScanProgress";

type ScanState = "idle" | "scanning" | "done" | "error";

import type { TranslationKey } from "@/lib/i18n";

const MODES: { value: ScanMode; icon: string; color: string; labelKey: TranslationKey }[] = [
  { value: "standard", icon: "🛡",  color: "#22d3ee", labelKey: "scan_mode_std" },
  { value: "passive",  icon: "👁",  color: "#3b82f6", labelKey: "scan_mode_passive" },
  { value: "pt",       icon: "⚡",  color: "#ef4444", labelKey: "scan_mode_pt" },
];

/* ── Animated shield empty state ───────────────────────────────────────────── */
function EmptyState() {
  const { t } = useLang();
  return (
    <div className="animate-fade-in" style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "60px 24px",
      textAlign: "center",
      gap: "0",
    }}>
      {/* Shield SVG with animated scan line */}
      <svg width="80" height="90" viewBox="0 0 80 90" fill="none"
           xmlns="http://www.w3.org/2000/svg" style={{ marginBottom: "28px", overflow: "visible" }}>
        <defs>
          <linearGradient id="slg" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.8"/>
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0"/>
          </linearGradient>
          <filter id="glow-es">
            <feGaussianBlur stdDeviation="1.5" result="blur"/>
            <feComposite in="SourceGraphic" in2="blur" operator="over"/>
          </filter>
        </defs>
        {/* Outer shield */}
        <path d="M40 4L8 16V44C8 62.4 22.4 79.6 40 84C57.6 79.6 72 62.4 72 44V16L40 4Z"
              fill="#090d1a" stroke="#243049" strokeWidth="1.5"/>
        {/* Inner shield */}
        <path d="M40 12L16 22V44C16 58.4 26.8 71.8 40 75.6C53.2 71.8 64 58.4 64 44V22L40 12Z"
              fill="#0c1120" stroke="rgba(34,211,238,0.15)" strokeWidth="1"/>
        {/* Lock body */}
        <rect x="27" y="44" width="26" height="20" rx="3"
              fill="rgba(34,211,238,0.07)" stroke="rgba(34,211,238,0.35)" strokeWidth="1.2"/>
        {/* Shackle */}
        <path d="M32 44v-6a8 8 0 0 1 16 0v6"
              fill="none" stroke="rgba(34,211,238,0.55)" strokeWidth="1.5" strokeLinecap="round"/>
        {/* Keyhole */}
        <circle cx="40" cy="53" r="2.5" fill="rgba(34,211,238,0.5)"/>
        <rect x="38.8" y="53" width="2.4" height="5" rx="1.2" fill="rgba(34,211,238,0.5)"/>
        {/* Animated scan line */}
        <g style={{ animation: "scanPulse 2.4s ease-in-out infinite" }}>
          <rect x="16" y="28" width="48" height="0.8" rx="0.4" fill="#22d3ee" opacity="0.6" filter="url(#glow-es)"/>
          <rect x="16" y="28" width="48" height="7" rx="2" fill="url(#slg)" opacity="0.12"/>
        </g>
      </svg>

      <h2 style={{
        fontSize: "1.3rem",
        fontWeight: 700,
        color: "#f1f5f9",
        margin: "0 0 10px",
      }}>
        {t("empty_title")}
      </h2>
      <p style={{
        color: "#64748b",
        fontSize: "0.88rem",
        maxWidth: "400px",
        lineHeight: 1.65,
        margin: "0 0 28px",
      }}>
        {t("empty_sub")}
      </p>

      {/* Tips */}
      <div style={{ display: "flex", flexDirection: "column", gap: "8px", width: "100%", maxWidth: "380px" }}>
        {(["tip_1", "tip_2", "tip_3"] as const).map((tip) => (
          <div key={tip} style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            padding: "9px 14px",
            background: "rgba(12,17,32,0.6)",
            border: "1px solid #1a2236",
            borderRadius: "8px",
            fontSize: "0.78rem",
            color: "#64748b",
            textAlign: "start",
          }}>
            <span style={{ color: "#22d3ee", flexShrink: 0 }}>✓</span>
            {t(tip)}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Loading skeleton ──────────────────────────────────────────────────────── */
function ScanningState({ url }: { url: string }) {
  return (
    <div className="animate-fade-in" style={{ padding: "24px 0" }}>
      {/* Banner skeleton */}
      <div style={{
        background: "rgba(12,17,32,0.8)",
        border: "1px solid #1a2236",
        borderRadius: "16px",
        padding: "20px 28px",
        marginBottom: "20px",
        display: "flex",
        alignItems: "center",
        gap: "24px",
      }}>
        {/* Ring skeleton */}
        <div style={{
          width: "128px", height: "128px",
          borderRadius: "50%",
          background: "rgba(26,34,54,0.5)",
          flexShrink: 0,
          position: "relative",
          overflow: "hidden",
        }}>
          <div style={{
            position: "absolute",
            inset: 0,
            background: "linear-gradient(90deg, transparent 25%, rgba(34,211,238,0.06) 50%, transparent 75%)",
            animation: "shimmer 2s linear infinite",
            backgroundSize: "200% 100%",
          }}/>
          {/* Spinner */}
          <svg style={{ position: "absolute", inset: "12px", animation: "spin 1s linear infinite" }}
               viewBox="0 0 104 104">
            <circle cx="52" cy="52" r="46" fill="none" stroke="#1a2236" strokeWidth="8"/>
            <circle cx="52" cy="52" r="46" fill="none" stroke="#22d3ee" strokeWidth="8"
                    strokeLinecap="round" strokeDasharray="80 206" transform="rotate(-90 52 52)"/>
          </svg>
        </div>

        {/* Text skeleton */}
        <div style={{ flex: 1 }}>
          <div style={{ color: "#64748b", fontSize: "0.64rem", textTransform: "uppercase", letterSpacing: "0.16em", marginBottom: "8px", fontFamily: "JetBrains Mono, monospace" }}>
            Scanning...
          </div>
          <div style={{ color: "#f1f5f9", fontSize: "1.1rem", fontWeight: 700, marginBottom: "10px" }}>{url}</div>
          {/* Loading dots */}
          <div className="loading-dots" style={{ display: "flex", gap: "5px" }}>
            <span/><span/><span/>
          </div>
        </div>
      </div>

      {/* Grid skeletons */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))", gap: "8px" }}>
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} style={{
            height: "88px",
            background: "rgba(12,17,32,0.75)",
            border: "1px solid #1a2236",
            borderRadius: "10px",
            overflow: "hidden",
            position: "relative",
          }}>
            <div style={{
              position: "absolute",
              inset: 0,
              background: "linear-gradient(90deg, transparent 25%, rgba(34,211,238,0.04) 50%, transparent 75%)",
              animation: `shimmer 2s linear ${i * 0.1}s infinite`,
              backgroundSize: "200% 100%",
            }}/>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Main page ─────────────────────────────────────────────────────────────── */
export default function DashboardPage() {
  const { t, isRTL } = useLang();
  const [url,    setUrl]    = useState("");
  const [mode,   setMode]   = useState<ScanMode>("standard");
  const [state,  setState]  = useState<ScanState>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error,  setError]  = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // SSE progress — active while scanning
  const progress = useScanProgress(state === "scanning" ? scanId : null);

  // Elapsed timer
  useEffect(() => {
    if (state !== "scanning") { setElapsed(0); return; }
    const t = setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, [state]);

  // When SSE completes, fetch the final scan summary
  useEffect(() => {
    if (!progress.isComplete || state !== "scanning" || !scanId) return;
    if (progress.error) {
      setError(progress.error);
      setState("error");
      return;
    }
    // Build a minimal ScanResult from SSE data + overallResult
    const r = progress.overallResult;
    const synthetic: ScanResult = {
      scan_id:           scanId,
      url,
      overall_score:     r?.score   ?? 0,
      overall_grade:     (r?.grade  ?? "F") as any,
      category_scores:   {},
      critical_findings: [],
      findings:          [],
      scan_mode:         mode,
      scan_duration_s:   elapsed,
      scanned_at:        new Date().toISOString(),
    };
    setResult(synthetic);
    setState("done");
  }, [progress.isComplete, progress.error, progress.overallResult, state, scanId, url, mode, elapsed]);

  const handleScan = useCallback(async () => {
    const target = url.trim();
    if (!target) { inputRef.current?.focus(); return; }
    setState("scanning");
    setScanId(null);
    setResult(null);
    setError(null);
    try {
      const { scan_id } = await triggerScan(target, mode);
      setScanId(scan_id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Scan failed");
      setState("error");
    }
  }, [url, mode]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleScan();
  };

  const scanning = state === "scanning";

  return (
    <>
      <Header
        title={t("nav_dashboard")}
        onNewScan={() => { setResult(null); setState("idle"); setUrl(""); setTimeout(() => inputRef.current?.focus(), 50); }}
      />

      <main style={{ flex: 1, padding: "28px 32px", maxWidth: "1100px", margin: "0 auto", width: "100%" }}>

        {/* ── Scan input card ─────────────────────────────────────────────── */}
        <div style={{
          background: "rgba(12,17,32,0.8)",
          border: "1px solid #1a2236",
          borderRadius: "16px",
          padding: "24px 28px",
          marginBottom: "24px",
          backdropFilter: "blur(12px)",
          WebkitBackdropFilter: "blur(12px)",
        }}>
          {/* Title */}
          <div style={{ marginBottom: "18px" }}>
            <h1 style={{
              margin: 0,
              fontSize: "1.05rem",
              fontWeight: 700,
              color: "#f1f5f9",
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}>
              <span className="text-gradient-cyber">AI CYBER SHIELD</span>
              <span style={{
                fontSize: "0.6rem",
                color: "#22d3ee",
                background: "rgba(34,211,238,0.07)",
                border: "1px solid rgba(34,211,238,0.2)",
                borderRadius: "4px",
                padding: "2px 7px",
                fontFamily: "JetBrains Mono, monospace",
                letterSpacing: "0.1em",
                fontWeight: 800,
              }}>
                v6.0
              </span>
            </h1>
            <p style={{ margin: "5px 0 0", color: "#64748b", fontSize: "0.82rem" }}>
              {t("scan_subtitle")}
            </p>
          </div>

          {/* URL input + scan button */}
          <div style={{
            display: "flex",
            gap: "10px",
            flexWrap: "wrap",
          }}>
            <div style={{ flex: 1, minWidth: "240px", position: "relative" }}>
              {/* Lock icon */}
              <span style={{
                position: "absolute",
                [isRTL ? "right" : "left"]: "14px",
                top: "50%",
                transform: "translateY(-50%)",
                color: "#64748b",
                pointerEvents: "none",
                fontSize: "0.9rem",
              }}>
                🔒
              </span>
              <input
                ref={inputRef}
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={t("scan_placeholder")}
                disabled={scanning}
                style={{
                  width: "100%",
                  padding: isRTL ? "12px 42px 12px 14px" : "12px 14px 12px 42px",
                  background: "#080c18",
                  border: "1px solid #1a2236",
                  borderRadius: "8px",
                  color: "#f1f5f9",
                  fontSize: "1rem",
                  fontFamily: "JetBrains Mono, Courier New, monospace",
                  outline: "none",
                  transition: "border-color 150ms ease, box-shadow 150ms ease",
                  opacity: scanning ? 0.6 : 1,
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = "#22d3ee";
                  e.target.style.boxShadow = "0 0 0 3px rgba(34,211,238,0.08)";
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = "#1a2236";
                  e.target.style.boxShadow = "";
                }}
              />
            </div>

            {/* Scan button */}
            <button
              onClick={handleScan}
              disabled={scanning}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "12px 24px",
                borderRadius: "8px",
                background: scanning
                  ? "rgba(34,211,238,0.15)"
                  : "linear-gradient(135deg, #22d3ee 0%, #0891b2 100%)",
                color: scanning ? "#22d3ee" : "#000d1a",
                fontWeight: 800,
                fontSize: "0.92rem",
                border: scanning ? "1px solid rgba(34,211,238,0.3)" : "none",
                cursor: scanning ? "not-allowed" : "pointer",
                letterSpacing: "0.02em",
                boxShadow: scanning ? "none" : "0 0 20px rgba(34,211,238,0.22), inset 0 1px 0 rgba(255,255,255,0.15)",
                transition: "all 200ms cubic-bezier(0.16,1,0.3,1)",
                minWidth: "130px",
                justifyContent: "center",
                flexShrink: 0,
              }}
              onMouseEnter={(e) => {
                if (!scanning) {
                  e.currentTarget.style.transform = "translateY(-2px)";
                  e.currentTarget.style.boxShadow = "0 8px 28px rgba(34,211,238,0.5), inset 0 1px 0 rgba(255,255,255,0.2)";
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = "";
                e.currentTarget.style.boxShadow = scanning ? "none" : "0 0 20px rgba(34,211,238,0.22), inset 0 1px 0 rgba(255,255,255,0.15)";
              }}
              onMouseDown={(e) => { if (!scanning) e.currentTarget.style.transform = "scale(0.97)"; }}
              onMouseUp={(e) => { if (!scanning) e.currentTarget.style.transform = "translateY(-2px)"; }}
            >
              {scanning ? (
                <>
                  <svg style={{ animation: "spin 1s linear infinite" }} width="14" height="14" viewBox="0 0 14 14">
                    <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeWidth="2"
                            strokeLinecap="round" strokeDasharray="25 10"/>
                  </svg>
                  {t("scanning")}
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                    <circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.6"/>
                    <path d="M9.5 9.5l3 3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
                  </svg>
                  {t("scan_button")}
                </>
              )}
            </button>
          </div>

          {/* Mode selector */}
          <div style={{ display: "flex", gap: "8px", marginTop: "14px", flexWrap: "wrap" }}>
            {MODES.map((m) => {
              const active = mode === m.value;
              return (
                <button
                  key={m.value}
                  onClick={() => setMode(m.value)}
                  disabled={scanning}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    padding: "5px 12px",
                    borderRadius: "999px",
                    border: `1px solid ${active ? m.color + "44" : "#1a2236"}`,
                    background: active ? `${m.color}11` : "transparent",
                    color: active ? m.color : "#64748b",
                    fontSize: "0.76rem",
                    fontWeight: active ? 700 : 400,
                    cursor: scanning ? "not-allowed" : "pointer",
                    transition: "all 150ms ease",
                    fontFamily: "JetBrains Mono, monospace",
                    letterSpacing: "0.06em",
                    opacity: scanning ? 0.6 : 1,
                  }}
                >
                  {m.icon} {t(m.labelKey)}
                </button>
              );
            })}
            <span style={{
              fontSize: "0.68rem",
              color: "#5a7084",
              fontFamily: "JetBrains Mono, monospace",
              alignSelf: "center",
              marginInlineStart: "4px",
            }}>
              Ctrl+Enter to scan
            </span>
          </div>
        </div>

        {/* ── Results area ─────────────────────────────────────────────────── */}
        {state === "idle" && <EmptyState />}
        {state === "scanning" && scanId && (
          <ScanProgressPanel
            scanId={scanId}
            url={url}
            progress={progress}
            elapsedSeconds={elapsed}
          />
        )}
        {state === "scanning" && !scanId && <ScanningState url={url} />}

        {state === "error" && error && (
          <div className="animate-fade-up" style={{
            background: "rgba(239,68,68,0.07)",
            border: "1px solid rgba(239,68,68,0.25)",
            borderLeft: "4px solid #ef4444",
            borderRadius: "10px",
            padding: "16px 20px",
            color: "#fca5a5",
            fontSize: "0.88rem",
          }}>
            <strong style={{ color: "#ef4444" }}>Scan failed: </strong>{error}
          </div>
        )}

        {state === "done" && result && (
          <div className="animate-fade-up">
            <GradeRing result={result} />
            <ScoreGrid scores={result.category_scores} />
            <FindingsPanel findings={result.findings} criticalFindings={result.critical_findings} />
          </div>
        )}
      </main>
    </>
  );
}

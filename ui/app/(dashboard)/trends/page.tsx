"use client";

/**
 * Trend Dashboard — Security posture evolution over time.
 *
 * Features:
 *  - Score-over-time line chart (custom SVG, zero deps)
 *  - Findings-over-time stacked bar chart (SVG)
 *  - Key metrics card (delta, grade change, MTTR, resolved, new)
 *  - Category health list with trend arrows
 *  - Period selector: 7d / 30d / 90d / 1y
 *  - Export Trend Report button
 */

import { useState, useEffect, useCallback } from "react";
import { Header } from "@/components/layout/header";
import { useLang } from "@/contexts/language-context";

const _CYAN   = "#22d3ee";
const _GREEN  = "#22c55e";
const _YELLOW = "#eab308";
const _ORANGE = "#f97316";
const _RED    = "#ef4444";
const _BLUE   = "#3b82f6";
const _MUTED  = "#64748b";

type Period = "7d" | "30d" | "90d" | "365d";

interface DataPoint {
  scan_id:   string;
  date:      string;
  score:     number | null;
  grade:     string | null;
  findings_by_severity: { critical: number; high: number; medium: number; low: number; info: number };
  category_scores: Record<string, number>;
}

interface CategoryAttention {
  category:      string;
  current_score: number | null;
  trend:         string;
  delta:         number;
}

interface TrendSummary {
  score_delta:                  number;
  grade_change:                 string | null;
  trend_direction:              string;
  findings_resolved:            number;
  findings_new:                 number;
  mean_time_to_remediate_days:  number | null;
  most_improved_category:       string | null;
  most_degraded_category:       string | null;
  categories_needing_attention: CategoryAttention[];
}

interface TrendsData {
  url:         string;
  period:      string;
  scan_count:  number;
  data_points: DataPoint[];
  summary:     TrendSummary;
}

const PERIODS: { id: Period; label: string }[] = [
  { id: "7d",   label: "7d" },
  { id: "30d",  label: "30d" },
  { id: "90d",  label: "90d" },
  { id: "365d", label: "1y" },
];

const GRADE_COLOR: Record<string, string> = {
  A: _GREEN, B: _BLUE, C: _YELLOW, D: _ORANGE, F: _RED,
};

/* ── Demo data ──────────────────────────────────────────────────────────────── */
function _demo(): TrendsData {
  const now = Date.now();
  const day = 86400000;
  const data_points: DataPoint[] = [
    { scan_id: "s1", date: new Date(now - 29 * day).toISOString(), score: 54, grade: "D",
      findings_by_severity: { critical: 4, high: 8,  medium: 12, low: 6, info: 2 },
      category_scores: { ssl: 55, headers: 40, dns: 80, cors: 35, cookies: 50 } },
    { scan_id: "s2", date: new Date(now - 22 * day).toISOString(), score: 60, grade: "C",
      findings_by_severity: { critical: 3, high: 7,  medium: 11, low: 5, info: 2 },
      category_scores: { ssl: 62, headers: 48, dns: 80, cors: 50, cookies: 55 } },
    { scan_id: "s3", date: new Date(now - 15 * day).toISOString(), score: 66, grade: "C",
      findings_by_severity: { critical: 2, high: 6,  medium: 10, low: 5, info: 3 },
      category_scores: { ssl: 70, headers: 58, dns: 82, cors: 60, cookies: 62 } },
    { scan_id: "s4", date: new Date(now - 8  * day).toISOString(), score: 71, grade: "C",
      findings_by_severity: { critical: 1, high: 5,  medium: 9,  low: 4, info: 3 },
      category_scores: { ssl: 78, headers: 65, dns: 84, cors: 68, cookies: 70 } },
    { scan_id: "s5", date: new Date(now).toISOString(),             score: 79, grade: "B",
      findings_by_severity: { critical: 0, high: 3,  medium: 8,  low: 4, info: 4 },
      category_scores: { ssl: 88, headers: 76, dns: 86, cors: 75, cookies: 78 } },
  ];
  return {
    url:        "example.co.il",
    period:     "30d",
    scan_count: 5,
    data_points,
    summary: {
      score_delta:                 25,
      grade_change:                "D → B",
      trend_direction:             "improving",
      findings_resolved:           18,
      findings_new:                2,
      mean_time_to_remediate_days: 7.2,
      most_improved_category:      "headers",
      most_degraded_category:      null,
      categories_needing_attention: [],
    },
  };
}

/* ── Score line chart (custom SVG) ─────────────────────────────────────────── */
function ScoreLineChart({ points, height = 140 }: { points: DataPoint[]; height?: number }) {
  if (points.length < 2) return null;
  const W = 520; const H = height;
  const PAD = { l: 36, r: 16, t: 10, b: 28 };
  const xs = points.map((_, i) => PAD.l + (i / (points.length - 1)) * (W - PAD.l - PAD.r));
  const scores = points.map((p) => p.score ?? 0);
  const minS = Math.min(...scores);
  const maxS = Math.max(...scores, minS + 5);
  const sy = (s: number) => PAD.t + ((maxS - s) / (maxS - minS + 1)) * (H - PAD.t - PAD.b);
  const d  = xs.map((x, i) => `${i === 0 ? "M" : "L"}${x},${sy(scores[i])}`).join(" ");

  const gradeBands = [
    { min: 90, max: 100, color: _GREEN   + "18", label: "A" },
    { min: 75, max: 90,  color: _BLUE    + "18", label: "B" },
    { min: 60, max: 75,  color: _YELLOW  + "15", label: "C" },
    { min: 40, max: 60,  color: _ORANGE  + "15", label: "D" },
    { min: 0,  max: 40,  color: _RED     + "15", label: "F" },
  ];

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height }} preserveAspectRatio="xMidYMid meet">
      {/* Grade zone backgrounds */}
      {gradeBands.map((b) => {
        const y1 = sy(Math.min(b.max, maxS));
        const y2 = sy(Math.max(b.min, minS));
        if (y2 <= y1) return null;
        return (
          <rect key={b.label} x={PAD.l} y={y1} width={W - PAD.l - PAD.r} height={y2 - y1}
                fill={b.color} />
        );
      })}
      {/* Grid lines */}
      {[0, 25, 50, 75, 100].map((v) => {
        const y = sy(v);
        if (y < PAD.t || y > H - PAD.b) return null;
        return (
          <g key={v}>
            <line x1={PAD.l} y1={y} x2={W - PAD.r} y2={y}
                  stroke="#1a2236" strokeWidth={1} />
            <text x={PAD.l - 4} y={y + 4} textAnchor="end" fontSize={9} fill={_MUTED}>{v}</text>
          </g>
        );
      })}
      {/* Data path */}
      <path d={d} fill="none" stroke={_CYAN} strokeWidth={2.5} strokeLinejoin="round" />
      {/* Data points */}
      {xs.map((x, i) => {
        const grade = points[i].grade ?? "F";
        const col = GRADE_COLOR[grade] ?? _MUTED;
        return (
          <g key={i}>
            <circle cx={x} cy={sy(scores[i])} r={5} fill={col} stroke="#080c18" strokeWidth={1.5} />
          </g>
        );
      })}
      {/* X-axis date labels */}
      {xs.map((x, i) => {
        if (i % Math.max(1, Math.floor(points.length / 4)) !== 0 && i !== points.length - 1) return null;
        const dt = new Date(points[i].date);
        const label = `${dt.getMonth() + 1}/${dt.getDate()}`;
        return <text key={i} x={x} y={H - 4} textAnchor="middle" fontSize={9} fill={_MUTED}>{label}</text>;
      })}
    </svg>
  );
}

/* ── Findings stacked bar chart ─────────────────────────────────────────────── */
function FindingsBarChart({ points, height = 100 }: { points: DataPoint[]; height?: number }) {
  if (points.length === 0) return null;
  const W = 520; const H = height;
  const PAD = { l: 8, r: 8, t: 4, b: 18 };
  const barW = (W - PAD.l - PAD.r) / points.length - 4;
  const maxTotal = Math.max(...points.map((p) => {
    const f = p.findings_by_severity;
    return f.critical + f.high + f.medium + f.low;
  }), 1);
  const chartH = H - PAD.t - PAD.b;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height }} preserveAspectRatio="xMidYMid meet">
      {points.map((p, i) => {
        const x = PAD.l + i * ((W - PAD.l - PAD.r) / points.length) + 2;
        const f = p.findings_by_severity;
        let y = PAD.t + chartH;
        const segs = [
          { val: f.critical, col: _RED    },
          { val: f.high,     col: _ORANGE },
          { val: f.medium,   col: _YELLOW },
          { val: f.low,      col: _GREEN  },
        ].filter((s) => s.val > 0);
        return (
          <g key={i}>
            {segs.map(({ val, col }) => {
              const h = (val / maxTotal) * chartH;
              y -= h;
              return <rect key={col} x={x} y={y} width={barW} height={h} fill={col} opacity={0.8} rx={1} />;
            })}
            {i % Math.max(1, Math.floor(points.length / 4)) === 0 && (
              <text x={x + barW / 2} y={H - 2} textAnchor="middle" fontSize={8} fill={_MUTED}>
                {new Date(p.date).getMonth() + 1}/{new Date(p.date).getDate()}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

/* ── Metric card ────────────────────────────────────────────────────────────── */
function MetricCard({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div style={{
      background: "rgba(13,20,33,0.8)",
      border: "1px solid #1a2236",
      borderRadius: "10px",
      padding: "14px 16px",
      display: "flex",
      flexDirection: "column",
      gap: "3px",
    }}>
      <div style={{ color: _MUTED, fontSize: "0.73rem" }}>{label}</div>
      <div style={{ color: color ?? "#f1f5f9", fontWeight: 800, fontSize: "1.15rem" }}>{value}</div>
      {sub && <div style={{ color: _MUTED, fontSize: "0.70rem" }}>{sub}</div>}
    </div>
  );
}

/* ── Category health row ────────────────────────────────────────────────────── */
function CategoryRow({ name, score, trend, delta }: { name: string; score: number | null; trend: string; delta: number }) {
  const arrow = trend === "improving" ? "↑" : trend === "degrading" ? "↓" : "→";
  const col   = trend === "improving" ? _GREEN : trend === "degrading" ? _RED : _MUTED;
  const scoreColor = score !== null
    ? score >= 90 ? _GREEN : score >= 75 ? _BLUE : score >= 60 ? _YELLOW : score >= 40 ? _ORANGE : _RED
    : _MUTED;

  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "7px 12px",
      borderRadius: "8px",
      background: "rgba(13,20,33,0.6)",
      border: "1px solid #1a2236",
    }}>
      <span style={{ color: "#94a3b8", fontSize: "0.8rem", fontFamily: "monospace" }}>
        {name.replace(/_/g, " ")}
      </span>
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <span style={{ color: scoreColor, fontWeight: 700, fontSize: "0.85rem" }}>
          {score ?? "—"}
        </span>
        <span style={{ color: col, fontSize: "0.8rem", fontWeight: 700 }}>
          {arrow} {Math.abs(delta) > 0 ? `${delta > 0 ? "+" : ""}${delta.toFixed(0)}` : ""}
        </span>
      </div>
    </div>
  );
}

/* ── Page ───────────────────────────────────────────────────────────────────── */
export default function TrendsPage() {
  const { t, lang } = useLang();
  const isHe = lang === "he";
  const [period, setPeriod]   = useState<Period>("30d");
  const [url, setUrl]         = useState("");
  const [data, setData]       = useState<TrendsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);

  const fetchTrends = useCallback(async (targetUrl: string, p: Period) => {
    if (!targetUrl) return;
    setLoading(true); setError(null);
    try {
      const mock = process.env.NEXT_PUBLIC_MOCK_API === "true";
      if (mock) {
        await new Promise((r) => setTimeout(r, 600));
        setData(_demo());
        return;
      }
      const key = process.env.NEXT_PUBLIC_AICS_API_KEY ?? "aics-dev-key-DO-NOT-USE-IN-PRODUCTION";
      const base = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
      const res = await fetch(
        `${base}/api/v1/trends?url=${encodeURIComponent(targetUrl)}&period=${p}`,
        { headers: { "X-API-Key": key } },
      );
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e?.detail?.error ?? `HTTP ${res.status}`); }
      setData(await res.json());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { if (url) fetchTrends(url, period); }, [period, url, fetchTrends]);

  const trendColor = !data ? _MUTED
    : data.summary.trend_direction === "improving" ? _GREEN
    : data.summary.trend_direction === "degrading" ? _RED
    : _YELLOW;
  const trendArrow = !data ? "" : data.summary.trend_direction === "improving" ? "↑" : data.summary.trend_direction === "degrading" ? "↓" : "→";

  const categoryList = data
    ? (data.data_points[data.data_points.length - 1]?.category_scores ?? {})
    : {};

  return (
    <>
      <Header title={isHe ? "מגמות אבטחה" : "Security Trends"} />
      <main style={{ flex: 1, padding: "28px 32px", maxWidth: "960px", margin: "0 auto", width: "100%" }}>

        {/* URL input + period selector */}
        <div style={{
          background: "rgba(12,17,32,0.8)", border: "1px solid #1a2236",
          borderRadius: "14px", padding: "20px 24px", marginBottom: "20px",
        }}>
          <div style={{ display: "flex", gap: "10px", marginBottom: "14px" }}>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") fetchTrends(url, period); }}
              placeholder="https://example.co.il"
              style={{
                flex: 1, padding: "10px 14px",
                background: "#080c18", border: "1px solid #1a2236",
                borderRadius: "8px", color: "#f1f5f9",
                fontSize: "0.9rem", fontFamily: "JetBrains Mono, monospace", outline: "none",
              }}
              onFocus={(e) => { e.target.style.borderColor = _CYAN; }}
              onBlur={(e)  => { e.target.style.borderColor = "#1a2236"; }}
            />
            <button
              onClick={() => fetchTrends(url, period)}
              disabled={!url || loading}
              style={{
                padding: "10px 20px", borderRadius: "8px", border: "none",
                background: url && !loading ? `linear-gradient(135deg, ${_CYAN} 0%, ${_CYAN}80 100%)` : "#1a2236",
                color: url && !loading ? "#000d1a" : "#475569",
                fontWeight: 800, fontSize: "0.85rem", cursor: url && !loading ? "pointer" : "not-allowed",
                transition: "all 200ms",
              }}
            >
              {loading ? "…" : (isHe ? "טען" : "Load")}
            </button>
          </div>

          {/* Period chips */}
          <div style={{ display: "flex", gap: "8px" }}>
            {PERIODS.map((p) => (
              <button
                key={p.id}
                onClick={() => setPeriod(p.id)}
                style={{
                  padding: "5px 14px", borderRadius: "6px",
                  border: `1px solid ${period === p.id ? _CYAN + "55" : "#1a2236"}`,
                  background: period === p.id ? `${_CYAN}12` : "transparent",
                  color: period === p.id ? _CYAN : _MUTED,
                  fontSize: "0.78rem", fontWeight: period === p.id ? 700 : 400,
                  cursor: "pointer", transition: "all 150ms",
                }}
              >
                {p.label}
              </button>
            ))}
            {data && (
              <span style={{ marginLeft: "auto", color: _MUTED, fontSize: "0.75rem", alignSelf: "center" }}>
                {data.scan_count} {isHe ? "סריקות" : "scans"} · {data.url}
              </span>
            )}
          </div>
        </div>

        {/* Error state */}
        {error && (
          <div style={{
            padding: "12px 16px", borderRadius: "10px", marginBottom: "16px",
            background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)",
            color: "#fca5a5", fontSize: "0.83rem",
          }}>
            {isHe ? "שגיאה:" : "Error:"} {error}
          </div>
        )}

        {/* Demo state (no URL entered) */}
        {!data && !loading && !error && (
          <div style={{ textAlign: "center", padding: "40px 0" }}>
            <div style={{ fontSize: "2rem", marginBottom: "12px" }}>📈</div>
            <div style={{ color: _MUTED, fontSize: "0.88rem", marginBottom: "20px" }}>
              {isHe ? "הזן כתובת URL וטען נתוני מגמות" : "Enter a URL above to load trend data"}
            </div>
            <button
              onClick={() => { setUrl("https://example.co.il"); fetchTrends("https://example.co.il", period); }}
              style={{
                padding: "8px 18px", borderRadius: "8px",
                border: `1px solid ${_CYAN}33`, background: `${_CYAN}0a`,
                color: _CYAN, fontSize: "0.8rem", cursor: "pointer",
              }}
            >
              {isHe ? "טען דמו" : "Load demo data"}
            </button>
          </div>
        )}

        {loading && (
          <div style={{ textAlign: "center", padding: "40px 0", color: _MUTED, fontSize: "0.88rem" }}>
            {isHe ? "טוען מגמות…" : "Loading trends…"}
          </div>
        )}

        {data && !loading && (
          <>
            {/* Key metrics row */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: "10px", marginBottom: "20px" }}>
              <MetricCard
                label={isHe ? "שינוי ציון" : "Score delta"}
                value={`${data.summary.score_delta > 0 ? "+" : ""}${data.summary.score_delta}`}
                color={data.summary.score_delta > 0 ? _GREEN : data.summary.score_delta < 0 ? _RED : _MUTED}
                sub={isHe ? "מסריקה ראשונה לאחרונה" : "first to last scan"}
              />
              <MetricCard
                label={isHe ? "מגמה" : "Trend"}
                value={`${trendArrow} ${data.summary.trend_direction}`}
                color={trendColor}
              />
              <MetricCard
                label={isHe ? "שינוי דרגה" : "Grade change"}
                value={data.summary.grade_change ?? "—"}
                color={data.summary.grade_change ? _CYAN : _MUTED}
              />
              <MetricCard
                label="MTTR"
                value={data.summary.mean_time_to_remediate_days != null
                  ? `${data.summary.mean_time_to_remediate_days}d` : "—"}
                sub={isHe ? "זמן ממוצע לתיקון" : "avg days to remediate"}
              />
              <MetricCard
                label={isHe ? "ממצאים שנפתרו" : "Findings resolved"}
                value={String(data.summary.findings_resolved)}
                color={_GREEN}
              />
              <MetricCard
                label={isHe ? "ממצאים חדשים" : "New findings"}
                value={String(data.summary.findings_new)}
                color={data.summary.findings_new > 0 ? _ORANGE : _MUTED}
              />
            </div>

            {/* Score chart */}
            <div style={{
              background: "rgba(12,17,32,0.8)", border: "1px solid #1a2236",
              borderRadius: "12px", padding: "16px 20px", marginBottom: "16px",
            }}>
              <div style={{ color: "#94a3b8", fontWeight: 700, fontSize: "0.85rem", marginBottom: "10px" }}>
                {isHe ? "ציון אבטחה לאורך זמן" : "Overall Score Over Time"}
              </div>
              <ScoreLineChart points={data.data_points} height={140} />
              <div style={{ display: "flex", gap: "16px", marginTop: "8px", flexWrap: "wrap" }}>
                {Object.entries(GRADE_COLOR).map(([g, c]) => (
                  <div key={g} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                    <div style={{ width: 10, height: 10, borderRadius: 2, background: c }} />
                    <span style={{ color: _MUTED, fontSize: "0.7rem" }}>Grade {g}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Findings chart */}
            <div style={{
              background: "rgba(12,17,32,0.8)", border: "1px solid #1a2236",
              borderRadius: "12px", padding: "16px 20px", marginBottom: "16px",
            }}>
              <div style={{ color: "#94a3b8", fontWeight: 700, fontSize: "0.85rem", marginBottom: "10px" }}>
                {isHe ? "ממצאים לאורך זמן" : "Findings Over Time"}
              </div>
              <FindingsBarChart points={data.data_points} height={90} />
              <div style={{ display: "flex", gap: "14px", marginTop: "8px", flexWrap: "wrap" }}>
                {[["Critical", _RED], ["High", _ORANGE], ["Medium", _YELLOW], ["Low", _GREEN]].map(([label, col]) => (
                  <div key={label} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                    <div style={{ width: 10, height: 10, borderRadius: 2, background: col }} />
                    <span style={{ color: _MUTED, fontSize: "0.7rem" }}>{label}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Category health */}
            {Object.keys(categoryList).length > 0 && (
              <div style={{
                background: "rgba(12,17,32,0.8)", border: "1px solid #1a2236",
                borderRadius: "12px", padding: "16px 20px", marginBottom: "16px",
              }}>
                <div style={{ color: "#94a3b8", fontWeight: 700, fontSize: "0.85rem", marginBottom: "12px" }}>
                  {isHe ? "בריאות לפי קטגוריה" : "Category Health"}
                  {data.summary.most_improved_category && (
                    <span style={{ color: _GREEN, fontSize: "0.72rem", marginLeft: "8px" }}>
                      ↑ Best: {data.summary.most_improved_category}
                    </span>
                  )}
                  {data.summary.most_degraded_category && (
                    <span style={{ color: _RED, fontSize: "0.72rem", marginLeft: "8px" }}>
                      ↓ Alert: {data.summary.most_degraded_category}
                    </span>
                  )}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: "6px" }}>
                  {Object.entries(categoryList).map(([cat, score]) => {
                    const firstScore = data.data_points[0]?.category_scores?.[cat];
                    const delta = firstScore != null ? score - firstScore : 0;
                    const trend = delta > 5 ? "improving" : delta < -5 ? "degrading" : "stable";
                    return (
                      <CategoryRow key={cat} name={cat} score={Math.round(score)} trend={trend} delta={Math.round(delta)} />
                    );
                  })}
                </div>
              </div>
            )}

            {/* Export button */}
            <div style={{ textAlign: "center", paddingBottom: "16px" }}>
              <button
                onClick={() => window.print()}
                style={{
                  padding: "10px 24px", borderRadius: "9px",
                  border: `1px solid ${_CYAN}44`, background: `${_CYAN}0a`,
                  color: _CYAN, fontSize: "0.85rem", fontWeight: 700, cursor: "pointer",
                  transition: "all 200ms",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = `${_CYAN}18`; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = `${_CYAN}0a`; }}
              >
                📄 {isHe ? "ייצוא דוח מגמות (PDF)" : "Export Trend Report (PDF)"}
              </button>
            </div>
          </>
        )}
      </main>
    </>
  );
}

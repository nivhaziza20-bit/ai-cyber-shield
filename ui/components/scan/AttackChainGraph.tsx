"use client";

import { useState } from "react";
import { useLang } from "@/contexts/LangContext";

// ── Types ──────────────────────────────────────────────────────────────────

interface ChainNode {
  finding_id: string;
  title: string;
  severity: string;
  tool: string;
  role: "prerequisite" | "amplifier";
}

interface AttackChain {
  id: string;
  name: string;
  description: string;
  severity: string;
  cvss: number;
  impact: string;
  remediation: string;
  detection_method: string;
  prerequisites: ChainNode[];
  amplifiers: ChainNode[];
}

interface AttackChainsListResponse {
  scan_id: string;
  chains: AttackChain[];
  total: number;
  critical: number;
  high: number;
}

interface Props {
  data: AttackChainsListResponse;
  onFindingClick?: (findingId: string) => void;
}

// ── Severity helpers ───────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  INFO: "#6366f1",
};

const SEV_BG: Record<string, string> = {
  CRITICAL: "rgba(239,68,68,0.15)",
  HIGH: "rgba(249,115,22,0.15)",
  MEDIUM: "rgba(234,179,8,0.15)",
  LOW: "rgba(34,197,94,0.15)",
  INFO: "rgba(99,102,241,0.15)",
};

function sevColor(sev: string) {
  return SEV_COLORS[sev?.toUpperCase()] ?? "#6b7280";
}
function sevBg(sev: string) {
  return SEV_BG[sev?.toUpperCase()] ?? "rgba(107,114,128,0.15)";
}

// ── SVG directed-graph for a single chain ─────────────────────────────────

const NODE_W = 140;
const NODE_H = 56;
const NODE_GAP_X = 40;
const NODE_GAP_Y = 16;
const RESULT_X = 360;

function ChainSVG({
  chain,
  onFindingClick,
}: {
  chain: AttackChain;
  onFindingClick?: (id: string) => void;
}) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const prereqs = chain.prerequisites;
  const amps = chain.amplifiers;
  const allNodes = [...prereqs, ...amps];

  // Layout: prerequisites on left, amplifiers below them, result on right
  const prereqYStart = 20;
  const ampYStart = prereqs.length * (NODE_H + NODE_GAP_Y) + prereqYStart + 24;

  const svgH =
    Math.max(
      allNodes.length * (NODE_H + NODE_GAP_Y) + 40,
      NODE_H + 80
    );
  const svgW = RESULT_X + NODE_W + 60;

  // Result node position: center vertically
  const resultY = svgH / 2 - NODE_H / 2;

  function nodeY(index: number, isAmp: boolean) {
    return isAmp
      ? ampYStart + index * (NODE_H + NODE_GAP_Y)
      : prereqYStart + index * (NODE_H + NODE_GAP_Y);
  }

  return (
    <svg
      width="100%"
      viewBox={`0 0 ${svgW} ${svgH}`}
      style={{ overflow: "visible", minHeight: 120 }}
    >
      <defs>
        <marker
          id={`arrow-${chain.id}`}
          markerWidth="8"
          markerHeight="8"
          refX="7"
          refY="3"
          orient="auto"
        >
          <path d="M0,0 L0,6 L8,3 z" fill="#4b5563" />
        </marker>
        <marker
          id={`arrow-amp-${chain.id}`}
          markerWidth="8"
          markerHeight="8"
          refX="7"
          refY="3"
          orient="auto"
        >
          <path d="M0,0 L0,6 L8,3 z" fill="#6366f1" />
        </marker>
      </defs>

      {/* Prerequisite nodes */}
      {prereqs.map((node, i) => {
        const y = nodeY(i, false);
        const cx = NODE_W / 2;
        const cy = y + NODE_H / 2;
        const isHovered = hoveredId === node.finding_id;
        return (
          <g key={node.finding_id}>
            {/* Arrow to result */}
            <line
              x1={NODE_W}
              y1={cy}
              x2={RESULT_X}
              y2={resultY + NODE_H / 2}
              stroke="#4b5563"
              strokeWidth="1.5"
              markerEnd={`url(#arrow-${chain.id})`}
            />
            {/* Node rect */}
            <rect
              x={2}
              y={y}
              width={NODE_W - 4}
              height={NODE_H}
              rx={6}
              fill={isHovered ? sevBg(node.severity) : "#1e293b"}
              stroke={sevColor(node.severity)}
              strokeWidth={isHovered ? 2 : 1.5}
              style={{ cursor: onFindingClick ? "pointer" : "default" }}
              onClick={() => onFindingClick?.(node.finding_id)}
              onMouseEnter={() => setHoveredId(node.finding_id)}
              onMouseLeave={() => setHoveredId(null)}
            />
            <text
              x={cx}
              y={y + 20}
              textAnchor="middle"
              fill="#e2e8f0"
              fontSize="10"
              fontFamily="Inter, sans-serif"
              fontWeight="500"
              style={{ pointerEvents: "none" }}
            >
              {node.title.length > 18
                ? node.title.slice(0, 17) + "…"
                : node.title}
            </text>
            <text
              x={cx}
              y={y + 34}
              textAnchor="middle"
              fill={sevColor(node.severity)}
              fontSize="9"
              fontFamily="Inter, sans-serif"
              style={{ pointerEvents: "none" }}
            >
              {node.severity}
            </text>
            <text
              x={cx}
              y={y + 46}
              textAnchor="middle"
              fill="#6b7280"
              fontSize="8"
              fontFamily="JetBrains Mono, monospace"
              style={{ pointerEvents: "none" }}
            >
              {node.tool}
            </text>
          </g>
        );
      })}

      {/* Amplifier nodes (dashed connections) */}
      {amps.map((node, i) => {
        const y = nodeY(i, true);
        const cx = NODE_W / 2;
        const cy = y + NODE_H / 2;
        const isHovered = hoveredId === node.finding_id;
        return (
          <g key={node.finding_id}>
            {/* Dashed arrow to result */}
            <line
              x1={NODE_W}
              y1={cy}
              x2={RESULT_X}
              y2={resultY + NODE_H / 2}
              stroke="#6366f1"
              strokeWidth="1.5"
              strokeDasharray="5,3"
              markerEnd={`url(#arrow-amp-${chain.id})`}
            />
            {/* Node rect */}
            <rect
              x={2}
              y={y}
              width={NODE_W - 4}
              height={NODE_H}
              rx={6}
              fill={isHovered ? sevBg(node.severity) : "#1e293b"}
              stroke={sevColor(node.severity)}
              strokeWidth={isHovered ? 2 : 1.5}
              strokeDasharray="4,2"
              style={{ cursor: onFindingClick ? "pointer" : "default" }}
              onClick={() => onFindingClick?.(node.finding_id)}
              onMouseEnter={() => setHoveredId(node.finding_id)}
              onMouseLeave={() => setHoveredId(null)}
            />
            <text
              x={cx}
              y={y + 18}
              textAnchor="middle"
              fill="#e2e8f0"
              fontSize="10"
              fontFamily="Inter, sans-serif"
              fontWeight="500"
              style={{ pointerEvents: "none" }}
            >
              {node.title.length > 18
                ? node.title.slice(0, 17) + "…"
                : node.title}
            </text>
            <text
              x={cx}
              y={y + 30}
              textAnchor="middle"
              fill={sevColor(node.severity)}
              fontSize="9"
              fontFamily="Inter, sans-serif"
              style={{ pointerEvents: "none" }}
            >
              {node.severity}
            </text>
            <text
              x={cx}
              y={y + 42}
              textAnchor="middle"
              fill="#6366f1"
              fontSize="8"
              fontFamily="Inter, sans-serif"
              style={{ pointerEvents: "none" }}
            >
              amplifies
            </text>
          </g>
        );
      })}

      {/* Result chain node */}
      <rect
        x={RESULT_X}
        y={resultY}
        width={NODE_W}
        height={NODE_H}
        rx={8}
        fill={sevBg(chain.severity)}
        stroke={sevColor(chain.severity)}
        strokeWidth={2.5}
      />
      <text
        x={RESULT_X + NODE_W / 2}
        y={resultY + 18}
        textAnchor="middle"
        fill="#e2e8f0"
        fontSize="11"
        fontFamily="Inter, sans-serif"
        fontWeight="700"
        style={{ pointerEvents: "none" }}
      >
        {chain.name.length > 18 ? chain.name.slice(0, 17) + "…" : chain.name}
      </text>
      <text
        x={RESULT_X + NODE_W / 2}
        y={resultY + 32}
        textAnchor="middle"
        fill={sevColor(chain.severity)}
        fontSize="10"
        fontFamily="Inter, sans-serif"
        fontWeight="600"
        style={{ pointerEvents: "none" }}
      >
        {chain.severity}
      </text>
      <text
        x={RESULT_X + NODE_W / 2}
        y={resultY + 46}
        textAnchor="middle"
        fill="#94a3b8"
        fontSize="9"
        fontFamily="JetBrains Mono, monospace"
        style={{ pointerEvents: "none" }}
      >
        CVSS {chain.cvss.toFixed(1)}
      </text>
    </svg>
  );
}

// ── Per-chain card ─────────────────────────────────────────────────────────

function ChainCard({
  chain,
  isHe,
  onFindingClick,
}: {
  chain: AttackChain;
  isHe: boolean;
  onFindingClick?: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      style={{
        background: "#111827",
        border: `1px solid ${sevColor(chain.severity)}`,
        borderRadius: 10,
        marginBottom: 16,
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded((p) => !p)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "14px 18px",
          background: "transparent",
          border: "none",
          cursor: "pointer",
          textAlign: isHe ? "right" : "left",
          direction: isHe ? "rtl" : "ltr",
        }}
      >
        <span style={{ fontSize: 18 }}>⚡</span>
        <span
          style={{
            flex: 1,
            color: "#e2e8f0",
            fontWeight: 600,
            fontSize: 15,
            fontFamily: "Inter, sans-serif",
          }}
        >
          {chain.name}
        </span>
        <span
          style={{
            padding: "2px 8px",
            borderRadius: 4,
            background: sevBg(chain.severity),
            color: sevColor(chain.severity),
            fontSize: 11,
            fontWeight: 700,
            fontFamily: "Inter, sans-serif",
          }}
        >
          {chain.severity}
        </span>
        <span
          style={{
            color: "#94a3b8",
            fontSize: 12,
            fontFamily: "JetBrains Mono, monospace",
          }}
        >
          CVSS {chain.cvss.toFixed(1)}
        </span>
        <span style={{ color: "#6b7280", fontSize: 14 }}>
          {expanded ? "▲" : "▼"}
        </span>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: "0 18px 18px" }}>
          {/* Graph */}
          <div style={{ marginBottom: 16 }}>
            <ChainSVG chain={chain} onFindingClick={onFindingClick} />
          </div>

          {/* Legend */}
          <div
            style={{
              display: "flex",
              gap: 20,
              marginBottom: 14,
              fontSize: 11,
              color: "#94a3b8",
              fontFamily: "Inter, sans-serif",
            }}
          >
            <span>
              <span style={{ borderBottom: "2px solid #4b5563", marginRight: 4 }}>────</span>
              {isHe ? "תנאי מוקדם" : "Prerequisite"}
            </span>
            <span>
              <span
                style={{
                  borderBottom: "2px dashed #6366f1",
                  marginRight: 4,
                  color: "#6366f1",
                }}
              >
                ─ ─ ─
              </span>
              {isHe ? "מגביר (אופציונלי)" : "Amplifier (optional)"}
            </span>
          </div>

          {/* Impact */}
          <div style={{ marginBottom: 10 }}>
            <span
              style={{
                color: "#94a3b8",
                fontSize: 12,
                fontFamily: "Inter, sans-serif",
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: 1,
              }}
            >
              {isHe ? "השפעה" : "Impact"}
            </span>
            <p
              style={{
                color: "#e2e8f0",
                fontSize: 13,
                marginTop: 4,
                fontFamily: "Inter, sans-serif",
                lineHeight: 1.5,
              }}
            >
              {chain.impact}
            </p>
          </div>

          {/* Remediation */}
          {chain.remediation && (
            <div style={{ marginBottom: 10 }}>
              <span
                style={{
                  color: "#94a3b8",
                  fontSize: 12,
                  fontFamily: "Inter, sans-serif",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: 1,
                }}
              >
                {isHe ? "תיקון" : "Remediation"}
              </span>
              <p
                style={{
                  color: "#e2e8f0",
                  fontSize: 13,
                  marginTop: 4,
                  fontFamily: "Inter, sans-serif",
                  lineHeight: 1.5,
                }}
              >
                {chain.remediation}
              </p>
            </div>
          )}

          {/* Fix-this-chain hint */}
          <div
            style={{
              background: "rgba(0,212,255,0.06)",
              border: "1px solid rgba(0,212,255,0.2)",
              borderRadius: 6,
              padding: "10px 14px",
              fontSize: 12,
              color: "#00d4ff",
              fontFamily: "Inter, sans-serif",
            }}
          >
            💡{" "}
            {isHe
              ? "תיקון כל אחד מהתנאים המוקדמים ישבור את שרשרת המתקפה."
              : "Fixing any single prerequisite breaks this attack chain."}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export default function AttackChainGraph({ data, onFindingClick }: Props) {
  const { lang } = useLang();
  const isHe = lang === "he";

  if (!data || data.chains.length === 0) {
    return (
      <div
        style={{
          padding: "40px 20px",
          textAlign: "center",
          color: "#6b7280",
          fontFamily: "Inter, sans-serif",
        }}
      >
        <div style={{ fontSize: 32, marginBottom: 12 }}>✅</div>
        <div style={{ fontSize: 15, fontWeight: 600, color: "#94a3b8" }}>
          {isHe
            ? "לא זוהו שרשראות מתקפה"
            : "No attack chains detected"}
        </div>
        <div style={{ fontSize: 13, marginTop: 6 }}>
          {isHe
            ? "הממצאים הנוכחיים לא נראה שמתחברים לנתיבי ניצול ידועים."
            : "Current findings don't appear to combine into known exploitation paths."}
        </div>
      </div>
    );
  }

  const criticalCount = data.chains.filter(
    (c) => c.severity === "CRITICAL"
  ).length;
  const highCount = data.chains.filter((c) => c.severity === "HIGH").length;

  return (
    <div style={{ direction: isHe ? "rtl" : "ltr" }}>
      {/* Summary bar */}
      <div
        style={{
          display: "flex",
          gap: 16,
          marginBottom: 20,
          flexWrap: "wrap",
        }}
      >
        <div
          style={{
            padding: "8px 16px",
            borderRadius: 8,
            background: "#1e293b",
            fontSize: 13,
            color: "#e2e8f0",
            fontFamily: "Inter, sans-serif",
          }}
        >
          {isHe ? "סה״כ שרשראות:" : "Total chains:"}
          <span style={{ fontWeight: 700, marginLeft: 6 }}>{data.total}</span>
        </div>
        {criticalCount > 0 && (
          <div
            style={{
              padding: "8px 16px",
              borderRadius: 8,
              background: "rgba(239,68,68,0.12)",
              border: "1px solid rgba(239,68,68,0.3)",
              fontSize: 13,
              color: "#ef4444",
              fontFamily: "Inter, sans-serif",
              fontWeight: 600,
            }}
          >
            🔴 {criticalCount} {isHe ? "קריטי" : "Critical"}
          </div>
        )}
        {highCount > 0 && (
          <div
            style={{
              padding: "8px 16px",
              borderRadius: 8,
              background: "rgba(249,115,22,0.12)",
              border: "1px solid rgba(249,115,22,0.3)",
              fontSize: 13,
              color: "#f97316",
              fontFamily: "Inter, sans-serif",
              fontWeight: 600,
            }}
          >
            🟠 {highCount} {isHe ? "גבוה" : "High"}
          </div>
        )}
        <div
          style={{
            fontSize: 12,
            color: "#6b7280",
            fontFamily: "Inter, sans-serif",
            alignSelf: "center",
          }}
        >
          {isHe
            ? "לחץ על ממצא כדי לקפוץ לטבלת הממצאים"
            : "Click a finding node to jump to the findings table"}
        </div>
      </div>

      {/* Chain cards */}
      {data.chains.map((chain) => (
        <ChainCard
          key={chain.id}
          chain={chain}
          isHe={isHe}
          onFindingClick={onFindingClick}
        />
      ))}
    </div>
  );
}

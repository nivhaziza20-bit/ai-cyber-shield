"use client";

import { useEffect, useState } from "react";
import type { ScanProgress, ToolStatus } from "@/lib/useScanProgress";

const TOOL_LABELS: Record<string, string> = {
  ssl:                "SSL/TLS Analysis",
  headers:            "Security Headers",
  html:               "HTML & Content Scan",
  tech:               "Technology Fingerprint",
  crawler:            "Web Crawler",
  cors_csp:           "CORS & CSP Check",
  dns:                "DNS Security (SPF/DMARC)",
  exposure:           "Sensitive File Exposure",
  waf:                "WAF Detection",
  cert_transparency:  "Certificate Transparency",
  hsts_preload:       "HSTS Preload Check",
  open_redirect:      "Open Redirect Scan",
  api_spec:           "API Spec Exposure",
  port_scanner:       "Port Scanner",
  cookie_security:    "Cookie Security Audit",
  deep_js_crawler:    "Deep JS Crawler",
  subdomain_takeover: "Subdomain Takeover",
};

function ToolRow({ tool }: { tool: ToolStatus }) {
  const label = TOOL_LABELS[tool.name] ?? tool.name;

  const icon =
    tool.status === "completed" ? "✅"
    : tool.status === "running"  ? "🔄"
    : tool.status === "failed"   ? "❌"
    : "⏳";

  const textColor =
    tool.status === "completed" ? "text-green-400"
    : tool.status === "running"  ? "text-blue-400"
    : tool.status === "failed"   ? "text-red-400"
    : "text-gray-500";

  const right =
    tool.status === "running"   ? <span className="text-blue-400 animate-pulse text-xs">scanning…</span>
    : tool.status === "completed"
      ? (
        <span className="flex items-center gap-2">
          {tool.durationMs != null && (
            <span className="text-gray-400 text-xs">
              {(tool.durationMs / 1000).toFixed(1)}s
            </span>
          )}
          {tool.score != null && (
            <span className="bg-gray-700 text-gray-200 text-xs px-1.5 py-0.5 rounded">
              {tool.score}
            </span>
          )}
        </span>
      )
    : tool.status === "failed"
      ? <span className="text-red-400 text-xs truncate max-w-[180px]">{tool.error ?? "failed"}</span>
    : <span className="text-gray-600 text-xs">queued</span>;

  return (
    <div className="flex items-center justify-between py-1.5 px-3 rounded hover:bg-white/5 transition-colors">
      <span className={`flex items-center gap-2 text-sm ${textColor}`}>
        <span>{icon}</span>
        <span>{label}</span>
      </span>
      <span>{right}</span>
    </div>
  );
}

interface Props {
  scanId: string;
  url: string;
  progress: ScanProgress;
  elapsedSeconds: number;
}

/**
 * Real-time scan progress panel.
 * Render while scanning; parent switches to results when progress.isComplete.
 */
export default function ScanProgressPanel({
  scanId,
  url,
  progress,
  elapsedSeconds,
}: Props) {
  const barPct = Math.min(progress.percent, 100);

  return (
    <div
      className="rounded-xl border border-[#1e293b] bg-[#111827] text-[#e2e8f0] p-5 shadow-xl w-full max-w-2xl mx-auto"
      role="status"
      aria-live="polite"
      aria-label={`Scanning ${url}: ${barPct}% complete`}
    >
      {/* Header */}
      <div className="mb-4">
        <p className="text-[#94a3b8] text-xs font-mono mb-1 truncate">{url}</p>
        <h2 className="text-[#00d4ff] font-semibold text-base">
          🔍 Security Scan In Progress
        </h2>
      </div>

      {/* Tool list */}
      <div className="space-y-0.5 mb-4">
        {progress.tools.map((tool) => (
          <ToolRow key={tool.name} tool={tool} />
        ))}
      </div>

      {/* Progress bar */}
      <div className="mt-3">
        <div className="flex justify-between text-xs text-[#94a3b8] mb-1">
          <span>{progress.completedCount}/{progress.totalCount} tools</span>
          <span>{barPct}%</span>
        </div>
        <div className="h-2 w-full bg-gray-800 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${barPct}%`,
              background: "linear-gradient(90deg, #3b82f6, #06b6d4)",
            }}
          />
        </div>
      </div>

      {/* Footer */}
      <div className="mt-3 flex items-center justify-between text-xs text-[#94a3b8]">
        <span>Elapsed: {elapsedSeconds}s</span>
        {progress.error && (
          <span className="text-red-400">{progress.error}</span>
        )}
      </div>
    </div>
  );
}

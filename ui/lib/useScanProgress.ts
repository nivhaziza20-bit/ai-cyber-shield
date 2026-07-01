"use client";

import { useCallback, useEffect, useRef, useState } from "react";

const ALL_TOOLS = [
  "ssl",
  "headers",
  "html",
  "tech",
  "crawler",
  "cors_csp",
  "dns",
  "exposure",
  "waf",
  "cert_transparency",
  "hsts_preload",
  "open_redirect",
  "api_spec",
  "port_scanner",
  "cookie_security",
  "deep_js_crawler",
  "subdomain_takeover",
] as const;

export type ToolName = (typeof ALL_TOOLS)[number];

export interface ToolStatus {
  name: string;
  status: "queued" | "running" | "completed" | "failed";
  score?: number;
  durationMs?: number;
  findingsCount?: number;
  error?: string;
}

export interface ScanProgress {
  tools: ToolStatus[];
  completedCount: number;
  totalCount: number;
  percent: number;
  overallResult?: { score: number; grade: string; findingsCount: number };
  isComplete: boolean;
  error?: string;
}

const DEFAULT_TOOLS: ToolStatus[] = ALL_TOOLS.map((name) => ({
  name,
  status: "queued",
}));

/**
 * Custom hook: connect to the SSE scan progress endpoint and return live status.
 *
 * Usage:
 *   const progress = useScanProgress(scanId);
 *   // progress.tools, progress.percent, progress.isComplete
 *
 * @param scanId   UUID returned by POST /api/v1/scans. Pass null to disable.
 * @param sseBase  Base path for the SSE URL. Default uses Next.js rewrite proxy.
 */
export function useScanProgress(
  scanId: string | null,
  sseBase = "/api/proxy"
): ScanProgress {
  const [tools, setTools] = useState<ToolStatus[]>(DEFAULT_TOOLS);
  const [completedCount, setCompletedCount] = useState(0);
  const [percent, setPercent] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const [overallResult, setOverallResult] =
    useState<ScanProgress["overallResult"]>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);

  const esRef = useRef<EventSource | null>(null);

  const reset = useCallback(() => {
    setTools(DEFAULT_TOOLS);
    setCompletedCount(0);
    setPercent(0);
    setIsComplete(false);
    setOverallResult(undefined);
    setError(undefined);
  }, []);

  useEffect(() => {
    if (!scanId) return;

    reset();

    const url = `${sseBase}/api/v1/scans/${scanId}/events`;
    const es = new EventSource(url);
    esRef.current = es;

    const updateTool = (name: string, patch: Partial<ToolStatus>) => {
      setTools((prev) =>
        prev.map((t) => (t.name === name ? { ...t, ...patch } : t))
      );
    };

    es.addEventListener("tool_started", (e) => {
      const data = JSON.parse((e as MessageEvent).data);
      updateTool(data.tool_name, { status: "running" });
    });

    es.addEventListener("tool_completed", (e) => {
      const data = JSON.parse((e as MessageEvent).data);
      updateTool(data.tool_name, {
        status: "completed",
        score: data.score ?? undefined,
        durationMs: data.duration_ms ?? undefined,
        findingsCount: data.findings_count ?? undefined,
      });
    });

    es.addEventListener("tool_failed", (e) => {
      const data = JSON.parse((e as MessageEvent).data);
      updateTool(data.tool_name, {
        status: "failed",
        error: data.error,
        durationMs: data.duration_ms ?? undefined,
      });
    });

    es.addEventListener("scan_progress", (e) => {
      const data = JSON.parse((e as MessageEvent).data);
      setCompletedCount(data.completed ?? 0);
      setPercent(data.percent ?? 0);
    });

    es.addEventListener("scan_completed", (e) => {
      const data = JSON.parse((e as MessageEvent).data);
      setOverallResult({
        score: data.overall_score,
        grade: data.grade,
        findingsCount: data.findings_count,
      });
      setIsComplete(true);
      es.close();
    });

    es.addEventListener("scan_failed", (e) => {
      const data = JSON.parse((e as MessageEvent).data);
      setError(data.error ?? "Scan failed");
      setIsComplete(true);
      es.close();
    });

    es.onerror = () => {
      // Don't set error on transient reconnects — EventSource auto-retries
      if (es.readyState === EventSource.CLOSED) {
        setError("Connection to scan progress stream lost");
        setIsComplete(true);
      }
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [scanId, sseBase, reset]);

  return {
    tools,
    completedCount,
    totalCount: ALL_TOOLS.length,
    percent,
    isComplete,
    overallResult,
    error,
  };
}

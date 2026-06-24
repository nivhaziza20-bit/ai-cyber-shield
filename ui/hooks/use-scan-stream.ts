"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { Finding, ScanEvent, ScanSummary } from "@/types";

export type StreamStatus = "idle" | "connecting" | "streaming" | "completed" | "error";

export interface ScanStreamState {
  status:   StreamStatus;
  findings: Finding[];
  summary:  ScanSummary | null;
  progress: { tool: string; pct: number } | null;
  error:    string | null;
  eventCount: number;
}

/**
 * Real-time SSE hook for scan events.
 *
 * Connects to /api/backend/api/v1/scans/{scanId}/stream
 * Reconnects automatically on transient errors (exponential backoff, max 30s).
 * Aborts cleanly on unmount or manual stop().
 */
export function useScanStream(scanId: string | null) {
  const [state, setState] = useState<ScanStreamState>({
    status:     "idle",
    findings:   [],
    summary:    null,
    progress:   null,
    error:      null,
    eventCount: 0,
  });

  const esRef    = useRef<EventSource | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryCountRef = useRef(0);

  const connect = useCallback(() => {
    if (!scanId) return;

    // Clean up any existing connection
    esRef.current?.close();
    if (retryRef.current) clearTimeout(retryRef.current);

    setState((prev) => ({ ...prev, status: "connecting", error: null }));

    const url = `/api/backend/api/v1/scans/${scanId}/stream`;
    const es  = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      retryCountRef.current = 0;
      setState((prev) => ({ ...prev, status: "streaming" }));
    };

    es.onmessage = (event: MessageEvent<string>) => {
      try {
        const parsed: ScanEvent = JSON.parse(event.data);
        setState((prev) => {
          switch (parsed.type) {
            case "finding":
              return {
                ...prev,
                findings:   [...prev.findings, parsed.data],
                eventCount: prev.eventCount + 1,
              };
            case "progress":
              return { ...prev, progress: parsed.data, eventCount: prev.eventCount + 1 };
            case "completed":
              return {
                ...prev,
                status:     "completed",
                summary:    parsed.data.summary,
                eventCount: prev.eventCount + 1,
              };
            case "error":
              return { ...prev, status: "error", error: parsed.data.message };
            default:
              return prev;
          }
        });

        if (parsed.type === "completed") {
          es.close();
        }
      } catch {
        // Ignore malformed events
      }
    };

    es.onerror = () => {
      es.close();
      setState((prev) => {
        if (prev.status === "completed") return prev;
        const delay = Math.min(1000 * 2 ** retryCountRef.current, 30_000);
        retryCountRef.current += 1;
        retryRef.current = setTimeout(connect, delay);
        return { ...prev, status: "connecting", error: `Reconnecting in ${delay / 1000}s…` };
      });
    };
  }, [scanId]);

  const stop = useCallback(() => {
    esRef.current?.close();
    if (retryRef.current) clearTimeout(retryRef.current);
    setState((prev) => ({ ...prev, status: "idle" }));
  }, []);

  useEffect(() => {
    if (scanId) connect();
    return () => {
      esRef.current?.close();
      if (retryRef.current) clearTimeout(retryRef.current);
    };
  }, [scanId, connect]);

  return { ...state, connect, stop };
}

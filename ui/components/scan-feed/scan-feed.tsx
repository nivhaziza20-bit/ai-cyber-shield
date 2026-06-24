"use client";

import { useRef, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Radio, Square, Wifi } from "lucide-react";
import { cn, severityColor, truncateUrl } from "@/lib/utils";
import type { Finding } from "@/types";
import type { StreamStatus } from "@/hooks/use-scan-stream";

interface ScanFeedProps {
  scanId:     string;
  status:     StreamStatus;
  findings:   Finding[];
  progress:   { tool: string; pct: number } | null;
  error:      string | null;
  eventCount: number;
  onStop:     () => void;
}

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function ScanFeed({
  scanId, status, findings, progress, error, eventCount, onStop,
}: ScanFeedProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to new findings
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [findings.length]);

  const isLive = status === "streaming";

  return (
    <Card className="flex flex-col h-full">
      <CardHeader className="flex-row items-center gap-3 pb-3">
        {/* Live indicator */}
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "h-2 w-2 rounded-full",
              isLive ? "bg-primary animate-live-pulse" :
              status === "completed" ? "bg-low" :
              status === "error"     ? "bg-critical" : "bg-muted-foreground"
            )}
          />
          <span className="text-xs font-medium uppercase tracking-widest text-muted-foreground">
            {isLive ? "LIVE" : status.toUpperCase()}
          </span>
        </div>

        <CardTitle className="flex-1 text-sm">
          Scan Feed — <span className="font-mono text-xs text-muted-foreground">{scanId}</span>
        </CardTitle>

        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground tabular-nums">
            {eventCount} events
          </span>
          {isLive && (
            <Button variant="ghost" size="sm" onClick={onStop} className="h-7 gap-1.5 text-xs">
              <Square className="h-3 w-3" />
              Stop
            </Button>
          )}
        </div>
      </CardHeader>

      {/* Tool progress */}
      {progress && isLive && (
        <div className="px-6 pb-3">
          <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
            <span className="font-mono">{progress.tool}</span>
            <span>{progress.pct.toFixed(0)}%</span>
          </div>
          <Progress value={progress.pct} className="h-1.5" />
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div className="mx-6 mb-3 rounded-md bg-critical/10 border border-critical/20 px-3 py-2 text-xs text-critical">
          {error}
        </div>
      )}

      {/* Feed */}
      <CardContent className="flex-1 overflow-hidden p-0">
        <ScrollArea className="h-full">
          <div className="divide-y">
            {findings.map((f) => (
              <FeedRow key={f.id} finding={f} />
            ))}
            {findings.length === 0 && (
              <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
                <Wifi className="h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  {isLive ? "Waiting for findings…" : "No findings yet"}
                </p>
              </div>
            )}
          </div>
          <div ref={bottomRef} />
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function FeedRow({ finding }: { finding: Finding }) {
  const sevCls = severityColor(finding.severity);

  return (
    <div className="flex items-start gap-4 px-6 py-3 hover:bg-accent/30 transition-colors">
      {/* Severity dot */}
      <span
        className={cn(
          "mt-1.5 h-2 w-2 shrink-0 rounded-full",
          finding.severity === "CRITICAL" ? "bg-critical" :
          finding.severity === "HIGH"     ? "bg-high" :
          finding.severity === "MEDIUM"   ? "bg-medium" :
          finding.severity === "LOW"      ? "bg-low" : "bg-info"
        )}
      />

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={cn("text-xs font-bold uppercase", sevCls.replace("severity-", "text-"))}>
            {finding.severity}
          </span>
          <span className="text-sm font-medium truncate">{finding.title}</span>
        </div>
        <p className="text-xs text-muted-foreground font-mono mt-0.5 truncate">
          {truncateUrl(finding.endpoint, 60)}
        </p>
      </div>

      {/* Meta */}
      <div className="flex items-center gap-2 shrink-0">
        <span className="text-xs font-black tabular-nums" style={{
          color: finding.cvss_score >= 9 ? "var(--color-critical)" :
                 finding.cvss_score >= 7 ? "var(--color-high)"     :
                 finding.cvss_score >= 4 ? "var(--color-medium)"   : "var(--color-low)"
        }}>
          {finding.cvss_score.toFixed(1)}
        </span>
        <Badge variant="outline" className="text-[10px] font-mono h-5">
          {finding.owasp_code}
        </Badge>
      </div>
    </div>
  );
}

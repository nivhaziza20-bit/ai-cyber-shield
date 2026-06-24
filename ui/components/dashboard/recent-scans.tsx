"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { cn, formatRelative } from "@/lib/utils";
import type { Scan } from "@/types";

const DEMO_SCANS: Scan[] = [
  {
    id: "s-001",
    target_url: "https://app.example.com",
    status: "completed",
    started_at:  new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    finished_at: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
    summary: { total: 31, critical: 3, high: 8, medium: 15, low: 5, info: 0, risk_score: 72, grade: "C" },
    profile: "prod-admin",
  },
  {
    id: "s-002",
    target_url: "https://api.example.com",
    status: "running",
    started_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    finished_at: null,
    summary: { total: 4, critical: 0, high: 2, medium: 2, low: 0, info: 0, risk_score: 24, grade: "B" },
    profile: "api-bearer",
  },
  {
    id: "s-003",
    target_url: "https://staging.example.com",
    status: "completed",
    started_at:  new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    finished_at: new Date(Date.now() - 1000 * 60 * 110).toISOString(),
    summary: { total: 12, critical: 0, high: 1, medium: 5, low: 6, info: 0, risk_score: 18, grade: "B" },
    profile: null,
  },
];

const STATUS_STYLE: Record<Scan["status"], string> = {
  pending:   "bg-muted-foreground/20 text-muted-foreground",
  running:   "bg-primary/15 text-primary animate-live-pulse",
  completed: "bg-low/15 text-low",
  failed:    "bg-critical/15 text-critical",
};

export function RecentScans() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Recent Scans</CardTitle>
            <CardDescription>Latest scan runs across all assets</CardDescription>
          </div>
          <button className="text-xs text-primary hover:underline">View all →</button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="divide-y">
          {DEMO_SCANS.map((scan) => (
            <div
              key={scan.id}
              className="flex items-center gap-4 px-6 py-4 hover:bg-accent/50 transition-colors cursor-pointer"
            >
              {/* Status dot */}
              <span className={cn(
                "h-2 w-2 rounded-full shrink-0",
                scan.status === "running"   ? "bg-primary animate-live-pulse" :
                scan.status === "completed" ? "bg-low" :
                scan.status === "failed"    ? "bg-critical" : "bg-muted-foreground"
              )} />

              {/* Target */}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{scan.target_url}</p>
                <p className="text-xs text-muted-foreground">
                  {formatRelative(scan.started_at)}
                  {scan.profile && (
                    <span className="ml-2 font-mono text-primary">@{scan.profile}</span>
                  )}
                </p>
              </div>

              {/* Findings summary */}
              <div className="flex items-center gap-2 shrink-0">
                {scan.summary.critical > 0 && (
                  <span className="text-xs font-bold text-critical">
                    {scan.summary.critical} CRIT
                  </span>
                )}
                {scan.summary.high > 0 && (
                  <span className="text-xs font-semibold text-high">
                    {scan.summary.high} HIGH
                  </span>
                )}
                <span className="text-xs text-muted-foreground">
                  {scan.summary.total} total
                </span>
              </div>

              {/* Risk score */}
              <div className="w-20 shrink-0">
                <div className="flex items-center justify-between text-[10px] mb-1">
                  <span className="text-muted-foreground">Risk</span>
                  <span className="font-bold tabular-nums">{scan.summary.risk_score}</span>
                </div>
                <Progress value={scan.summary.risk_score} className="h-1" />
              </div>

              {/* Status badge */}
              <span className={cn(
                "shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium capitalize",
                STATUS_STYLE[scan.status]
              )}>
                {scan.status}
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

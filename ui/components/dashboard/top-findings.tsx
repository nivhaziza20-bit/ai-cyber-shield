"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, ChevronRight } from "lucide-react";
import { cn, severityColor, truncateUrl } from "@/lib/utils";
import type { Severity } from "@/types";

interface TopFinding {
  id:         string;
  title:      string;
  severity:   Severity;
  cvss:       number;
  endpoint:   string;
  owasp:      string;
}

const DEMO_FINDINGS: TopFinding[] = [
  { id: "f-001", title: "SQL Injection via search parameter",     severity: "CRITICAL", cvss: 9.8, endpoint: "https://app.example.com/api/v1/search", owasp: "A03" },
  { id: "f-002", title: "Authentication Bypass on admin route",   severity: "CRITICAL", cvss: 9.1, endpoint: "https://app.example.com/admin/panel",   owasp: "A01" },
  { id: "f-003", title: "SSRF via webhook URL parameter",         severity: "HIGH",     cvss: 8.3, endpoint: "https://app.example.com/api/webhook",   owasp: "A10" },
  { id: "f-004", title: "Stored XSS in comment field",            severity: "HIGH",     cvss: 7.6, endpoint: "https://app.example.com/api/comments",  owasp: "A03" },
  { id: "f-005", title: "Sensitive data in HTTP headers",         severity: "MEDIUM",   cvss: 5.3, endpoint: "https://app.example.com/login",         owasp: "A02" },
];

const SEVERITY_BADGE: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH:     "high",
  MEDIUM:   "medium",
  LOW:      "low",
  INFO:     "info",
};

export function TopFindings() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Top Findings</CardTitle>
            <CardDescription>Highest-risk open vulnerabilities</CardDescription>
          </div>
          <button className="flex items-center gap-1 text-xs text-primary hover:underline">
            View all <ChevronRight className="h-3 w-3" />
          </button>
        </div>
      </CardHeader>
      <CardContent className="space-y-1 p-0">
        {DEMO_FINDINGS.map((f, i) => (
          <div
            key={f.id}
            className="flex items-center gap-4 border-t px-6 py-3 hover:bg-accent/50 transition-colors cursor-pointer"
          >
            {/* Rank */}
            <span className="w-5 text-center text-xs font-bold text-muted-foreground tabular-nums">
              {i + 1}
            </span>

            {/* CVSS score */}
            <span
              className={cn(
                "w-9 text-center text-sm font-black tabular-nums",
                severityColor(f.severity).replace("severity-", "text-")
              )}
            >
              {f.cvss}
            </span>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{f.title}</p>
              <p className="text-xs text-muted-foreground truncate">{truncateUrl(f.endpoint, 52)}</p>
            </div>

            {/* Tags */}
            <div className="flex items-center gap-2 shrink-0">
              <Badge variant={SEVERITY_BADGE[f.severity]} className="text-[10px] uppercase">
                {f.severity}
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono">
                {f.owasp}
              </Badge>
            </div>

            <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

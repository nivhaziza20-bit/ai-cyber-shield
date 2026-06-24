"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

interface SeverityBreakdownProps {
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
}

export function SeverityBreakdown({ critical, high, medium, low }: SeverityBreakdownProps) {
  const total = critical + high + medium + low || 1;

  const rows = [
    { label: "Critical", count: critical, pct: (critical / total) * 100, cls: "bg-critical", text: "text-critical" },
    { label: "High",     count: high,     pct: (high     / total) * 100, cls: "bg-high",     text: "text-high"     },
    { label: "Medium",   count: medium,   pct: (medium   / total) * 100, cls: "bg-medium",   text: "text-medium"   },
    { label: "Low",      count: low,      pct: (low      / total) * 100, cls: "bg-low",      text: "text-low"      },
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">Severity Breakdown</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {rows.map((row) => (
          <div key={row.label} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className={`font-medium ${row.text}`}>{row.label}</span>
              <span className="tabular-nums text-muted-foreground">
                {row.count} <span className="opacity-50">({row.pct.toFixed(0)}%)</span>
              </span>
            </div>
            <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full rounded-full transition-all duration-500 ${row.cls}`}
                style={{ width: `${row.pct}%` }}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

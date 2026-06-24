"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const FRAMEWORKS = [
  { name: "PCI-DSS v4.0",    pass: 0.74, readiness: "At Risk"       },
  { name: "SOC 2",           pass: 0.82, readiness: "Compliant"     },
  { name: "ISO 27001:2022",  pass: 0.61, readiness: "Non-Compliant" },
  { name: "NIST CSF 2.0",    pass: 0.78, readiness: "At Risk"       },
];

const READINESS_STYLE: Record<string, string> = {
  "Compliant":     "text-low border-low/30 bg-low/10",
  "At Risk":       "text-medium border-medium/30 bg-medium/10",
  "Non-Compliant": "text-critical border-critical/30 bg-critical/10",
};

export function ComplianceStatus() {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">Compliance Status</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {FRAMEWORKS.map((fw) => (
          <div key={fw.name} className="flex items-center gap-3">
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium truncate">{fw.name}</p>
              <div className="mt-1 relative h-1 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-500"
                  style={{ width: `${fw.pass * 100}%` }}
                />
              </div>
            </div>
            <div className="shrink-0 text-right">
              <p className="text-xs tabular-nums text-muted-foreground">
                {(fw.pass * 100).toFixed(0)}%
              </p>
            </div>
            <span
              className={cn(
                "shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium",
                READINESS_STYLE[fw.readiness]
              )}
            >
              {fw.readiness}
            </span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

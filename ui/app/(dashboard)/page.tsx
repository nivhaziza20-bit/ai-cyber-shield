import { Header } from "@/components/layout/header";
import { RiskScoreGauge } from "@/components/dashboard/risk-score-gauge";
import { SeverityBreakdown } from "@/components/dashboard/severity-breakdown";
import { RecentScans } from "@/components/dashboard/recent-scans";
import { ComplianceStatus } from "@/components/dashboard/compliance-status";
import { TrendChart } from "@/components/dashboard/trend-chart";
import { TopFindings } from "@/components/dashboard/top-findings";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, AlertTriangle, TrendingDown, CheckCircle2 } from "lucide-react";

// Static demo data (replaced by real API calls via SWR/TanStack Query in production)
const DEMO_STATS = {
  risk_score:      72,
  grade:           "C",
  total_findings:  47,
  critical:        3,
  high:            8,
  medium:          21,
  low:             15,
  scans_this_week: 12,
  assets_covered:  28,
  mttr_days:       4.2,
};

export default function DashboardPage() {
  return (
    <>
      <Header
        title="Security Dashboard"
        subtitle="AI Cyber Shield v6 — Real-time vulnerability intelligence"
      />

      <div className="flex-1 overflow-auto p-6 scrollbar-thin">
        {/* KPI row */}
        <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
          <KpiCard
            label="Risk Score"
            value={`${DEMO_STATS.risk_score}/100`}
            icon={<Shield className="h-4 w-4" />}
            trend="up"
            detail={`Grade ${DEMO_STATS.grade}`}
            color="text-destructive"
          />
          <KpiCard
            label="Open Findings"
            value={String(DEMO_STATS.total_findings)}
            icon={<AlertTriangle className="h-4 w-4" />}
            trend="down"
            detail={`${DEMO_STATS.critical} critical`}
            color="text-high"
          />
          <KpiCard
            label="MTTR"
            value={`${DEMO_STATS.mttr_days}d`}
            icon={<TrendingDown className="h-4 w-4" />}
            trend="down"
            detail="mean time to remediate"
            color="text-primary"
          />
          <KpiCard
            label="Assets Scanned"
            value={String(DEMO_STATS.assets_covered)}
            icon={<CheckCircle2 className="h-4 w-4" />}
            trend="up"
            detail={`${DEMO_STATS.scans_this_week} scans this week`}
            color="text-low"
          />
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Left column */}
          <div className="space-y-6 lg:col-span-2">
            <TrendChart />
            <TopFindings />
          </div>

          {/* Right column */}
          <div className="space-y-6">
            <RiskScoreGauge score={DEMO_STATS.risk_score} grade={DEMO_STATS.grade} />
            <SeverityBreakdown
              critical={DEMO_STATS.critical}
              high={DEMO_STATS.high}
              medium={DEMO_STATS.medium}
              low={DEMO_STATS.low}
            />
            <ComplianceStatus />
          </div>
        </div>

        {/* Bottom: Recent scans */}
        <div className="mt-6">
          <RecentScans />
        </div>
      </div>
    </>
  );
}

// ─── KPI card ──────────────────────────────────────────────────────────────

interface KpiCardProps {
  label:  string;
  value:  string;
  icon:   React.ReactNode;
  trend:  "up" | "down";
  detail: string;
  color:  string;
}

function KpiCard({ label, value, icon, detail, color }: KpiCardProps) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
            {label}
          </p>
          <div className={`${color} opacity-70`}>{icon}</div>
        </div>
        <p className={`mt-2 text-3xl font-bold tracking-tight ${color}`}>{value}</p>
        <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
      </CardContent>
    </Card>
  );
}

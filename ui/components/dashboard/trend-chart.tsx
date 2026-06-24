"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

const DEMO_TREND = [
  { week: "W-6", critical: 7,  high: 18, medium: 32 },
  { week: "W-5", critical: 6,  high: 15, medium: 28 },
  { week: "W-4", critical: 5,  high: 14, medium: 25 },
  { week: "W-3", critical: 4,  high: 11, medium: 23 },
  { week: "W-2", critical: 4,  high: 10, medium: 22 },
  { week: "W-1", critical: 3,  high: 8,  medium: 21 },
];

const COLORS = {
  critical: "var(--color-critical)",
  high:     "var(--color-high)",
  medium:   "var(--color-medium)",
};

export function TrendChart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Vulnerability Trend</CardTitle>
        <CardDescription>Open findings by severity over the last 6 weeks</CardDescription>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={DEMO_TREND} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="gCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={COLORS.critical} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.critical} stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="gHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={COLORS.high} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.high} stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="gMedium" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={COLORS.medium} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.medium} stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--color-border)"
              strokeOpacity={0.5}
            />
            <XAxis
              dataKey="week"
              tick={{ fontSize: 11, fill: "var(--color-muted-foreground)" }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 11, fill: "var(--color-muted-foreground)" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--color-card)",
                border: "1px solid var(--color-border)",
                borderRadius: "8px",
                fontSize: "12px",
              }}
              labelStyle={{ color: "var(--color-foreground)", fontWeight: 600 }}
            />
            <Legend
              iconType="circle"
              iconSize={8}
              wrapperStyle={{ fontSize: 11, paddingTop: 12 }}
            />
            <Area type="monotone" dataKey="medium"   name="Medium"   stroke={COLORS.medium}   fill="url(#gMedium)"   strokeWidth={2} />
            <Area type="monotone" dataKey="high"     name="High"     stroke={COLORS.high}     fill="url(#gHigh)"     strokeWidth={2} />
            <Area type="monotone" dataKey="critical" name="Critical" stroke={COLORS.critical} fill="url(#gCritical)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

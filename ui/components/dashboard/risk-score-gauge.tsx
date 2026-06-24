"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface RiskScoreGaugeProps {
  score: number;
  grade: string;
}

const GRADE_COLORS: Record<string, string> = {
  A: "text-low stroke-low",
  B: "text-low stroke-low",
  C: "text-medium stroke-medium",
  D: "text-high stroke-high",
  F: "text-critical stroke-critical",
};

export function RiskScoreGauge({ score, grade }: RiskScoreGaugeProps) {
  const pct        = score / 100;
  const circumference = 2 * Math.PI * 45; // radius = 45
  const dashOffset = circumference * (1 - pct);
  const colorClass = GRADE_COLORS[grade] ?? GRADE_COLORS.F;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-3 pb-5">
        <div className="relative h-36 w-36">
          <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
            {/* Track */}
            <circle
              cx="50" cy="50" r="45"
              fill="none"
              strokeWidth="8"
              className="stroke-muted"
            />
            {/* Progress */}
            <circle
              cx="50" cy="50" r="45"
              fill="none"
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
              className={cn("transition-all duration-700", colorClass.split(" ").find(c => c.startsWith("stroke-")))}
            />
          </svg>

          {/* Centre label */}
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={cn("text-4xl font-black tabular-nums", colorClass.split(" ")[0])}>
              {score}
            </span>
            <span className="text-xs text-muted-foreground">/ 100</span>
          </div>
        </div>

        {/* Grade */}
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Security Grade</span>
          <span className={cn("text-2xl font-black", colorClass.split(" ")[0])}>
            {grade}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

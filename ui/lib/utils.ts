import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL": return "severity-critical";
    case "HIGH":     return "severity-high";
    case "MEDIUM":   return "severity-medium";
    case "LOW":      return "severity-low";
    default:         return "severity-info";
  }
}

export function cvssToSeverity(score: number): string {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score >= 0.1) return "LOW";
  return "INFO";
}

export function formatRelative(isoString: string): string {
  const date = new Date(isoString);
  const now   = new Date();
  const diff  = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diff < 60)       return `${diff}s ago`;
  if (diff < 3600)     return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400)    return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function truncateUrl(url: string, max = 48): string {
  if (url.length <= max) return url;
  const parsed = new URL(url);
  const short  = `${parsed.hostname}${parsed.pathname}`;
  return short.length <= max ? short : short.slice(0, max - 3) + "…";
}

export function cvssGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score <= 10) return "A";
  if (score >= 90) return "F";
  if (score >= 80) return "D";
  if (score >= 65) return "C";
  if (score >= 50) return "B";
  return "A";
}

export function riskScore(findings: { severity: string }[]): number {
  const weights: Record<string, number> = {
    CRITICAL: 40, HIGH: 10, MEDIUM: 3, LOW: 1, INFO: 0,
  };
  const raw = findings.reduce((sum, f) => sum + (weights[f.severity] ?? 0), 0);
  return Math.min(100, raw);
}

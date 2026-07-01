/* ─────────────────────────────────────────────────────────────────────────────
   AI Cyber Shield — API client
   Calls the Python backend (FastAPI / Streamlit proxy) or returns mock data.
   Set NEXT_PUBLIC_MOCK_API=true in .env.local to use mock data without backend.
───────────────────────────────────────────────────────────────────────────── */

export type ScanMode = "standard" | "passive" | "pt";
export type Grade    = "A" | "B" | "C" | "D" | "F";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface CategoryScore {
  name: string;
  score: number;    // 0–100
  label: string;
  icon: string;
}

export interface Finding {
  id: string;
  tool: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation?: string;
  url?: string;
}

export interface ScanResult {
  scan_id:          string;
  url:              string;
  overall_score:    number;
  overall_grade:    Grade;
  category_scores:  Record<string, number>;
  critical_findings:string[];
  findings:         Finding[];
  scan_mode:        ScanMode;
  scan_duration_s:  number;
  scanned_at:       string;
}

export interface HistoryRecord {
  scan_id:       string;
  url:           string;
  overall_grade: Grade;
  overall_score: number;
  prev_score?:   number;
  critical_count:number;
  scanned_at:    string;
}

export interface Schedule {
  id:             string;
  url:            string;
  label?:         string;
  cron_expression:string;
  enabled:        boolean;
  last_grade?:    Grade;
  last_score?:    number;
  run_count:      number;
  next_run_at?:   string;
  last_run_at?:   string;
  status:         "ok" | "error" | "running";
}

/* ── Mock data ────────────────────────────────────────────────────────────── */
const MOCK_RESULT: ScanResult = {
  scan_id:       "mock-001",
  url:           "https://example.com",
  overall_score: 72,
  overall_grade: "B",
  category_scores: {
    "SSL/TLS":         88,
    "Headers":         65,
    "DNS Security":    90,
    "Vulnerabilities": 55,
    "Privacy":         70,
    "Email Security":  80,
    "JavaScript":      60,
    "Performance":     75,
  },
  critical_findings: [
    "Missing Content-Security-Policy header",
    "X-Frame-Options not set — clickjacking risk",
  ],
  findings: [
    {
      id: "f1", tool: "Headers Scanner", severity: "CRITICAL",
      title: "Missing Content-Security-Policy",
      description: "No CSP header found. XSS attacks are not mitigated.",
      recommendation: "Add a strict CSP policy: Content-Security-Policy: default-src 'self'",
    },
    {
      id: "f2", tool: "Headers Scanner", severity: "HIGH",
      title: "X-Frame-Options not set",
      description: "The site is vulnerable to clickjacking attacks.",
      recommendation: "Add: X-Frame-Options: DENY",
    },
    {
      id: "f3", tool: "SSL Scanner", severity: "MEDIUM",
      title: "TLS 1.1 still supported",
      description: "Legacy TLS versions should be disabled.",
      recommendation: "Configure server to accept TLS 1.2+ only",
    },
    {
      id: "f4", tool: "DNS Scanner", severity: "LOW",
      title: "DNSSEC not enabled",
      description: "DNS responses can be spoofed without DNSSEC.",
      recommendation: "Enable DNSSEC on your domain registrar",
    },
    {
      id: "f5", tool: "Email Scanner", severity: "INFO",
      title: "SPF record present",
      description: "SPF is configured correctly for this domain.",
    },
  ],
  scan_mode:       "standard",
  scan_duration_s: 47,
  scanned_at:      new Date().toISOString(),
};

const MOCK_HISTORY: HistoryRecord[] = [
  { scan_id: "h1", url: "https://example.com",  overall_grade: "B", overall_score: 72, prev_score: 68, critical_count: 2, scanned_at: new Date(Date.now() - 3600000).toISOString() },
  { scan_id: "h2", url: "https://google.com",   overall_grade: "A", overall_score: 94, prev_score: 92, critical_count: 0, scanned_at: new Date(Date.now() - 7200000).toISOString() },
  { scan_id: "h3", url: "https://startup.io",   overall_grade: "D", overall_score: 38, prev_score: 45, critical_count: 5, scanned_at: new Date(Date.now() - 86400000).toISOString() },
  { scan_id: "h4", url: "https://shopify.com",  overall_grade: "A", overall_score: 91, prev_score: 88, critical_count: 0, scanned_at: new Date(Date.now() - 172800000).toISOString() },
  { scan_id: "h5", url: "https://medium.com",   overall_grade: "C", overall_score: 58, prev_score: 61, critical_count: 1, scanned_at: new Date(Date.now() - 259200000).toISOString() },
];

const MOCK_SCHEDULES: Schedule[] = [
  { id: "s1", url: "https://example.com",  label: "Main site",       cron_expression: "0 8 * * *",  enabled: true,  last_grade: "B", last_score: 72, run_count: 14, next_run_at: new Date(Date.now() + 3600000).toISOString(),  last_run_at: new Date(Date.now() - 86400000).toISOString(),  status: "ok" },
  { id: "s2", url: "https://api.example.com", label: "API endpoint", cron_expression: "0 * * * *",  enabled: true,  last_grade: "A", last_score: 91, run_count: 72, next_run_at: new Date(Date.now() + 1800000).toISOString(),  last_run_at: new Date(Date.now() - 3600000).toISOString(),   status: "ok" },
  { id: "s3", url: "https://staging.example.com", label: "Staging", cron_expression: "0 0 * * 1",  enabled: false, last_grade: "C", last_score: 54, run_count: 8,  next_run_at: undefined, last_run_at: new Date(Date.now() - 604800000).toISOString(), status: "error" },
];

/* ── API functions ────────────────────────────────────────────────────────── */
const MOCK = process.env.NEXT_PUBLIC_MOCK_API === "true";
const API_KEY = process.env.NEXT_PUBLIC_AICS_API_KEY ?? "aics-dev-key-DO-NOT-USE-IN-PRODUCTION";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/proxy${path}`, {
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
    },
    ...init,
  });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

/**
 * Trigger an async scan — returns immediately with scan_id.
 * Connect to useScanProgress(scanId) for real-time progress.
 */
export async function triggerScan(
  url: string,
  mode: ScanMode = "standard"
): Promise<{ scan_id: string }> {
  return apiFetch<{ scan_id: string }>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({ url, mode }),
  });
}

/**
 * Fetch the status / basic result of a completed scan.
 */
export interface ScanStatusResult {
  scan_id:       string;
  status:        string;
  url:           string;
  overall_score: number | null;
  overall_grade: string | null;
  finding_count: number | null;
  error_message: string | null;
  started_at:    string | null;
  completed_at:  string | null;
}

export async function getScan(scanId: string): Promise<ScanStatusResult> {
  return apiFetch<ScanStatusResult>(`/api/v1/scans/${scanId}`);
}

/** SSE URL for scan progress (no auth required — scan_id is the token). */
export function sseUrl(scanId: string): string {
  return `/api/proxy/api/v1/scans/${scanId}/events`;
}

export async function startScan(url: string, mode: ScanMode = "standard"): Promise<ScanResult> {
  if (MOCK) {
    await new Promise((r) => setTimeout(r, 2500)); // simulate scan
    return { ...MOCK_RESULT, url, overall_score: 50 + Math.floor(Math.random() * 45), scanned_at: new Date().toISOString() };
  }
  return apiFetch<ScanResult>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({ url, mode }),
  });
}

export async function getScanHistory(limit = 50): Promise<HistoryRecord[]> {
  if (MOCK) return MOCK_HISTORY;
  return apiFetch<HistoryRecord[]>(`/api/v1/history?limit=${limit}`);
}

export async function getSchedules(): Promise<Schedule[]> {
  if (MOCK) return MOCK_SCHEDULES;
  return apiFetch<Schedule[]>("/api/v1/schedules");
}

export async function toggleSchedule(id: string, enabled: boolean): Promise<void> {
  if (MOCK) return;
  await apiFetch(`/api/v1/schedules/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled }),
  });
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */
export function gradeColor(grade: Grade): string {
  return { A: "#22d3ee", B: "#3b82f6", C: "#f59e0b", D: "#ef4444", F: "#dc2626" }[grade] ?? "#94a3b8";
}

export function scoreColor(score: number): string {
  if (score >= 80) return "#22d3ee";
  if (score >= 60) return "#f59e0b";
  return "#ef4444";
}

export function gradeDesc(grade: Grade, lang: "en" | "he" = "en"): string {
  const map = {
    en: { A: "Excellent", B: "Good", C: "Fair", D: "Poor", F: "Critical Risk" },
    he: { A: "מצוין", B: "טוב", C: "סביר", D: "גרוע", F: "סיכון קריטי" },
  };
  return map[lang][grade] ?? grade;
}

export function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function categoryIcon(name: string): string {
  const icons: Record<string, string> = {
    "SSL/TLS": "🔒", Headers: "📋", "DNS Security": "🌐",
    Vulnerabilities: "🐛", Privacy: "👁", "Email Security": "✉️",
    JavaScript: "⚡", Performance: "🚀", "Content Security": "🛡",
  };
  return icons[name] ?? "📊";
}

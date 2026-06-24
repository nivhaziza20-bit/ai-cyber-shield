// Core domain types for AI Cyber Shield UI

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingState =
  | "OPEN"
  | "CONFIRMED"
  | "FALSE_POS"
  | "SUPPRESSED"
  | "FIXED";

export interface Finding {
  id:           string;
  title:        string;
  severity:     Severity;
  cvss_score:   number;
  cvss_vector:  string;
  cwe_id:       string;
  owasp_code:   string;
  owasp_name:   string;
  endpoint:     string;
  parameter:    string;
  description:  string;
  evidence:     string;
  remediation:  string;
  effort_hours: number;
  fingerprint:  string;
  state:        FindingState;
  confirmed:    boolean;
  scan_id:      string;
  created_at:   string;
  // Code diff (optional)
  code_before?: string;
  code_after?:  string;
  // Compliance
  pci_controls:  string[];
  soc2_controls: string[];
  iso_controls:  string[];
  nist_controls: string[];
}

export interface ScanSummary {
  total:    number;
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
  info:     number;
  risk_score: number;
  grade:    string;
}

export interface Scan {
  id:          string;
  target_url:  string;
  status:      "pending" | "running" | "completed" | "failed";
  started_at:  string;
  finished_at: string | null;
  summary:     ScanSummary;
  profile:     string | null;
}

export interface Asset {
  id:          string;
  domain:      string;
  ip:          string | null;
  tags:        string[];
  last_scan:   string | null;
  risk_score:  number;
  open_findings: number;
}

export interface ComplianceFramework {
  name:      string;
  pass_rate: number;
  readiness: "Compliant" | "At Risk" | "Non-Compliant";
  controls_total:  number;
  controls_pass:   number;
  controls_fail:   number;
}

// Attack chain for React Flow
export interface AttackNode {
  id:       string;
  type:     "recon" | "exploit" | "impact" | "pivot";
  label:    string;
  finding?: Finding;
  x:        number;
  y:        number;
}

export interface AttackEdge {
  id:     string;
  source: string;
  target: string;
  label?: string;
}

// SSE stream event
export type ScanEvent =
  | { type: "finding";   data: Finding }
  | { type: "progress";  data: { tool: string; pct: number } }
  | { type: "completed"; data: { scan_id: string; summary: ScanSummary } }
  | { type: "error";     data: { message: string } };

// Workspace (multi-tenant)
export interface Workspace {
  id:    string;
  name:  string;
  slug:  string;
  plan:  "free" | "pro" | "enterprise";
  role:  "owner" | "admin" | "analyst" | "viewer";
}

export interface TeamMember {
  id:       string;
  email:    string;
  name:     string;
  role:     Workspace["role"];
  avatar?:  string;
  last_active: string;
}

// API response wrapper
export interface ApiResponse<T> {
  data:    T;
  error?:  string;
  status:  number;
}

// Pagination
export interface Page<T> {
  items:    T[];
  total:    number;
  page:     number;
  per_page: number;
  pages:    number;
}

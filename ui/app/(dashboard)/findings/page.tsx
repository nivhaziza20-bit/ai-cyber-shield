"use client";

import { Header } from "@/components/layout/header";
import { VulnerabilityMatrix } from "@/components/vulnerability-matrix/vulnerability-matrix";
import type { Finding } from "@/types";

// Demo findings data
const DEMO_FINDINGS: Finding[] = [
  {
    id: "f-001", title: "SQL Injection via search parameter", severity: "CRITICAL",
    cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe_id: "CWE-89", owasp_code: "A03", owasp_name: "Injection",
    endpoint: "https://app.example.com/api/v1/search", parameter: "q",
    description: "The search endpoint is vulnerable to SQL injection via the 'q' parameter.",
    evidence: "' OR '1'='1", remediation: "Use parameterised queries.",
    effort_hours: 2, fingerprint: "abc123", state: "CONFIRMED", confirmed: true,
    scan_id: "s-001", created_at: new Date().toISOString(),
    pci_controls: ["6.3.1"], soc2_controls: ["CC6.1"], iso_controls: ["A.14.2.5"], nist_controls: ["PR.DS-5"],
  },
  {
    id: "f-002", title: "Authentication Bypass on admin route", severity: "CRITICAL",
    cvss_score: 9.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    cwe_id: "CWE-287", owasp_code: "A01", owasp_name: "Broken Access Control",
    endpoint: "https://app.example.com/admin/panel", parameter: "role",
    description: "Admin panel accessible without authentication.", evidence: "HTTP 200 on /admin without token.",
    remediation: "Add authentication middleware to all admin routes.", effort_hours: 4,
    fingerprint: "def456", state: "OPEN", confirmed: false, scan_id: "s-001",
    created_at: new Date().toISOString(),
    pci_controls: ["8.6.1"], soc2_controls: ["CC6.2"], iso_controls: ["A.9.4.1"], nist_controls: ["PR.AC-3"],
  },
  {
    id: "f-003", title: "SSRF via webhook URL parameter", severity: "HIGH",
    cvss_score: 8.3, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    cwe_id: "CWE-918", owasp_code: "A10", owasp_name: "SSRF",
    endpoint: "https://app.example.com/api/webhook", parameter: "url",
    description: "Webhook URL parameter allows SSRF.", evidence: "http://169.254.169.254/latest/meta-data/",
    remediation: "Validate and block private IP ranges.", effort_hours: 3,
    fingerprint: "ghi789", state: "OPEN", confirmed: false, scan_id: "s-001",
    created_at: new Date().toISOString(),
    pci_controls: [], soc2_controls: ["CC6.7"], iso_controls: ["A.13.1.3"], nist_controls: ["PR.DS-5"],
  },
  {
    id: "f-004", title: "Stored XSS in comment field", severity: "HIGH",
    cvss_score: 7.6, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
    cwe_id: "CWE-79", owasp_code: "A03", owasp_name: "Injection",
    endpoint: "https://app.example.com/api/comments", parameter: "body",
    description: "Stored XSS via unescaped comment body.", evidence: "<script>alert(1)</script>",
    remediation: "HTML-encode all user output.", effort_hours: 2,
    fingerprint: "jkl012", state: "OPEN", confirmed: false, scan_id: "s-001",
    created_at: new Date().toISOString(),
    pci_controls: ["6.3.2"], soc2_controls: ["CC6.1"], iso_controls: ["A.14.2.5"], nist_controls: [],
  },
  {
    id: "f-005", title: "Sensitive data in HTTP response headers", severity: "MEDIUM",
    cvss_score: 5.3, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cwe_id: "CWE-200", owasp_code: "A02", owasp_name: "Cryptographic Failures",
    endpoint: "https://app.example.com/login", parameter: "",
    description: "Server version disclosed in X-Powered-By header.", evidence: "X-Powered-By: Express 4.18.2",
    remediation: "Remove or sanitise X-Powered-By and Server headers.", effort_hours: 1,
    fingerprint: "mno345", state: "SUPPRESSED", confirmed: false, scan_id: "s-001",
    created_at: new Date().toISOString(),
    pci_controls: ["2.2.7"], soc2_controls: [], iso_controls: ["A.14.2.1"], nist_controls: [],
  },
  {
    id: "f-006", title: "Missing HSTS header", severity: "LOW",
    cvss_score: 3.7, cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cwe_id: "CWE-319", owasp_code: "A05", owasp_name: "Security Misconfiguration",
    endpoint: "https://app.example.com/", parameter: "",
    description: "HSTS not configured.", evidence: "No Strict-Transport-Security header.",
    remediation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains", effort_hours: 0.5,
    fingerprint: "pqr678", state: "FIXED", confirmed: false, scan_id: "s-001",
    created_at: new Date().toISOString(),
    pci_controls: ["4.2.1"], soc2_controls: [], iso_controls: [], nist_controls: [],
  },
];

export default function FindingsPage() {
  return (
    <>
      <Header title="Findings" subtitle="Vulnerability matrix — sortable, filterable, exportable" />
      <div className="flex-1 overflow-auto p-6 scrollbar-thin">
        <VulnerabilityMatrix findings={DEMO_FINDINGS} />
      </div>
    </>
  );
}

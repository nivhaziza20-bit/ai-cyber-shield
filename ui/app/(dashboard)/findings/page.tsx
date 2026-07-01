"use client";

import { useState, useMemo } from "react";
import { Header } from "@/components/layout/header";
import { useLang } from "@/contexts/language-context";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

interface Finding {
  finding_id:  string;
  title:       string;
  tool:        string;
  severity:    Severity;
  cvss_score:  number;
  cwe_id:      number;
  owasp_code:  string;
  remediation_summary: string;
  remediation_code_before: string;
  remediation_code_after:  string;
  endpoint:    string;
  confirmed:   boolean;
}

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
  INFO:     "#6366f1",
};

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/* Demo data while no live scan in state */
const DEMO_FINDINGS: Finding[] = [
  {
    finding_id: "f1", title: "Missing Content-Security-Policy",
    tool: "headers", severity: "CRITICAL", cvss_score: 7.5,
    cwe_id: 693, owasp_code: "A05:2021", remediation_summary: "Add CSP header",
    remediation_code_before: '# No CSP header',
    remediation_code_after:  'Content-Security-Policy: default-src \'self\'',
    endpoint: "/", confirmed: true,
  },
  {
    finding_id: "f2", title: "TLS 1.1 still accepted",
    tool: "ssl", severity: "HIGH", cvss_score: 5.9,
    cwe_id: 326, owasp_code: "A02:2021", remediation_summary: "Disable TLS < 1.2",
    remediation_code_before: 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2;',
    remediation_code_after:  'ssl_protocols TLSv1.2 TLSv1.3;',
    endpoint: "443/tcp", confirmed: true,
  },
  {
    finding_id: "f3", title: "DNSSEC not enabled",
    tool: "dns", severity: "MEDIUM", cvss_score: 4.3,
    cwe_id: 345, owasp_code: "A08:2021", remediation_summary: "Enable DNSSEC via registrar",
    remediation_code_before: '; No DNSSEC records',
    remediation_code_after:  '; Enable DNSSEC at your registrar',
    endpoint: "DNS", confirmed: false,
  },
  {
    finding_id: "f4", title: "SPF soft-fail (-all → ~all)",
    tool: "dns", severity: "LOW", cvss_score: 2.1,
    cwe_id: 183, owasp_code: "A05:2021", remediation_summary: "Use -all in SPF record",
    remediation_code_before: 'v=spf1 include:sendgrid.net ~all',
    remediation_code_after:  'v=spf1 include:sendgrid.net -all',
    endpoint: "DNS/TXT", confirmed: true,
  },
];

function SeverityBadge({ sev }: { sev: Severity }) {
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: "4px",
      fontSize: "0.65rem",
      fontWeight: 800,
      fontFamily: "JetBrains Mono, monospace",
      letterSpacing: "0.08em",
      color: SEV_COLOR[sev],
      background: `${SEV_COLOR[sev]}18`,
      border: `1px solid ${SEV_COLOR[sev]}40`,
    }}>
      {sev}
    </span>
  );
}

function FindingRow({
  f,
  expanded,
  onToggle,
}: {
  f: Finding;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div style={{
      border: "1px solid #1a2236",
      borderRadius: "10px",
      overflow: "hidden",
      marginBottom: "6px",
    }}>
      {/* Summary row */}
      <div
        onClick={onToggle}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          padding: "12px 16px",
          background: expanded ? "rgba(12,17,32,0.95)" : "rgba(12,17,32,0.75)",
          cursor: "pointer",
          transition: "background 150ms ease",
        }}
        onMouseEnter={(e) => { if (!expanded) e.currentTarget.style.background = "rgba(16,22,40,0.9)"; }}
        onMouseLeave={(e) => { if (!expanded) e.currentTarget.style.background = "rgba(12,17,32,0.75)"; }}
      >
        {/* Severity color strip */}
        <div style={{ width: "3px", height: "32px", borderRadius: "2px", background: SEV_COLOR[f.severity], flexShrink: 0 }} />

        <SeverityBadge sev={f.severity} />

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ color: "#f1f5f9", fontWeight: 600, fontSize: "0.88rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {f.title}
          </div>
          <div style={{ color: "#64748b", fontSize: "0.72rem", fontFamily: "JetBrains Mono, monospace", marginTop: "2px" }}>
            {f.tool} · {f.endpoint}
            {!f.confirmed && <span style={{ marginInlineStart: "8px", color: "#f59e0b" }}>unconfirmed</span>}
          </div>
        </div>

        <div style={{ textAlign: "end", flexShrink: 0 }}>
          <div style={{ color: "#94a3b8", fontSize: "0.75rem", fontFamily: "JetBrains Mono, monospace", fontWeight: 700 }}>
            {f.cvss_score.toFixed(1)}
          </div>
          <div style={{ color: "#64748b", fontSize: "0.65rem" }}>CVSS</div>
        </div>

        <div style={{ color: "#64748b", fontSize: "0.7rem", fontFamily: "JetBrains Mono, monospace", flexShrink: 0 }}>
          {f.owasp_code}
        </div>

        <div style={{ color: expanded ? "#22d3ee" : "#64748b", flexShrink: 0, transition: "color 150ms" }}>
          {expanded ? "▲" : "▼"}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{
          padding: "16px 20px",
          background: "#080c18",
          borderTop: "1px solid #1a2236",
        }}>
          <div style={{ marginBottom: "12px", color: "#94a3b8", fontSize: "0.82rem" }}>
            <strong style={{ color: "#f1f5f9" }}>CWE-{f.cwe_id}</strong> · {f.owasp_code}
          </div>

          <div style={{ marginBottom: "12px", color: "#94a3b8", fontSize: "0.82rem" }}>
            <strong style={{ color: "#e2e8f0", display: "block", marginBottom: "4px" }}>Remediation</strong>
            {f.remediation_summary}
          </div>

          {/* Before / After code */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
            <div>
              <div style={{ fontSize: "0.65rem", color: "#ef4444", fontFamily: "JetBrains Mono, monospace", marginBottom: "4px" }}>BEFORE</div>
              <pre style={{
                background: "#0a0f1e",
                border: "1px solid #1e293b",
                borderRadius: "6px",
                padding: "10px 12px",
                color: "#fca5a5",
                fontSize: "0.72rem",
                fontFamily: "JetBrains Mono, monospace",
                overflow: "auto",
                margin: 0,
              }}>
                {f.remediation_code_before}
              </pre>
            </div>
            <div>
              <div style={{ fontSize: "0.65rem", color: "#22c55e", fontFamily: "JetBrains Mono, monospace", marginBottom: "4px" }}>AFTER</div>
              <pre style={{
                background: "#0a0f1e",
                border: "1px solid #1e293b",
                borderRadius: "6px",
                padding: "10px 12px",
                color: "#86efac",
                fontSize: "0.72rem",
                fontFamily: "JetBrains Mono, monospace",
                overflow: "auto",
                margin: 0,
              }}>
                {f.remediation_code_after}
              </pre>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
            <button style={{
              padding: "6px 14px", borderRadius: "6px",
              border: "1px solid #1a2236", background: "transparent",
              color: "#64748b", fontSize: "0.75rem", cursor: "pointer",
            }}>
              🔄 Verify Fix
            </button>
            <button style={{
              padding: "6px 14px", borderRadius: "6px",
              border: "1px solid #1a2236", background: "transparent",
              color: "#64748b", fontSize: "0.75rem", cursor: "pointer",
            }}>
              🚫 Mark False Positive
            </button>
            <button style={{
              padding: "6px 14px", borderRadius: "6px",
              border: "1px solid #1a2236", background: "transparent",
              color: "#64748b", fontSize: "0.75rem", cursor: "pointer",
            }}>
              📋 Copy to Jira
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function FindingsPage() {
  const { t } = useLang();
  const [findings] = useState<Finding[]>(DEMO_FINDINGS);
  const [sevFilter, setSevFilter] = useState<Severity | "ALL">("ALL");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const PER_PAGE = 25;

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (sevFilter !== "ALL" && f.severity !== sevFilter) return false;
      if (search && !f.title.toLowerCase().includes(search.toLowerCase()) &&
          !f.tool.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [findings, sevFilter, search]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    findings.forEach((f) => { c[f.severity] = (c[f.severity] ?? 0) + 1; });
    return c;
  }, [findings]);

  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE);
  const totalPages = Math.ceil(filtered.length / PER_PAGE);

  return (
    <>
      <Header title="Findings" />
      <main style={{ flex: 1, padding: "28px 32px", maxWidth: "1000px", margin: "0 auto", width: "100%" }}>

        {/* Summary chips */}
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "16px" }}>
          <button
            onClick={() => setSevFilter("ALL")}
            style={{
              padding: "4px 14px", borderRadius: "999px",
              border: `1px solid ${sevFilter === "ALL" ? "rgba(34,211,238,0.3)" : "#1a2236"}`,
              background: sevFilter === "ALL" ? "rgba(34,211,238,0.06)" : "transparent",
              color: sevFilter === "ALL" ? "#22d3ee" : "#64748b",
              fontSize: "0.75rem", fontWeight: 600, cursor: "pointer",
              fontFamily: "JetBrains Mono, monospace",
            }}
          >
            ALL ({findings.length})
          </button>
          {SEV_ORDER.filter((s) => counts[s]).map((sev) => (
            <button
              key={sev}
              onClick={() => setSevFilter(sev)}
              style={{
                padding: "4px 14px", borderRadius: "999px",
                border: `1px solid ${sevFilter === sev ? SEV_COLOR[sev] + "44" : "#1a2236"}`,
                background: sevFilter === sev ? `${SEV_COLOR[sev]}12` : "transparent",
                color: sevFilter === sev ? SEV_COLOR[sev] : "#64748b",
                fontSize: "0.75rem", fontWeight: 600, cursor: "pointer",
                fontFamily: "JetBrains Mono, monospace",
              }}
            >
              {sev} ({counts[sev]})
            </button>
          ))}
        </div>

        {/* Search */}
        <input
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          placeholder="Search findings…"
          style={{
            width: "100%", padding: "10px 14px", marginBottom: "16px",
            background: "#080c18", border: "1px solid #1a2236", borderRadius: "8px",
            color: "#f1f5f9", fontSize: "0.88rem", outline: "none",
            fontFamily: "Inter, sans-serif",
          }}
        />

        {/* Findings list */}
        {paged.length === 0 ? (
          <div style={{ color: "#64748b", textAlign: "center", padding: "40px" }}>
            No findings match current filters
          </div>
        ) : (
          paged.map((f) => (
            <FindingRow
              key={f.finding_id}
              f={f}
              expanded={expandedId === f.finding_id}
              onToggle={() => setExpandedId(expandedId === f.finding_id ? null : f.finding_id)}
            />
          ))
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{ display: "flex", gap: "6px", justifyContent: "center", marginTop: "16px" }}>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
              <button
                key={p}
                onClick={() => setPage(p)}
                style={{
                  padding: "5px 11px", borderRadius: "6px",
                  border: `1px solid ${p === page ? "rgba(34,211,238,0.3)" : "#1a2236"}`,
                  background: p === page ? "rgba(34,211,238,0.08)" : "transparent",
                  color: p === page ? "#22d3ee" : "#64748b",
                  fontSize: "0.75rem", cursor: "pointer",
                }}
              >
                {p}
              </button>
            ))}
          </div>
        )}
      </main>
    </>
  );
}

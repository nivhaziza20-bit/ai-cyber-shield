"""
core/attack_chain_engine.py — AI Cyber Shield v6

Detects how individual security findings combine into exploitable attack chains.
Uses hardcoded pattern matching first (deterministic, testable), with optional
LLM augmentation for novel patterns.

Public API:
    chains = detect_chains(findings: list[SecurityFinding]) -> list[AttackChain]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from finding_enricher import SecurityFinding


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class ChainNode:
    finding_id:  str
    title:       str
    severity:    str
    tool:        str
    role:        str   # "prerequisite" | "amplifier"


@dataclass
class AttackChain:
    id:             str
    name:           str
    description:    str
    prerequisites:  list[ChainNode]
    amplifiers:     list[ChainNode]
    impact:         str
    severity:       str        # overall chain severity (usually worse than individuals)
    cvss:           float
    remediation:    str
    detection_method: str = "pattern_matched"   # "pattern_matched" | "ai_detected"

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "name":             self.name,
            "description":      self.description,
            "severity":         self.severity,
            "cvss":             self.cvss,
            "impact":           self.impact,
            "remediation":      self.remediation,
            "detection_method": self.detection_method,
            "prerequisites": [
                {"finding_id": n.finding_id, "title": n.title,
                 "severity": n.severity, "tool": n.tool, "role": n.role}
                for n in self.prerequisites
            ],
            "amplifiers": [
                {"finding_id": n.finding_id, "title": n.title,
                 "severity": n.severity, "tool": n.tool, "role": n.role}
                for n in self.amplifiers
            ],
        }


# ─── Chain patterns (hardcoded rules) ────────────────────────────────────────

_CHAIN_PATTERNS = [
    {
        "id": "session_hijack_cors",
        "name": "Cross-Origin Session Hijacking",
        "description": "CORS wildcard combined with missing SameSite cookie flag enables cross-origin session theft.",
        "prerequisites": [
            {"tool": "cors_csp",         "finding_types": ["cors_wildcard", "cors_credentials", "cors_misconfiguration"]},
            {"tool": "cookie_security",  "finding_types": ["missing_samesite", "samesite_none_without_secure", "missing_httponly"]},
        ],
        "amplifiers": [
            {"tool": "cors_csp", "finding_types": ["missing_csp_frame_ancestors", "missing_csp", "unsafe_inline"]},
        ],
        "impact": "An attacker controlling a malicious origin can steal authenticated sessions from legitimate users.",
        "severity": "CRITICAL",
        "cvss": 8.1,
        "remediation": (
            "1. Restrict CORS origins to a specific allowlist — never use wildcard with credentials. "
            "2. Add SameSite=Strict (or Lax) to all session cookies. "
            "3. Add frame-ancestors to your CSP."
        ),
    },
    {
        "id": "credential_harvest_redirect",
        "name": "Credential Harvesting via Open Redirect",
        "description": "Open redirect combined with missing HSTS allows attackers to redirect users to phishing pages from trusted URLs.",
        "prerequisites": [
            {"tool": "open_redirect", "finding_types": ["confirmed_redirect", "potential_redirect", "open_redirect"]},
            {"tool": "hsts_preload",  "finding_types": ["missing_hsts", "hsts_too_short", "hsts_disabled"]},
        ],
        "amplifiers": [
            {"tool": "ssl",    "finding_types": ["mixed_content", "weak_tls", "protocol_downgrade"]},
        ],
        "impact": "Attacker can craft a legitimate-looking link (your domain) that redirects to a phishing page, harvesting credentials.",
        "severity": "HIGH",
        "cvss": 7.4,
        "remediation": (
            "1. Validate redirect destinations against an allowlist. "
            "2. Set Strict-Transport-Security with max-age ≥ 31536000 and includeSubDomains. "
            "3. Add your domain to the HSTS preload list."
        ),
    },
    {
        "id": "source_code_exposure_rce",
        "name": "Source Code Exposure → Credential Extraction",
        "description": "Exposed .git or .env files reveal credentials or internal secrets that can be used to escalate privileges.",
        "prerequisites": [
            {"tool": "exposure", "finding_types": ["exposed_git", "exposed_env", "exposed_backup", "directory_listing"]},
        ],
        "amplifiers": [
            {"tool": "tech",   "finding_types": ["outdated_dependency", "vulnerable_component", "cve_detected"]},
            {"tool": "headers","finding_types": ["missing_csp", "server_version_disclosed", "x_powered_by"]},
        ],
        "impact": "An attacker can download source code, extract hardcoded credentials, and use them to access databases, cloud accounts, or API services.",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "remediation": (
            "1. Remove all exposed sensitive files — add .git, .env, backup extensions to your web server's deny rules. "
            "2. Rotate any credentials that may have been exposed. "
            "3. Update all outdated dependencies to eliminate known CVEs."
        ),
    },
    {
        "id": "dns_email_spoofing",
        "name": "DNS Misconfiguration → Email Spoofing & Phishing",
        "description": "Missing or weak SPF/DMARC allows attackers to send phishing emails appearing to come from your domain.",
        "prerequisites": [
            {"tool": "dns", "finding_types": ["spf_missing", "spf_softfail", "dmarc_missing", "dmarc_none"]},
        ],
        "amplifiers": [
            {"tool": "dns", "finding_types": ["dkim_missing", "dnssec_missing"]},
        ],
        "impact": "Attackers can impersonate your domain in emails, targeting your customers or employees with convincing phishing attacks.",
        "severity": "HIGH",
        "cvss": 7.2,
        "remediation": (
            "1. Add SPF record with -all (hard fail). "
            "2. Set DMARC to p=reject with rua/ruf reporting. "
            "3. Configure DKIM signing for all outbound mail. "
            "4. Enable DNSSEC on your registrar."
        ),
    },
    {
        "id": "subdomain_takeover_cookie",
        "name": "Subdomain Takeover → Cookie Scope Hijacking",
        "description": "A dangling subdomain combined with overly broad cookie domain scope allows cookie theft.",
        "prerequisites": [
            {"tool": "subdomain_takeover", "finding_types": ["dangling_cname", "potential_takeover", "subdomain_takeover"]},
            {"tool": "cookie_security",    "finding_types": ["broad_cookie_domain", "missing_secure_flag", "missing_httponly"]},
        ],
        "amplifiers": [],
        "impact": "An attacker who takes over a dangling subdomain can receive cookies scoped to the parent domain, gaining authenticated access.",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "remediation": (
            "1. Immediately remove or reclaim dangling DNS records. "
            "2. Scope cookies to the exact origin (not .example.com). "
            "3. Add Secure and HttpOnly flags to all session cookies."
        ),
    },
    {
        "id": "xss_via_csp_bypass",
        "name": "XSS Amplification via Missing CSP",
        "description": "An HTML injection vulnerability is significantly amplified by the absence of Content-Security-Policy.",
        "prerequisites": [
            {"tool": "html",     "finding_types": ["potential_xss", "form_without_csrf", "inline_script"]},
            {"tool": "cors_csp", "finding_types": ["missing_csp", "unsafe_inline", "unsafe_eval"]},
        ],
        "amplifiers": [
            {"tool": "headers", "finding_types": ["missing_xss_protection", "missing_x_content_type"]},
        ],
        "impact": "Without CSP, any XSS vulnerability can execute arbitrary JavaScript, steal session tokens, or perform actions on behalf of the user.",
        "severity": "HIGH",
        "cvss": 7.6,
        "remediation": (
            "1. Implement a strict Content-Security-Policy — avoid unsafe-inline and unsafe-eval. "
            "2. Audit and sanitize all user-controlled HTML injection points. "
            "3. Add X-Content-Type-Options: nosniff and X-XSS-Protection: 1; mode=block."
        ),
    },
    {
        "id": "waf_bypass_exposed_ports",
        "name": "WAF Bypass via Direct Origin Access",
        "description": "An exposed backend port allows attackers to bypass WAF protections by communicating directly with the origin server.",
        "prerequisites": [
            {"tool": "waf",          "finding_types": ["no_waf_detected", "waf_bypass"]},
            {"tool": "port_scanner", "finding_types": ["exposed_database_port", "exposed_admin_port", "high_risk_port"]},
        ],
        "amplifiers": [
            {"tool": "exposure", "finding_types": ["exposed_admin_panel", "exposed_phpinfo"]},
        ],
        "impact": "Even if a WAF is configured, attackers who discover the origin IP can communicate directly, bypassing all WAF rules and rate limits.",
        "severity": "HIGH",
        "cvss": 7.5,
        "remediation": (
            "1. Restrict origin server access to WAF/CDN IP ranges via firewall rules. "
            "2. Close or firewall all non-essential ports. "
            "3. Enable IP allowlisting at the origin."
        ),
    },
    {
        "id": "tech_stack_cve_exploit",
        "name": "Known CVE Exploitation via Outdated Components",
        "description": "An outdated component with known CVEs combined with exposed version information allows targeted exploitation.",
        "prerequisites": [
            {"tool": "tech",    "finding_types": ["cve_detected", "outdated_dependency", "vulnerable_component"]},
            {"tool": "headers", "finding_types": ["server_version_disclosed", "x_powered_by", "x_aspnet_version"]},
        ],
        "amplifiers": [
            {"tool": "exposure", "finding_types": ["exposed_phpinfo", "exposed_debug_page"]},
        ],
        "impact": "Disclosed version information helps attackers identify exact CVEs to target. Known exploits may be publicly available.",
        "severity": "HIGH",
        "cvss": 7.8,
        "remediation": (
            "1. Remove all version-disclosing headers (Server, X-Powered-By, X-AspNet-Version). "
            "2. Update all dependencies to patched versions. "
            "3. Implement a dependency scanning process in CI/CD."
        ),
    },
]


# ─── Detection logic ──────────────────────────────────────────────────────────

def _matches_criterion(finding: SecurityFinding, criterion: dict) -> bool:
    """Check if a finding matches a chain prerequisite or amplifier criterion."""
    tool_matches = finding.tool.lower() == criterion["tool"].lower()
    type_matches = finding.finding_type.lower() in [
        t.lower() for t in criterion["finding_types"]
    ]
    return tool_matches and type_matches


def detect_chains(findings: list[SecurityFinding]) -> list[AttackChain]:
    """
    Match a list of enriched findings against all known chain patterns.
    Returns detected chains, sorted by CVSS (highest first).

    A chain is detected only if ALL prerequisites are met.
    Amplifiers are included when present but are optional.
    """
    chains: list[AttackChain] = []

    for pattern in _CHAIN_PATTERNS:
        # Check all prerequisites
        matched_prereqs: list[tuple[SecurityFinding, dict]] = []
        for criterion in pattern["prerequisites"]:
            match = next(
                (f for f in findings if _matches_criterion(f, criterion)),
                None,
            )
            if match is None:
                break
            matched_prereqs.append((match, criterion))
        else:
            # All prerequisites matched — chain is possible
            prereq_nodes = [
                ChainNode(
                    finding_id = f.finding_id,
                    title      = f.title,
                    severity   = f.severity,
                    tool       = f.tool,
                    role       = "prerequisite",
                )
                for f, _ in matched_prereqs
            ]

            # Check optional amplifiers
            amp_nodes: list[ChainNode] = []
            for criterion in pattern.get("amplifiers", []):
                match = next(
                    (f for f in findings if _matches_criterion(f, criterion)),
                    None,
                )
                if match:
                    amp_nodes.append(ChainNode(
                        finding_id = match.finding_id,
                        title      = match.title,
                        severity   = match.severity,
                        tool       = match.tool,
                        role       = "amplifier",
                    ))

            chains.append(AttackChain(
                id            = pattern["id"],
                name          = pattern["name"],
                description   = pattern["description"],
                prerequisites = prereq_nodes,
                amplifiers    = amp_nodes,
                impact        = pattern["impact"],
                severity      = pattern["severity"],
                cvss          = pattern["cvss"],
                remediation   = pattern["remediation"],
            ))

    # Sort: highest CVSS first, then CRITICAL before HIGH
    _sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    chains.sort(key=lambda c: (_sev.get(c.severity, 5), -c.cvss))
    return chains

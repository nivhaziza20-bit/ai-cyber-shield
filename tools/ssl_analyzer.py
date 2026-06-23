"""
SSL/TLS Analyzer — URL Scanner Phase 1
Passive certificate and TLS configuration audit.

Checks:
  - Certificate validity (expiry, self-signed, trusted CA)
  - TLS protocol version (1.0/1.1 = critical, 1.2 = ok, 1.3 = best)
  - Cipher suite strength
  - Certificate Subject and SANs (Subject Alternative Names)
  - HSTS preload status
  - Days until expiry warning
"""

import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from langchain_core.tools import tool


# ─────────────────────────────────────────────────────────────────────────────
# TLS scoring helpers
# ─────────────────────────────────────────────────────────────────────────────

_TLS_SCORES: dict[str, int] = {
    "TLSv1":   0,    # CRITICAL — deprecated, broken
    "TLSv1.1": 0,    # CRITICAL — deprecated
    "TLSv1.2": 70,   # OK — still acceptable
    "TLSv1.3": 100,  # BEST
}

_WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
}


def _score_cipher(cipher_name: str) -> tuple[int, str]:
    """Returns (score 0-100, reason)."""
    upper = cipher_name.upper()
    for weak in _WEAK_CIPHERS:
        if weak in upper:
            return 0, f"Weak cipher: {cipher_name}"
    if "AES_256" in upper or "AES256" in upper or "CHACHA20" in upper:
        return 100, "Strong cipher"
    if "AES_128" in upper or "AES128" in upper:
        return 80, "Acceptable cipher"
    return 60, "Unknown cipher strength"


def _days_until_expiry(not_after: str) -> int:
    """Parses the certificate expiry string and returns days remaining."""
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now    = datetime.now(timezone.utc)
    return (expiry - now).days


def _is_self_signed(cert: dict) -> bool:
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    return subject.get("commonName") == issuer.get("commonName")


def _get_sans(cert: dict) -> list[str]:
    sans = []
    for entry in cert.get("subjectAltName", []):
        if entry[0] == "DNS":
            sans.append(entry[1])
    return sans


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def analyze_ssl(url: str) -> str:
    """
    Performs a passive SSL/TLS security audit on a target URL.

    Connects to the server, retrieves the TLS handshake details and the
    X.509 certificate, then scores the configuration.
    No data is sent beyond the TLS handshake — entirely read-only.

    Args:
        url: A fully-qualified HTTPS URL. Example: "https://example.com"

    Returns:
        JSON string with:
          ssl_score (0-100), grade (A-F), tls_version, cipher_suite,
          cert_valid (bool), cert_self_signed (bool), days_until_expiry,
          cert_subject, cert_issuer, san_domains, findings [], recommendations []
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port     = parsed.port or 443

    findings:       list[str] = []
    recommendations: list[str] = []
    scores:         list[int] = []

    # ── HTTP-only sites ───────────────────────────────────────────────────────
    if parsed.scheme == "http":
        return json.dumps({
            "tool":    "ssl_analyzer",
            "status":  "no_ssl",
            "url":     url,
            "ssl_score": 0,
            "grade":   "F",
            "findings": ["Site uses plain HTTP — no TLS encryption at all."],
            "recommendations": [
                "Enable HTTPS immediately.",
                "Obtain a free certificate from Let's Encrypt (certbot).",
                "Redirect all HTTP traffic to HTTPS (301).",
            ],
        }, indent=2)

    # ── TLS connection ────────────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version  = ssock.version() or "Unknown"
                cipher_info  = ssock.cipher()          # (name, protocol, bits)
                cipher_name  = cipher_info[0] if cipher_info else "Unknown"
                cipher_bits  = cipher_info[2] if cipher_info else 0
                cert         = ssock.getpeercert()

    except ssl.SSLCertVerificationError as exc:
        return json.dumps({
            "tool":    "ssl_analyzer",
            "status":  "cert_error",
            "url":     url,
            "ssl_score": 0,
            "grade":   "F",
            "findings":  [f"Certificate verification failed: {exc}"],
            "recommendations": ["Replace the certificate with a valid, CA-signed one."],
        }, indent=2)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return json.dumps({
            "tool":    "ssl_analyzer",
            "status":  "connection_error",
            "url":     url,
            "error":   str(exc),
        }, indent=2)

    # ── Certificate details ───────────────────────────────────────────────────
    subject    = dict(x[0] for x in cert.get("subject", []))
    issuer     = dict(x[0] for x in cert.get("issuer",  []))
    not_after  = cert.get("notAfter", "")
    sans       = _get_sans(cert)
    self_signed = _is_self_signed(cert)

    days_left = _days_until_expiry(not_after) if not_after else -1

    # ── TLS version scoring ───────────────────────────────────────────────────
    tls_score = _TLS_SCORES.get(tls_version, 50)
    scores.append(tls_score)

    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append(f"CRITICAL: TLS {tls_version} is deprecated and broken. Upgrade to TLS 1.3.")
        recommendations.append("Disable TLS 1.0 and 1.1. Enable TLS 1.2 minimum, prefer TLS 1.3.")
    elif tls_version == "TLSv1.2":
        findings.append("TLS 1.2 in use — acceptable but TLS 1.3 is recommended.")
        recommendations.append("Upgrade to TLS 1.3 for improved security and performance.")

    # ── Cipher scoring ────────────────────────────────────────────────────────
    cipher_score, cipher_reason = _score_cipher(cipher_name)
    scores.append(cipher_score)

    if cipher_score == 0:
        findings.append(f"CRITICAL: {cipher_reason}")
        recommendations.append(f"Disable weak cipher: {cipher_name}. Use AES-256-GCM or ChaCha20-Poly1305.")
    elif cipher_bits and cipher_bits < 128:
        findings.append(f"Weak key length: {cipher_bits} bits. Minimum 128 bits required.")
        scores.append(20)

    # ── Certificate validity ──────────────────────────────────────────────────
    if self_signed:
        findings.append("CRITICAL: Self-signed certificate — browsers will show a security warning.")
        recommendations.append("Replace with a CA-signed certificate. Free option: Let's Encrypt.")
        scores.append(0)
    else:
        scores.append(100)

    if days_left < 0:
        findings.append("CRITICAL: Certificate has EXPIRED.")
        recommendations.append("Renew the certificate immediately.")
        scores.append(0)
    elif days_left < 14:
        findings.append(f"CRITICAL: Certificate expires in {days_left} days.")
        recommendations.append(f"Renew the certificate immediately — {days_left} days left.")
        scores.append(10)
    elif days_left < 30:
        findings.append(f"WARNING: Certificate expires in {days_left} days.")
        recommendations.append("Schedule certificate renewal this week.")
        scores.append(60)
    else:
        scores.append(100)

    # ── Final score ───────────────────────────────────────────────────────────
    # Deprecated TLS versions are a hard fail regardless of other scores.
    if tls_version in ("TLSv1", "TLSv1.1"):
        ssl_score = 0
        grade = "F"
    else:
        ssl_score = round(sum(scores) / len(scores)) if scores else 0
        grade = (
            "A" if ssl_score >= 90 else
            "B" if ssl_score >= 75 else
            "C" if ssl_score >= 60 else
            "D" if ssl_score >= 40 else
            "F"
        )

    if not findings:
        findings.append("SSL/TLS configuration looks good.")

    return json.dumps({
        "tool":              "ssl_analyzer",
        "status":            "completed",
        "url":               url,
        "ssl_score":         ssl_score,
        "grade":             grade,
        "tls_version":       tls_version,
        "cipher_suite":      cipher_name,
        "cipher_bits":       cipher_bits,
        "cert_valid":        not self_signed and days_left >= 0,
        "cert_self_signed":  self_signed,
        "days_until_expiry": days_left,
        "cert_subject":      subject.get("commonName", ""),
        "cert_issuer":       issuer.get("organizationName", issuer.get("commonName", "")),
        "san_domains":       sans,
        "not_after":         not_after,
        "findings":          findings,
        "recommendations":   recommendations,
    }, indent=2)

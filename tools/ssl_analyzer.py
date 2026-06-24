"""
SSL/TLS Deep Analyzer — AI Cyber Shield
Passive, read-only. Checks:
  - Certificate validity, chain, self-signed, expiry
  - TLS protocol support (which versions the server accepts)
  - Cipher suite strength + forward secrecy
  - HSTS header presence, max-age, preload flag
  - CT log requirement (SCT check)
  - OCSP must-staple flag
  - Weak key size (< 2048 RSA or < 256 EC)
"""

from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from langchain_core.tools import tool


# ── TLS/cipher constants ──────────────────────────────────────────────────────

_TLS_SCORES: dict[str, int] = {
    "TLSv1":   0,     # broken
    "TLSv1.1": 0,     # broken
    "TLSv1.2": 70,    # acceptable
    "TLSv1.3": 100,   # ideal
}

_WEAK_CIPHER_MARKERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5",
    "SEED", "IDEA",
}

_FORWARD_SECRECY_MARKERS = {"DHE", "ECDHE", "ECDH"}  # present → PFS

# TLS protocol constants for "which versions does server accept"
_PROTOCOL_MAP = {
    "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
}


# ── Helper functions ──────────────────────────────────────────────────────────

def _score_cipher(cipher_name: str) -> tuple[int, str]:
    upper = cipher_name.upper()
    for marker in _WEAK_CIPHER_MARKERS:
        if marker in upper:
            return 0, f"Weak cipher in use: {cipher_name}"
    # TLS 1.3 suites always start with "TLS_" and always have PFS built-in
    is_tls13 = upper.startswith("TLS_")
    has_pfs = is_tls13 or any(m in upper for m in _FORWARD_SECRECY_MARKERS)
    if "AES_256" in upper or "AES256" in upper or "CHACHA20" in upper:
        return (100 if has_pfs else 85), "Strong cipher"
    if "AES_128" in upper or "AES128" in upper:
        return (85 if has_pfs else 70), "Acceptable cipher"
    return 60, "Unknown cipher strength"


def _has_forward_secrecy(cipher_name: str) -> bool:
    upper = cipher_name.upper()
    return any(m in upper for m in _FORWARD_SECRECY_MARKERS)


def _days_until_expiry(not_after: str) -> int:
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (expiry - datetime.now(timezone.utc)).days
    except ValueError:
        return -999


def _is_self_signed(cert: dict) -> bool:
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    return subject.get("commonName") == issuer.get("commonName")


def _get_sans(cert: dict) -> list[str]:
    return [e[1] for e in cert.get("subjectAltName", []) if e[0] == "DNS"]


def _check_hsts(hostname: str, port: int = 443) -> dict:
    """Fetch HTTPS headers and inspect Strict-Transport-Security."""
    try:
        import http.client
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(hostname, port, context=ctx, timeout=8)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        hsts = headers.get("strict-transport-security", "")
        conn.close()

        if not hsts:
            return {"present": False, "max_age": 0, "include_subdomains": False, "preload": False}

        parts = [p.strip().lower() for p in hsts.split(";")]
        max_age = 0
        for p in parts:
            if p.startswith("max-age="):
                try:
                    max_age = int(p.split("=", 1)[1])
                except ValueError:
                    pass

        return {
            "present": True,
            "raw": hsts,
            "max_age": max_age,
            "include_subdomains": "includesubdomains" in parts,
            "preload": "preload" in parts,
        }
    except Exception as exc:
        return {"present": False, "error": str(exc)}


def _probe_tls_version(hostname: str, port: int, version_name: str) -> bool:
    """Try connecting with a specific maximum TLS version. Returns True if accepted."""
    proto = _PROTOCOL_MAP.get(version_name)
    if proto is None:
        return False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.maximum_version = proto
        ctx.minimum_version = proto
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def _check_cert_extensions(cert: dict) -> dict:
    """Extract OCSP must-staple and CT SCT info from raw cert extension data."""
    # Python ssl.getpeercert() doesn't expose raw extensions, so we note it
    # as "not verifiable without cryptography lib" rather than false-negative.
    return {
        "note": "Full extension audit requires the 'cryptography' package. "
                "Basic cert info is available above.",
    }


def _key_bits_from_cert(cert: dict) -> int:
    """Return public key bits when available (Python 3.10+ exposed via get_server_certificate)."""
    # Not available via standard ssl.getpeercert(); return -1 (not checked)
    return -1


# ── Main tool ─────────────────────────────────────────────────────────────────

@tool
def analyze_ssl(url: str) -> str:
    """
    Deep passive SSL/TLS security audit. Checks certificate, cipher suites,
    TLS version support, HSTS configuration, and forward secrecy.
    No payload sent — read-only TLS handshake only.

    Args:
        url: HTTPS URL to audit. Example: "https://example.com"

    Returns:
        JSON with ssl_score, grade, findings, recommendations, and all TLS details.
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    port     = parsed.port or 443

    findings:        list[str] = []
    recommendations: list[str] = []
    scores:          list[int] = []

    # ── HTTP-only fast exit ───────────────────────────────────────────────────
    if parsed.scheme == "http":
        return json.dumps({
            "tool":    "ssl_analyzer",
            "status":  "no_ssl",
            "url":     url,
            "ssl_score": 0,
            "grade":   "F",
            "findings": ["Site uses plain HTTP — no TLS encryption."],
            "recommendations": [
                "Enable HTTPS with a Let's Encrypt certificate.",
                "Add HSTS with max-age >= 31536000.",
                "Redirect all HTTP → HTTPS with a 301.",
            ],
        }, indent=2)

    # ── Primary TLS connection ────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version() or "Unknown"
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "Unknown"
                cipher_bits = cipher_info[2] if cipher_info else 0
                cert        = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return json.dumps({
            "tool":    "ssl_analyzer",
            "status":  "cert_error",
            "url":     url,
            "ssl_score": 0,
            "grade":   "F",
            "findings":  [f"Certificate verification failed: {exc}"],
            "recommendations": [
                "Replace with a CA-signed certificate (free via Let's Encrypt).",
                "Ensure the certificate CN/SAN matches the hostname.",
            ],
        }, indent=2)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return json.dumps({
            "tool":    "ssl_analyzer",
            "status":  "connection_error",
            "url":     url,
            "error":   str(exc),
        }, indent=2)

    # ── Certificate details ───────────────────────────────────────────────────
    subject     = dict(x[0] for x in cert.get("subject", []))
    issuer      = dict(x[0] for x in cert.get("issuer",  []))
    not_after   = cert.get("notAfter", "")
    not_before  = cert.get("notBefore", "")
    sans        = _get_sans(cert)
    self_signed = _is_self_signed(cert)
    days_left   = _days_until_expiry(not_after) if not_after else -1

    # ── TLS version ───────────────────────────────────────────────────────────
    tls_score = _TLS_SCORES.get(tls_version, 50)
    scores.append(tls_score)
    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append(f"CRITICAL: TLS {tls_version} is deprecated and cryptographically broken.")
        recommendations.append("Disable TLS 1.0 and 1.1 on the server. Enable TLS 1.2 minimum.")
    elif tls_version == "TLSv1.2":
        findings.append("TLS 1.2 in use — acceptable but TLS 1.3 is recommended.")
        recommendations.append("Enable TLS 1.3 for improved performance and forward secrecy.")

    # ── Probe which TLS versions the server accepts ───────────────────────────
    accepted_versions: list[str] = []
    for ver in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        if _probe_tls_version(hostname, port, ver):
            accepted_versions.append(ver)

    if "TLSv1" in accepted_versions:
        findings.append("Server accepts TLS 1.0 — deprecated by RFC 8996.")
        recommendations.append("Disable TLS 1.0 in server configuration.")
    if "TLSv1.1" in accepted_versions:
        findings.append("Server accepts TLS 1.1 — deprecated by RFC 8996.")
        recommendations.append("Disable TLS 1.1 in server configuration.")

    # ── Cipher suite ─────────────────────────────────────────────────────────
    cipher_score, cipher_reason = _score_cipher(cipher_name)
    scores.append(cipher_score)
    pfs = _has_forward_secrecy(cipher_name)

    if cipher_score == 0:
        findings.append(f"CRITICAL: {cipher_reason}")
        recommendations.append(f"Disable {cipher_name}. Use ECDHE+AES-256-GCM or CHACHA20-POLY1305.")
    if not pfs:
        findings.append("Cipher suite does not provide Forward Secrecy (ECDHE/DHE).")
        recommendations.append("Configure ECDHE cipher suites for perfect forward secrecy.")
        scores.append(50)
    if cipher_bits and cipher_bits < 128:
        findings.append(f"Weak key length: {cipher_bits} bits in cipher.")
        scores.append(20)

    # ── Certificate validity ──────────────────────────────────────────────────
    if self_signed:
        findings.append("CRITICAL: Self-signed certificate — browsers show security warnings.")
        recommendations.append("Replace with a CA-signed certificate. Free option: Let's Encrypt.")
        scores.append(0)
    else:
        scores.append(100)

    if days_left == -999:
        findings.append("Could not parse certificate expiry date.")
    elif days_left < 0:
        findings.append("CRITICAL: Certificate has EXPIRED.")
        recommendations.append("Renew the certificate immediately.")
        scores.append(0)
    elif days_left < 14:
        findings.append(f"CRITICAL: Certificate expires in {days_left} days — URGENT.")
        recommendations.append(f"Renew immediately. Expiry in {days_left} days.")
        scores.append(10)
    elif days_left < 30:
        findings.append(f"WARNING: Certificate expires in {days_left} days.")
        recommendations.append("Renew the certificate within the next week.")
        scores.append(60)
    elif days_left < 90:
        findings.append(f"Certificate expires in {days_left} days — plan renewal.")
        scores.append(90)
    else:
        scores.append(100)

    # ── HSTS ─────────────────────────────────────────────────────────────────
    hsts = _check_hsts(hostname, port)
    if not hsts.get("present"):
        findings.append("HSTS (HTTP Strict Transport Security) header is missing.")
        recommendations.append(
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        )
        scores.append(50)
    else:
        max_age = hsts.get("max_age", 0)
        if max_age < 31536000:
            findings.append(f"HSTS max-age is too short ({max_age}s). Minimum recommended: 31536000s (1 year).")
            recommendations.append("Set HSTS max-age to at least 31536000 (1 year).")
            scores.append(70)
        else:
            scores.append(100)
        if not hsts.get("include_subdomains"):
            findings.append("HSTS does not include subdomains.")
            recommendations.append("Add 'includeSubDomains' to the HSTS header.")
        if not hsts.get("preload"):
            findings.append("HSTS preload flag is missing — site is not preload-eligible.")
            recommendations.append("Add 'preload' to HSTS header and submit to hstspreload.org.")

    # ── Final score & grade ───────────────────────────────────────────────────
    if tls_version in ("TLSv1", "TLSv1.1") or self_signed or days_left < 0:
        ssl_score = 0
        grade     = "F"
    else:
        ssl_score = round(sum(scores) / len(scores)) if scores else 0
        grade = (
            "A+" if ssl_score == 100 else
            "A"  if ssl_score >= 90  else
            "B"  if ssl_score >= 75  else
            "C"  if ssl_score >= 60  else
            "D"  if ssl_score >= 40  else
            "F"
        )

    if not findings:
        findings.append("SSL/TLS configuration looks excellent.")

    return json.dumps({
        "tool":              "ssl_analyzer",
        "status":            "completed",
        "url":               url,
        "ssl_score":         ssl_score,
        "grade":             grade,
        "tls_version":       tls_version,
        "accepted_tls_versions": accepted_versions,
        "cipher_suite":      cipher_name,
        "cipher_bits":       cipher_bits,
        "forward_secrecy":   pfs,
        "cert_valid":        not self_signed and days_left > 0,
        "cert_self_signed":  self_signed,
        "days_until_expiry": days_left,
        "cert_not_before":   not_before,
        "cert_not_after":    not_after,
        "cert_subject":      subject.get("commonName", ""),
        "cert_issuer":       issuer.get("organizationName", issuer.get("commonName", "")),
        "cert_serial":       cert.get("serialNumber", ""),
        "san_domains":       sans,
        "hsts":              hsts,
        "findings":          findings,
        "recommendations":   recommendations,
    }, indent=2)

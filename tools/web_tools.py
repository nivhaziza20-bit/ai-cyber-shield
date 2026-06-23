"""
Web Security Headers Tool — Phase 1
Passive HTTP audit: one GET request, zero attack payloads.

Checks for the nine OWASP-recommended response headers, detects server
banner disclosure, and blocks SSRF attempts against private networks.
"""

import json
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from tools.http_utils import SSRFError, is_ssrf_blocked, safe_get

# ─────────────────────────────────────────────────────────────────────────────
# Reference data
# ─────────────────────────────────────────────────────────────────────────────

_SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
]

_DISCLOSURE_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
    "X-Runtime",
    "X-Version",
]

_HEADER_GUIDANCE: dict[str, str] = {
    "Strict-Transport-Security":
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy":
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
    "X-Content-Type-Options":
        "X-Content-Type-Options: nosniff",
    "X-Frame-Options":
        "X-Frame-Options: DENY",
    "X-XSS-Protection":
        "X-XSS-Protection: 1; mode=block",
    "Referrer-Policy":
        "Referrer-Policy: strict-origin-when-cross-origin",
    "Permissions-Policy":
        "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Embedder-Policy":
        "Cross-Origin-Embedder-Policy: require-corp",
    "Cross-Origin-Opener-Policy":
        "Cross-Origin-Opener-Policy: same-origin",
}


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def check_security_headers(url: str) -> str:
    """
    Performs a passive HTTP security-headers audit against a target URL.

    Issues a single GET request and inspects the response headers against
    the OWASP recommended set. No payloads are sent; this is read-only.
    Private / loopback addresses are blocked to prevent SSRF abuse.

    Args:
        url: A fully-qualified HTTP or HTTPS URL.
             Example: "https://example.com"

    Returns:
        JSON string with fields:
          tool, url, status_code, final_url (after redirects),
          security_score (0–100 % of recommended headers present),
          present_headers {name: value},
          missing_headers [name, …],
          recommendations [suggested header values for missing ones],
          information_disclosure {header: value} — server banners / tech stack,
          risk_summary string
    """
    # ── Input validation ──────────────────────────────────────────────────────
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({
            "tool": "security_headers",
            "status": "invalid_input",
            "error": f"Only http/https URLs allowed. Got: '{parsed.scheme}'",
        })

    # ── Request (SSRF-safe, redirect-aware, size-limited) ─────────────────────
    try:
        response = safe_get(url, timeout=15)
    except SSRFError as exc:
        return json.dumps({"tool": "security_headers", "status": "ssrf_blocked", "error": str(exc)})
    except requests.exceptions.SSLError as exc:
        return json.dumps({"tool": "security_headers", "status": "ssl_error", "error": str(exc)})
    except requests.exceptions.ConnectionError as exc:
        return json.dumps({"tool": "security_headers", "status": "connection_error", "error": str(exc)})
    except requests.exceptions.Timeout:
        return json.dumps({"tool": "security_headers", "status": "timeout", "error": "Request timed out"})

    # ── Header analysis ───────────────────────────────────────────────────────
    present: dict[str, str] = {}
    missing: list[str] = []

    for header in _SECURITY_HEADERS:
        value = response.headers.get(header)
        if value:
            present[header] = value
        else:
            missing.append(header)

    disclosure = {
        h: response.headers[h]
        for h in _DISCLOSURE_HEADERS
        if h in response.headers
    }

    security_score = round(len(present) / len(_SECURITY_HEADERS) * 100)

    if security_score >= 80:
        risk_summary = "LOW — Most security headers are in place."
    elif security_score >= 50:
        risk_summary = "MEDIUM — Several important headers are missing."
    else:
        risk_summary = "HIGH — The application is missing critical security headers."

    return json.dumps({
        "tool":                   "security_headers",
        "status":                 "completed",
        "url":                    url,
        "final_url":              response.url,
        "status_code":            response.status_code,
        "security_score":         security_score,
        "risk_summary":           risk_summary,
        "present_headers":        present,
        "missing_headers":        missing,
        "recommendations":        [_HEADER_GUIDANCE[h] for h in missing if h in _HEADER_GUIDANCE],
        "information_disclosure": disclosure,
    }, indent=2)

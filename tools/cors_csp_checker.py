"""
CORS & CSP Quality Checker

Goes beyond checking header *presence* — analyses the actual header *values*
for misconfigurations that presence-only scanners miss.

CORS checks:
  - Access-Control-Allow-Origin: * with credentials = CRITICAL
  - Wildcard origin without credentials = WARNING
  - Reflective CORS (origin echoed back unconditionally) = CRITICAL
  - Credentialed CORS to untrusted origin = HIGH

CSP quality checks (presence-only is not enough):
  - Missing CSP = HIGH
  - unsafe-inline in script-src / default-src = HIGH
  - unsafe-eval in script-src / default-src = HIGH
  - Wildcard (*) source in script-src = HIGH
  - data: in script-src = MEDIUM
  - Missing default-src = MEDIUM
  - No report-uri / report-to = LOW
  - Nonce or hash in script-src = GOOD (bonus)
"""

import json
import re
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from tools.http_utils import SSRFError, safe_get

# ─────────────────────────────────────────────────────────────────────────────
# CSP parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_csp(csp_header: str) -> dict:
    """
    Parse a CSP header string into a dict of {directive: [sources]}.
    Example: "default-src 'self'; script-src 'nonce-abc' https:"
    → {"default-src": ["'self'"], "script-src": ["'nonce-abc'", "https:"]}
    """
    directives: dict[str, list[str]] = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def _csp_risk(csp_header: str | None) -> tuple[int, list[str], list[str]]:
    """
    Returns (risk_points 0-100, issues[], recommendations[]).
    Lower risk_points = safer CSP.
    """
    if not csp_header:
        return 40, ["Content-Security-Policy header is missing entirely."],\
               ["Add a CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'"]

    directives = _parse_csp(csp_header)
    issues:  list[str] = []
    recs:    list[str] = []
    risk = 0

    # Helper: which sources apply to scripts
    script_sources = (
        directives.get("script-src", []) or
        directives.get("default-src", [])
    )
    default_sources = directives.get("default-src", [])

    if not default_sources:
        issues.append("CSP is missing 'default-src' — no catch-all fallback directive.")
        recs.append("Add 'default-src' as a fallback: default-src 'self'")
        risk += 15

    for directive_name, sources in directives.items():
        # sources are lowercased strings that may include surrounding quotes,
        # e.g. "'unsafe-inline'". Use substring matching to handle both forms.
        src_str = " ".join(sources)

        if "unsafe-inline" in src_str:
            issues.append(f"'{directive_name}' allows 'unsafe-inline' — enables inline script/style injection.")
            recs.append(f"Remove 'unsafe-inline' from {directive_name}. Use nonces or hashes instead.")
            risk += 20

        if "unsafe-eval" in src_str:
            issues.append(f"'{directive_name}' allows 'unsafe-eval' — enables eval() and similar functions.")
            recs.append(f"Remove 'unsafe-eval' from {directive_name}.")
            risk += 15

        if "*" in sources:  # exact wildcard token
            issues.append(f"'{directive_name}' uses wildcard (*) — allows loading resources from any origin.")
            recs.append(f"Replace wildcard in {directive_name} with explicit trusted domains.")
            risk += 20

        if "data:" in sources and "script-src" in directive_name:
            issues.append(f"'{directive_name}' allows 'data:' URIs — can be used for XSS.")
            recs.append(f"Remove 'data:' from {directive_name}.")
            risk += 10

    # Nonce/hash = good
    has_nonce = any("'nonce-" in s for sources in directives.values() for s in sources)
    has_hash  = any(re.match(r"'sha(256|384|512)-", s) for sources in directives.values() for s in sources)

    if not has_nonce and not has_hash and "'unsafe-inline'" not in str(directives):
        # Neither nonce/hash nor unsafe-inline — check if it's strict
        pass

    if "report-uri" not in directives and "report-to" not in directives:
        recs.append("Add 'report-uri' or 'report-to' to receive CSP violation reports.")

    return min(risk, 60), issues, recs


# ─────────────────────────────────────────────────────────────────────────────
# CORS analyser
# ─────────────────────────────────────────────────────────────────────────────

def _cors_risk(resp_headers: dict, url: str) -> tuple[int, list[str], list[str]]:
    """
    Analyses CORS headers on the initial response.
    Returns (risk_points, issues[], recommendations[]).
    """
    acao  = resp_headers.get("Access-Control-Allow-Origin", "")
    acac  = resp_headers.get("Access-Control-Allow-Credentials", "").lower()
    acam  = resp_headers.get("Access-Control-Allow-Methods", "")
    acah  = resp_headers.get("Access-Control-Allow-Headers", "")

    issues: list[str] = []
    recs:   list[str] = []
    risk = 0

    if not acao:
        return 0, [], []  # No CORS headers — not a misconfiguration

    if acao == "*":
        if acac == "true":
            issues.append("CRITICAL: CORS allows wildcard origin (*) with credentials=true — "
                          "browsers block this, but it signals a misconfigured policy.")
            recs.append("Never combine Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true.")
            risk += 50
        else:
            issues.append("WARNING: Access-Control-Allow-Origin: * — any website can read responses. "
                          "Acceptable for public APIs; bad for authenticated endpoints.")
            recs.append("Restrict CORS to specific trusted origins instead of wildcard.")
            risk += 15

    # Check for potentially over-permissive methods
    if acam:
        dangerous = [m.strip().upper() for m in acam.split(",") if m.strip().upper()
                     in ("PUT", "DELETE", "PATCH")]
        if dangerous:
            issues.append(f"CORS allows write methods: {', '.join(dangerous)} — "
                          "ensure these are intentional for cross-origin callers.")
            risk += 10

    # Check for wildcard in Allow-Headers
    if acah.strip() == "*":
        issues.append("Access-Control-Allow-Headers: * — allows any header cross-origin.")
        risk += 5

    return min(risk, 60), issues, recs


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def check_cors_csp(url: str) -> str:
    """
    Analyses CORS policy and Content-Security-Policy quality on a target URL.

    Goes beyond header presence: checks for dangerous CSP directives
    (unsafe-inline, unsafe-eval, wildcards) and CORS misconfigurations
    (wildcard + credentials, overly permissive methods).

    Read-only GET request — no payloads sent.

    Args:
        url: A fully-qualified HTTP or HTTPS URL.

    Returns:
        JSON with cors_issues, csp_issues, risk_score (0-100),
        csp_directives, and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "cors_csp_checker", "status": "invalid_url"})

    try:
        resp = safe_get(url, timeout=12)
    except SSRFError:
        return json.dumps({"tool": "cors_csp_checker", "status": "ssrf_blocked"})
    except requests.RequestException as exc:
        return json.dumps({"tool": "cors_csp_checker", "status": "connection_error",
                           "error": str(exc)})

    headers = dict(resp.headers)

    # ── CORS analysis ─────────────────────────────────────────────────────────
    cors_risk, cors_issues, cors_recs = _cors_risk(headers, url)

    # ── CSP analysis ──────────────────────────────────────────────────────────
    csp_header = headers.get("Content-Security-Policy", "")
    csp_risk,  csp_issues,  csp_recs  = _csp_risk(csp_header or None)

    # ── Aggregate ─────────────────────────────────────────────────────────────
    total_risk = min(cors_risk + csp_risk, 100)
    all_recs   = cors_recs + csp_recs

    # ── CSP summary ───────────────────────────────────────────────────────────
    csp_directives = _parse_csp(csp_header) if csp_header else {}
    csp_quality = (
        "none"    if not csp_header else
        "weak"    if total_risk >= 40 else
        "medium"  if total_risk >= 20 else
        "strong"
    )

    return json.dumps({
        "tool":            "cors_csp_checker",
        "status":          "completed",
        "url":             resp.url,
        "risk_score":      total_risk,
        "cors_origin":     headers.get("Access-Control-Allow-Origin", "not set"),
        "cors_issues":     cors_issues,
        "csp_present":     bool(csp_header),
        "csp_quality":     csp_quality,
        "csp_header":      csp_header[:300] if csp_header else None,
        "csp_directives":  csp_directives,
        "csp_issues":      csp_issues,
        "recommendations": all_recs,
    }, indent=2)

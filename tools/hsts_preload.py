"""
HSTS Preload Checker

Two-layer analysis beyond what the basic headers checker does:

Layer 1 — Header quality:
  - Missing HSTS header entirely
  - max-age below 1-year minimum (31 536 000 s)
  - Missing includeSubDomains → subdomains can be served over HTTP
  - Missing preload directive → cannot be submitted to preload list

Layer 2 — Preload list status (via hstspreload.org public API):
  - preloaded  → browsers enforce HTTPS before ever connecting (gold standard)
  - eligible   → header is correct; submit to hstspreload.org
  - pending    → submission in progress
  - unknown    → not yet submitted
  - error      → API unreachable

Preload list membership eliminates SSL-strip and first-connection MITM attacks.
"""
import json
import re
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from tools.http_utils import SSRFError, safe_get

_MIN_MAX_AGE   = 31_536_000        # 1 year in seconds
_PRELOAD_API   = "https://hstspreload.org/api/v2/status?domain={domain}"


def _parse_hsts(header: str) -> dict:
    """Parse a Strict-Transport-Security header value into components."""
    result = {"max_age": 0, "include_sub": False, "preload_directive": False}
    for part in header.split(";"):
        part = re.sub(r"\s*=\s*", "=", part.strip().lower())  # normalise spaces around =
        if part.startswith("max-age="):
            m = re.search(r"\d+", part)
            if m:
                result["max_age"] = int(m.group())
        elif part == "includesubdomains":
            result["include_sub"] = True
        elif part == "preload":
            result["preload_directive"] = True
    return result


def _query_preload_list(domain: str) -> str:
    """Query hstspreload.org API. Returns status string or 'api_error'."""
    try:
        resp = requests.get(
            _PRELOAD_API.format(domain=domain),
            timeout=8,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            return resp.json().get("status", "unknown")
    except Exception:
        pass
    return "api_error"


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def check_hsts_preload(url: str) -> str:
    """
    Checks HSTS header quality and preload list membership for the target domain.

    Inspects the Strict-Transport-Security header for completeness
    (max-age, includeSubDomains, preload directive) and queries the public
    hstspreload.org API to determine actual preload list status.

    Args:
        url: Target HTTP/HTTPS URL.

    Returns:
        JSON with hsts_present, hsts_quality (none/weak/medium/strong),
        preloaded (bool), preload_status, risk_score, and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "hsts_preload", "status": "invalid_url"})

    hostname = parsed.hostname or ""
    domain   = hostname.lstrip("www.")

    try:
        resp = safe_get(url, timeout=12)
    except SSRFError:
        return json.dumps({"tool": "hsts_preload", "status": "ssrf_blocked"})
    except requests.RequestException as exc:
        return json.dumps({"tool": "hsts_preload", "status": "connection_error",
                           "error": str(exc)})

    hsts_header  = resp.headers.get("Strict-Transport-Security", "")
    hsts_present = bool(hsts_header)

    issues: list[str] = []
    recs:   list[str] = []
    risk = 0

    if not hsts_present:
        issues.append("Strict-Transport-Security header is absent.")
        recs.append(
            "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        )
        risk += 30
        parsed_hsts  = {}
        hsts_quality = "none"
    else:
        parsed_hsts = _parse_hsts(hsts_header)
        max_age     = parsed_hsts["max_age"]

        if max_age < _MIN_MAX_AGE:
            issues.append(
                f"max-age={max_age:,}s is below the 1-year minimum ({_MIN_MAX_AGE:,}s). "
                "Browsers may not cache the HSTS policy long enough."
            )
            recs.append(f"Set max-age to at least {_MIN_MAX_AGE} (1 year).")
            risk += 15

        if not parsed_hsts["include_sub"]:
            issues.append(
                "includeSubDomains missing — subdomains can be served over plain HTTP "
                "even if the root domain uses HSTS."
            )
            recs.append("Add includeSubDomains to cover all subdomains.")
            risk += 10

        if not parsed_hsts["preload_directive"]:
            issues.append(
                "preload directive absent — domain cannot be submitted to browser preload lists."
            )
            recs.append("Add preload directive and submit to hstspreload.org.")
            risk += 10

        if max_age >= _MIN_MAX_AGE and parsed_hsts["include_sub"] and parsed_hsts["preload_directive"]:
            hsts_quality = "strong"
        elif max_age >= _MIN_MAX_AGE and parsed_hsts["include_sub"]:
            hsts_quality = "medium"
        elif max_age > 0:
            hsts_quality = "weak"
        else:
            hsts_quality = "none"

    # ── Preload list lookup ────────────────────────────────────────────────────
    preload_status = _query_preload_list(domain) if domain else "unknown"
    preloaded      = preload_status == "preloaded"

    if preloaded:
        risk = max(0, risk - 20)  # preloaded = strong protection
    elif hsts_present and preload_status not in ("api_error", "unknown"):
        recs.append(
            f"Domain preload status: '{preload_status}'. "
            "Submit to hstspreload.org to get into all major browser preload lists."
        )

    return json.dumps({
        "tool":             "hsts_preload",
        "status":           "completed",
        "url":              resp.url,
        "domain":           domain,
        "risk_score":       min(risk, 60),
        "hsts_present":     hsts_present,
        "hsts_quality":     hsts_quality,
        "hsts_header":      hsts_header or None,
        "parsed_hsts":      parsed_hsts,
        "preloaded":        preloaded,
        "preload_status":   preload_status,
        "issues":           issues,
        "recommendations":  recs,
    }, indent=2)

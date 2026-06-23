"""
Cookie Security Scanner

Performs a deep analysis of Set-Cookie headers returned by the target URL.
Checks every cookie for compliance with OWASP Session Management best practices
and browser-enforced cookie security mechanisms.

Checks performed
────────────────
  Secure flag        — required on HTTPS; missing = cookie sent over HTTP too
  HttpOnly flag      — prevents JavaScript document.cookie access (XSS mitigation)
  SameSite attribute — CSRF protection: Strict > Lax > None (None = cross-site allowed)
  __Secure- prefix   — browser enforces Secure; flag must be present
  __Host- prefix     — browser enforces Secure + Path=/ + no Domain; strongest binding
  Domain scope       — overly-broad domain (e.g. .example.com) shares cookie with subdomains
  Expiry             — session cookies vs persistent cookies
  Partitioned (CHIPS)— opt-in cookie partitioning for third-party contexts

Risk scoring
────────────
  Missing Secure on auth/session cookie (HTTPS target)   +40
  Missing Secure on other cookie (HTTPS target)           +25
  Missing HttpOnly on auth/session cookie                 +30
  Missing HttpOnly on regular cookie                      +15
  SameSite=None without Secure                            +35
  SameSite missing on auth/session cookie                 +20
  SameSite=None (cross-site allowed)                      +10
  __Secure- prefix without Secure flag                    +25
  __Host- prefix violations                               +20
  Overly broad domain on auth/session cookie              +15
  Score capped at 80 to leave headroom for other tools.

SSRF protection: is_ssrf_blocked() before every network request.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

from tools.http_utils import is_ssrf_blocked

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_UA = "AICyberShield-Scanner/1.0 (security audit - authorized use only)"

# Cookie name patterns that suggest the cookie carries authentication state.
_AUTH_COOKIE_RE = re.compile(
    r"(session|sess|token|auth|jwt|access|refresh|id|login|user|account|sid|uid|csrf)",
    re.IGNORECASE,
)

_RISK_CAP = 80


# ─────────────────────────────────────────────────────────────────────────────
# Cookie attribute parser (pure Python — testable without network)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_set_cookie(header_value: str) -> dict:
    """
    Parse a raw Set-Cookie header string into a structured dict.

    Returns:
        {
            "name":        str,
            "value_len":   int,      # length only — value never stored
            "secure":      bool,
            "httponly":    bool,
            "samesite":    str|None, # "Strict", "Lax", "None", or None (missing)
            "domain":      str|None,
            "path":        str|None,
            "expires":     str|None,
            "max_age":     int|None,
            "partitioned": bool,
            "prefix":      str|None, # "__Secure-" | "__Host-" | None
        }
    """
    parts = [p.strip() for p in header_value.split(";")]
    if not parts:
        return {}

    # First part is name=value
    name_val = parts[0]
    if "=" in name_val:
        name, value = name_val.split("=", 1)
    else:
        name, value = name_val, ""
    name  = name.strip()
    value = value.strip()

    attrs = {p.lower(): True for p in parts[1:]}
    attr_kv: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attr_kv[k.strip().lower()] = v.strip()

    samesite_raw = attr_kv.get("samesite")
    samesite = samesite_raw.capitalize() if samesite_raw else None

    prefix = None
    if name.startswith("__Host-"):
        prefix = "__Host-"
    elif name.startswith("__Secure-"):
        prefix = "__Secure-"

    max_age = None
    if "max-age" in attr_kv:
        try:
            max_age = int(attr_kv["max-age"])
        except ValueError:
            pass

    return {
        "name":        name,
        "value_len":   len(value),
        "secure":      "secure" in attrs,
        "httponly":    "httponly" in attrs,
        "samesite":    samesite,
        "domain":      attr_kv.get("domain"),
        "path":        attr_kv.get("path"),
        "expires":     attr_kv.get("expires"),
        "max_age":     max_age,
        "partitioned": "partitioned" in attrs,
        "prefix":      prefix,
    }


def _is_auth_cookie(name: str) -> bool:
    """Return True if the cookie name suggests it carries authentication state."""
    return bool(_AUTH_COOKIE_RE.search(name))


def _audit_cookie(cookie: dict, is_https: bool) -> list[dict]:
    """
    Run all security checks on a single parsed cookie.

    Returns a list of issue dicts: {"check", "severity", "description", "risk"}.
    """
    issues: list[dict] = []
    name   = cookie.get("name", "")
    is_auth = _is_auth_cookie(name)
    prefix  = cookie.get("prefix")

    # ── Secure flag ────────────────────────────────────────────────────────────
    if is_https and not cookie["secure"]:
        risk = 40 if is_auth else 25
        issues.append({
            "check":       "Secure flag missing",
            "severity":    "HIGH" if is_auth else "MEDIUM",
            "description": (
                f"Cookie '{name}' is missing the Secure flag on an HTTPS site. "
                "It will be transmitted over unencrypted HTTP connections, "
                "exposing it to network eavesdropping."
            ),
            "risk": risk,
        })

    # ── HttpOnly flag ──────────────────────────────────────────────────────────
    if not cookie["httponly"]:
        risk = 30 if is_auth else 15
        issues.append({
            "check":       "HttpOnly flag missing",
            "severity":    "HIGH" if is_auth else "LOW",
            "description": (
                f"Cookie '{name}' lacks HttpOnly. JavaScript can read it via "
                "document.cookie — XSS attacks can steal this cookie."
            ),
            "risk": risk,
        })

    # ── SameSite attribute ─────────────────────────────────────────────────────
    samesite = cookie.get("samesite")
    if samesite is None:
        # Missing SameSite — modern browsers default to Lax but it's not explicit
        if is_auth:
            issues.append({
                "check":       "SameSite attribute missing",
                "severity":    "MEDIUM",
                "description": (
                    f"Auth cookie '{name}' has no SameSite attribute. "
                    "Add SameSite=Lax or Strict for CSRF protection."
                ),
                "risk": 20,
            })
    elif samesite == "None":
        if not cookie["secure"]:
            issues.append({
                "check":       "SameSite=None without Secure",
                "severity":    "HIGH",
                "description": (
                    f"Cookie '{name}' sets SameSite=None but is missing the Secure flag. "
                    "Modern browsers will REJECT this cookie (RFC 6265bis §5.3.7). "
                    "Additionally, SameSite=None allows cross-site requests."
                ),
                "risk": 35,
            })
        else:
            issues.append({
                "check":       "SameSite=None (cross-site allowed)",
                "severity":    "INFO",
                "description": (
                    f"Cookie '{name}' allows cross-site requests (SameSite=None). "
                    "Acceptable for third-party embed scenarios only. "
                    "Consider Lax or Strict if this cookie is for same-site auth."
                ),
                "risk": 10,
            })

    # ── Cookie prefix compliance ───────────────────────────────────────────────
    if prefix == "__Secure-" and not cookie["secure"]:
        issues.append({
            "check":       "__Secure- prefix without Secure flag",
            "severity":    "HIGH",
            "description": (
                f"Cookie '{name}' uses the __Secure- prefix but is missing the Secure flag. "
                "Browsers will REJECT this cookie (RFC 6265bis §4.1.3)."
            ),
            "risk": 25,
        })

    if prefix == "__Host-":
        violations: list[str] = []
        if not cookie["secure"]:
            violations.append("missing Secure flag")
        if cookie.get("domain"):
            violations.append(f"has Domain={cookie['domain']} (must be absent)")
        if cookie.get("path") != "/":
            violations.append(f"Path={cookie.get('path')!r} (must be '/')")
        if violations:
            issues.append({
                "check":       "__Host- prefix violations",
                "severity":    "HIGH",
                "description": (
                    f"Cookie '{name}' uses __Host- prefix but violates constraints: "
                    + "; ".join(violations) + ". Browsers will REJECT this cookie."
                ),
                "risk": 20,
            })

    # ── Domain scope ───────────────────────────────────────────────────────────
    domain = cookie.get("domain") or ""
    if domain.startswith(".") and is_auth:
        issues.append({
            "check":       "Broad domain scope on auth cookie",
            "severity":    "LOW",
            "description": (
                f"Auth cookie '{name}' is scoped to '{domain}' — it is sent to ALL "
                "subdomains. A compromised subdomain can access this cookie."
            ),
            "risk": 15,
        })

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# Core scan (pure logic — testable independently of HTTP)
# ─────────────────────────────────────────────────────────────────────────────

def _audit_all_cookies(
    raw_set_cookie_headers: list[str],
    is_https: bool,
) -> tuple[list[dict], list[dict], int]:
    """
    Parse and audit every Set-Cookie header.

    Returns:
        (cookies_parsed, all_issues, risk_score)
    Exposed for direct testing.
    """
    cookies: list[dict] = []
    all_issues: list[dict] = []

    for raw in raw_set_cookie_headers:
        parsed = _parse_set_cookie(raw)
        if not parsed.get("name"):
            continue
        issues = _audit_cookie(parsed, is_https)
        parsed["issues"] = [i["check"] for i in issues]
        cookies.append(parsed)
        all_issues.extend(issues)

    risk_score = min(sum(i["risk"] for i in all_issues), _RISK_CAP)
    return cookies, all_issues, risk_score


# ─────────────────────────────────────────────────────────────────────────────
# HTTP fetch (kept separate for testability)
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_set_cookie_headers(url: str) -> list[str]:
    """
    Make a single GET to the URL and return all raw Set-Cookie header values.
    Uses httpx so we can access multiple values for the same header name.
    Merges thread-local scan auth (cookies + headers) when an authenticated
    scan is in progress.
    """
    from tools.http_utils import get_scan_auth
    auth_headers, auth_cookies = get_scan_auth()

    req_headers = {"User-Agent": _UA, **auth_headers}

    timeout = httpx.Timeout(10.0, connect=6.0)
    with httpx.Client(
        headers=req_headers,
        cookies=auth_cookies if auth_cookies else None,
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        resp = client.get(url)

    # httpx exposes multiple headers with the same name via headers.get_list()
    return resp.headers.get_list("set-cookie")


# ─────────────────────────────────────────────────────────────────────────────
# @tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def scan_cookie_security(url: str) -> str:
    """
    Fetches the target URL and deeply audits every Set-Cookie header for security
    misconfigurations: Secure, HttpOnly, SameSite, cookie prefixes (__Secure-/__Host-),
    domain scope, and SameSite=None usage.

    Args:
        url: Target HTTP or HTTPS URL.

    Returns:
        JSON with cookies_found, issues list, risk_score (0-80), and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "cookie_security", "status": "invalid_url"})

    hostname = parsed.hostname or ""
    if is_ssrf_blocked(hostname):
        return json.dumps({"tool": "cookie_security", "status": "ssrf_blocked"})

    is_https = parsed.scheme == "https"

    try:
        raw_headers = _fetch_set_cookie_headers(url)
    except Exception as exc:
        return json.dumps({"tool": "cookie_security", "status": "error", "error": str(exc)})

    if not raw_headers:
        return json.dumps({
            "tool":            "cookie_security",
            "status":          "completed",
            "url":             url,
            "is_https":        is_https,
            "cookies_found":   0,
            "cookies":         [],
            "issues":          [],
            "issue_count":     0,
            "risk_score":      0,
            "recommendations": [
                "No cookies set by this page. If the application uses sessions, "
                "ensure session cookies are audited after authentication."
            ],
        })

    cookies, all_issues, risk_score = _audit_all_cookies(raw_headers, is_https)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []

    no_secure = [c for c in cookies if is_https and not c["secure"]]
    if no_secure:
        names = ", ".join(c["name"] for c in no_secure[:3])
        recommendations.append(
            f"CRITICAL: Cookies missing Secure flag on HTTPS site: {names}. "
            "Add 'Secure' to every Set-Cookie directive. "
            "nginx: `add_header Set-Cookie \"name=value; Secure; HttpOnly; SameSite=Lax\"`"
        )

    no_httponly = [c for c in cookies if not c["httponly"] and _is_auth_cookie(c["name"])]
    if no_httponly:
        names = ", ".join(c["name"] for c in no_httponly[:3])
        recommendations.append(
            f"Auth cookies without HttpOnly: {names}. "
            "HttpOnly prevents XSS-driven cookie theft — add it to all session cookies."
        )

    samesite_none = [c for c in cookies if c.get("samesite") == "None"]
    if samesite_none:
        names = ", ".join(c["name"] for c in samesite_none[:3])
        recommendations.append(
            f"Cookies with SameSite=None: {names}. "
            "These are sent in cross-site requests. Verify this is intentional "
            "(e.g., needed for OAuth iframe embed). Use SameSite=Lax for auth cookies."
        )

    samesite_missing = [
        c for c in cookies
        if c.get("samesite") is None and _is_auth_cookie(c["name"])
    ]
    if samesite_missing:
        names = ", ".join(c["name"] for c in samesite_missing[:3])
        recommendations.append(
            f"Auth cookies missing SameSite: {names}. "
            "Add SameSite=Lax for CSRF protection. "
            "Express: `res.cookie('session', val, {{ sameSite: 'lax', httpOnly: true }})`"
        )

    if not recommendations:
        recommendations.append(
            "All cookies appear to have appropriate security attributes. "
            "Periodically re-audit after authentication flow changes."
        )

    # Strip value from cookie output (never log cookie values)
    safe_cookies = [{k: v for k, v in c.items() if k != "value_len"} for c in cookies]

    return json.dumps({
        "tool":            "cookie_security",
        "status":          "completed",
        "url":             url,
        "is_https":        is_https,
        "cookies_found":   len(cookies),
        "cookies":         safe_cookies,
        "issues":          all_issues,
        "issue_count":     len(all_issues),
        "risk_score":      risk_score,
        "recommendations": recommendations,
    }, indent=2)

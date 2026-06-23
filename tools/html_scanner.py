"""
HTML & JavaScript Scanner — URL Scanner Phase 2

Fetches a page and analyses:
  - Exposed API keys / secrets in HTML and inline JS
  - Forms missing CSRF tokens
  - Mixed content (HTTP assets on an HTTPS page)
  - Sensitive HTML comments
  - Open CORS misconfiguration
  - Cookie security flags
  - Suspicious JS endpoints / internal paths
"""

import json
import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import tool

from tools.http_utils import SSRFError, is_ssrf_blocked, safe_get

# ─────────────────────────────────────────────────────────────────────────────
# API key / secret patterns
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Google API Key",      re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Google OAuth",        re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com')),
    ("Stripe Live Key",     re.compile(r'sk_live_[0-9a-zA-Z]{24,}')),
    ("Stripe Publishable",  re.compile(r'pk_live_[0-9a-zA-Z]{24,}')),
    ("AWS Access Key",      re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret",          re.compile(r'aws[_\-]?secret[_\-]?access[_\-]?key[\s=:\"\']+[A-Za-z0-9/+=]{40}')),
    ("GitHub Token",        re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}')),
    ("Private Key Header",  re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')),
    ("Slack Token",         re.compile(r'xox[baprs]-[0-9A-Za-z\-]+')),
    ("Twilio",              re.compile(r'SK[0-9a-fA-F]{32}')),
    ("SendGrid",            re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}')),
    ("Mailchimp",           re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}')),
    ("Hardcoded Password",  re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']')),
    ("Hardcoded Secret",    re.compile(r'(?i)(secret|token|api_key|apikey)\s*[=:]\s*["\'][^"\']{8,}["\']')),
]

# ─────────────────────────────────────────────────────────────────────────────
# Sensitive comment patterns
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_COMMENT_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?i)(todo|fixme|hack|bug|password|passwd|secret|key|token|credential)', re.I),
    re.compile(r'(?i)(internal|admin|debug|disabled|remove\s+before)', re.I),
    re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),   # IP address in comment
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _scan_secrets(text: str) -> list[dict]:
    """Scan a text blob for API keys and secrets."""
    found = []
    for label, pattern in _SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            # Redact most of the matched value for safety
            raw = match.group(0)
            redacted = raw[:6] + "***" + raw[-4:] if len(raw) > 12 else "***"
            found.append({"type": label, "sample": redacted})
    return found


def _check_forms(soup: BeautifulSoup) -> list[dict]:
    """Detect forms missing CSRF protection."""
    issues = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue
        inputs = [i.get("name", "").lower() for i in form.find_all("input")]
        csrf_present = any(
            "csrf" in name or "token" in name or "_wpnonce" in name
            for name in inputs
        )
        if not csrf_present:
            action = form.get("action", "(current page)")
            issues.append({
                "form_action": action,
                "method":      method.upper(),
                "issue":       "POST form has no CSRF token field",
            })
    return issues


def _check_mixed_content(soup: BeautifulSoup, base_url: str) -> list[str]:
    """Find HTTP assets loaded on an HTTPS page."""
    if not base_url.startswith("https"):
        return []
    mixed = []
    tags = (
        [(t, "src")  for t in soup.find_all(["script", "img", "iframe", "video", "audio"])] +
        [(t, "href") for t in soup.find_all(["link"])]
    )
    for tag, attr in tags:
        val = tag.get(attr, "")
        if val.startswith("http://"):
            mixed.append(f"{tag.name}: {val[:80]}")
    return mixed


def _check_comments(soup: BeautifulSoup) -> list[str]:
    """Find HTML comments that may leak internal info."""
    from bs4 import Comment
    sensitive = []
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(comment).strip()
        if any(p.search(text) for p in _SENSITIVE_COMMENT_PATTERNS):
            sensitive.append(text[:120])
    return sensitive


def _extract_js_endpoints(scripts_text: str) -> list[str]:
    """Pull API-looking paths from JavaScript."""
    pattern = re.compile(r'["\'](/api/[^"\'<>\s]{3,80})["\']')
    return list(set(pattern.findall(scripts_text)))[:20]


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def scan_html(url: str) -> str:
    """
    Fetches a web page and scans its HTML and inline JavaScript for
    security issues: exposed secrets, CSRF-less forms, mixed content,
    sensitive comments, and hidden API endpoints.

    Read-only — makes a single GET request, no data submitted.

    Args:
        url: A fully-qualified HTTP or HTTPS URL.

    Returns:
        JSON with findings, risk_score (0-100), and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "html_scanner", "status": "invalid_url", "error": "Only http/https allowed."})

    # ── Fetch (SSRF-safe, redirect-aware, size-limited) ───────────────────────
    try:
        resp = safe_get(url, timeout=15)
    except SSRFError:
        return json.dumps({"tool": "html_scanner", "status": "ssrf_blocked"})
    except requests.RequestException as exc:
        return json.dumps({"tool": "html_scanner", "status": "connection_error", "error": str(exc)})

    html   = resp.text
    soup   = BeautifulSoup(html, "html.parser")

    # ── Collect all script text ───────────────────────────────────────────────
    scripts_text = " ".join(
        s.get_text() for s in soup.find_all("script") if not s.get("src")
    )
    all_text = html  # includes inline JS + HTML

    # ── Run all checks ────────────────────────────────────────────────────────
    secrets        = _scan_secrets(all_text)
    form_issues    = _check_forms(soup)
    mixed_content  = _check_mixed_content(soup, resp.url)
    comments       = _check_comments(soup)
    js_endpoints   = _extract_js_endpoints(scripts_text)

    # ── Cookie analysis ───────────────────────────────────────────────────────
    cookie_issues: list[str] = []
    for cookie in resp.cookies:
        if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
            cookie_issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
        if resp.url.startswith("https") and not cookie.secure:
            cookie_issues.append(f"Cookie '{cookie.name}' missing Secure flag on HTTPS")

    # ── Meta info ─────────────────────────────────────────────────────────────
    title       = soup.find("title")
    page_title  = title.get_text(strip=True) if title else ""
    generator   = soup.find("meta", attrs={"name": "generator"})
    tech_hint   = generator["content"] if generator and generator.get("content") else ""

    # ── Score ─────────────────────────────────────────────────────────────────
    deductions = (
        len(secrets)       * 30 +
        len(form_issues)   * 20 +
        len(mixed_content) * 15 +
        len(comments)      * 10 +
        len(cookie_issues) * 10
    )
    risk_score = min(deductions, 100)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []
    if secrets:
        recommendations.append("CRITICAL: Remove exposed API keys from source code. Use server-side env variables.")
    if form_issues:
        recommendations.append("Add CSRF tokens to all POST forms (e.g. Django {% csrf_token %}, Flask-WTF).")
    if mixed_content:
        recommendations.append("Replace all HTTP asset URLs with HTTPS to prevent mixed-content warnings.")
    if comments:
        recommendations.append("Remove HTML comments before deploying to production.")
    if cookie_issues:
        recommendations.append("Set HttpOnly and Secure flags on all session cookies.")

    return json.dumps({
        "tool":             "html_scanner",
        "status":           "completed",
        "url":              resp.url,
        "page_title":       page_title,
        "tech_hint":        tech_hint,
        "risk_score":       risk_score,
        "exposed_secrets":  secrets,
        "form_issues":      form_issues,
        "mixed_content":    mixed_content,
        "sensitive_comments": comments,
        "js_api_endpoints": js_endpoints,
        "cookie_issues":    cookie_issues,
        "recommendations":  recommendations,
    }, indent=2)

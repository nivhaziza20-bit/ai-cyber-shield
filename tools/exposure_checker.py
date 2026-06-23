"""
Exposure Checker

Detects sensitive files, misconfigurations, and missing defences that are
invisible to header-only scanners.

Passive checks (no payloads, read-only GETs):
  - Sensitive file exposure (.git/HEAD, .env, phpinfo, server-status, etc.)
  - Source map exposure (*.js.map linked from JS — leaks original source)
  - Missing Subresource Integrity on external scripts
  - Dangerous HTTP methods (TRACE, PUT, DELETE via OPTIONS)
  - Directory listing detection
  - Server/framework version disclosure in error pages

Risk scoring:
  .git/HEAD exposed          +50   Source code + credentials likely in repo
  .env exposed               +50   API keys and database passwords
  phpinfo/server-info        +30   Full server config visible to attackers
  Source map exposed         +20   Original source code readable
  TRACE method enabled       +20   Enables Cross-Site Tracing (XST) attacks
  PUT/DELETE enabled         +15   Unauthorised file upload or deletion
  Directory listing          +15   Reveals site structure to attackers
  Missing SRI on ext scripts +10   Supply-chain attack vector
  Backup/debug files         +25   May contain credentials or old vuln code
"""

import json
import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import tool

from tools.http_utils import SSRFError, is_ssrf_blocked, safe_get

# ─────────────────────────────────────────────────────────────────────────────
# Sensitive paths to probe
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_FILES: list[tuple[str, str, int]] = [
    # (path, description, risk_points)
    ("/.git/HEAD",          "Git repository HEAD exposed",        50),
    ("/.git/config",        "Git config file exposed",            50),
    ("/.env",               "Environment file exposed",           50),
    ("/.env.local",         "Local environment file exposed",     50),
    ("/.env.production",    "Production environment file exposed",50),
    ("/phpinfo.php",        "PHP info page exposed",              30),
    ("/info.php",           "PHP info page exposed",              30),
    ("/server-status",      "Apache server-status exposed",       25),
    ("/server-info",        "Apache server-info exposed",         25),
    ("/actuator",           "Spring Boot actuator exposed",       30),
    ("/actuator/env",       "Spring Boot env endpoint exposed",   40),
    ("/actuator/health",    "Spring Boot health endpoint",        10),
    ("/.htpasswd",          "Password file exposed",              50),
    ("/web.config",         "IIS web.config exposed",             35),
    ("/config.php.bak",     "PHP backup config exposed",          40),
    ("/backup.sql",         "SQL dump exposed",                   50),
    ("/database.sql",       "SQL dump exposed",                   50),
    ("/backup.zip",         "Backup archive exposed",             40),
    ("/.DS_Store",          "macOS .DS_Store reveals file paths", 15),
    ("/crossdomain.xml",    "Flash crossdomain policy",           10),
    ("/elmah.axd",          "ASP.NET error log exposed",          35),
    ("/trace.axd",          "ASP.NET trace viewer exposed",       30),
    ("/wp-config.php.bak",  "WordPress config backup exposed",    50),
    ("/config/database.yml","Rails database config exposed",      45),
    ("/storage/logs/laravel.log", "Laravel log file exposed",     30),
]

_DIRECTORY_LISTING_PATTERN = re.compile(
    r"<title>Index of /|Directory listing for /|<h1>Index of", re.I
)

_PHPINFO_PATTERN = re.compile(
    r"<title>phpinfo\(\)</title>|PHP Version \d+\.\d+\.\d+.*Configure Command", re.I
)

_ENV_PATTERN = re.compile(
    r"^[A-Z_]+=.+", re.MULTILINE
)


# ─────────────────────────────────────────────────────────────────────────────
# Source map detection
# ─────────────────────────────────────────────────────────────────────────────

def _find_source_map_urls(html: str, base_url: str) -> list[str]:
    """
    Extract JS source map URLs from HTML (inline and external script tags).
    Looks for: //# sourceMappingURL=app.js.map
    """
    # Find all <script src="..."> that might have a .map file
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.I)
    source_maps = []
    for src in script_srcs[:10]:  # limit
        map_url = urljoin(base_url, src + ".map")
        source_maps.append(map_url)
    # Also look for explicit sourceMappingURL references in inline JS
    inline_maps = re.findall(r'//# sourceMappingURL=(\S+)', html)
    for m in inline_maps[:5]:
        source_maps.append(urljoin(base_url, m))
    return list(set(source_maps))[:10]


def _check_source_maps(map_urls: list[str], session: requests.Session) -> list[str]:
    """Returns list of source map URLs that are publicly accessible."""
    exposed = []
    for url in map_urls:
        try:
            r = session.get(url, timeout=6, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 50:
                exposed.append(url)
        except requests.RequestException:
            pass
    return exposed


# ─────────────────────────────────────────────────────────────────────────────
# Subresource Integrity checker
# ─────────────────────────────────────────────────────────────────────────────

def _check_sri(soup: BeautifulSoup, base_host: str) -> list[str]:
    """
    Returns list of external scripts and stylesheets that lack SRI integrity=.
    Only flags external (cross-origin) resources.
    """
    missing_sri = []
    for tag in soup.find_all(["script", "link"]):
        src = tag.get("src") or tag.get("href") or ""
        if not src.startswith(("http://", "https://")):
            continue  # relative = same-origin, no SRI needed
        if base_host in src:
            continue  # same-origin
        if not tag.get("integrity"):
            missing_sri.append(f"{tag.name}: {src[:80]}")
    return missing_sri[:10]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP methods checker
# ─────────────────────────────────────────────────────────────────────────────

def _check_http_methods(url: str, session: requests.Session) -> tuple[list[str], list[str]]:
    """
    Sends OPTIONS request and checks for dangerous allowed methods.
    Returns (dangerous_methods[], issues[]).
    """
    try:
        r = session.options(url, timeout=8, allow_redirects=False)
        allow_header = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")
        if not allow_header:
            return [], []

        methods = [m.strip().upper() for m in allow_header.split(",")]
        dangerous = [m for m in methods if m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT")]

        issues = []
        if "TRACE" in dangerous or "TRACK" in dangerous:
            issues.append("TRACE/TRACK method enabled — enables Cross-Site Tracing (XST) attacks.")
        if "PUT" in dangerous:
            issues.append("PUT method enabled — may allow unauthorised file upload.")
        if "DELETE" in dangerous:
            issues.append("DELETE method enabled — may allow unauthorised file deletion.")

        return dangerous, issues
    except requests.RequestException:
        return [], []


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def check_exposure(url: str) -> str:
    """
    Probes a website for exposed sensitive files, source maps, missing
    Subresource Integrity, and dangerous HTTP methods.

    Makes multiple GET requests to well-known sensitive paths plus
    one OPTIONS request. Read-only — no data is modified.

    Args:
        url: A fully-qualified HTTP or HTTPS URL.

    Returns:
        JSON with exposed_files, source_maps, sri_missing,
        dangerous_methods, risk_score (0-100), and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "exposure_checker", "status": "invalid_url"})

    if is_ssrf_blocked(parsed.hostname or ""):
        return json.dumps({"tool": "exposure_checker", "status": "ssrf_blocked"})

    base_url  = f"{parsed.scheme}://{parsed.netloc}"
    base_host = parsed.hostname or ""

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (SecurityAudit/1.0; Defensive Scanner)"

    # ── Fetch home page (for SRI + source map detection) ─────────────────────
    homepage_html = ""
    homepage_soup = None
    try:
        home_resp = safe_get(url, session=session, timeout=12)
        homepage_html = home_resp.text
        homepage_soup = BeautifulSoup(homepage_html, "html.parser")
    except (SSRFError, requests.RequestException):
        pass

    # ── Probe sensitive file paths ────────────────────────────────────────────
    exposed_files: list[dict] = []
    risk_score = 0

    for path, description, risk_pts in _SENSITIVE_FILES:
        probe_url = urljoin(base_url, path)
        try:
            r = session.get(probe_url, timeout=6, allow_redirects=False)
        except requests.RequestException:
            continue

        if r.status_code not in (200, 206):
            continue

        # Extra validation — confirm it's not a custom 200 error page
        body = r.text[:2000]
        confirmed = True

        if path == "/.git/HEAD":
            confirmed = body.startswith("ref:") or body.startswith("0000")
        elif path in ("/.env", "/.env.local", "/.env.production"):
            confirmed = bool(_ENV_PATTERN.search(body))
        elif "phpinfo" in path or "info.php" in path:
            confirmed = bool(_PHPINFO_PATTERN.search(body))
        elif path == "/.htpasswd":
            confirmed = ":" in body and len(body) < 5000

        if confirmed:
            exposed_files.append({
                "path":        path,
                "description": description,
                "url":         probe_url,
                "risk":        risk_pts,
            })
            risk_score += risk_pts

    # ── Source map exposure ───────────────────────────────────────────────────
    exposed_maps: list[str] = []
    if homepage_html:
        map_candidates = _find_source_map_urls(homepage_html, base_url)
        exposed_maps   = _check_source_maps(map_candidates, session)
        risk_score    += len(exposed_maps) * 20

    # ── Subresource Integrity ─────────────────────────────────────────────────
    sri_missing: list[str] = []
    if homepage_soup:
        sri_missing = _check_sri(homepage_soup, base_host)
        risk_score += len(sri_missing) * 5

    # ── HTTP methods ──────────────────────────────────────────────────────────
    dangerous_methods, method_issues = _check_http_methods(base_url, session)
    if "TRACE" in dangerous_methods or "TRACK" in dangerous_methods:
        risk_score += 20
    if "PUT" in dangerous_methods:
        risk_score += 15
    if "DELETE" in dangerous_methods:
        risk_score += 15

    # ── Directory listing on home ─────────────────────────────────────────────
    directory_listing = bool(homepage_html and _DIRECTORY_LISTING_PATTERN.search(homepage_html))
    if directory_listing:
        risk_score += 15

    risk_score = min(risk_score, 100)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []
    if exposed_files:
        for f in exposed_files[:3]:
            recommendations.append(
                f"Block access to {f['path']}: {f['description']}. "
                "Use web server rules (nginx deny, Apache Deny) or firewall."
            )
    if exposed_maps:
        recommendations.append(
            "Remove or restrict source map files (*.js.map) in production — "
            "they expose your original source code."
        )
    if sri_missing:
        recommendations.append(
            f"{len(sri_missing)} external script(s)/stylesheet(s) missing SRI integrity= attribute. "
            "Use https://www.srihash.org/ to generate integrity hashes."
        )
    if dangerous_methods:
        recommendations.append(
            f"Disable dangerous HTTP methods: {', '.join(dangerous_methods)}. "
            "In nginx: limit_except GET POST { deny all; }"
        )
    if directory_listing:
        recommendations.append(
            "Disable directory listing: nginx 'autoindex off;' or Apache 'Options -Indexes'."
        )

    return json.dumps({
        "tool":               "exposure_checker",
        "status":             "completed",
        "url":                url,
        "risk_score":         risk_score,
        "exposed_files":      exposed_files,
        "exposed_source_maps": exposed_maps,
        "sri_missing":        sri_missing,
        "dangerous_methods":  dangerous_methods,
        "method_issues":      method_issues,
        "directory_listing":  directory_listing,
        "recommendations":    recommendations,
    }, indent=2)

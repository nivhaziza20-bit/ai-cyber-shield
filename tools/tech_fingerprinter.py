"""
Technology Fingerprinter — URL Scanner Phase 3

Detects what software stack a website runs on, then maps known
vulnerable versions to CVEs.

Detects:
  - CMS: WordPress, Joomla, Drupal, Shopify, Wix, Squarespace
  - Frameworks: Django, Laravel, Rails, ASP.NET, Next.js, Nuxt
  - JS libraries: jQuery, React, Angular, Vue (with version)
  - Servers: nginx, Apache, IIS, Cloudflare (via headers)
  - Analytics / trackers: GA4, GTM, Hotjar, Facebook Pixel
  - Known vulnerable versions → CVE references
"""

import json
import logging
import re
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from tools.http_utils import SSRFError, is_ssrf_blocked, safe_get

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Detection signatures
# Each entry: (technology_name, detection_type, pattern/header/path)
# ─────────────────────────────────────────────────────────────────────────────

# HTML/JS content patterns
_HTML_SIGNATURES: list[tuple[str, re.Pattern]] = [
    # CMS
    ("WordPress",    re.compile(r'/wp-content/|/wp-includes/|wp-json', re.I)),
    ("Joomla",       re.compile(r'/components/com_|Joomla!', re.I)),
    ("Drupal",       re.compile(r'Drupal\.settings|/sites/default/files/', re.I)),
    ("Shopify",      re.compile(r'cdn\.shopify\.com|Shopify\.theme', re.I)),
    ("Wix",          re.compile(r'static\.wixstatic\.com|wix\.com/lpvideo', re.I)),
    ("Squarespace",  re.compile(r'squarespace\.com|static1\.squarespace', re.I)),
    # Frameworks
    ("Django",       re.compile(r'csrfmiddlewaretoken|__django', re.I)),
    ("Laravel",      re.compile(r'laravel_session|Laravel', re.I)),
    ("Ruby on Rails",re.compile(r'authenticity_token.*rails|rails-ujs', re.I)),
    ("Next.js",      re.compile(r'__NEXT_DATA__|/_next/static/', re.I)),
    ("Nuxt.js",      re.compile(r'__NUXT__|/_nuxt/', re.I)),
    ("ASP.NET",      re.compile(r'__VIEWSTATE|ASP\.NET', re.I)),
    # Analytics
    ("Google Analytics", re.compile(r'google-analytics\.com/analytics\.js|gtag\(', re.I)),
    ("Google Tag Manager", re.compile(r'googletagmanager\.com/gtm\.js', re.I)),
    ("Facebook Pixel",    re.compile(r'connect\.facebook\.net.*fbevents', re.I)),
    ("Hotjar",            re.compile(r'static\.hotjar\.com', re.I)),
]

# Server / response header patterns
_HEADER_SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    # (tech_name, header_name, value_pattern)
    ("nginx",       "Server",    re.compile(r'nginx', re.I)),
    ("Apache",      "Server",    re.compile(r'Apache', re.I)),
    ("IIS",         "Server",    re.compile(r'Microsoft-IIS', re.I)),
    ("Cloudflare",  "Server",    re.compile(r'cloudflare', re.I)),
    ("LiteSpeed",   "Server",    re.compile(r'LiteSpeed', re.I)),
    ("PHP",         "X-Powered-By", re.compile(r'PHP', re.I)),
    ("ASP.NET",     "X-Powered-By", re.compile(r'ASP\.NET', re.I)),
    ("Express.js",  "X-Powered-By", re.compile(r'Express', re.I)),
]

# JavaScript library version extractors
_JS_VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jQuery",  re.compile(r'jquery[.-](\d+\.\d+[\.\d]*)(\.min)?\.js', re.I)),
    ("jQuery",  re.compile(r'[Jj]query.*v?(\d+\.\d+[\.\d]*)')),
    ("React",   re.compile(r'react(?:\.development|\.production\.min)?\.js.*?(\d+\.\d+[\.\d]*)', re.I)),
    ("Angular", re.compile(r'@angular/core.*?(\d+\.\d+[\.\d]*)', re.I)),
    ("Vue.js",  re.compile(r'vue(?:\.min)?\.js.*?(\d+\.\d+[\.\d]*)', re.I)),
    ("Bootstrap",re.compile(r'bootstrap[.-](\d+\.\d+[\.\d]*)', re.I)),
]

# Fallback: hardcoded known vulnerabilities used when cve_feed is unavailable
# (offline mode, rate limiting, import error). cve_feed.py is the primary source.
_FALLBACK_VULNS: list[tuple[str, str, str, str]] = [
    ("jQuery",   "3.5.0", "CVE-2019-11358", "Prototype pollution via $.extend()"),
    ("jQuery",   "1.12.0","CVE-2015-9251",  "XSS via location.hash"),
    ("Bootstrap","4.3.0", "CVE-2019-8331",  "XSS via data-template attribute"),
    ("Bootstrap","3.4.0", "CVE-2018-14040", "XSS in data-target"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _version_tuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return (0,)


def _check_cves_live(tech: str, version: str) -> list[dict]:
    """
    Fetch CVEs for tech+version from the real-time CVE feed (NVD+GitHub+OSV+EPSS).
    Falls back to hardcoded table if the feed is unavailable.
    """
    try:
        from tools.cve_feed import enrich_technology
        records = enrich_technology(tech, version)
        return [
            {
                "cve":             r.cve_id,
                "affected":        r.affects_versions or f"{tech} (detected: {version})",
                "detected":        version,
                "description":     r.description or r.title,
                "severity":        r.severity,
                "cvss_score":      r.cvss_score,
                "epss_score":      r.epss_score,
                "exploit_available": r.exploit_available,
                "fixed_version":   r.fixed_version,
                "sources":         r.sources,
            }
            for r in records
        ]
    except Exception as exc:
        _log.debug("CVE feed unavailable for %s %s, using fallback: %s", tech, version, exc)
        return _check_fallback_cves(tech, version)


def _check_fallback_cves(tech: str, version: str) -> list[dict]:
    """Hardcoded CVE table — used when cve_feed.py is unreachable."""
    issues = []
    ver_t = _version_tuple(version)
    for vuln_tech, safe_from, cve, desc in _FALLBACK_VULNS:
        if vuln_tech.lower() != tech.lower():
            continue
        if ver_t < _version_tuple(safe_from):
            issues.append({
                "cve":         cve,
                "affected":    f"{tech} < {safe_from}",
                "detected":    version,
                "description": desc,
                "severity":    "HIGH",
            })
    return issues


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def fingerprint_technologies(url: str) -> str:
    """
    Detects the technology stack of a website (CMS, framework, JS libraries,
    server software) and maps detected versions to known CVEs.

    Makes a single GET request — read-only, no payloads.

    Args:
        url: A fully-qualified HTTP or HTTPS URL.

    Returns:
        JSON with detected_technologies, versioned_libraries, cve_findings,
        risk_score (0-100), and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "tech_fingerprinter", "status": "invalid_url"})

    try:
        resp = safe_get(url, timeout=15)
    except SSRFError:
        return json.dumps({"tool": "tech_fingerprinter", "status": "ssrf_blocked"})
    except requests.RequestException as exc:
        return json.dumps({"tool": "tech_fingerprinter", "status": "connection_error", "error": str(exc)})

    html    = resp.text
    headers = resp.headers

    # ── HTML/JS signature detection ───────────────────────────────────────────
    detected: list[str] = []
    for tech_name, pattern in _HTML_SIGNATURES:
        if pattern.search(html) and tech_name not in detected:
            detected.append(tech_name)

    # ── Header-based detection ────────────────────────────────────────────────
    server_info: dict[str, str] = {}
    for tech_name, header_name, pattern in _HEADER_SIGNATURES:
        val = headers.get(header_name, "")
        if val and pattern.search(val):
            if tech_name not in detected:
                detected.append(tech_name)
            server_info[tech_name] = val

    # ── Version extraction ────────────────────────────────────────────────────
    versioned: list[dict] = []
    seen_libs: set[str] = set()

    # Also scan <script src> attributes for versioned filenames
    script_sources = " ".join(re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I))
    scan_text = html + " " + script_sources

    for lib_name, pattern in _JS_VERSION_PATTERNS:
        if lib_name in seen_libs:
            continue
        match = pattern.search(scan_text)
        if match:
            version = match.group(1)
            seen_libs.add(lib_name)
            if lib_name not in detected:
                detected.append(lib_name)
            versioned.append({"library": lib_name, "version": version})

    # ── CVE check (live feed with fallback) ──────────────────────────────────
    cve_findings: list[dict] = []
    for entry in versioned:
        cves = _check_cves_live(entry["library"], entry["version"])
        cve_findings.extend(cves)

    # ── WordPress version (special case — often in meta generator) ────────────
    wp_ver_match = re.search(r'WordPress (\d+\.\d+[\.\d]*)', html, re.I)
    if wp_ver_match:
        wp_version = wp_ver_match.group(1)
        versioned.append({"library": "WordPress", "version": wp_version})
        # Try live CVE feed first; fallback to static check
        wp_cves = _check_cves_live("WordPress", wp_version)
        if wp_cves:
            cve_findings.extend(wp_cves)
        elif _version_tuple(wp_version) < (6, 4, 0):
            cve_findings.append({
                "cve":         "WP-OUTDATED",
                "affected":    "WordPress < 6.4",
                "detected":    wp_version,
                "description": "Outdated WordPress — check for available security updates.",
                "severity":    "MEDIUM",
            })

    # ── Risk score ────────────────────────────────────────────────────────────
    risk_score = min(len(cve_findings) * 25 + len(server_info) * 5, 100)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []
    if cve_findings:
        for cve in cve_findings:
            recommendations.append(
                f"Update {cve['affected'].split('<')[0].strip()} — {cve['description']} ({cve['cve']})"
            )
    if "PHP" in server_info:
        recommendations.append("Remove or mask X-Powered-By: PHP header to avoid version disclosure.")
    if any(s in detected for s in ("ASP.NET",)) and "X-Powered-By" in str(server_info):
        recommendations.append("Remove X-Powered-By header from ASP.NET responses.")
    if "WordPress" in detected and not wp_ver_match:
        recommendations.append("Verify WordPress is up to date — version not visible in page source.")

    return json.dumps({
        "tool":                   "tech_fingerprinter",
        "status":                 "completed",
        "url":                    resp.url,
        "detected_technologies":  detected,
        "server_info":            server_info,
        "versioned_libraries":    versioned,
        "cve_findings":           cve_findings,
        "risk_score":             risk_score,
        "recommendations":        recommendations,
    }, indent=2)

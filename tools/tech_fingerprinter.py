"""
Technology Fingerprinter — URL Scanner Phase 3

Detects what software stack a website runs on using the Wappalyzer community
database (7 537 technologies as of 2026-06), then maps detected versions to
live CVE findings via the multi-source CVE feed.

Detection surfaces (pure-Python, no browser):
  html / scriptSrc / scripts — HTML content & script URL patterns
  headers                    — HTTP response header patterns
  meta                       — <meta> tag content patterns
  url / cookies              — URL and cookie name/value patterns

Implies chains:
  e.g. detecting WordPress automatically adds PHP + MySQL at confidence 75.
"""

import json
import logging
import re
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from tools.http_utils import SSRFError, safe_get
from tools.wappalyzer_engine import detect_technologies

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Fallback CVE table — used when cve_feed.py is unreachable
# ─────────────────────────────────────────────────────────────────────────────

_FALLBACK_VULNS: list[tuple[str, str, str, str]] = [
    ("jQuery",   "3.5.0",  "CVE-2019-11358", "Prototype pollution via $.extend()"),
    ("jQuery",   "1.12.0", "CVE-2015-9251",  "XSS via location.hash"),
    ("Bootstrap","4.3.0",  "CVE-2019-8331",  "XSS via data-template attribute"),
    ("Bootstrap","3.4.0",  "CVE-2018-14040", "XSS in data-target"),
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
    Fetch CVEs from the real-time NVD+GitHub+OSV+EPSS feed.
    Falls back to hardcoded table on error/unavailability.
    """
    try:
        from tools.cve_feed import enrich_technology
        records = enrich_technology(tech, version)
        return [
            {
                "cve":               r.cve_id,
                "affected":          r.affects_versions or f"{tech} (detected: {version})",
                "detected":          version,
                "description":       r.description or r.title,
                "severity":          r.severity,
                "cvss_score":        r.cvss_score,
                "epss_score":        r.epss_score,
                "exploit_available": r.exploit_available,
                "fixed_version":     r.fixed_version,
                "sources":           r.sources,
            }
            for r in records
        ]
    except Exception as exc:
        _log.debug("CVE feed unavailable for %s %s: %s", tech, version, exc)
        return _fallback_cves(tech, version)


def _fallback_cves(tech: str, version: str) -> list[dict]:
    """Hardcoded CVE table — offline / rate-limited fallback."""
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


# backward-compat alias used by tests and external callers
_check_fallback_cves = _fallback_cves


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def fingerprint_technologies(url: str) -> str:
    """
    Detects the technology stack of a website (CMS, framework, JS libraries,
    server software) using the Wappalyzer database (7 500+ technologies) and
    maps detected versions to known CVEs.

    Makes a single GET request — read-only, no payloads.

    Args:
        url: A fully-qualified HTTP or HTTPS URL.

    Returns:
        JSON with detected_technologies, versioned_libraries, cve_findings,
        detection_count, risk_score (0-100), and recommendations.
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
    headers = dict(resp.headers)

    # ── Wappalyzer-based detection (7 537 technologies) ───────────────────────
    matches = detect_technologies(html, headers, url=str(resp.url))

    detected: list[str] = []
    server_info: dict[str, str] = {}
    versioned: list[dict] = []

    for m in matches:
        if m.name not in detected:
            detected.append(m.name)
        if m.version:
            versioned.append({"library": m.name, "version": m.version})
        # Capture server-type headers for recommendations
        server_hdr = headers.get("Server", "") or headers.get("server", "")
        if server_hdr and re.search(
            rf'\b{re.escape(m.name)}\b', server_hdr, re.I
        ):
            server_info[m.name] = server_hdr

    # Expose PHP/ASP.NET via X-Powered-By (Wappalyzer catches these via headers
    # patterns, but we also want them in server_info for recommendations)
    xpb = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
    if xpb:
        for tech in ("PHP", "ASP.NET"):
            if re.search(tech, xpb, re.I):
                server_info[tech] = xpb
                if tech not in detected:
                    detected.append(tech)

    # ── CVE lookup for versioned libraries ───────────────────────────────────
    cve_findings: list[dict] = []
    seen_cve_libs: set[str] = set()
    for entry in versioned:
        lib = entry["library"]
        if lib in seen_cve_libs:
            continue
        seen_cve_libs.add(lib)
        cve_findings.extend(_check_cves_live(lib, entry["version"]))

    # ── Risk score ────────────────────────────────────────────────────────────
    risk_score = min(len(cve_findings) * 25 + len(server_info) * 5, 100)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []
    for cve in cve_findings:
        base = cve["affected"].split("<")[0].strip()
        recommendations.append(
            f"Update {base} — {cve['description']} ({cve['cve']})"
        )
    if "PHP" in server_info:
        recommendations.append(
            "Remove or mask X-Powered-By: PHP header to avoid version disclosure."
        )
    if "ASP.NET" in server_info:
        recommendations.append(
            "Remove X-Powered-By: ASP.NET header — discloses platform and version."
        )
    if "WordPress" in detected:
        wp_versioned = next(
            (e for e in versioned if e["library"] == "WordPress"), None
        )
        if not wp_versioned:
            recommendations.append(
                "Verify WordPress is up to date — version not detectable from page source."
            )

    return json.dumps({
        "tool":                  "tech_fingerprinter",
        "status":                "completed",
        "url":                   str(resp.url),
        "detected_technologies": detected,
        "detection_count":       len(detected),
        "server_info":           server_info,
        "versioned_libraries":   versioned,
        "cve_findings":          cve_findings,
        "risk_score":            risk_score,
        "recommendations":       recommendations,
    }, indent=2)

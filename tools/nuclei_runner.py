"""
tools/nuclei_runner.py — Nuclei template scanner (PT mode only)

Nuclei is an open-source, template-based vulnerability scanner by ProjectDiscovery.
It runs read-only HTTP checks (GET/HEAD probes) against a target using community
templates that detect CVEs, misconfigurations, and exposed panels.

Authorization requirement
─────────────────────────
This tool is gated behind PT mode — active scanning against a target you do not
own or have written permission to test may violate the CFAA, CMA, or local law.
The caller (url_scanner_pipeline.py) MUST check scan_auth.pt_approved before
invoking this tool.

SSRF protection
───────────────
The target URL hostname is validated via is_ssrf_blocked() before any probe.
Nuclei is run as a subprocess with a short wall-clock timeout.

Installation
────────────
Nuclei is a standalone Go binary (~40 MB).  It is NOT installed via pip.
Download from: https://github.com/projectdiscovery/nuclei/releases
Place the binary at one of:
  - /usr/local/bin/nuclei          (Linux/Mac)
  - C:\\tools\\nuclei.exe           (Windows)
  - Path listed in NUCLEI_PATH env var

Template updates:  nuclei -update-templates  (run periodically, not on every scan)

Rate limiting + stealth
────────────────────────
Default concurrency is capped at 5 goroutines and rate-limited at 50 req/s to
avoid triggering WAF/IDS on the target.  This is conservative but polite.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from langchain_core.tools import tool

from tools.http_utils import is_ssrf_blocked

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Binary resolution
# ─────────────────────────────────────────────────────────────────────────────

_NUCLEI_SEARCH_PATHS = [
    os.environ.get("NUCLEI_PATH", ""),
    "/usr/local/bin/nuclei",
    "/usr/bin/nuclei",
    str(Path.home() / "go" / "bin" / "nuclei"),
    r"C:\tools\nuclei.exe",
    r"C:\ProgramData\nuclei\nuclei.exe",
]

# Template categories to include by default in PT mode.
# Excludes DoS, brute-force, and intrusive templates.
_DEFAULT_TEMPLATE_TAGS = "cve,misconfig,exposed-panels,takeover,default-login"

# Hard timeout: no single Nuclei run may exceed this
_NUCLEI_TIMEOUT_S = 120

# Conservative rate limits to avoid alarming WAFs / IDS
_NUCLEI_RATE_LIMIT   = "50"    # requests per second
_NUCLEI_CONCURRENCY  = "5"     # parallel goroutines


def _find_nuclei_binary() -> str | None:
    """Locate the nuclei binary.  Returns full path or None if not found."""
    # 1. shutil.which honours $PATH (works on Linux/Mac/Windows)
    which_result = shutil.which("nuclei")
    if which_result:
        return which_result
    # 2. Check hardcoded paths
    for path_str in _NUCLEI_SEARCH_PATHS:
        if path_str and Path(path_str).is_file():
            return path_str
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Output parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_nuclei_jsonl(output: str) -> list[dict]:
    """
    Parse Nuclei JSONL output (-json flag) into a list of finding dicts.
    Each Nuclei finding line is one JSON object.
    """
    findings: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            findings.append({
                "template_id":   obj.get("template-id", ""),
                "template_name": obj.get("info", {}).get("name", ""),
                "severity":      obj.get("info", {}).get("severity", "info").upper(),
                "description":   obj.get("info", {}).get("description", ""),
                "matched_at":    obj.get("matched-at", ""),
                "tags":          obj.get("info", {}).get("tags", []),
                "cvss_score":    obj.get("info", {}).get("classification", {}).get("cvss-score", 0.0),
                "cve_id":        (obj.get("info", {}).get("classification", {}).get("cve-id") or [""])[0],
            })
        except (json.JSONDecodeError, TypeError, KeyError):
            pass
    return findings


def _severity_to_risk(severity: str) -> int:
    """Map Nuclei severity string to a 0-100 additive risk integer."""
    return {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0}.get(severity, 0)


# ─────────────────────────────────────────────────────────────────────────────
# @tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def run_nuclei_scan(url: str) -> str:
    """
    Run a Nuclei template scan against the target URL (PT mode only).

    Uses community templates tagged: cve, misconfig, exposed-panels,
    takeover, default-login.  Read-only probes (no exploitation).

    Args:
        url: A fully-qualified HTTPS or HTTP URL.  Must be an authorised target.

    Returns:
        JSON with findings list, risk_score (0-100), nuclei_version, and
        recommendations.  Returns status=not_installed if the nuclei binary
        is not found.
    """
    # ── SSRF guard ────────────────────────────────────────────────────────────
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname:
        return json.dumps({"tool": "nuclei_runner", "status": "invalid_url"})

    if is_ssrf_blocked(hostname):
        return json.dumps({"tool": "nuclei_runner", "status": "ssrf_blocked"})

    # ── Binary check ──────────────────────────────────────────────────────────
    nuclei_bin = _find_nuclei_binary()
    if not nuclei_bin:
        return json.dumps({
            "tool":   "nuclei_runner",
            "status": "not_installed",
            "message": (
                "nuclei binary not found.  Install from "
                "https://github.com/projectdiscovery/nuclei/releases "
                "and place it in $PATH or set NUCLEI_PATH env var."
            ),
        })

    # ── Get nuclei version ────────────────────────────────────────────────────
    try:
        ver_result = subprocess.run(
            [nuclei_bin, "-version"],
            capture_output=True, text=True, timeout=10,
        )
        nuclei_version = ver_result.stdout.strip() or ver_result.stderr.strip()
    except Exception:
        nuclei_version = "unknown"

    # ── Build command ─────────────────────────────────────────────────────────
    cmd = [
        nuclei_bin,
        "-target",      url,
        "-tags",        _DEFAULT_TEMPLATE_TAGS,
        "-json",                                  # machine-readable output
        "-silent",                                # no progress banner
        "-no-color",
        "-rate-limit",  _NUCLEI_RATE_LIMIT,
        "-concurrency", _NUCLEI_CONCURRENCY,
        "-timeout",     "10",                     # per-request timeout (seconds)
        "-max-host-error", "3",                   # give up after 3 consecutive host errors
    ]

    _log.info("Running nuclei against %s with tags: %s", hostname, _DEFAULT_TEMPLATE_TAGS)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_NUCLEI_TIMEOUT_S,
        )
        raw_output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return json.dumps({
            "tool":    "nuclei_runner",
            "status":  "timeout",
            "message": f"Nuclei scan exceeded {_NUCLEI_TIMEOUT_S}s timeout.",
        })
    except OSError as exc:
        return json.dumps({
            "tool":    "nuclei_runner",
            "status":  "execution_error",
            "error":   str(exc),
        })

    # ── Parse findings ────────────────────────────────────────────────────────
    findings = _parse_nuclei_jsonl(raw_output)

    risk_score = min(sum(_severity_to_risk(f["severity"]) for f in findings), 100)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []
    for f in sorted(findings, key=lambda x: _severity_to_risk(x["severity"]), reverse=True)[:8]:
        sev = f["severity"]
        name = f["template_name"] or f["template_id"]
        cve = f" ({f['cve_id']})" if f["cve_id"] else ""
        recommendations.append(f"[{sev}] {name}{cve} — {f['description'][:120]}")

    if not findings:
        recommendations.append(
            "Nuclei found no issues with the selected templates — "
            "consider expanding to additional tag sets for deeper coverage."
        )

    return json.dumps({
        "tool":            "nuclei_runner",
        "status":          "completed",
        "url":             url,
        "nuclei_version":  nuclei_version,
        "templates_tags":  _DEFAULT_TEMPLATE_TAGS,
        "findings":        findings,
        "finding_count":   len(findings),
        "risk_score":      risk_score,
        "recommendations": recommendations,
    }, indent=2)

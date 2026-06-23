"""
VirusTotal Tool — Phase 1
Wraps VirusTotal API v3 as a LangChain tool.

Flow:
  1. Encode the URL to VT's base64url format (their canonical ID).
  2. Try a GET first — VirusTotal caches results, so we skip re-submission
     when the URL was analysed recently.
  3. If not cached, POST to submit, then poll the analysis endpoint with
     exponential backoff until status == "completed".
  4. Normalise the raw API response into a compact, agent-readable JSON.

Rate limits (free tier): 4 requests/min, 500/day.
The tenacity retry decorator handles transient 429 responses automatically.
"""

import base64
import json
import os
import time
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from config import get_settings

VT_BASE = "https://www.virustotal.com/api/v3"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _vt_headers() -> dict:
    api_key = get_settings().virustotal_api_key
    if not api_key:
        raise ValueError("VIRUSTOTAL_API_KEY is not set")
    return {"x-apikey": api_key, "Accept": "application/json"}


def _url_id(url: str) -> str:
    """VirusTotal canonical URL identifier: base64url(url) without padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _validate_url(url: str) -> str | None:
    """Returns an error string if the URL is unsafe, else None."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"Only http/https URLs are allowed. Got scheme: '{parsed.scheme}'"
    if not parsed.hostname:
        return "URL has no hostname."
    return None


@retry(
    retry=retry_if_exception_type(requests.HTTPError),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(4),
    reraise=True,
)
def _vt_get(path: str) -> requests.Response:
    resp = requests.get(f"{VT_BASE}{path}", headers=_vt_headers(), timeout=30)
    if resp.status_code == 429:
        resp.raise_for_status()  # triggers tenacity retry
    return resp


@retry(
    retry=retry_if_exception_type(requests.HTTPError),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(4),
    reraise=True,
)
def _vt_post(path: str, data: dict) -> requests.Response:
    resp = requests.post(
        f"{VT_BASE}{path}", headers=_vt_headers(), data=data, timeout=30
    )
    if resp.status_code == 429:
        resp.raise_for_status()
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def check_url_virustotal(url: str) -> str:
    """
    Checks a URL's reputation against 70+ security vendors via VirusTotal API v3.

    Retrieves malicious/suspicious verdict counts, per-vendor results,
    URL categories, and computes a 0–100 risk score.

    Args:
        url: A fully-qualified HTTP or HTTPS URL to inspect.
             Example: "https://example.com/login"

    Returns:
        JSON string with fields:
          tool, url, threat_level (CLEAN/LOW/MEDIUM/HIGH/CRITICAL),
          risk_score (0–100), analysis_stats {malicious/suspicious/undetected/…},
          total_engines_checked, flagged_by {vendor: {category, result}},
          categories, reputation, tags, last_analysis_date
    """
    err = _validate_url(url)
    if err:
        return json.dumps({"tool": "virustotal", "status": "invalid_input", "error": err})

    url_id = _url_id(url)

    try:
        # ── Step 1: check cache ───────────────────────────────────────────────
        cached = _vt_get(f"/urls/{url_id}")
        if cached.status_code == 200:
            return json.dumps(_normalise_vt_report(cached.json(), url), indent=2)

        # ── Step 2: submit for analysis ───────────────────────────────────────
        submit = _vt_post("/urls", {"url": url})
        submit.raise_for_status()
        analysis_id = submit.json()["data"]["id"]

        # ── Step 3: poll with exponential back-off ────────────────────────────
        delays = [3, 6, 12, 20, 30]
        for delay in delays:
            time.sleep(delay)
            poll = _vt_get(f"/analyses/{analysis_id}")
            poll.raise_for_status()
            status = (
                poll.json()
                .get("data", {})
                .get("attributes", {})
                .get("status", "")
            )
            if status == "completed":
                final = _vt_get(f"/urls/{url_id}")
                final.raise_for_status()
                return json.dumps(_normalise_vt_report(final.json(), url), indent=2)

        return json.dumps({
            "tool": "virustotal",
            "status": "analysis_timeout",
            "analysis_id": analysis_id,
            "error": "Analysis did not complete within polling window.",
        })

    except ValueError as exc:
        return json.dumps({"tool": "virustotal", "status": "config_error", "error": str(exc)})
    except requests.exceptions.RequestException as exc:
        return json.dumps({"tool": "virustotal", "status": "request_error", "error": str(exc)})


# ─────────────────────────────────────────────────────────────────────────────
# Normaliser
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_vt_report(raw: dict, original_url: str) -> dict:
    attrs   = raw.get("data", {}).get("attributes", {})
    stats   = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    total       = sum(stats.values()) if stats else 0

    # Risk score: malicious vendors weighted 1.0, suspicious 0.5
    risk_score = round(((malicious + suspicious * 0.5) / total * 100), 1) if total else 0.0

    # Threat level bands
    if malicious >= 10 or risk_score >= 30:
        threat_level = "CRITICAL"
    elif malicious >= 3 or risk_score >= 10:
        threat_level = "HIGH"
    elif malicious >= 1 or suspicious >= 5:
        threat_level = "MEDIUM"
    elif suspicious >= 1:
        threat_level = "LOW"
    else:
        threat_level = "CLEAN"

    # Collect only engines that raised a flag
    flagged_by = {
        vendor: {
            "category": data.get("category"),
            "result":   data.get("result"),
        }
        for vendor, data in results.items()
        if data.get("category") in ("malicious", "suspicious")
    }

    return {
        "tool":                 "virustotal",
        "status":               "completed",
        "url":                  attrs.get("url", original_url),
        "threat_level":         threat_level,
        "risk_score":           risk_score,
        "analysis_stats":       stats,
        "total_engines_checked": total,
        "flagged_by":           flagged_by,
        "categories":           attrs.get("categories", {}),
        "reputation":           attrs.get("reputation", 0),
        "tags":                 attrs.get("tags", []),
        "last_analysis_date":   attrs.get("last_analysis_date"),
        "times_submitted":      attrs.get("times_submitted", 0),
    }

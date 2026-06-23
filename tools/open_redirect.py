"""
Open Redirect Scanner

Finds URL parameters that allow redirecting users to arbitrary domains:

Phase 1 — Discovery (passive):
  Parse the homepage for <a href> and <form action> containing known
  redirect parameter names (next, url, redirect, return, goto…).

Phase 2 — Confirmation (semi-active):
  For each candidate, send a GET request with the parameter set to a
  known benign test value (example.com). Check the Location header.
  Only confirmed if the server actually redirects to our test domain.

Safe by design:
  - Test destination is example.com (IANA-reserved, harmless)
  - allow_redirects=False — we never follow the redirect
  - Probes go to the same host as the target (netloc validated)
  - No exploit payloads, no cross-origin side effects
"""
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import tool

from tools.http_utils import SSRFError, safe_get

_REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_url", "redirect_uri",
    "return", "returnto", "return_to", "return_url",
    "to", "goto", "destination", "dest", "redir", "r",
    "forward", "forward_url", "location", "back", "continue",
    "callback", "target", "ref", "referer", "referrer",
    "login_url", "exit", "out",
}

_TEST_VALUE  = "https://example.com/redirect-test-AICYBERSHIELD"
_MAX_PROBES  = 10  # limit probes per scan


def _extract_candidates(html: str, base_url: str, target_netloc: str) -> list[dict]:
    """Parse HTML for links/forms containing redirect-like parameters."""
    soup       = BeautifulSoup(html, "html.parser")
    candidates = []
    seen       = set()

    for tag in soup.find_all("a", href=True):
        try:
            full   = urljoin(base_url, tag["href"])
            parsed = urlparse(full)
            if parsed.netloc != target_netloc:
                continue  # only scan same-origin links
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if param.lower() in _REDIRECT_PARAMS:
                    key = f"{parsed.netloc}{parsed.path}?{param.lower()}"
                    if key not in seen:
                        seen.add(key)
                        candidates.append({"url": full, "param": param, "found_in": "anchor"})
        except Exception:
            pass

    for form in soup.find_all("form"):
        try:
            action      = form.get("action", base_url)
            full_action = urljoin(base_url, action)
            if urlparse(full_action).netloc != target_netloc:
                continue
            for inp in form.find_all("input"):
                name = (inp.get("name") or "").lower()
                if name in _REDIRECT_PARAMS:
                    key = f"{urlparse(full_action).netloc}{urlparse(full_action).path}?{name}"
                    if key not in seen:
                        seen.add(key)
                        candidates.append({"url": full_action, "param": name, "found_in": "form"})
        except Exception:
            pass

    return candidates[:15]


def _probe_candidate(candidate: dict, session: requests.Session,
                     target_netloc: str) -> dict | None:
    """
    Replace the redirect param value with _TEST_VALUE and check if server
    issues a Location: pointing to our test domain.
    Returns a finding dict if confirmed, else None.
    """
    original_url = candidate["url"]
    param        = candidate["param"]

    try:
        p      = urlparse(original_url)
        # Safety check: only probe same-origin URLs
        if p.netloc != target_netloc:
            return None

        qs     = parse_qs(p.query, keep_blank_values=True)
        qs[param] = [_TEST_VALUE]
        probe  = urlunparse(p._replace(query=urlencode(qs, doseq=True)))

        resp   = session.get(probe, allow_redirects=False, timeout=8)
        loc    = resp.headers.get("Location", "")

        if "example.com" in loc and "AICYBERSHIELD" in loc:
            return {
                "url":       probe,
                "param":     param,
                "status":    resp.status_code,
                "location":  loc,
                "severity":  "HIGH",
                "confirmed": True,
            }
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def scan_open_redirects(url: str) -> str:
    """
    Discovers and confirms open redirect vulnerabilities by parsing redirect
    parameters from HTML and probing with a safe test value (example.com).

    Open redirects allow attackers to craft phishing links that appear to
    point to a trusted domain but deliver victims to a malicious site.

    Args:
        url: Target HTTP/HTTPS URL.

    Returns:
        JSON with confirmed_redirects (list), candidates_found (int),
        risk_score (0-80), and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "open_redirect", "status": "invalid_url"})

    target_netloc = parsed.netloc

    try:
        resp = safe_get(url, timeout=12)
    except SSRFError:
        return json.dumps({"tool": "open_redirect", "status": "ssrf_blocked"})
    except requests.RequestException as exc:
        return json.dumps({"tool": "open_redirect", "status": "connection_error",
                           "error": str(exc)})

    candidates = _extract_candidates(resp.text, resp.url, target_netloc)

    confirmed: list[dict] = []
    if candidates:
        session = requests.Session()
        session.headers["User-Agent"] = (
            "AICyberShield-Scanner/1.0 (security audit — authorized use only)"
        )
        for cand in candidates[:_MAX_PROBES]:
            finding = _probe_candidate(cand, session, target_netloc)
            if finding:
                confirmed.append(finding)

    risk = min(len(confirmed) * 25 + min(len(candidates), 5) * 3, 80)

    recs = []
    if confirmed:
        recs.append(
            f"CRITICAL: {len(confirmed)} confirmed open redirect(s). "
            "Validate redirect targets against a strict allowlist of trusted domains. "
            "Never redirect based on raw user-supplied URL values."
        )
    if candidates and not confirmed:
        params_preview = ", ".join(c["param"] for c in candidates[:5])
        recs.append(
            f"{len(candidates)} redirect-parameter candidates found but none confirmed. "
            f"Review these parameters manually: {params_preview}."
        )
    if not candidates:
        recs.append(
            "No redirect parameter patterns detected in the homepage. "
            "Authenticated pages may still contain redirect parameters — review manually."
        )

    return json.dumps({
        "tool":               "open_redirect",
        "status":             "completed",
        "url":                resp.url,
        "risk_score":         risk,
        "candidates_found":   len(candidates),
        "candidates":         candidates[:10],
        "confirmed_redirects": confirmed,
        "recommendations":    recs,
    }, indent=2)

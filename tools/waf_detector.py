"""
WAF (Web Application Firewall) Detector

Two-phase detection:
1. Passive — response header fingerprinting (no extra request needed)
2. Semi-active probe — sends a standard WAF-trigger query parameter
   (URL-encoded, identical technique used by open-source tool wafw00f)
   to confirm blocking behaviour.

Neither phase sends actual exploit payloads.
All probes go to the target domain only.
"""
import json
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from tools.http_utils import SSRFError, safe_get, _is_waf_response, stealth_safe_get

# ─────────────────────────────────────────────────────────────────────────────
# WAF signatures: header names, Server string patterns, cookie prefixes
# ─────────────────────────────────────────────────────────────────────────────

_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {
        "headers": {"cf-ray", "cf-cache-status", "cf-request-id", "cf-connecting-ip"},
        "server":  ["cloudflare"],
        "cookies": ["__cflb", "__cfuid", "cf_clearance"],
    },
    "AWS CloudFront/WAF": {
        "headers": {"x-amz-cf-id", "x-amzn-requestid", "x-amzn-trace-id"},
        "server":  [],
        "via":     ["cloudfront"],
        "cookies": [],
    },
    "Akamai": {
        "headers": {"x-akamai-transformed", "akamai-origin-hop", "x-akamai-request-id"},
        "server":  ["akamaighost", "akamai"],
        "cookies": ["akamai_", "ak_bmsc"],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id", "x-sucuri-cache"},
        "server":  ["sucuri/cloudproxy"],
        "cookies": [],
    },
    "Imperva / Incapsula": {
        "headers": {"x-iinfo", "x-cdn"},
        "server":  ["incapsula"],
        "cookies": ["incap_ses_", "visid_incap_"],
    },
    "F5 BIG-IP ASM": {
        "headers": set(),
        "server":  ["bigip"],
        "cookies": ["bigipserver", "ts01"],
    },
    "ModSecurity": {
        "headers": {"x-mod-security-action"},
        "server":  [],
        "cookies": [],
    },
    "Fastly": {
        "headers": {"x-fastly-request-id", "fastly-restarts"},
        "server":  [],
        "cookies": [],
    },
    "Barracuda": {
        "headers": {"x-barracuda-connect", "x-barracuda-start-time"},
        "server":  [],
        "cookies": ["barra_counter_session"],
    },
}

# URL-encoded XSS probe — standard WAF detection pattern (wafw00f technique).
# Not an actual exploit: sent as a query parameter value to see if WAF blocks it.
_PROBE_PARAM = "waf_probe=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"


def _score_headers(resp_headers: dict, set_cookie_list: list[str]) -> tuple[str | None, int]:
    """Fingerprint WAF from headers. Returns (waf_name | None, confidence 0-100)."""
    h_lower    = {k.lower(): v.lower() for k, v in resp_headers.items()}
    server_val = h_lower.get("server", "")
    via_val    = h_lower.get("via", "")
    cookies_str = " ".join(set_cookie_list).lower()

    best_waf, best_score = None, 0
    for waf_name, sigs in _SIGNATURES.items():
        score = 0
        for sig_h in sigs.get("headers", set()):
            if sig_h.lower() in h_lower:
                score += 40
        for pat in sigs.get("server", []):
            if pat in server_val:
                score += 35
        for pat in sigs.get("via", []):
            if pat in via_val:
                score += 25
        for pat in sigs.get("cookies", []):
            if pat.lower() in cookies_str:
                score += 40  # vendor-specific cookie = strong signal
        if score > best_score:
            best_score = score
            best_waf   = waf_name

    return (best_waf, min(best_score, 100)) if best_score >= 35 else (None, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def detect_waf(url: str) -> str:
    """
    Detects WAF presence via passive header fingerprinting plus a standard
    probe request. Returns WAF name, confidence, and a protection_score
    (higher = more protected).

    Technique is identical to open-source wafw00f: URL-encoded probe
    parameter to check WAF response; no actual exploit sent.

    Args:
        url: Target HTTP/HTTPS URL.

    Returns:
        JSON with waf_detected, waf_name, confidence, probe_blocked,
        protection_score, and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "waf_detector", "status": "invalid_url"})

    stealth_used = False

    try:
        resp = safe_get(url, timeout=12)
    except SSRFError:
        return json.dumps({"tool": "waf_detector", "status": "ssrf_blocked"})
    except requests.RequestException as exc:
        return json.dumps({"tool": "waf_detector", "status": "connection_error",
                           "error": type(exc).__name__})

    # ── Stealth upgrade: if the initial response is itself a WAF block,
    #    retry with a browser TLS fingerprint to get the real page headers.
    #    This lets us detect WAF vendor even when it blocks our scanner UA.
    if _is_waf_response(resp):
        try:
            stealth_resp = stealth_safe_get(url, timeout=12)
            if stealth_resp is not None:
                resp         = stealth_resp
                stealth_used = True
                # If stealth also got blocked, both responses are WAF signals
        except SSRFError:
            return json.dumps({"tool": "waf_detector", "status": "ssrf_blocked"})
        except Exception:
            pass  # stealth failure is non-fatal — continue with original resp

    # Passive fingerprint from initial (or stealth) response
    sc_list  = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
    waf_name, confidence = _score_headers(dict(resp.headers), sc_list)

    # Semi-active probe: same host, URL-encoded query param
    final_url     = getattr(resp, "url", url).rstrip("/")
    sep           = "&" if "?" in final_url else "?"
    probe_url     = f"{final_url}{sep}{_PROBE_PARAM}"
    probe_blocked = False

    try:
        probe_resp    = safe_get(probe_url, timeout=8)
        probe_blocked = probe_resp.status_code in (403, 406, 429, 503)
        # If probe is blocked but we didn't identify the WAF yet, try stealth probe
        if probe_blocked and not waf_name:
            try:
                stealth_probe = stealth_safe_get(probe_url, timeout=8)
                if stealth_probe is not None:
                    sc2 = [v for k, v in stealth_probe.headers.items()
                           if k.lower() == "set-cookie"]
                    waf_name, confidence = _score_headers(dict(stealth_probe.headers), sc2)
                    if waf_name:
                        stealth_used = True
            except Exception:
                pass
        elif not waf_name:
            sc2 = [v for k, v in probe_resp.headers.items() if k.lower() == "set-cookie"]
            waf_name, confidence = _score_headers(dict(probe_resp.headers), sc2)
    except Exception:
        pass  # probe failure is non-fatal

    if probe_blocked:
        if waf_name:
            confidence = min(confidence + 20, 100)
        else:
            waf_name, confidence = "Unknown WAF", 55

    waf_detected = waf_name is not None

    protection_score = (
        min(60 + confidence // 3, 95) if waf_detected
        else 40 if probe_blocked
        else 30
    )

    recs = []
    if not waf_detected:
        recs.append("No WAF detected. Consider Cloudflare, AWS WAF, or self-hosted ModSecurity "
                    "to filter malicious requests before they reach your application.")
    elif confidence < 60:
        recs.append(f"Low-confidence WAF signal (possible {waf_name}). Verify WAF is properly configured.")

    return json.dumps({
        "tool":             "waf_detector",
        "status":           "completed",
        "url":              getattr(resp, "url", url),
        "waf_detected":     waf_detected,
        "waf_name":         waf_name,
        "confidence":       confidence,
        "probe_blocked":    probe_blocked,
        "protection_score": protection_score,
        "stealth_used":     stealth_used,
        "recommendations":  recs,
    }, indent=2)

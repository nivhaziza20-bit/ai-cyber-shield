"""
Certificate Transparency (CT) Log Scanner

Queries crt.sh — a completely PUBLIC database of all SSL/TLS certificates
ever issued to a domain. No requests are made to discovered subdomains.

Why it matters:
  - CT logs are public and permanent — attackers already enumerate them
  - Reveals forgotten staging/dev/admin subdomains (often less secure)
  - Maps the full external attack surface before a security review
  - Discovers wildcard certs that may indicate overly-broad trust
"""
import json
import re
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

_CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_MAX_RESULTS = 200  # cap API response processing

_SENSITIVE_NAMES = re.compile(
    r"(admin|staging|dev|test|api|internal|uat|qa|beta|old|legacy|vpn|mail|"
    r"smtp|ftp|sftp|git|jenkins|jira|confluence|backup|db|database|portal|"
    r"manage|management|cpanel|webmail|phpmyadmin|kibana|grafana|elastic|"
    r"consul|vault|k8s|kubernetes|docker|registry|ci|cd|build|deploy)",
    re.IGNORECASE,
)


def _query_crtsh(domain: str) -> list[dict]:
    """Query crt.sh for all certificates issued to *.domain."""
    try:
        resp = requests.get(
            _CRT_SH_URL.format(domain=domain),
            timeout=15,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()[:_MAX_RESULTS]
    except Exception:
        return []


def _extract_subdomains(records: list[dict], root_domain: str) -> set[str]:
    """Extract unique subdomains from CT records."""
    subs: set[str] = set()
    for rec in records:
        name_value = rec.get("name_value", "")
        for name in name_value.splitlines():
            name = name.strip().lstrip("*.")  # strip wildcard prefix
            if name and "." in name and name.endswith(root_domain):
                subs.add(name.lower())
    subs.discard(root_domain)  # root itself is not a subdomain
    subs.discard(f"www.{root_domain}")
    return subs


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def scan_certificate_transparency(url: str) -> str:
    """
    Queries public Certificate Transparency logs (crt.sh) to enumerate
    subdomains disclosed in SSL/TLS certificate records.

    Completely passive — only reads from crt.sh, makes no requests to
    discovered subdomains. CT logs are permanently public; this is
    standard OSINT used before any security assessment.

    Args:
        url: Target URL — uses the root domain for the lookup.

    Returns:
        JSON with subdomain_count, interesting_subdomains (sensitive-looking
        names), all_subdomains (up to 50), risk_score, cert_count, and
        recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "cert_transparency", "status": "invalid_url"})

    hostname = parsed.hostname or ""
    domain   = hostname.lstrip("www.")

    if not domain or "." not in domain:
        return json.dumps({"tool": "cert_transparency", "status": "invalid_domain"})

    records = _query_crtsh(domain)
    if not records:
        return json.dumps({
            "tool":   "cert_transparency",
            "status": "no_data",
            "domain": domain,
            "note":   "crt.sh returned no results — domain may be very new, or query failed.",
            "risk_score": 0,
        })

    subdomains   = _extract_subdomains(records, domain)
    interesting  = sorted(s for s in subdomains if _SENSITIVE_NAMES.search(s))
    count        = len(subdomains)

    risk = min(
        len(interesting) * 6          # each sensitive subdomain += 6
        + max(0, count - 10) * 2      # each extra subdomain over 10 += 2
        + (5 if count > 5 else 0),    # base if any subdomains exist
        50,
    )

    recs = []
    if interesting:
        preview = ", ".join(interesting[:5])
        suffix  = f"... (+{len(interesting) - 5} more)" if len(interesting) > 5 else ""
        recs.append(
            f"Review {len(interesting)} sensitive-looking subdomains: {preview}{suffix}. "
            "Confirm each is intentional and has the same security posture as the main site."
        )
    if count > 20:
        recs.append(
            f"{count} subdomains found in CT logs. Audit all for forgotten, "
            "misconfigured, or deprecated endpoints."
        )
    if not recs:
        recs.append(
            "CT log attack surface appears manageable. "
            "Periodically re-check crt.sh for unexpected new certificates."
        )

    return json.dumps({
        "tool":                   "cert_transparency",
        "status":                 "completed",
        "domain":                 domain,
        "risk_score":             risk,
        "cert_count":             len(records),
        "subdomain_count":        count,
        "interesting_subdomains": interesting[:20],
        "all_subdomains":         sorted(subdomains)[:50],
        "recommendations":        recs,
    }, indent=2)

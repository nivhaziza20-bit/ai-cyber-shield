"""
DNS Security Scanner

Checks email authentication and domain security records:
  - SPF  (Sender Policy Framework) — prevents email spoofing
  - DMARC (Domain-based Message Authentication) — enforces SPF/DKIM policy
  - CAA  (Certification Authority Authorization) — restricts who can issue certs

Uses Cloudflare DNS-over-HTTPS as the resolver (no extra dependency, works
everywhere, returns JSON). Falls back gracefully if the DoH call fails.

Risk scoring:
  Missing SPF     +30   Allows anyone to spoof emails from this domain
  SPF +all/? all  +40   SPF record explicitly permits ALL senders (broken)
  Missing DMARC   +20   No enforcement even if SPF/DKIM fails
  DMARC p=none    +10   Monitor-only — attackers still get through
  No CAA          +5    Any CA can issue certificates for this domain
"""

import json
import re
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

_DOH_URL = "https://cloudflare-dns.com/dns-query"
_DOH_HEADERS = {"Accept": "application/dns-json"}
_DOH_TIMEOUT = 8


# ─────────────────────────────────────────────────────────────────────────────
# DNS-over-HTTPS helper
# ─────────────────────────────────────────────────────────────────────────────

def _doh_query(name: str, rtype: str) -> list[str]:
    """
    Queries Cloudflare DoH for TXT/CAA records.
    Returns list of record data strings, or [] on error.
    """
    try:
        resp = requests.get(
            _DOH_URL,
            params={"name": name, "type": rtype},
            headers=_DOH_HEADERS,
            timeout=_DOH_TIMEOUT,
        )
        data = resp.json()
        answers = data.get("Answer", [])
        return [
            a.get("data", "").strip('"')
            for a in answers
            if a.get("type") == {"TXT": 16, "CAA": 257}.get(rtype, 0)
        ]
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# SPF analyser
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_spf(domain: str) -> tuple[int, str | None, list[str], list[str]]:
    """
    Returns (risk, spf_record | None, issues, recommendations).
    """
    records = _doh_query(domain, "TXT")
    spf_records = [r for r in records if r.startswith("v=spf1")]

    if not spf_records:
        return (
            30,
            None,
            ["No SPF record found — anyone can send email claiming to be this domain."],
            ["Add an SPF record: v=spf1 include:_spf.google.com ~all  (adjust for your mail provider)"],
        )

    spf = spf_records[0]
    issues:  list[str] = []
    recs:    list[str] = []
    risk = 0

    if "+all" in spf:
        issues.append(f"CRITICAL: SPF record uses '+all' — permits ANY server to send email. "
                      f"Record: {spf}")
        recs.append("Change '+all' to '-all' (hard fail) or '~all' (soft fail).")
        risk += 40
    elif "?all" in spf:
        issues.append(f"WARNING: SPF record uses '?all' (neutral) — provides no protection. "
                      f"Record: {spf}")
        recs.append("Change '?all' to '-all' for strict enforcement.")
        risk += 25
    elif "~all" in spf:
        issues.append(f"INFO: SPF uses '~all' (soft fail) — marks spoofed email but may still deliver. "
                      f"Record: {spf}")
        recs.append("Consider upgrading to '-all' (hard fail) for stricter protection.")
        risk += 5
    elif "-all" in spf:
        # Good
        pass
    else:
        issues.append(f"SPF record has no 'all' mechanism — policy is incomplete. Record: {spf}")
        recs.append("Add '-all' at the end of your SPF record.")
        risk += 15

    return risk, spf, issues, recs


# ─────────────────────────────────────────────────────────────────────────────
# DMARC analyser
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_dmarc(domain: str) -> tuple[int, str | None, list[str], list[str]]:
    """
    Returns (risk, dmarc_record | None, issues, recommendations).
    """
    dmarc_domain = f"_dmarc.{domain}"
    records = _doh_query(dmarc_domain, "TXT")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return (
            20,
            None,
            ["No DMARC record found — SPF/DKIM failures are not acted upon."],
            [f"Add a DMARC record at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"],
        )

    dmarc = dmarc_records[0]
    issues: list[str] = []
    recs:   list[str] = []
    risk = 0

    policy_match = re.search(r'p=(\w+)', dmarc)
    policy = policy_match.group(1).lower() if policy_match else "unknown"

    if policy == "none":
        issues.append(f"DMARC policy is 'p=none' — monitor only, emails still delivered. Record: {dmarc}")
        recs.append("Upgrade DMARC policy to 'p=quarantine' or 'p=reject' after reviewing reports.")
        risk += 10
    elif policy == "quarantine":
        issues.append(f"INFO: DMARC policy is 'p=quarantine' — failing emails go to spam. Record: {dmarc}")
        recs.append("Consider upgrading to 'p=reject' for maximum protection.")
        risk += 3
    elif policy == "reject":
        pass  # Best practice — no issue
    else:
        issues.append(f"DMARC record has unexpected policy '{policy}'. Record: {dmarc}")
        risk += 10

    # Check for reporting address
    if "rua=" not in dmarc and "ruf=" not in dmarc:
        issues.append("DMARC has no reporting address (rua=/ruf=) — you won't receive failure reports.")
        recs.append(f"Add rua=mailto:dmarc@{domain} to your DMARC record to receive reports.")
        risk += 3

    return risk, dmarc, issues, recs


# ─────────────────────────────────────────────────────────────────────────────
# CAA analyser
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_caa(domain: str) -> tuple[int, list[str], list[str], list[str]]:
    """
    Returns (risk, caa_records[], issues[], recommendations[]).
    """
    caa_records = _doh_query(domain, "CAA")
    if not caa_records:
        return (
            5,
            [],
            ["No CAA record — any certificate authority can issue TLS certs for this domain."],
            [f"Add CAA: 0 issue \"letsencrypt.org\" (or your CA) to restrict cert issuance."],
        )
    return 0, caa_records, [], []


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def scan_dns_security(url: str) -> str:
    """
    Checks DNS security records for the domain in the given URL:
    SPF (email spoofing protection), DMARC (authentication policy),
    and CAA (certificate issuance restriction).

    Uses Cloudflare DNS-over-HTTPS — no network access to the target
    server itself, only DNS queries via Cloudflare's resolver.

    Args:
        url: Any URL — only the domain is used for DNS lookups.
             Example: "https://example.com/page"

    Returns:
        JSON with spf, dmarc, caa findings, risk_score (0-100),
        and prioritised recommendations.
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        return json.dumps({"tool": "dns_scanner", "status": "invalid_url"})

    domain = parsed.hostname
    # Strip leading 'www.' for DNS records (they live on the apex domain)
    if domain.startswith("www."):
        domain = domain[4:]

    # ── SPF ───────────────────────────────────────────────────────────────────
    spf_risk, spf_record, spf_issues, spf_recs = _analyse_spf(domain)

    # ── DMARC ─────────────────────────────────────────────────────────────────
    dmarc_risk, dmarc_record, dmarc_issues, dmarc_recs = _analyse_dmarc(domain)

    # ── CAA ───────────────────────────────────────────────────────────────────
    caa_risk, caa_records, caa_issues, caa_recs = _analyse_caa(domain)

    total_risk = min(spf_risk + dmarc_risk + caa_risk, 100)
    all_issues = spf_issues + dmarc_issues + caa_issues
    all_recs   = spf_recs   + dmarc_recs   + caa_recs

    return json.dumps({
        "tool":           "dns_scanner",
        "status":         "completed",
        "domain":         domain,
        "risk_score":     total_risk,
        "spf": {
            "record":  spf_record,
            "risk":    spf_risk,
            "issues":  spf_issues,
        },
        "dmarc": {
            "record":  dmarc_record,
            "risk":    dmarc_risk,
            "issues":  dmarc_issues,
        },
        "caa": {
            "records": caa_records,
            "risk":    caa_risk,
            "issues":  caa_issues,
        },
        "all_issues":     all_issues,
        "recommendations": all_recs,
    }, indent=2)

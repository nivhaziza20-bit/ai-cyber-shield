"""
Subdomain Takeover Checker

Detects subdomains whose DNS CNAME records still point to orphaned cloud
resources — a condition that allows attackers to claim the resource and
serve arbitrary content under the victim's own domain.

Attack scenario
───────────────
1. Organisation creates  staging.victim.com → CNAME → myapp.herokuapp.com
2. Heroku app is decommissioned (dyno deleted)
3. DNS record is forgotten and left in place
4. Attacker registers myapp.herokuapp.com (free tier)
5. Attacker now controls https://staging.victim.com: phishing, cookie theft,
   malware hosting — all under a domain the victim's TLS certificate trusts

Performance design
──────────────────
Uses httpx.AsyncClient to run all subdomain checks CONCURRENTLY:
  • Cloudflare DoH queries (CNAME resolution) — parallel for all subdomains
  • HTTP fingerprint probes — parallel once CNAME match is confirmed
  Sequential (requests): N subdomains × (2 DoH + 1 HTTP) = 3N requests in series
  Parallel   (httpx):    all N subdomains checked simultaneously

Architecture:
  @tool check_subdomain_takeover (sync) ← LangChain / ThreadPoolExecutor
    └─ asyncio.run(_async_scan_core)    ← single httpx.AsyncClient for all I/O
         └─ asyncio.gather(...)         ← one coroutine per subdomain
              └─ _check_single(...)     ← DoH CNAME chain → HTTP fingerprint

Supported cloud services (14): AWS S3, GitHub Pages, Heroku, Netlify,
  Azure Web Apps, Fastly, Ghost.io, Surge.sh, Tumblr, Pantheon,
  WordPress.com, Shopify, Bitbucket Pages, Unbounce

SSRF protection: is_ssrf_blocked() is checked before every fingerprint
  HTTP request — cloud provider subdomains should resolve to public IPs,
  but we verify before connecting.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

from tools.http_utils import is_ssrf_blocked

# ─────────────────────────────────────────────────────────────────────────────
# Cloud service fingerprint table
# ─────────────────────────────────────────────────────────────────────────────

_CLOUD_SERVICES: dict[str, dict] = {
    "AWS S3": {
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website[-.][\w-]+\.amazonaws\.com$",
            r"\.s3-accelerate\.amazonaws\.com$",
        ],
        "http_fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "NoSuchKey",
        ],
        "severity": "CRITICAL",
        "attack": "Register the deleted S3 bucket to host malicious files under this subdomain.",
    },
    "GitHub Pages": {
        "cname_patterns": [r"\.github\.io$", r"\.github\.com$"],
        "http_fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html",
        ],
        "severity": "HIGH",
        "attack": "Create a GitHub Pages site at this username/org to serve phishing content.",
    },
    "Heroku": {
        "cname_patterns": [r"\.herokuapp\.com$", r"\.herokussl\.com$"],
        "http_fingerprints": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "severity": "HIGH",
        "attack": "Register a Heroku dyno with this name to serve arbitrary content.",
    },
    "Netlify": {
        "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "http_fingerprints": ["Not Found - Request ID:", "not found"],
        "severity": "HIGH",
        "attack": "Create a Netlify site claiming this name.",
    },
    "Azure Web Apps": {
        "cname_patterns": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.cloudapp\.net$",
            r"\.azureedge\.net$",
        ],
        "http_fingerprints": [
            "Error 404 - Web app not found",
            "The resource you are looking for has been removed",
        ],
        "severity": "HIGH",
        "attack": "Create an Azure Web App at this name.",
    },
    "Fastly": {
        "cname_patterns": [r"\.fastly\.net$", r"\.global\.ssl\.fastly\.net$"],
        "http_fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "severity": "HIGH",
        "attack": "Configure a Fastly CDN service to serve from this subdomain.",
    },
    "Ghost.io": {
        "cname_patterns": [r"\.ghost\.io$"],
        "http_fingerprints": ["The thing you were looking for is no longer here"],
        "severity": "MEDIUM",
        "attack": "Create a Ghost.io blog at this address.",
    },
    "Surge.sh": {
        "cname_patterns": [r"\.surge\.sh$"],
        "http_fingerprints": ["project not found", "surge project not found"],
        "severity": "MEDIUM",
        "attack": "Publish a Surge.sh project to this address.",
    },
    "Tumblr": {
        "cname_patterns": [r"\.tumblr\.com$"],
        "http_fingerprints": [
            "There's nothing here",
            "Whatever you were looking for doesn't currently exist at this address",
        ],
        "severity": "MEDIUM",
        "attack": "Create a Tumblr blog at this address.",
    },
    "Pantheon": {
        "cname_patterns": [r"\.pantheonsite\.io$", r"\.panth\.io$"],
        "http_fingerprints": ["The gods are wise", "404 Unknown Site"],
        "severity": "MEDIUM",
        "attack": "Create a Pantheon site at this address.",
    },
    "WordPress.com": {
        "cname_patterns": [r"\.wordpress\.com$"],
        "http_fingerprints": ["Do you want to register", "doesn't exist"],
        "severity": "MEDIUM",
        "attack": "Register a WordPress.com blog at this address.",
    },
    "Shopify": {
        "cname_patterns": [r"\.myshopify\.com$"],
        "http_fingerprints": [
            "Sorry, this shop is currently unavailable",
            "this shop is currently unavailable",
        ],
        "severity": "MEDIUM",
        "attack": "Create a Shopify store at this name.",
    },
    "Bitbucket": {
        "cname_patterns": [r"\.bitbucket\.io$"],
        "http_fingerprints": [
            "Repository not found",
            "The page you have requested does not exist",
        ],
        "severity": "MEDIUM",
        "attack": "Create a Bitbucket Pages repo at this name.",
    },
    "Unbounce": {
        "cname_patterns": [r"\.unbounce\.com$"],
        "http_fingerprints": ["The requested URL was not found"],
        "severity": "MEDIUM",
        "attack": "Create an Unbounce landing page at this address.",
    },
}

# Pre-compile CNAME patterns once for O(1) repeated matching
_COMPILED: list[tuple[str, list[re.Pattern[str]], list[str], dict]] = [
    (
        name,
        [re.compile(p, re.IGNORECASE) for p in info["cname_patterns"]],
        info["http_fingerprints"],
        info,
    )
    for name, info in _CLOUD_SERVICES.items()
]

_DOH_URL     = "https://cloudflare-dns.com/dns-query"
_DOH_HEADERS = {"Accept": "application/dns-json"}
_UA          = "AICyberShield-Scanner/1.0 (security audit — authorized use only)"

_MAX_SUBDOMAINS = 25   # cap to keep total scan time reasonable
_MAX_CNAME_HOPS = 5


# ─────────────────────────────────────────────────────────────────────────────
# Async DNS helpers (Cloudflare DoH — no extra dependencies)
# ─────────────────────────────────────────────────────────────────────────────

async def _doh_query(
    client: httpx.AsyncClient,
    hostname: str,
    rtype: str,
) -> list[dict]:
    """Single Cloudflare DoH query.  Returns Answer records (may be empty)."""
    try:
        resp = await client.get(
            _DOH_URL,
            params={"name": hostname, "type": rtype},
            headers=_DOH_HEADERS,
        )
        return resp.json().get("Answer", []) or []
    except Exception:
        return []


async def _resolve_cname_chain(
    client: httpx.AsyncClient,
    hostname: str,
) -> list[str]:
    """
    Follow CNAME chain via DoH, returning every intermediate CNAME target.
    Stops at max hops or when the chain terminates.
    Exposed for direct testing.
    """
    chain: list[str] = []
    current = hostname.lower().rstrip(".")

    for _ in range(_MAX_CNAME_HOPS):
        answers = await _doh_query(client, current, "CNAME")
        targets = [
            a.get("data", "").rstrip(".").lower()
            for a in answers
            if a.get("type") == 5 and a.get("data")
        ]
        if not targets:
            break
        target = targets[0]
        if target == current or target in chain:
            break  # cycle guard
        chain.append(target)
        current = target

    return chain


async def _has_a_record(
    client: httpx.AsyncClient,
    hostname: str,
) -> bool:
    """Return True if hostname has at least one A or AAAA record."""
    for rtype in ("A", "AAAA"):
        answers = await _doh_query(client, hostname, rtype)
        if any(a.get("type") in (1, 28) for a in answers):
            return True
    return False


def _identify_cloud_service(
    cname_chain: list[str],
) -> tuple[str | None, dict | None]:
    """
    Match any CNAME in the chain against known cloud provider patterns.
    Returns (service_name, service_info) or (None, None).
    Exposed for direct testing.
    """
    for cname in cname_chain:
        for name, patterns, _, info in _COMPILED:
            if any(p.search(cname) for p in patterns):
                return name, info
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Async HTTP fingerprint check
# ─────────────────────────────────────────────────────────────────────────────

async def _check_http_fingerprint(
    client: httpx.AsyncClient,
    subdomain: str,
    scheme: str,
    fingerprints: list[str],
) -> tuple[bool, str]:
    """
    Fetch https://<subdomain> and check if the response body contains any
    provider-specific "unclaimed resource" fingerprint string.

    Returns (matched, body_snippet).
    SSRF guard is applied before every request.
    Exposed for direct testing.
    """
    if is_ssrf_blocked(subdomain):
        return False, ""

    for try_scheme in (scheme, "http"):
        target_url = f"{try_scheme}://{subdomain}"
        try:
            r = await client.get(target_url, follow_redirects=True)
            body = r.text[:4_000]
            for fp in fingerprints:
                if fp.lower() in body.lower():
                    return True, body[:300].replace("\n", " ")
        except (httpx.TimeoutException, httpx.NetworkError,
                httpx.TooManyRedirects, httpx.HTTPError):
            pass
        except Exception:
            pass

    return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Per-subdomain check (async)
# ─────────────────────────────────────────────────────────────────────────────

async def _check_single(
    doh_client:  httpx.AsyncClient,
    http_client: httpx.AsyncClient,
    subdomain:   str,
    scheme:      str,
) -> tuple[dict | None, dict | None]:
    """
    Full takeover check for one subdomain.

    Returns
    ────────
    (confirmed_entry, potential_entry) — at most one will be non-None.
    """
    cname_chain = await _resolve_cname_chain(doh_client, subdomain)
    if not cname_chain:
        return None, None

    service_name, service_info = _identify_cloud_service(cname_chain)
    if not service_name or not service_info:
        return None, None

    final_cname  = cname_chain[-1]
    fingerprints = service_info.get("http_fingerprints", [])

    matched, snippet = await _check_http_fingerprint(
        http_client, subdomain, scheme, fingerprints
    )

    base_entry = {
        "subdomain":   subdomain,
        "service":     service_name,
        "cname_chain": cname_chain,
        "severity":    service_info.get("severity", "MEDIUM"),
        "attack":      service_info.get("attack", ""),
    }

    if matched:
        return {**base_entry, "evidence": snippet[:200], "confidence": "HIGH"}, None

    # No HTTP fingerprint — check if CNAME target is NXDOMAIN (dangling)
    resolves = await _has_a_record(doh_client, final_cname)
    if not resolves:
        return None, {
            **base_entry,
            "note": (
                f"CNAME → {final_cname} does not resolve (NXDOMAIN). "
                "Cloud resource may be deleted — registration may be available."
            ),
            "confidence": "MEDIUM",
        }

    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Async scan core (exposed for testing)
# ─────────────────────────────────────────────────────────────────────────────

async def _async_scan_core(
    url: str,
    subdomains: list[str],
) -> tuple[list[dict], list[dict]]:
    """
    Check all subdomains concurrently.
    Returns (confirmed_takeovers, potential_takeovers).
    Exposed as a module-level coroutine so tests can inject a mock transport.
    """
    sample = subdomains[:_MAX_SUBDOMAINS]
    if not sample:
        return [], []

    parsed = urlparse(url)
    scheme = parsed.scheme or "https"

    doh_limits  = httpx.Limits(max_connections=30, max_keepalive_connections=10)
    http_limits = httpx.Limits(max_connections=25, max_keepalive_connections=10)
    timeout     = httpx.Timeout(10.0, connect=5.0)

    # Semaphore limits concurrent subdomain checks — avoids DoH provider throttling
    # and prevents generating a burst of HTTP fingerprint probes that look like a scan.
    sem = asyncio.Semaphore(12)

    async def _bounded(sub):
        async with sem:
            return await _check_single(doh_client, http_client, sub, scheme)

    async with (
        httpx.AsyncClient(
            timeout=timeout, limits=doh_limits,
            follow_redirects=False, verify=True,
        ) as doh_client,
        httpx.AsyncClient(
            headers={"User-Agent": _UA},
            timeout=timeout, limits=http_limits,
            follow_redirects=True, verify=False,
        ) as http_client,
    ):
        tasks = [_bounded(sub) for sub in sample]
        pairs = await asyncio.gather(*tasks, return_exceptions=True)

    confirmed:  list[dict] = []
    potential:  list[dict] = []

    for pair in pairs:
        if isinstance(pair, Exception) or not isinstance(pair, tuple):
            continue
        conf, pot = pair
        if conf:
            confirmed.append(conf)
        if pot:
            potential.append(pot)

    return confirmed, potential


# ─────────────────────────────────────────────────────────────────────────────
# crt.sh fallback (same logic as cert_transparency.py)
# ─────────────────────────────────────────────────────────────────────────────

def _fallback_ct_query(domain: str) -> list[str]:
    """Query crt.sh if no subdomains were passed from the pipeline."""
    import requests  # only imported here — avoids top-level import side-effect
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15, headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        records = resp.json()[:200]
    except Exception:
        return []

    subs: set[str] = set()
    for rec in records:
        for name in rec.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name and "." in name and name.endswith(domain):
                subs.add(name.lower())
    subs.discard(domain)
    subs.discard(f"www.{domain}")
    return sorted(subs)


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def check_subdomain_takeover(url: str, subdomains_json: str = "[]") -> str:
    """
    Checks subdomains discovered in CT logs for orphaned CNAME records pointing
    to unclaimed cloud resources (AWS S3, GitHub Pages, Heroku, Netlify, etc.).

    Uses httpx.AsyncClient with asyncio.gather() to check ALL subdomains
    concurrently — checking 25 subdomains takes ~10s instead of ~75s
    sequential. SSRF protection is applied before every fingerprint request.

    Args:
        url:             Target HTTP or HTTPS URL (provides root domain context).
        subdomains_json: JSON array of subdomain strings from cert_transparency.
                         If empty or "[]", falls back to a crt.sh query.

    Returns:
        JSON with confirmed_takeovers, potential_takeovers, checked_count,
        risk_score (0–100), and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "subdomain_takeover", "status": "invalid_url"})

    hostname    = parsed.hostname or ""
    root_domain = hostname.lstrip("www.")

    try:
        subdomains: list[str] = json.loads(subdomains_json) if subdomains_json else []
    except (json.JSONDecodeError, ValueError):
        subdomains = []

    if not subdomains:
        subdomains = _fallback_ct_query(root_domain)

    if not subdomains:
        return json.dumps({
            "tool":                "subdomain_takeover",
            "status":              "no_subdomains",
            "domain":              root_domain,
            "note":                "No subdomains available — CT logs empty or crt.sh unreachable.",
            "confirmed_takeovers": [],
            "potential_takeovers": [],
            "checked_count":       0,
            "risk_score":          0,
            "recommendations": [
                "No subdomains found. Re-run after more CT log data is available."
            ],
        })

    try:
        confirmed, potential = asyncio.run(_async_scan_core(url, subdomains))
    except RuntimeError as exc:
        return json.dumps({"tool": "subdomain_takeover", "status": "error", "error": str(exc)})

    # ── Risk scoring ──────────────────────────────────────────────────────────
    risk_score = min(len(confirmed) * 50, 100)
    if risk_score < 100:
        risk_score = min(risk_score + len(potential) * 25, 100)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []

    if confirmed:
        preview = ", ".join(c["subdomain"] for c in confirmed[:3])
        recommendations.append(
            f"CRITICAL: {len(confirmed)} confirmed subdomain takeover candidate(s): {preview}. "
            "Immediate action: (1) Remove the dangling CNAME record from DNS, "
            "(2) Recreate the cloud resource to block third-party registration, "
            "(3) Audit crt.sh for SSL certificates issued to these subdomains."
        )

    if potential:
        preview = ", ".join(p["subdomain"] for p in potential[:3])
        recommendations.append(
            f"{len(potential)} potential takeover(s) — CNAME to cloud provider, "
            f"resource appears deleted: {preview}. "
            "Verify the cloud resource is still active; if not, remove the CNAME immediately."
        )

    if not confirmed and not potential:
        recommendations.append(
            f"No takeover vulnerabilities detected across {min(len(subdomains), _MAX_SUBDOMAINS)} "
            "sampled subdomain(s). Re-run after any infrastructure decommissioning."
        )

    return json.dumps({
        "tool":                "subdomain_takeover",
        "status":              "completed",
        "domain":              root_domain,
        "risk_score":          risk_score,
        "checked_count":       min(len(subdomains), _MAX_SUBDOMAINS),
        "confirmed_takeovers": confirmed,
        "potential_takeovers": potential,
        "recommendations":     recommendations,
    }, indent=2)

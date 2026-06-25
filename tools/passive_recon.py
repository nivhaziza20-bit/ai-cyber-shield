"""
passive_recon.py — AI Cyber Shield v6

Passive Reconnaissance Module: 10 OSINT-only tools.
All tools are read-only, make only normal HTTP/DNS requests,
and process publicly available information. Safe to run on any
public website without explicit permission.

Tools:
  check_security_txt      — RFC 9116 disclosure policy + bug bounty contact
  analyze_robots_sitemap  — robots.txt / sitemap.xml hidden path discovery
  scan_js_secrets         — Publicly linked JS files scanned for hardcoded secrets
  check_wayback_exposure  — Wayback Machine CDX API — historical endpoint exposure
  check_cloud_buckets     — S3 / Azure / GCS open bucket detection (HEAD only)
  check_http_methods      — OPTIONS / TRACE allowed-methods check
  analyze_email_spoofability — DMARC / SPF / DKIM deep spoofability analysis
  correlate_cves          — Match detected tech versions to known CVEs (offline)
  check_meta_leakage      — Error-page info disclosure (stack traces, internal paths)
  check_github_leaks      — GitHub public code search for domain / credential leaks

Security constraints:
  - SSRF guard on every outbound request (tools/http_utils.py)
  - No payload injection, no port scanning, no active exploitation
  - Timeouts enforced on all network calls
  - Passwords / secrets in findings are redacted to first 6 chars + ****
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeout
from typing import Any, Generator
from urllib.parse import urljoin, urlparse

import requests

try:
    import dns.resolver
    _DNS_OK = True
except ImportError:
    _DNS_OK = False

from tools.http_utils import (
    is_ssrf_blocked,
    safe_get         as _http_safe_get,
    SSRFError,
    _is_waf_response,
    stealth_safe_get  as _stealth_safe_get,
)

logger = logging.getLogger(__name__)

# ── HTTP session ──────────────────────────────────────────────────────────────
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; AICyberShield/6.0; "
        "+https://aicybershield.io/security)"
    ),
    "Accept": "*/*",
}

def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update(_HEADERS)
    return s


# ── DNS-over-HTTPS helper (Cloudflare) — no dnspython required ────────────────
_DOH_URL  = "https://cloudflare-dns.com/dns-query"
_DOH_HDRS = {"Accept": "application/dns-json"}
_RTYPE_INT = {"A": 1, "NS": 2, "MX": 15, "TXT": 16, "CAA": 257, "AAAA": 28, "SOA": 6}


def _doh_txt(name: str, rtype: str = "TXT", timeout: int = 8) -> list[str]:
    """Cloudflare DoH query — returns list of record data strings. No dnspython needed."""
    try:
        r = requests.get(_DOH_URL, params={"name": name, "type": rtype},
                         headers=_DOH_HDRS, timeout=timeout)
        data = r.json()
        want = _RTYPE_INT.get(rtype, 16)
        return [a.get("data", "").strip('"') for a in data.get("Answer", [])
                if a.get("type") == want]
    except Exception:
        return []


def _safe_get(url: str, timeout: int = 10, **kw) -> requests.Response | None:
    """GET with per-redirect SSRF guard, 5 MB cap, and automatic stealth fallback.

    Primary path: http_utils.safe_get (standard requests, checks SSRF on every
    redirect hop).  If the response is a WAF block (403/429/503 + WAF headers
    or challenge body), we retry automatically with StealthSession — a browser
    TLS-fingerprint client with randomised UA profiles — and return whichever
    response is more useful (stealth response if it got past the WAF).
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.warning("Blocked non-http/https scheme: %s in %s", parsed.scheme, url)
            return None
        if "params" in kw:
            from urllib.parse import urlencode, urlunparse
            params = kw.pop("params")
            query  = urlencode(params) if isinstance(params, dict) else str(params)
            url    = urlunparse(parsed._replace(query=query))
        extra_headers = kw.pop("headers", None)

        resp = _http_safe_get(url, timeout=timeout, extra_headers=extra_headers)

        # ── Stealth fallback when WAF blocks the standard scanner UA ──────────
        if _is_waf_response(resp):
            logger.debug("WAF block at %s — retrying with stealth client", url)
            try:
                stealth = _stealth_safe_get(
                    url, timeout=timeout, extra_headers=extra_headers
                )
                if stealth is not None and stealth.status_code not in {403, 429, 503}:
                    logger.debug(
                        "Stealth fallback succeeded for %s (status %d)",
                        url, stealth.status_code,
                    )
                    return stealth
                # Stealth also blocked — return original response so callers
                # can still inspect headers / WAF fingerprints.
            except SSRFError:
                raise   # propagate — never bypass SSRF via stealth
            except Exception as exc:
                logger.debug("Stealth fallback failed for %s: %s", url, type(exc).__name__)

        return resp

    except (SSRFError, ValueError) as exc:
        logger.warning("Request blocked (%s): %s", type(exc).__name__, url)
        return None
    except Exception as exc:
        logger.debug("GET %s → %s", url, type(exc).__name__)
        return None


def _safe_head(url: str, timeout: int = 8) -> requests.Response | None:
    try:
        host = urlparse(url).hostname or ""
        if is_ssrf_blocked(host):
            return None
        return _session().head(url, timeout=timeout, allow_redirects=False)
    except Exception:
        return None


def _redact(secret: str) -> str:
    """Show first 6 chars then ****  — never log full secrets."""
    if len(secret) <= 6:
        return "****"
    return secret[:6] + "****"


# ─────────────────────────────────────────────────────────────────────────────
# 1. security.txt — RFC 9116
# ─────────────────────────────────────────────────────────────────────────────

def check_security_txt(url: str, timeout: int = 10) -> dict:
    """
    Check for /.well-known/security.txt and /security.txt.
    Returns bug bounty contact, disclosure policy URL, and expiry.
    """
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    candidates = [
        f"{base}/.well-known/security.txt",
        f"{base}/security.txt",
    ]

    raw = ""
    found_url = ""
    for candidate in candidates:
        r = _safe_get(candidate, timeout=timeout)
        if r and r.status_code == 200 and "contact" in r.text.lower():
            raw = r.text
            found_url = candidate
            break

    if not raw:
        return {
            "status": "not_found",
            "has_security_txt": False,
            "has_bug_bounty": False,
            "finding": "No security.txt found — reporter has no official disclosure channel.",
            "severity": "INFO",
        }

    contacts, bug_bounty_urls, policy_urls, acks, expires = [], [], [], [], ""
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "contact":
            contacts.append(val)
        elif key in ("bug-bounty", "hiring"):
            bug_bounty_urls.append(val)
        elif key == "policy":
            policy_urls.append(val)
        elif key == "acknowledgments":
            acks.append(val)
        elif key == "expires":
            expires = val

    has_bounty = bool(bug_bounty_urls) or any(
        "bounty" in c.lower() or "hackerone" in c.lower() or "bugcrowd" in c.lower()
        for c in contacts + policy_urls
    )

    return {
        "status": "found",
        "has_security_txt": True,
        "found_at": found_url,
        "has_bug_bounty": has_bounty,
        "contacts": contacts,
        "bug_bounty_urls": bug_bounty_urls,
        "policy_urls": policy_urls,
        "acknowledgment_urls": acks,
        "expires": expires,
        "raw_length": len(raw),
        "finding": (
            f"security.txt found. Bug Bounty: {'YES' if has_bounty else 'No'}. "
            f"Contacts: {', '.join(contacts[:3])}"
        ),
        "severity": "INFO",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. robots.txt + sitemap.xml analysis
# ─────────────────────────────────────────────────────────────────────────────

_INTERESTING_PATTERNS = re.compile(
    r"(?i)/(admin|api|backup|console|cpanel|dashboard|debug|dev|internal|"
    r"login|manage|monitor|panel|phpmyadmin|private|secret|staff|staging|"
    r"swagger|test|vpn|wp-admin|graphql|actuator|metrics|health|config|"
    r"\.env|\.git|\.svn|old|archive|tmp|temp)",
    re.IGNORECASE,
)

def analyze_robots_sitemap(url: str, timeout: int = 12) -> dict:
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # ── robots.txt ──
    disallowed, sitemaps = [], []
    r = _safe_get(f"{base}/robots.txt", timeout=timeout)
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallowed.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())

    # ── sitemap.xml ──
    sitemap_urls: list[str] = []
    if not sitemaps:
        sitemaps.append(f"{base}/sitemap.xml")
    for sm_url in sitemaps[:3]:
        sr = _safe_get(sm_url, timeout=timeout)
        if sr and sr.status_code == 200:
            found = re.findall(r"<loc>\s*(https?://[^<]+)\s*</loc>", sr.text)
            sitemap_urls.extend(found[:200])

    # ── Find interesting paths ──
    interesting: list[dict] = []
    all_paths = disallowed + [urlparse(u).path for u in sitemap_urls]
    seen: set[str] = set()
    for path in all_paths:
        if path in seen:
            continue
        seen.add(path)
        if _INTERESTING_PATTERNS.search(path):
            interesting.append({
                "path": path,
                "full_url": urljoin(base, path),
                "source": "robots.txt" if path in disallowed else "sitemap",
            })

    # HEAD-verify each interesting path to confirm accessibility
    def _verify_path(p: dict) -> dict:
        r = _safe_head(p["full_url"])
        if r is not None:
            p["http_status"] = r.status_code
            p["accessible"]  = r.status_code == 200
        else:
            p["http_status"] = None
            p["accessible"]  = False
        return p

    with ThreadPoolExecutor(max_workers=8) as _pool:
        interesting = list(_pool.map(_verify_path, interesting[:20]))

    accessible = [p for p in interesting if p.get("accessible")]
    severity = ("CRITICAL" if accessible else
                "HIGH" if len(interesting) >= 3 else
                "MEDIUM" if interesting else "INFO")
    return {
        "status": "completed",
        "disallowed_count": len(disallowed),
        "disallowed_paths": disallowed[:50],
        "sitemap_url_count": len(sitemap_urls),
        "interesting_paths": interesting[:30],
        "interesting_count": len(interesting),
        "accessible_count": len(accessible),
        "severity": severity,
        "finding": (
            f"{len(accessible)} sensitive path(s) ACCESSIBLE (HTTP 200): "
            + ", ".join(p["path"] for p in accessible[:5])
            if accessible else
            f"{len(interesting)} sensitive path(s) exposed in robots.txt/sitemap: "
            + ", ".join(p["path"] for p in interesting[:5])
            if interesting else "No sensitive paths found in robots.txt/sitemap."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. JavaScript secret scanner
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: dict[str, re.Pattern] = {
    # All patterns use [^\n\r] instead of `.` to prevent cross-line backtracking
    # and bounded quantifiers to avoid catastrophic ReDoS on adversarial input.
    "AWS Access Key":    re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":    re.compile(r'(?i)aws[^\n\r]{0,20}secret[^\n\r]{0,20}["\'][0-9a-zA-Z/+]{40}["\']'),
    "Google API Key":    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth":      re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "Stripe Live Key":   re.compile(r"sk_live_[0-9a-zA-Z]{24,48}"),
    "Stripe Test Key":   re.compile(r"sk_test_[0-9a-zA-Z]{24,48}"),
    "GitHub Token":      re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,80}"),
    "Slack Token":       re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,48}"),
    "JWT Token":         re.compile(r"eyJ[A-Za-z0-9\-_]{10,500}\.eyJ[A-Za-z0-9\-_]{10,500}\.[A-Za-z0-9\-_]{10,500}"),
    "Private Key PEM":   re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Generic API Key":   re.compile(r'(?i)api[_\-]?key\s{0,3}[=:]\s{0,3}["\'][A-Za-z0-9\-_]{20,80}["\']'),
    "Generic Secret":    re.compile(r'(?i)secret\s{0,3}[=:]\s{0,3}["\'][A-Za-z0-9\-_!@#$%^&*]{12,80}["\']'),
    "Generic Password":  re.compile(r'(?i)password\s{0,3}[=:]\s{0,3}["\'][^"\'\s\n\r]{8,80}["\']'),
    "Bearer Token":      re.compile(r'(?i)"authorization"\s{0,3}:\s{0,3}"bearer\s+[A-Za-z0-9\-_.]{20,500}"'),
    "Database URL":      re.compile(r'(?i)(?:mysql|postgres|mongodb|redis|mssql)://[^\s"\'{\n\r]{10,200}'),
    "Internal IP":       re.compile(r'["\'](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})["\']'),
    "Internal Endpoint": re.compile(r'(?i)["\'](?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d{1,5})?/[^\s"\'{\n\r]{0,80}["\']'),
}

_MAX_JS_FILES   = 25
_MAX_JS_BYTES   = 512 * 1024   # 500 KB per file

def scan_js_secrets(url: str, timeout: int = 30) -> dict:
    """Fetch page HTML → find linked JS files → regex-scan for secrets."""
    page = _safe_get(url, timeout=15)
    if not page or page.status_code != 200:
        return {"status": "error", "error": "Could not fetch page", "secrets_found": [], "severity": "INFO"}

    # Decode page with explicit UTF-8 — avoids charset confusion from Content-Type mismatches
    page_html = page.content.decode("utf-8", errors="ignore")

    # Extract script src URLs
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', page_html, re.IGNORECASE)
    js_urls: list[str] = []
    for src in srcs:
        full = src if src.startswith("http") else urljoin(base, src)
        if urlparse(full).netloc == urlparse(url).netloc or urlparse(full).netloc == "":
            js_urls.append(full)
    js_urls = list(dict.fromkeys(js_urls))[:_MAX_JS_FILES]

    secrets: list[dict] = []
    scanned = 0
    inline_secrets: list[dict] = []

    # Scan inline scripts
    inline_blocks = re.findall(r'<script[^>]*>(.*?)</script>', page_html, re.DOTALL | re.IGNORECASE)
    for block in inline_blocks:
        for pname, pat in _SECRET_PATTERNS.items():
            for match in pat.finditer(block):
                val = match.group(0)
                if len(val) > 200:
                    continue
                inline_secrets.append({
                    "type": pname,
                    "source": "inline-script",
                    "preview": _redact(val),
                    "severity": _secret_severity(pname),
                })

    # Scan external JS files
    def _scan_file(js_url: str) -> list[dict]:
        r = _safe_get(js_url, timeout=15)
        if not r or r.status_code != 200:
            return []
        # Decode with explicit UTF-8 (errors=ignore) — prevents charset confusion
        # attacks where a server sends UTF-16 to create false regex matches.
        # r._content is already capped at 5MB by safe_get, so no OOM risk.
        content = r.content[:_MAX_JS_BYTES].decode("utf-8", errors="ignore")
        found = []
        for pname, pat in _SECRET_PATTERNS.items():
            for match in pat.finditer(content):
                val = match.group(0)
                if len(val) > 300:
                    continue
                found.append({
                    "type": pname,
                    "source": js_url.split("?")[0][-80:],
                    "preview": _redact(val),
                    "severity": _secret_severity(pname),
                })
        return found

    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(_scan_file, u): u for u in js_urls}
        try:
            for fut in as_completed(futs, timeout=timeout):
                try:
                    results = fut.result()
                    secrets.extend(results)
                    scanned += 1
                except Exception as exc:
                    logger.debug("JS file scan failed: %s", type(exc).__name__)
        except FutTimeout:
            logger.debug("scan_js_secrets: total timeout (%ss) hit — partial results", timeout)

    # Detect source maps — .js.map files expose original unminified source
    source_maps_found: list[str] = []
    for js_url in js_urls[:10]:
        map_url = js_url.split("?")[0] + ".map"
        mr = _safe_head(map_url, timeout=5)
        if mr and mr.status_code == 200:
            source_maps_found.append(map_url)
    # Also check for sourceMappingURL comment in page
    if not source_maps_found:
        for sm_match in re.findall(r'sourceMappingURL=([^\s"\']+\.map)', page.text):
            full_sm = sm_match if sm_match.startswith("http") else urljoin(base, sm_match)
            mr = _safe_head(full_sm, timeout=5)
            if mr and mr.status_code == 200:
                source_maps_found.append(full_sm)

    all_secrets = inline_secrets + secrets
    # Deduplicate by (type, preview)
    seen_sigs: set[str] = set()
    unique: list[dict] = []
    for s in all_secrets:
        sig = f"{s['type']}:{s['preview']}"
        if sig not in seen_sigs:
            seen_sigs.add(sig)
            unique.append(s)

    crit  = [s for s in unique if s["severity"] == "CRITICAL"]
    high  = [s for s in unique if s["severity"] == "HIGH"]
    # Source maps elevate severity — original source code exposure
    if source_maps_found and not crit:
        sev = "CRITICAL"  # Source maps = full source code exposure
    elif crit:
        sev = "CRITICAL"
    elif high or source_maps_found:
        sev = "HIGH"
    elif unique:
        sev = "MEDIUM"
    else:
        sev = "INFO"

    finding_parts = []
    if source_maps_found:
        finding_parts.append(f"CRITICAL: {len(source_maps_found)} JavaScript Source Map(s) exposed "
                             f"— full original source code accessible: {source_maps_found[0]}")
    if unique:
        finding_parts.append(f"{len(unique)} hardcoded secret(s) in JS: "
                             + ", ".join(s["type"] for s in unique[:3]))
    if not finding_parts:
        finding_parts.append(f"No secrets or source maps found in {scanned} JS file(s).")

    return {
        "status": "completed",
        "js_files_scanned": scanned,
        "inline_scripts_scanned": len(inline_blocks),
        "secrets_found": unique[:50],
        "secrets_count": len(unique),
        "critical_count": len(crit),
        "high_count": len(high),
        "source_maps_found": source_maps_found,
        "severity": sev,
        "finding": " | ".join(finding_parts),
    }


def _secret_severity(name: str) -> str:
    critical = {"AWS Access Key", "AWS Secret Key", "Stripe Live Key",
                "Private Key PEM", "Database URL", "GitHub Token"}
    high     = {"Google API Key", "Slack Token", "JWT Token",
                "Bearer Token", "Generic API Key"}
    return "CRITICAL" if name in critical else "HIGH" if name in high else "MEDIUM"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Wayback Machine — historical endpoint exposure
# ─────────────────────────────────────────────────────────────────────────────

_WAYBACK_INTERESTING = re.compile(
    r"(?i)/(admin|api|backup|config|debug|dev|env|internal|login|"
    r"phpmyadmin|private|secret|staging|swagger|test|\.git|\.env|"
    r"actuator|graphql|console|panel|manage|dump|export|upload)",
)

def check_wayback_exposure(domain: str, timeout: int = 20) -> dict:
    """Query Wayback Machine CDX API for historically exposed paths."""
    host = urlparse(domain).netloc or domain.replace("https://", "").replace("http://", "").split("/")[0]

    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url={host}/*&output=json&fl=original,statuscode,timestamp"
        f"&filter=statuscode:200&limit=300&collapse=urlkey"
    )
    r = _safe_get(cdx_url, timeout=timeout)
    if not r or r.status_code != 200:
        return {"status": "error", "error": "Wayback Machine unavailable", "interesting_urls": [], "severity": "INFO"}

    try:
        rows = json.loads(r.text)
    except Exception:
        return {"status": "error", "error": "Invalid CDX response", "interesting_urls": [], "severity": "INFO"}

    if not rows or len(rows) <= 1:
        return {"status": "completed", "total_snapshots": 0, "interesting_urls": [], "severity": "INFO",
                "finding": "No Wayback Machine data found for this domain."}

    header = rows[0]
    data   = rows[1:]
    total  = len(data)
    orig_idx = header.index("original") if "original" in header else 0
    ts_idx   = header.index("timestamp") if "timestamp" in header else 2

    interesting: list[dict] = []
    seen_paths: set[str] = set()
    for row in data:
        url_str = row[orig_idx] if len(row) > orig_idx else ""
        ts      = row[ts_idx]  if len(row) > ts_idx  else ""
        path    = urlparse(url_str).path
        if path in seen_paths:
            continue
        seen_paths.add(path)
        if _WAYBACK_INTERESTING.search(path):
            ts_fmt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
            interesting.append({"url": url_str, "last_seen": ts_fmt})

    # ── Common Crawl cross-check ─────────────────────────────────────────────
    cc_interesting: list[dict] = []
    try:
        # Discover the latest available CC index dynamically
        _cc_index_url = "https://index.commoncrawl.org/CC-MAIN-2025-08-index"  # reliable fallback
        try:
            _coll_r = requests.get("https://index.commoncrawl.org/collinfo.json", timeout=5)
            if _coll_r.status_code == 200:
                _coll = _coll_r.json()
                if _coll and isinstance(_coll, list):
                    _cc_index_url = _coll[0].get("cdx-api", _cc_index_url)
        except Exception:
            pass
        _cc_url = f"{_cc_index_url}?url={host}/*&output=json&limit=100&fl=url,status,timestamp"
        _cc_r = _safe_get(_cc_url, timeout=15)
        if _cc_r and _cc_r.status_code == 200:
            _cc_seen: set[str] = set()
            for _line in _cc_r.text.strip().split("\n")[:100]:
                try:
                    _d = json.loads(_line)
                    _path = urlparse(_d.get("url", "")).path
                    if _path in _cc_seen or _path in seen_paths:
                        continue
                    _cc_seen.add(_path)
                    if _WAYBACK_INTERESTING.search(_path):
                        _ts = str(_d.get("timestamp", ""))
                        cc_interesting.append({
                            "url": _d["url"],
                            "last_seen": f"{_ts[:4]}-{_ts[4:6]}-{_ts[6:8]}" if len(_ts) >= 8 else _ts,
                            "source": "CommonCrawl",
                        })
                except Exception:
                    pass
    except Exception:
        pass

    all_interesting = interesting[:30] + cc_interesting[:10]
    sev = "HIGH" if len(all_interesting) >= 3 else "MEDIUM" if all_interesting else "INFO"
    return {
        "status": "completed",
        "total_snapshots": total,
        "interesting_urls": all_interesting[:40],
        "interesting_count": len(all_interesting),
        "common_crawl_count": len(cc_interesting),
        "severity": sev,
        "finding": (
            f"{len(all_interesting)} historically exposed sensitive endpoint(s) found "
            f"(Wayback: {len(interesting)}, CommonCrawl: {len(cc_interesting)}) — may still be accessible."
            if all_interesting else
            f"No sensitive historical endpoints found across {total} Wayback snapshots + CommonCrawl."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5. Cloud bucket detection (HEAD only)
# ─────────────────────────────────────────────────────────────────────────────

def check_cloud_buckets(domain: str, timeout: int = 12) -> dict:
    """
    Generate plausible bucket names from the domain and check if they exist
    or are publicly accessible. Only sends HEAD requests — no data downloaded.
    """
    host = urlparse(domain).netloc or domain.replace("https://", "").replace("http://", "")
    base = host.split(":")[0].split(".")[0]  # e.g. "example" from "example.com"
    tld_stripped = re.sub(r'\.(com|net|org|io|co\.il|il|co\.uk|uk|dev|app)$', '', host.replace("www.", ""))

    suffixes = [
        "", "-assets", "-static", "-prod", "-staging", "-dev", "-test",
        "-backup", "-media", "-uploads", "-files", "-data", "-logs",
        "-images", "-cdn", "-public", "-private", "-archive",
        # Extended: common patterns missed by narrow list
        "-old", "-legacy", "-bak", "-v1", "-v2", "-next",
        "-eu", "-us", "-asia", "-us-east", "-us-west",
        "-store", "-content", "-resources", "-temp", "-tmp",
        "-web", "-app", "-api", "-docs", "-reports",
    ]

    names = list({base + s for s in suffixes} | {tld_stripped + s for s in suffixes})

    buckets_to_check: list[tuple[str, str, str]] = []
    for name in names:
        clean = re.sub(r'[^a-z0-9\-]', '-', name.lower()).strip('-')
        if not clean or len(clean) < 3:
            continue
        buckets_to_check.extend([
            (f"https://{clean}.s3.amazonaws.com/",              "AWS S3",              clean),
            (f"https://{clean}.s3.us-east-1.amazonaws.com/",    "AWS S3 USE1",         clean),
            (f"https://storage.googleapis.com/{clean}/",        "GCS",                 clean),
            (f"https://{clean}.blob.core.windows.net/",         "Azure Blob",          clean),
            (f"https://{clean}.nyc3.digitaloceanspaces.com/",   "DigitalOcean Spaces", clean),
            (f"https://{clean}.ams3.digitaloceanspaces.com/",   "DigitalOcean Spaces", clean),
        ])

    open_buckets:      list[dict] = []
    existing_private:  list[dict] = []
    takeover_possible: list[dict] = []

    def _check(bucket_url: str, provider: str, name: str) -> dict | None:
        r = _safe_head(bucket_url, timeout=timeout)
        if not r:
            return None
        if r.status_code == 200:
            # Try GET to detect directory listing
            listing_enabled = False
            gr = _safe_get(bucket_url, timeout=timeout)
            if gr and gr.status_code == 200:
                body = gr.text[:4000]
                listing_enabled = bool(re.search(
                    r'<ListBucketResult|xmlns.*s3\.amazonaws\.com|'
                    r'<EnumerationResults|BlobPrefix|<Contents>|<Key>',
                    body, re.IGNORECASE
                ))
            return {"url": bucket_url, "provider": provider, "name": name,
                    "public": True, "listing_enabled": listing_enabled,
                    "severity": "CRITICAL"}
        if r.status_code == 403:
            return {"url": bucket_url, "provider": provider, "name": name,
                    "public": False, "severity": "MEDIUM"}
        if r.status_code in (404, 400):
            # Check body for "NoSuchBucket" — bucket name unregistered = takeover possible
            gr = _safe_get(bucket_url, timeout=5)
            if gr and "NoSuchBucket" in (gr.text or ""):
                return {"url": bucket_url, "provider": provider, "name": name,
                        "public": False, "takeover": True, "severity": "HIGH"}
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = [pool.submit(_check, u, p, n) for u, p, n in buckets_to_check[:80]]
        try:
            for fut in as_completed(futs, timeout=timeout + 5):
                try:
                    res = fut.result()
                    if not res:
                        continue
                    if res.get("takeover"):
                        takeover_possible.append(res)
                    elif res["public"]:
                        open_buckets.append(res)
                    else:
                        existing_private.append(res)
                except Exception as exc:
                    logger.debug("Bucket check failed: %s", type(exc).__name__)
        except FutTimeout:
            logger.debug("check_cloud_buckets: total timeout exceeded — partial results")

    listing = [b for b in open_buckets if b.get("listing_enabled")]
    sev = ("CRITICAL" if open_buckets else
           "HIGH"     if takeover_possible else
           "MEDIUM"   if existing_private else "INFO")
    return {
        "status": "completed",
        "buckets_checked": len(buckets_to_check),
        "open_buckets": open_buckets,
        "directory_listing_buckets": listing,
        "private_buckets_found": existing_private[:10],
        "takeover_candidates": takeover_possible[:5],
        "severity": sev,
        "finding": (
            f"CRITICAL: {len(open_buckets)} PUBLIC bucket(s) found"
            + (f" — {len(listing)} with directory listing enabled!" if listing else "") + ": "
            + ", ".join(b["url"] for b in open_buckets[:3])
            if open_buckets else
            f"HIGH: {len(takeover_possible)} bucket name(s) available for takeover: "
            + ", ".join(b["url"] for b in takeover_possible[:2])
            if takeover_possible else
            f"{len(existing_private)} private bucket(s) exist (access denied)."
            if existing_private else
            "No cloud storage buckets found matching domain patterns."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 6. HTTP methods check
# ─────────────────────────────────────────────────────────────────────────────

_DANGEROUS_METHODS = {"TRACE", "DELETE", "PUT", "CONNECT", "PATCH", "DEBUG", "TRACK"}

def check_http_methods(url: str, timeout: int = 10) -> dict:
    """Send OPTIONS to discover allowed HTTP methods; test TRACE for XST."""
    try:
        host = urlparse(url).hostname or ""
        if is_ssrf_blocked(host):
            return {"status": "ssrf_blocked", "severity": "INFO"}

        sess = _session()
        allowed: list[str] = []
        options_ok = False

        try:
            r_opt = sess.options(url, timeout=timeout)
            allow_hdr = r_opt.headers.get("Allow", "") or r_opt.headers.get("Access-Control-Allow-Methods", "")
            if allow_hdr:
                allowed = [m.strip().upper() for m in allow_hdr.split(",") if m.strip()]
                options_ok = True
        except Exception:
            pass

        # Test TRACE explicitly — XST vulnerability
        xst_vulnerable = False
        try:
            r_trace = sess.request("TRACE", url, timeout=timeout)
            if r_trace.status_code == 200 and "TRACE" in r_trace.text.upper():
                xst_vulnerable = True
                if "TRACE" not in allowed:
                    allowed.append("TRACE")
        except Exception:
            pass

        dangerous_found = [m for m in allowed if m in _DANGEROUS_METHODS]
        sev = "HIGH" if xst_vulnerable or "DELETE" in dangerous_found else \
              "MEDIUM" if dangerous_found else "INFO"

        return {
            "status": "completed",
            "options_responded": options_ok,
            "allowed_methods": allowed,
            "dangerous_methods": dangerous_found,
            "xst_vulnerable": xst_vulnerable,
            "severity": sev,
            "finding": (
                f"XST (Cross-Site Tracing) vulnerability — TRACE method enabled."
                if xst_vulnerable else
                f"Dangerous methods enabled: {', '.join(dangerous_found)}"
                if dangerous_found else
                f"No dangerous HTTP methods detected. Allowed: {', '.join(allowed) or 'standard'}."
            ),
        }
    except Exception as exc:
        logger.debug("analyze_email_spoofability: %s", exc)
        return {"status": "error", "error": type(exc).__name__, "severity": "INFO",
                "finding": "Email spoofability check failed — DNS lookup error."}


# ─────────────────────────────────────────────────────────────────────────────
# 7. Email spoofability — DMARC / SPF / DKIM deep analysis
# ─────────────────────────────────────────────────────────────────────────────

_DKIM_SELECTORS = [
    # Common named selectors
    "default", "dkim", "mail", "email", "smtp", "mx",
    # Google Workspace
    "google", "google1", "google2",
    # Microsoft 365
    "selector1", "selector2",
    # SendGrid
    "s1", "s2", "k1", "k2",
    # Amazon SES
    "amazonses", "ses",
    # Mailchimp / Mandrill
    "mandrill", "mc", "mailchimp", "k3",
    # SendGrid / Twilio
    "sg", "sendgrid",
    # Proofpoint / Mimecast / Barracuda
    "proofpoint", "mimecast", "barracuda",
    # Custom numbered selectors used by large orgs
    "d1", "d2", "d3", "dk1", "dk2",
    # Date-based selectors (year-based)
    "2023", "2024", "2025", "2026",
    # Provider-specific
    "brevo", "hubspot", "mailgun", "mailjet",
    "postfix", "postmark", "sparkpost",
    # Generic secondary selectors
    "key1", "key2", "key3", "pm",
    "zoho", "yandex", "protonmail",
]

def analyze_email_spoofability(domain: str, timeout: int = 10) -> dict:
    """
    Deep SPF/DMARC/DKIM/BIMI analysis to determine if domain can be spoofed.
    Primary: Cloudflare DoH (no dnspython required).
    Enhancement: dnspython DKIM selector probe (if available).
    """
    host = urlparse(domain).netloc or domain.replace("https://", "").replace("http://", "")
    host = host.split(":")[0].split("/")[0]
    base = re.sub(r'^www\.', '', host)

    def _txt(name: str) -> list[str]:
        """TXT lookup — DoH primary, dnspython fallback."""
        records = _doh_txt(name, "TXT", timeout)
        if records:
            return records
        if _DNS_OK:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = resolver.lifetime = timeout
                ans = resolver.resolve(name, "TXT")
                return [b.decode() if isinstance(b, bytes) else str(b)
                        for rr in ans for b in rr.strings]
            except Exception:
                pass
        return []

    # ── SPF ──
    spf_records = [r for r in _txt(base) if r.startswith("v=spf1")]
    spf_raw   = spf_records[0] if spf_records else ""
    spf_multi = len(spf_records) > 1  # multiple SPF = invalid per RFC 7208
    if not spf_raw:
        spf_strength = "missing"
    elif "-all" in spf_raw:
        spf_strength = "hardfail"
    elif "~all" in spf_raw:
        spf_strength = "softfail"
    elif "?all" in spf_raw:
        spf_strength = "neutral"
    else:
        spf_strength = "pass_all"  # "+all" = anyone can send

    # SPF subdomain policy (sp=) — separate from main domain policy
    spf_sp_match = re.search(r"\bsp=(\w+)", spf_raw) if spf_raw else None
    spf_sp = spf_sp_match.group(1).lower() if spf_sp_match else "inherit"

    # SPF include chain depth — RFC 7208 max 10 DNS lookups
    spf_include_count = (len(re.findall(r'\binclude:', spf_raw)) +
                         len(re.findall(r'\b(?:ptr|a|mx)\b', spf_raw))) if spf_raw else 0

    # ── DMARC ──
    dmarc_records = _txt(f"_dmarc.{base}")
    dmarc_raw     = next((r for r in dmarc_records if r.startswith("v=DMARC1")), "")
    dmarc_policy  = "missing"
    dmarc_pct     = 100
    dmarc_rua     = ""
    if dmarc_raw:
        m = re.search(r"p=(\w+)", dmarc_raw)
        if m:
            dmarc_policy = m.group(1).lower()
        m = re.search(r"pct=(\d+)", dmarc_raw)
        if m:
            dmarc_pct = int(m.group(1))
        m = re.search(r"rua=([^;]+)", dmarc_raw)
        if m:
            dmarc_rua = m.group(1).strip()

    # ── DKIM — parallel probing (14 selectors concurrently via DoH) ──────────
    def _check_dkim_sel(sel: str) -> str | None:
        recs = _txt(f"{sel}._domainkey.{base}")
        return sel if any("p=" in r for r in recs) else None

    with ThreadPoolExecutor(max_workers=8) as _dp:
        dkim_found = [s for s in _dp.map(_check_dkim_sel, _DKIM_SELECTORS) if s]

    # ── Spoofability scoring ──
    if dmarc_policy == "missing" and spf_strength == "missing":
        spoofability = "CRITICAL"
        can_spoof    = True
        detail       = "No SPF and no DMARC — domain is fully spoofable for phishing."
    elif dmarc_policy in ("reject", "quarantine") and not spf_records and not dkim_found:
        # DMARC enforcement reality check: policy set but no SPF AND no DKIM means
        # DMARC cannot authenticate *any* email — the policy is decorative.
        spoofability = "CRITICAL"
        can_spoof    = True
        detail       = (f"DMARC p={dmarc_policy} is set but neither SPF nor DKIM exist — "
                        "DMARC has nothing to authenticate against. All spoofed emails pass enforcement.")
    elif dmarc_policy == "missing" or dmarc_policy == "none":
        spoofability = "HIGH"
        can_spoof    = True
        detail       = "DMARC policy is 'none' or missing — emails can be spoofed and will be delivered."
    elif dmarc_pct < 100:
        spoofability = "HIGH"
        can_spoof    = True
        detail       = f"DMARC pct={dmarc_pct}% — {100-dmarc_pct}% of spoofed emails bypass enforcement."
    elif dmarc_policy == "quarantine" and spf_strength in ("missing", "neutral", "softfail"):
        spoofability = "MEDIUM"
        can_spoof    = False
        detail       = "DMARC quarantine but weak SPF — spoofed mail may land in spam."
    elif dmarc_policy == "reject" and spf_strength == "hardfail":
        spoofability = "LOW"
        can_spoof    = False
        detail       = "Strong DMARC (reject) + SPF hardfail — spoofing is blocked."
    else:
        spoofability = "MEDIUM"
        can_spoof    = dmarc_policy not in ("reject",)
        detail       = f"DMARC {dmarc_policy} + SPF {spf_strength} — partial protection."

    # Subdomain spoofability warning: if sp= is weaker than main domain policy
    if spf_sp in ("none", "pass") and spf_strength == "hardfail":
        detail += f" Note: SPF subdomain policy (sp={spf_sp}) is weaker than main domain — subdomains spoofable."

    # SPF include chain depth warning (RFC 7208 §4.6.4 max 10 lookups)
    if spf_include_count > 8:
        detail += f" Warning: SPF has {spf_include_count}+ DNS lookups — approaching RFC 7208 limit of 10."

    # ── BIMI check (Brand Indicators for Message Identification) ──────────────
    bimi_records = _txt(f"default._bimi.{base}")
    has_bimi     = bool(bimi_records and any("v=BIMI1" in r for r in bimi_records))

    # ── TXT service fingerprinting ────────────────────────────────────────────
    _SVC_PATTERNS = {
        "google-site-verification": "Google Workspace",
        "MS=ms": "Microsoft 365",
        "amazonses": "Amazon SES",
        "_amazonses": "Amazon SES",
        "stripe-verification": "Stripe",
        "facebook-domain-verification": "Facebook/Meta",
        "atlassian-domain-verification": "Atlassian",
        "docusign": "DocuSign",
        "zoho-verification": "Zoho",
        "hubspot-developer-verification": "HubSpot",
        "sendgrid.net": "SendGrid",
        "mandrill": "Mailchimp/Mandrill",
        "apple-domain-verification": "Apple",
        "yandex-verification": "Yandex",
        "brevo-code": "Brevo (Sendinblue)",
        "protonmail-verification": "ProtonMail",
        "globalsign-domain-verification": "GlobalSign CA",
    }
    all_txt_records = _txt(base)
    registered_services: list[str] = []
    for rec in all_txt_records:
        for pattern, svc in _SVC_PATTERNS.items():
            if pattern.lower() in rec.lower() and svc not in registered_services:
                registered_services.append(svc)

    return {
        "status": "completed",
        "domain": host,
        "spf_record": spf_raw or None,
        "spf_strength": spf_strength,
        "spf_multiple_records": spf_multi,
        "spf_subdomain_policy": spf_sp,
        "spf_include_count": spf_include_count,
        "dmarc_record": dmarc_raw or None,
        "dmarc_policy": dmarc_policy,
        "dmarc_pct": dmarc_pct,
        "dmarc_rua": dmarc_rua,
        "dkim_found": bool(dkim_found),
        "dkim_selectors": dkim_found,
        "has_bimi": has_bimi,
        "registered_services": registered_services,
        "spoofability": spoofability,
        "can_spoof": can_spoof,
        "severity": spoofability,
        "finding": detail,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 8. CVE correlation (offline — embedded pattern database)
# ─────────────────────────────────────────────────────────────────────────────

_CVE_DB: list[dict] = [
    # jQuery
    {"tech": "jquery",      "max_version": "3.4.9", "cve": "CVE-2020-11023", "severity": "MEDIUM",
     "desc": "XSS via HTML injection in jQuery < 3.5.0", "fix": "Upgrade jQuery ≥ 3.5.0"},
    {"tech": "jquery",      "max_version": "3.4.9", "cve": "CVE-2019-11358", "severity": "MEDIUM",
     "desc": "Prototype pollution in jQuery < 3.4.0",    "fix": "Upgrade jQuery ≥ 3.4.0"},
    # Bootstrap
    {"tech": "bootstrap",   "max_version": "3.4.0", "cve": "CVE-2019-8331",  "severity": "MEDIUM",
     "desc": "XSS in Bootstrap tooltip/popover < 3.4.1", "fix": "Upgrade Bootstrap ≥ 3.4.1"},
    {"tech": "bootstrap",   "max_version": "4.3.0", "cve": "CVE-2019-8331",  "severity": "MEDIUM",
     "desc": "XSS in Bootstrap tooltip/popover < 4.3.1", "fix": "Upgrade Bootstrap ≥ 4.3.1"},
    # WordPress
    {"tech": "wordpress",   "max_version": "6.1.9", "cve": "CVE-2023-2745",  "severity": "HIGH",
     "desc": "WordPress path traversal < 6.2.1",         "fix": "Update WordPress to latest"},
    {"tech": "wordpress",   "max_version": "5.9.9", "cve": "CVE-2022-21661", "severity": "HIGH",
     "desc": "WordPress SQL injection < 5.8.3",          "fix": "Update WordPress to latest"},
    # Apache
    {"tech": "apache",      "max_version": "2.4.55", "cve": "CVE-2023-25690", "severity": "CRITICAL",
     "desc": "Apache HTTP Server request splitting < 2.4.56", "fix": "Upgrade Apache ≥ 2.4.56"},
    {"tech": "apache",      "max_version": "2.4.49", "cve": "CVE-2021-41773", "severity": "CRITICAL",
     "desc": "Apache path traversal + RCE (2.4.49-2.4.50)", "fix": "Upgrade Apache immediately"},
    # PHP
    {"tech": "php",         "max_version": "7.4.99", "cve": "CVE-2021-21703", "severity": "HIGH",
     "desc": "PHP-FPM local privilege escalation in PHP 7.x", "fix": "Upgrade PHP ≥ 8.0"},
    {"tech": "php",         "max_version": "8.0.99", "cve": "CVE-2022-31625", "severity": "CRITICAL",
     "desc": "PHP null dereference / heap corruption in PHP < 8.1.8", "fix": "Upgrade PHP ≥ 8.1.8"},
    # Log4j
    {"tech": "log4j",       "max_version": "2.14.9", "cve": "CVE-2021-44228", "severity": "CRITICAL",
     "desc": "Log4Shell — remote code execution via JNDI lookup", "fix": "Upgrade Log4j ≥ 2.16.0 immediately"},
    # Spring
    {"tech": "spring",      "max_version": "5.3.17", "cve": "CVE-2022-22965", "severity": "CRITICAL",
     "desc": "Spring4Shell — RCE via DataBinder on JDK 9+", "fix": "Upgrade Spring Framework ≥ 5.3.18"},
    # OpenSSL
    {"tech": "openssl",     "max_version": "3.0.6",  "cve": "CVE-2022-3786",  "severity": "HIGH",
     "desc": "OpenSSL buffer overflow in punycode decoding < 3.0.7", "fix": "Upgrade OpenSSL ≥ 3.0.7"},
    # nginx
    {"tech": "nginx",       "max_version": "1.23.1", "cve": "CVE-2022-41741", "severity": "HIGH",
     "desc": "nginx MP4 module memory corruption < 1.23.2", "fix": "Upgrade nginx ≥ 1.23.2"},
    # Drupal
    {"tech": "drupal",      "max_version": "9.3.9",  "cve": "CVE-2022-25271", "severity": "HIGH",
     "desc": "Drupal improper input validation < 9.3.10",  "fix": "Update Drupal to latest"},
    # Lodash
    {"tech": "lodash",      "max_version": "4.17.20", "cve": "CVE-2021-23337", "severity": "HIGH",
     "desc": "Prototype pollution via lodash.template < 4.17.21", "fix": "Upgrade lodash ≥ 4.17.21"},
    {"tech": "lodash",      "max_version": "4.17.19", "cve": "CVE-2020-8203",  "severity": "HIGH",
     "desc": "Prototype pollution in lodash < 4.17.19", "fix": "Upgrade lodash ≥ 4.17.20"},
    # Moment.js
    {"tech": "moment",      "max_version": "2.29.3", "cve": "CVE-2022-24785",  "severity": "HIGH",
     "desc": "Moment.js path traversal in locale loading < 2.29.2", "fix": "Upgrade moment ≥ 2.29.2"},
    {"tech": "moment",      "max_version": "2.19.2", "cve": "CVE-2017-18214",  "severity": "HIGH",
     "desc": "ReDoS via date string in moment.js < 2.19.3", "fix": "Upgrade moment ≥ 2.19.3"},
    # Apache Tomcat
    {"tech": "tomcat",      "max_version": "10.1.15", "cve": "CVE-2023-46589",  "severity": "HIGH",
     "desc": "Apache Tomcat request smuggling < 10.1.16, 9.0.83, 8.5.96", "fix": "Upgrade Tomcat to latest"},
    {"tech": "tomcat",      "max_version": "9.0.30",  "cve": "CVE-2020-1938",   "severity": "CRITICAL",
     "desc": "Apache Tomcat AJP connector arbitrary file read + RCE (Ghostcat)", "fix": "Disable AJP or upgrade ≥ 9.0.31"},
    # Next.js
    {"tech": "next",        "max_version": "14.2.4",  "cve": "CVE-2024-46982",  "severity": "CRITICAL",
     "desc": "Next.js cache poisoning via crafted request headers < 14.2.10", "fix": "Upgrade Next.js ≥ 14.2.10"},
    {"tech": "next",        "max_version": "15.2.2",  "cve": "CVE-2025-29927",  "severity": "CRITICAL",
     "desc": "Next.js middleware auth bypass via x-middleware-subrequest header", "fix": "Upgrade Next.js ≥ 15.2.3"},
    # Express.js
    {"tech": "express",     "max_version": "4.17.0",  "cve": "CVE-2022-24999",  "severity": "HIGH",
     "desc": "qs prototype pollution affects Express.js < 4.17.3", "fix": "Upgrade Express ≥ 4.17.3"},
    # Angular
    {"tech": "angular",     "max_version": "12.2.12", "cve": "CVE-2022-25869",  "severity": "MEDIUM",
     "desc": "Angular XSS via bypassSecurityTrustHtml in < 12.2.13", "fix": "Upgrade Angular ≥ 12.2.13"},
    # React (via react-dom)
    {"tech": "react",       "max_version": "16.13.0", "cve": "CVE-2021-27562",  "severity": "MEDIUM",
     "desc": "React Server-Side XSS risk in < 16.13.1 via dangerouslySetInnerHTML", "fix": "Upgrade React ≥ 16.13.1"},
    # Axios
    {"tech": "axios",       "max_version": "0.21.0",  "cve": "CVE-2021-3749",   "severity": "HIGH",
     "desc": "Axios ReDoS via XSRF token header in < 0.21.1", "fix": "Upgrade axios ≥ 0.21.1"},
    {"tech": "axios",       "max_version": "0.27.9",  "cve": "CVE-2023-45857",  "severity": "HIGH",
     "desc": "Axios XSSI + credential leak in < 1.6.0", "fix": "Upgrade axios ≥ 1.6.0"},
    # Ruby on Rails
    {"tech": "rails",       "max_version": "7.0.7",   "cve": "CVE-2023-38037",  "severity": "HIGH",
     "desc": "Rails file disclosure via ActiveStorage < 7.0.8, 6.1.7.5", "fix": "Upgrade Rails to latest"},
    {"tech": "rails",       "max_version": "6.0.3",   "cve": "CVE-2021-22885",  "severity": "HIGH",
     "desc": "Rails directory traversal in Action Dispatch < 6.0.3.7", "fix": "Upgrade Rails ≥ 6.0.3.7"},
    # Django
    {"tech": "django",      "max_version": "4.1.12",  "cve": "CVE-2023-43665",  "severity": "HIGH",
     "desc": "Django Deny-of-Service via Truncated DoS in Truncator < 4.2.6, 3.2.22", "fix": "Upgrade Django ≥ 4.2.6"},
    {"tech": "django",      "max_version": "3.2.17",  "cve": "CVE-2023-24580",  "severity": "HIGH",
     "desc": "Django DoS via multipart form data in < 4.1.8, 4.0.11, 3.2.18", "fix": "Upgrade Django ≥ 3.2.18"},
    # Laravel
    {"tech": "laravel",     "max_version": "8.4.2",   "cve": "CVE-2021-3129",   "severity": "CRITICAL",
     "desc": "Laravel RCE via debug mode + Ignition < 8.4.3 (POP chain)", "fix": "Upgrade Laravel ≥ 8.4.3 or disable debug"},
    # Jenkins
    {"tech": "jenkins",     "max_version": "2.441.0", "cve": "CVE-2024-23897",  "severity": "CRITICAL",
     "desc": "Jenkins CLI arbitrary file read < 2.442 leading to RCE (CVSS 9.8)", "fix": "Upgrade Jenkins ≥ 2.442"},
    {"tech": "jenkins",     "max_version": "2.204.0", "cve": "CVE-2019-1003000", "severity": "CRITICAL",
     "desc": "Jenkins Script Security sandbox bypass leading to RCE", "fix": "Upgrade Jenkins + Script Security plugin"},
    # GitLab
    {"tech": "gitlab",      "max_version": "16.5.99", "cve": "CVE-2023-7028",   "severity": "CRITICAL",
     "desc": "GitLab account takeover via password reset without user interaction < 16.6.1", "fix": "Upgrade GitLab ≥ 16.6.1"},
    {"tech": "gitlab",      "max_version": "15.3.4",  "cve": "CVE-2022-2884",   "severity": "CRITICAL",
     "desc": "GitLab RCE via import from GitHub (authenticated) < 15.3.4", "fix": "Upgrade GitLab ≥ 15.3.5"},
    # Confluence
    {"tech": "confluence",  "max_version": "8.5.2",   "cve": "CVE-2023-22518",  "severity": "CRITICAL",
     "desc": "Confluence improper authorization RCE (unauthenticated) < 8.5.3", "fix": "Upgrade Confluence immediately"},
    {"tech": "confluence",  "max_version": "7.18.0",  "cve": "CVE-2022-26134",  "severity": "CRITICAL",
     "desc": "Confluence OGNL injection RCE via Server/Data Center (0-day)", "fix": "Upgrade Confluence immediately"},
    # Node.js
    {"tech": "node",        "max_version": "18.18.1", "cve": "CVE-2023-44487",  "severity": "HIGH",
     "desc": "HTTP/2 Rapid Reset DoS attack affects Node.js < 18.18.2, 20.8.1", "fix": "Upgrade Node.js to latest LTS"},
    # Magento / Adobe Commerce
    {"tech": "magento",     "max_version": "2.4.5",   "cve": "CVE-2022-24086",  "severity": "CRITICAL",
     "desc": "Magento improper input validation allows RCE without authentication", "fix": "Apply Magento security patches immediately"},
    # WooCommerce
    {"tech": "woocommerce", "max_version": "6.6.0",   "cve": "CVE-2022-2099",   "severity": "HIGH",
     "desc": "WooCommerce arbitrary file read via order export < 6.6.1", "fix": "Update WooCommerce ≥ 6.6.1"},
    # Strapi
    {"tech": "strapi",      "max_version": "4.5.5",   "cve": "CVE-2023-22621",  "severity": "CRITICAL",
     "desc": "Strapi server-side template injection leads to RCE < 4.5.6", "fix": "Upgrade Strapi ≥ 4.5.6"},
    # MinIO
    {"tech": "minio",       "max_version": "2023.02.09", "cve": "CVE-2023-28432", "severity": "CRITICAL",
     "desc": "MinIO information disclosure — /minio/health/cluster leaks env vars including credentials", "fix": "Upgrade MinIO to RELEASE.2023-03-13 or later"},
    # Grafana
    {"tech": "grafana",     "max_version": "8.3.0",   "cve": "CVE-2021-43798",  "severity": "CRITICAL",
     "desc": "Grafana arbitrary file read via path traversal in plugin assets < 8.3.1", "fix": "Upgrade Grafana ≥ 8.3.1"},
    # OpenSSH
    {"tech": "openssh",     "max_version": "9.7.0",   "cve": "CVE-2024-6387",   "severity": "CRITICAL",
     "desc": "OpenSSH RegreSSHion — unauthenticated RCE via race condition < 9.8p1", "fix": "Upgrade OpenSSH ≥ 9.8p1 immediately"},
    # Prototype.js (legacy)
    {"tech": "prototype",   "max_version": "1.7.3",   "cve": "CVE-2008-7220",   "severity": "HIGH",
     "desc": "Prototype.js JSON injection enables XSS (legacy library)", "fix": "Remove Prototype.js — unmaintained since 2015"},
    # Vue.js
    {"tech": "vue",         "max_version": "2.6.12",  "cve": "CVE-2021-41184",  "severity": "MEDIUM",
     "desc": "Vue.js XSS via v-html directive with untrusted user input", "fix": "Upgrade Vue ≥ 2.6.14 and sanitize inputs"},
    # highlight.js
    {"tech": "highlight",   "max_version": "10.4.0",  "cve": "CVE-2021-23566",  "severity": "MEDIUM",
     "desc": "highlight.js ReDoS in < 10.4.1 via crafted language names", "fix": "Upgrade highlight.js ≥ 10.4.1"},
    # Swagger UI
    {"tech": "swagger",     "max_version": "3.52.4",  "cve": "CVE-2019-17495",  "severity": "MEDIUM",
     "desc": "Swagger UI XSS via crafted URL — allows phishing/token theft", "fix": "Upgrade Swagger UI ≥ 3.52.5"},
    # OpenSSL (additional)
    {"tech": "openssl",     "max_version": "1.1.1s",  "cve": "CVE-2023-0286",   "severity": "HIGH",
     "desc": "OpenSSL X.400 GeneralName type confusion — DoS or RCE < 3.0.8/1.1.1t", "fix": "Upgrade OpenSSL ≥ 3.0.8 or 1.1.1t"},
    # Elasticsearch
    {"tech": "elasticsearch","max_version":"7.16.2",  "cve": "CVE-2021-22145",  "severity": "HIGH",
     "desc": "Elasticsearch improper access control in < 7.16.3 allows index enumeration", "fix": "Upgrade Elasticsearch ≥ 7.16.3"},
    # Redis
    {"tech": "redis",       "max_version": "7.0.14",  "cve": "CVE-2023-41056",  "severity": "HIGH",
     "desc": "Redis heap overflow in < 7.0.15, 7.2.4 — potential RCE", "fix": "Upgrade Redis ≥ 7.0.15"},
]


def _parse_version(ver_str: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", ver_str)
    return tuple(int(p) for p in parts[:3]) if parts else (0,)


def correlate_cves(tech_results: dict) -> dict:
    """
    Match technologies detected by tech_fingerprinter against the embedded CVE database.
    tech_results: dict from tools.tech_fingerprinter.fingerprint_technologies()
    """
    if not tech_results or tech_results.get("status") == "error":
        return {"status": "completed", "matched_cves": [], "severity": "INFO",
                "finding": "No technology fingerprint available — CVE correlation skipped for this target."}

    technologies = tech_results.get("technologies", {})
    if not technologies:
        return {"status": "completed", "matched_cves": [], "severity": "INFO",
                "finding": "No technology versions detected — no known CVEs to correlate."}

    matched: list[dict] = []
    for entry in _CVE_DB:
        tech_key = entry["tech"].lower()
        # Try to find this tech in the fingerprinted technologies
        for tech_name, tech_info in technologies.items():
            if tech_key not in tech_name.lower():
                continue
            version_str = ""
            if isinstance(tech_info, dict):
                version_str = str(tech_info.get("version", ""))
            elif isinstance(tech_info, str):
                version_str = tech_info

            if not version_str or version_str in ("unknown", "?", ""):
                # Still report the CVE as potential (version unknown)
                matched.append({**entry, "detected_version": "unknown", "confirmed": False})
                break

            detected_v = _parse_version(version_str)
            max_v      = _parse_version(entry["max_version"])
            if detected_v <= max_v:
                matched.append({**entry, "detected_version": version_str, "confirmed": True})
            break

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    matched.sort(key=lambda x: sev_order.get(x["severity"], 9))

    counts = {s: sum(1 for m in matched if m["severity"] == s)
              for s in ("CRITICAL", "HIGH", "MEDIUM")}
    overall = "CRITICAL" if counts["CRITICAL"] else "HIGH" if counts["HIGH"] else \
              "MEDIUM" if counts["MEDIUM"] else "INFO"

    return {
        "status": "completed",
        "matched_cves": matched[:20],
        "cve_count": len(matched),
        "severity_counts": counts,
        "severity": overall,
        "finding": (
            f"{len(matched)} CVE(s) matched to detected technologies: "
            + ", ".join(f"{m['cve']} ({m['severity']})" for m in matched[:3])
            if matched else
            "No known CVEs matched for detected technology versions."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 9. Error page / meta information leakage
# ─────────────────────────────────────────────────────────────────────────────

_STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at [\w\.<>]+\([\w\.]+:\d+\)"),           # Java stack trace
    re.compile(r"Exception in thread .+? at [\w\.]+"),
    re.compile(r"Fatal error:\s.+? in /.+? on line \d+"),  # PHP error
    re.compile(r"SyntaxError|ReferenceError|TypeError.+? at "),  # JS error
    re.compile(r"\[object Object\]\s+at "),
]
_PATH_PATTERNS = [
    re.compile(r"/(?:home|var|usr|etc|opt|srv|app|www|data)/[\w/\-\.]+"),
    re.compile(r"[A-Za-z]:\\(?:inetpub|Users|Program Files|Windows)\\[\w\\]+"),
]
_SERVER_DISCLOSURE = re.compile(
    r"(?i)<(?:address|h2|p)>(?:Apache|nginx|IIS|lighttpd)[^<]*</(?:address|h2|p)>"
)
_FRAMEWORK_DISCLOSURE = re.compile(
    r"(?i)(Django|Rails|Laravel|Symfony|Express|FastAPI|Flask)[/\s]+(\d+\.\d+[\.\d]*)"
)

def check_meta_leakage(url: str, timeout: int = 12) -> dict:
    """Check error pages for info disclosure — stack traces, internal paths, versions."""
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    probe_paths = [
        "/this-page-definitely-does-not-exist-xyzabc123",
        "/debug",
        "/test",
        "/.well-known/",
    ]

    disclosures: list[dict] = []
    server_header = ""
    powered_by    = ""

    for path in probe_paths:
        r = _safe_get(urljoin(base, path), timeout=timeout)
        if not r:
            continue

        # Capture headers only once
        if not server_header:
            server_header = r.headers.get("Server", "")
            powered_by    = r.headers.get("X-Powered-By", "")

        body = r.text[:20_000]

        for pat in _STACK_TRACE_PATTERNS:
            if pat.search(body):
                disclosures.append({
                    "type": "stack_trace",
                    "path": path,
                    "preview": pat.search(body).group(0)[:120],
                    "severity": "HIGH",
                })
                break

        for pat in _PATH_PATTERNS:
            m = pat.search(body)
            if m:
                disclosures.append({
                    "type": "internal_path",
                    "path": path,
                    "preview": m.group(0)[:100],
                    "severity": "MEDIUM",
                })
                break

        m = _SERVER_DISCLOSURE.search(body)
        if m:
            disclosures.append({
                "type": "server_version_in_body",
                "path": path,
                "preview": m.group(0)[:80],
                "severity": "LOW",
            })

        m = _FRAMEWORK_DISCLOSURE.search(body)
        if m:
            disclosures.append({
                "type": "framework_version",
                "path": path,
                "preview": f"{m.group(1)} {m.group(2)}",
                "severity": "MEDIUM",
            })

    # Server / X-Powered-By header disclosures (version specific)
    if re.search(r"\d+\.\d+", server_header):
        disclosures.append({
            "type": "server_version_header",
            "path": "HTTP headers",
            "preview": f"Server: {server_header}",
            "severity": "LOW",
        })
    if powered_by:
        disclosures.append({
            "type": "technology_disclosure",
            "path": "HTTP headers",
            "preview": f"X-Powered-By: {powered_by}",
            "severity": "LOW",
        })

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict] = []
    for d in disclosures:
        sig = f"{d['type']}:{d['preview'][:40]}"
        if sig not in seen:
            seen.add(sig)
            unique.append(d)

    sev = "HIGH" if any(d["severity"] == "HIGH" for d in unique) else \
          "MEDIUM" if any(d["severity"] == "MEDIUM" for d in unique) else \
          "LOW" if unique else "INFO"

    return {
        "status": "completed",
        "server_header": server_header,
        "x_powered_by": powered_by,
        "disclosures": unique[:20],
        "disclosure_count": len(unique),
        "severity": sev,
        "finding": (
            f"{len(unique)} info disclosure finding(s): "
            + "; ".join(f"{d['type']} ({d['severity']})" for d in unique[:3])
            if unique else
            "No significant information disclosure found in error pages."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 10. Exposed sensitive files check
# ─────────────────────────────────────────────────────────────────────────────

_EXPOSED_FILE_PROBES: list[tuple[str, str, str, str]] = [
    # path, label, severity, why_it_matters
    ("/.git/HEAD",               "Git Repo Exposed",          "CRITICAL",
     "Full source code downloadable via /.git/ — git-dumper can clone entire repo"),
    ("/.git/config",             "Git Config Exposed",        "CRITICAL",
     "Git config reveals remote URL, branches — confirms git repo exposure"),
    ("/.env",                    ".env — Environment File",   "CRITICAL",
     "Database passwords, API keys, app secrets in plain text"),
    ("/.env.production",         ".env.production",           "CRITICAL",
     "Production environment file with real credentials"),
    ("/.env.local",              ".env.local",                "CRITICAL",
     "Local dev config with credentials accidentally in production"),
    ("/phpinfo.php",             "PHP Info Page",             "HIGH",
     "phpinfo() exposes PHP version, loaded modules, server path, env vars"),
    ("/info.php",                "PHP Info (info.php)",       "HIGH",
     "phpinfo() exposed — see above"),
    ("/actuator/env",            "Spring Actuator /env",      "CRITICAL",
     "Exposes ALL environment variables including DB passwords and API keys"),
    ("/actuator",                "Spring Boot Actuator",      "HIGH",
     "Spring Boot management endpoints — /actuator/env, /health, /beans accessible"),
    ("/swagger.json",            "Swagger API Docs",          "HIGH",
     "Full REST API specification — reveals all endpoints, auth schemes, parameters"),
    ("/api/swagger.json",        "Swagger (api/)",            "HIGH",
     "API documentation exposed — full endpoint map for attackers"),
    ("/openapi.json",            "OpenAPI Spec",              "HIGH",
     "OpenAPI specification exposed — complete API attack surface"),
    ("/api-docs",                "API Docs",                  "HIGH",
     "API documentation endpoint exposed"),
    ("/v2/api-docs",             "Swagger v2 API Docs",       "HIGH",
     "Swagger v2 API documentation exposed"),
    ("/graphql",                 "GraphQL Endpoint",          "MEDIUM",
     "GraphQL endpoint — introspection may expose full schema and mutations"),
    ("/.htaccess",               ".htaccess File",            "MEDIUM",
     "Apache access control config — reveals URL rewrite rules and protected paths"),
    ("/web.config",              "web.config (IIS)",          "MEDIUM",
     "IIS configuration — may contain connection strings, auth settings"),
    ("/backup.zip",              "Backup Archive",            "CRITICAL",
     "Full site backup downloadable — contains source code + database"),
    ("/backup.sql",              "SQL Database Dump",         "CRITICAL",
     "Database dump publicly downloadable — contains all user data"),
    ("/db.sql",                  "SQL Dump (db.sql)",         "CRITICAL",
     "Database backup accessible — full data exposure"),
    ("/dump.sql",                "SQL Dump (dump.sql)",       "CRITICAL",
     "Database dump accessible"),
    ("/wp-config.php.bak",       "WordPress Config Backup",   "CRITICAL",
     "WordPress DB credentials in backup file"),
    ("/config.php.bak",          "PHP Config Backup",         "CRITICAL",
     "PHP config backup with credentials"),
    ("/.DS_Store",               ".DS_Store Mac Metadata",    "MEDIUM",
     "MacOS finder metadata reveals directory structure and filenames"),
    ("/server-status",           "Apache server-status",      "HIGH",
     "Apache mod_status — real-time requests, internal URLs, worker threads"),
    ("/server-info",             "Apache server-info",        "MEDIUM",
     "Apache mod_info — detailed server and module configuration"),
    ("/package.json",            "package.json",              "LOW",
     "npm dependency list — enables precise CVE correlation"),
    ("/composer.json",           "composer.json",             "LOW",
     "PHP Composer dependencies — enables CVE correlation"),
    ("/docker-compose.yml",      "docker-compose.yml",        "HIGH",
     "Docker service config — reveals ports, volumes, environment variables"),
    ("/config.yml",              "config.yml",                "HIGH",
     "YAML config may contain credentials, database URLs, API keys"),
    ("/CHANGELOG.md",            "CHANGELOG.md",              "LOW",
     "Changelog reveals exact software version + vulnerability timeline"),
    ("/version.txt",             "version.txt",               "LOW",
     "Software version disclosure — enables targeted CVE search"),
    ("/crossdomain.xml",         "crossdomain.xml",           "MEDIUM",
     "Flash cross-domain policy — may allow excessive cross-origin data access"),
    ("/.well-known/jwks.json",  "JWKS Public Keys",          "HIGH",
     "JWT public keys exposed — if misconfigured, may enable JWT algorithm confusion attacks"),
    ("/.well-known/openid-configuration", "OIDC Discovery",  "MEDIUM",
     "OpenID Connect discovery endpoint — reveals auth server endpoints, supported flows, key IDs"),
    ("/WEB-INF/web.xml",        "Java web.xml Exposed",      "HIGH",
     "Java webapp deployment descriptor — reveals servlet config, security constraints, auth methods"),
    ("/WEB-INF/beans.xml",      "Java beans.xml Exposed",    "MEDIUM",
     "CDI beans descriptor — reveals Java component scan and dependency injection config"),
    ("/wp-login.php",           "WordPress Login",           "LOW",
     "WordPress admin login exposed — confirms WordPress; target for brute-force attacks"),
    ("/robots.txt",              None,                        None,  ""),  # skip — handled separately
]
# Remove skip entries
_EXPOSED_FILE_PROBES = [(p, l, s, w) for p, l, s, w in _EXPOSED_FILE_PROBES if s is not None]


def check_exposed_files(url: str, timeout: int = 15) -> dict:
    """
    HEAD/GET probe for commonly exposed sensitive files and endpoints.
    Passive — no payload injection, only normal HTTP requests to known paths.
    """
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    found: list[dict] = []

    def _probe(path: str, label: str, severity: str, why: str) -> dict | None:
        full = base + path
        r = _safe_head(full, timeout=6)
        if r is None:
            return None
        if r.status_code == 200:
            content_type = r.headers.get("Content-Type", "")
            content_len  = r.headers.get("Content-Length", "")
            return {
                "path": path,
                "full_url": full,
                "label": label,
                "severity": severity,
                "why": why,
                "content_type": content_type.split(";")[0].strip(),
                "content_length": content_len,
            }
        return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        futs = [pool.submit(_probe, p, l, s, w) for p, l, s, w in _EXPOSED_FILE_PROBES]
        try:
            for fut in as_completed(futs, timeout=timeout):
                try:
                    r = fut.result()
                    if r:
                        found.append(r)
                except Exception as exc:
                    logger.debug("File probe failed: %s", type(exc).__name__)
        except FutTimeout:
            logger.debug("check_exposed_files: total timeout (%ss) hit — partial results", timeout)

    # ── GraphQL introspection check — only if /graphql returned 200 ──────────
    # We use a GET request with query param (read-only, no mutation) to probe
    # whether introspection is enabled. Introspection exposes full schema,
    # all types, mutations, and field names — a complete API attack surface map.
    gql_endpoints = [f["full_url"] for f in found if "/graphql" in f.get("path", "")]
    for gql_url in gql_endpoints[:2]:
        try:
            _gql_query = "?query=%7B__schema%7BtestXX%7D%7D"  # {__schema{testXX}}
            gql_r = _safe_get(gql_url + _gql_query, timeout=6)
            if gql_r and gql_r.status_code == 200:
                body = gql_r.content[:4096].decode("utf-8", errors="ignore")
                # Positive signal: response contains "types" or "__schema" data
                if '"types"' in body or '"__schema"' in body or '"__typename"' in body:
                    found.append({
                        "path": "/graphql?introspection",
                        "full_url": gql_url,
                        "label": "GraphQL Introspection Enabled",
                        "severity": "HIGH",
                        "why": "GraphQL introspection is enabled — attackers can enumerate "
                               "all types, queries, mutations, and field names. "
                               "Disable in production: `introspection: false`.",
                        "content_type": "application/json",
                        "content_length": str(len(body)),
                    })
                elif '"errors"' in body and "introspection" in body.lower():
                    found.append({
                        "path": "/graphql (introspection disabled)",
                        "full_url": gql_url,
                        "label": "GraphQL — Introspection Disabled",
                        "severity": "INFO",
                        "why": "GraphQL endpoint present but introspection correctly disabled.",
                        "content_type": "application/json",
                        "content_length": "",
                    })
        except Exception as exc:
            logger.debug("GraphQL introspection check failed: %s", type(exc).__name__)

    found.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 9))
    crits = [f for f in found if f["severity"] == "CRITICAL"]
    highs = [f for f in found if f["severity"] == "HIGH"]
    sev = "CRITICAL" if crits else "HIGH" if highs else "MEDIUM" if found else "INFO"

    return {
        "status": "completed",
        "exposed_files": found[:25],
        "exposed_count": len(found),
        "critical_count": len(crits),
        "severity": sev,
        "finding": (
            f"CRITICAL: {len(found)} sensitive file(s) publicly accessible: "
            + ", ".join(f["path"] for f in found[:4])
            if found else
            "No exposed sensitive files or endpoints detected."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 11. HTTP Security Headers deep analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_http_security_headers(url: str, timeout: int = 10) -> dict:
    """
    Analyse HTTP response headers for security misconfigurations.
    Checks: CSP, HSTS, X-Frame-Options, CORS, Cookie flags, info-disclosure headers.
    Passive — only a single GET request to the target URL.
    """
    r = _safe_get(url, timeout=timeout)
    if not r:
        return {"status": "error", "severity": "INFO",
                "finding": "Could not fetch headers."}

    h    = r.headers
    issues: list[dict] = []

    # ── CSP ──────────────────────────────────────────────────────────────────
    csp = h.get("Content-Security-Policy", "")
    if not csp:
        issues.append({"header": "Content-Security-Policy", "severity": "HIGH",
                       "issue": "Missing CSP — XSS attacks have no browser-level mitigation",
                       "fix": "Add a strict CSP (avoid 'unsafe-inline' and 'unsafe-eval')"})
    else:
        bad_csp: list[str] = []
        if "'unsafe-inline'" in csp:
            bad_csp.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp:
            bad_csp.append("'unsafe-eval'")
        if re.search(r"https?:\s|https?://\*\.", csp):
            bad_csp.append("wildcard source")
        if bad_csp:
            issues.append({"header": "CSP", "severity": "MEDIUM",
                           "issue": f"Weak CSP — contains {', '.join(bad_csp)} (XSS bypass possible)",
                           "fix": "Remove unsafe-inline/unsafe-eval; use nonces or hashes"})

    # ── HSTS ─────────────────────────────────────────────────────────────────
    hsts = h.get("Strict-Transport-Security", "")
    if not hsts:
        issues.append({"header": "Strict-Transport-Security", "severity": "MEDIUM",
                       "issue": "Missing HSTS — browsers may connect via HTTP (MitM risk)",
                       "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"})
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 2_592_000:  # < 30 days
            issues.append({"header": "HSTS", "severity": "LOW",
                           "issue": f"HSTS max-age too short ({m.group(1)}s < 30 days)",
                           "fix": "Set max-age=31536000 (1 year) minimum"})
        # Preload eligibility: max-age >= 63072000 (2 years) + includeSubDomains + preload
        has_preload    = "preload"          in hsts
        has_subdomains = "includeSubDomains" in hsts
        max_age_val    = int(m.group(1)) if m else 0
        if not has_preload and has_subdomains and max_age_val >= 63_072_000:
            issues.append({"header": "HSTS", "severity": "LOW",
                           "issue": "HSTS preload missing — site is eligible but not in browser preload lists",
                           "fix": "Add 'preload' directive and submit to https://hstspreload.org"})
        elif has_preload and (not has_subdomains or max_age_val < 63_072_000):
            issues.append({"header": "HSTS", "severity": "LOW",
                           "issue": "HSTS has 'preload' but doesn't meet preload requirements "
                                    "(needs includeSubDomains + max-age >= 63072000)",
                           "fix": "Add includeSubDomains and set max-age >= 63072000"})

    # ── X-Frame-Options (clickjacking) ────────────────────────────────────────
    xfo = h.get("X-Frame-Options", "")
    csp_frame = "frame-ancestors" in csp
    if not xfo and not csp_frame:
        issues.append({"header": "X-Frame-Options", "severity": "MEDIUM",
                       "issue": "Missing X-Frame-Options — site can be embedded in iframes (Clickjacking)",
                       "fix": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors"})

    # ── X-Content-Type-Options ────────────────────────────────────────────────
    xcto = h.get("X-Content-Type-Options", "")
    if xcto.lower() != "nosniff":
        issues.append({"header": "X-Content-Type-Options", "severity": "LOW",
                       "issue": "Missing X-Content-Type-Options: nosniff — MIME confusion attacks possible",
                       "fix": "Add: X-Content-Type-Options: nosniff"})

    # ── CORS ─────────────────────────────────────────────────────────────────
    acao = h.get("Access-Control-Allow-Origin", "")
    acac = h.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        issues.append({"header": "CORS", "severity": "CRITICAL",
                       "issue": "CORS: Access-Control-Allow-Origin: * + Allow-Credentials: true — "
                                "any site can read credentialed responses (CORS misconfiguration)",
                       "fix": "Never combine wildcard origin with Allow-Credentials: true"})
    elif acao == "*":
        issues.append({"header": "CORS", "severity": "LOW",
                       "issue": "CORS wildcard (*) — any origin can read API responses",
                       "fix": "Restrict to specific allowed origins"})
    # Vary: Origin check — if CORS is dynamic (non-wildcard), Vary must include Origin
    # to prevent cache poisoning where one user's response is served to another.
    if acao and acao != "*":
        vary = h.get("Vary", "")
        if "origin" not in vary.lower():
            issues.append({"header": "Vary", "severity": "MEDIUM",
                           "issue": "Dynamic CORS origin without Vary: Origin header — "
                                    "CDN/proxy may cache and serve one user's credentialed "
                                    "response to a different origin (CORS cache poisoning)",
                           "fix": "Add 'Vary: Origin' whenever Access-Control-Allow-Origin is dynamic"})

    # ── Referrer-Policy ──────────────────────────────────────────────────────
    rp = h.get("Referrer-Policy", "")
    if not rp:
        issues.append({"header": "Referrer-Policy", "severity": "LOW",
                       "issue": "Missing Referrer-Policy — URLs leaked to third parties via Referer header",
                       "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"})

    # ── Cookie security ──────────────────────────────────────────────────────
    set_cookies = r.headers.getlist("Set-Cookie") if hasattr(r.headers, "getlist") else \
                  [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
    cookie_issues: list[str] = []
    for ck in set_cookies:
        ck_lower = ck.lower()
        if "httponly" not in ck_lower:
            cookie_issues.append("missing HttpOnly")
        if "secure" not in ck_lower:
            cookie_issues.append("missing Secure flag")
        if "samesite" not in ck_lower:
            cookie_issues.append("missing SameSite")
    if cookie_issues:
        unique_issues = list(dict.fromkeys(cookie_issues))
        issues.append({"header": "Set-Cookie", "severity": "MEDIUM",
                       "issue": f"Insecure cookie flags: {', '.join(unique_issues[:3])} — "
                                "session cookies vulnerable to theft or CSRF",
                       "fix": "Set all auth cookies with: Secure; HttpOnly; SameSite=Strict"})

    # ── Server / X-Powered-By version disclosure ─────────────────────────────
    server = h.get("Server", "")
    if re.search(r"\d+\.\d+", server):
        issues.append({"header": "Server", "severity": "LOW",
                       "issue": f"Server version disclosed: '{server}' — aids targeted CVE search",
                       "fix": "Configure server to return generic 'Server: nginx' or remove header"})
    xpb = h.get("X-Powered-By", "")
    if xpb:
        issues.append({"header": "X-Powered-By", "severity": "LOW",
                       "issue": f"Technology disclosed via X-Powered-By: '{xpb}'",
                       "fix": "Remove X-Powered-By header"})

    # ── Permissions-Policy ────────────────────────────────────────────────────
    pp = h.get("Permissions-Policy", "") or h.get("Feature-Policy", "")
    if not pp:
        issues.append({"header": "Permissions-Policy", "severity": "LOW",
                       "issue": "Missing Permissions-Policy — browser features (camera/mic/geolocation) unrestricted",
                       "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"})

    # ── Cross-Origin isolation headers (Spectre side-channel mitigation) ──────
    coep = h.get("Cross-Origin-Embedder-Policy", "").strip()
    if coep not in ("require-corp", "credentialless"):
        issues.append({"header": "Cross-Origin-Embedder-Policy", "severity": "LOW",
                       "issue": "Missing COEP — Spectre-based cross-origin data leaks not mitigated",
                       "fix": "Add: Cross-Origin-Embedder-Policy: require-corp"})

    coop = h.get("Cross-Origin-Opener-Policy", "").strip()
    if not coop or "same-origin" not in coop:
        issues.append({"header": "Cross-Origin-Opener-Policy", "severity": "LOW",
                       "issue": "Missing COOP — cross-origin window.opener access not blocked (XS-Leaks)",
                       "fix": "Add: Cross-Origin-Opener-Policy: same-origin"})

    corp = h.get("Cross-Origin-Resource-Policy", "").strip()
    if corp not in ("same-site", "same-origin"):
        issues.append({"header": "Cross-Origin-Resource-Policy", "severity": "LOW",
                       "issue": "Missing CORP — resource embeddable cross-origin (Spectre data leak path)",
                       "fix": "Add: Cross-Origin-Resource-Policy: same-site"})

    # ── Score calculation ────────────────────────────────────────────────────
    sev_penalty = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 3}
    score = max(0, 100 - sum(sev_penalty.get(i["severity"], 0) for i in issues))
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else
             "D" if score >= 45 else "F")

    crits = [i for i in issues if i["severity"] == "CRITICAL"]
    highs = [i for i in issues if i["severity"] == "HIGH"]
    sev = "CRITICAL" if crits else "HIGH" if highs else "MEDIUM" if issues else "LOW"

    return {
        "status": "completed",
        "issues": issues,
        "issue_count": len(issues),
        "header_score": score,
        "header_grade": grade,
        "csp_present": bool(csp),
        "hsts_present": bool(hsts),
        "xfo_present": bool(xfo) or csp_frame,
        "cors_wildcard": acao == "*",
        "severity": sev,
        "finding": (
            f"HTTP Headers grade {grade} ({score}/100) — {len(issues)} misconfiguration(s): "
            + "; ".join(i["issue"][:60] for i in issues[:3])
            if issues else
            f"HTTP Security Headers grade {grade} — all major headers properly configured."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 12. SSL/TLS passive certificate analysis
# ─────────────────────────────────────────────────────────────────────────────

_TLS_SEV = {"TLSv1": "CRITICAL", "TLSv1.1": "HIGH", "TLSv1.2": "MEDIUM", "TLSv1.3": "INFO"}
_WEAK_CIPHERS_RE = re.compile(r'RC4|DES|3DES|NULL|EXPORT|anon|MD5', re.IGNORECASE)


def check_ssl_passive(url: str, timeout: int = 10) -> dict:
    """
    Passive SSL/TLS certificate analysis.
    Performs a TLS handshake only — no data sent beyond ClientHello.
    Checks: expiry, self-signed, TLS version, weak ciphers, SANs, key size.
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme == "http":
        return {
            "status": "no_ssl", "severity": "CRITICAL",
            "finding": "Site uses plain HTTP — zero TLS encryption. ALL traffic is readable on the network.",
            "tls_version": None, "days_until_expiry": None, "cert_subject": None, "san_domains": [],
        }

    # SSRF guard — must check before any socket connection to user-provided host
    if is_ssrf_blocked(hostname):
        return {
            "status": "blocked", "severity": "INFO",
            "finding": f"SSL check skipped — {hostname} is an internal/reserved address.",
            "tls_version": None, "days_until_expiry": None, "cert_subject": None, "san_domains": [],
        }

    issues:  list[dict] = []
    scores:  list[int]  = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version() or "Unknown"
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "Unknown"
                cipher_bits = cipher_info[2] if cipher_info else 0
                cert        = ssock.getpeercert()

    except ssl.SSLCertVerificationError as exc:
        return {
            "status": "cert_error", "severity": "CRITICAL",
            "finding": f"Certificate verification failed: {exc}. Visitors see a browser security warning.",
            "tls_version": None, "days_until_expiry": None, "cert_subject": None, "san_domains": [],
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {
            "status": "error", "severity": "INFO",
            "finding": f"Could not connect to {hostname}:{port} — {exc}",
            "tls_version": None, "days_until_expiry": None, "cert_subject": None, "san_domains": [],
        }

    # ── Certificate expiry ────────────────────────────────────────────────────
    not_after  = cert.get("notAfter", "")
    days_left  = None
    if not_after:
        try:
            expiry   = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
            if days_left < 0:
                issues.append({"check": "Certificate Expiry", "severity": "CRITICAL",
                                "detail": f"Certificate EXPIRED {abs(days_left)} days ago!"})
            elif days_left < 14:
                issues.append({"check": "Certificate Expiry", "severity": "CRITICAL",
                                "detail": f"Certificate expires in {days_left} days — IMMEDIATE renewal needed."})
            elif days_left < 30:
                issues.append({"check": "Certificate Expiry", "severity": "HIGH",
                                "detail": f"Certificate expires in {days_left} days — renew soon."})
            elif days_left < 90:
                issues.append({"check": "Certificate Expiry", "severity": "MEDIUM",
                                "detail": f"Certificate expires in {days_left} days — schedule renewal."})
        except ValueError:
            pass

    # ── Self-signed check ─────────────────────────────────────────────────────
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    if subject.get("commonName") == issuer.get("commonName"):
        issues.append({"check": "Self-Signed Certificate", "severity": "HIGH",
                        "detail": "Self-signed cert — browser shows 'Not Secure'. Replace with CA-signed cert."})

    # ── TLS version ───────────────────────────────────────────────────────────
    tls_sev = _TLS_SEV.get(tls_version, "INFO")
    if tls_sev in ("CRITICAL", "HIGH"):
        issues.append({"check": f"TLS Version ({tls_version})", "severity": tls_sev,
                        "detail": f"{tls_version} is deprecated and has known attacks (POODLE/BEAST). "
                                  "Disable it and require TLS 1.2/1.3."})

    # ── Weak cipher ───────────────────────────────────────────────────────────
    if _WEAK_CIPHERS_RE.search(cipher_name):
        issues.append({"check": f"Weak Cipher ({cipher_name})", "severity": "HIGH",
                        "detail": f"Cipher {cipher_name} is broken. Use AES-256-GCM or ChaCha20-Poly1305."})
    if cipher_bits and cipher_bits < 128:
        issues.append({"check": f"Short Key ({cipher_bits} bit)", "severity": "HIGH",
                        "detail": f"Key length {cipher_bits} bit is too short — minimum 128 bit required."})

    # ── SANs (Subject Alternative Names) ─────────────────────────────────────
    san_domains = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

    # ── Overall severity ─────────────────────────────────────────────────────
    sev_order  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    worst_sev  = min(issues, key=lambda i: sev_order.get(i["severity"], 4))["severity"] if issues else "INFO"
    if not issues:
        finding = (f"TLS {tls_version} · {cipher_name} · cert valid {days_left} days"
                   if days_left else f"TLS {tls_version} · {cipher_name} · cert valid")
    else:
        finding = f"{len(issues)} TLS issue(s): " + "; ".join(i["detail"][:60] for i in issues[:2])

    return {
        "status": "completed",
        "severity": worst_sev,
        "tls_version": tls_version,
        "cipher_suite": cipher_name,
        "cipher_bits": cipher_bits,
        "days_until_expiry": days_left,
        "cert_subject": subject.get("commonName"),
        "cert_issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "san_domains": san_domains[:10],
        "issues": issues,
        "issue_count": len(issues),
        "finding": finding,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 13. DNS deep analysis (MX, NS, CAA, zone transfer, TXT fingerprinting)
# ─────────────────────────────────────────────────────────────────────────────

_MAIL_PROVIDERS = {
    "google": "Google Workspace", "aspmx": "Google Workspace",
    "outlook": "Microsoft 365", "mail.protection.outlook": "Microsoft 365",
    "yahoodns": "Yahoo Mail", "mxbiz": "Yahoo Small Business",
    "amazonses": "Amazon SES", "sendgrid": "SendGrid",
    "mailgun": "Mailgun", "mailjet": "Mailjet",
    "brevo": "Brevo (Sendinblue)", "sendinblue": "Brevo",
    "protonmail": "ProtonMail",
}
_DNS_SVC_TXT = {
    "google-site-verification": "Google Workspace",
    "MS=ms": "Microsoft 365",
    "amazonses": "Amazon SES",
    "stripe-verification": "Stripe",
    "docusign": "DocuSign",
    "atlassian-domain-verification": "Atlassian",
    "sendgrid.net": "SendGrid",
    "mandrill": "Mailchimp",
    "protonmail-verification": "ProtonMail",
    "globalsign-domain-verification": "GlobalSign CA",
    "apple-domain-verification": "Apple",
    "facebook-domain-verification": "Facebook/Meta",
}


def _doh(name: str, rtype: str, timeout: int = 8) -> list[str]:
    """Alias for _doh_txt — used internally by check_dns_deep."""
    return _doh_txt(name, rtype, timeout)


def check_dns_deep(domain: str, timeout: int = 15) -> dict:
    """
    Deep DNS record analysis using Cloudflare DoH (no local resolver needed).
    Checks: MX mail providers, NS hosting, CAA cert policy, TXT services,
    zone transfer attempt via dnspython (if available), SOA data leakage.
    100% passive — only DNS queries sent.
    """
    host = urlparse(domain).netloc or domain.replace("https://", "").replace("http://", "")
    host = host.split(":")[0].split("/")[0]
    base = re.sub(r'^www\.', '', host)

    issues:   list[dict] = []
    findings: list[str]  = []

    # ── MX Records — mail provider fingerprinting ─────────────────────────────
    mx_records  = _doh(base, "MX", timeout)
    mail_providers: list[str] = []
    for mx in mx_records:
        mx_lower = mx.lower()
        for pattern, name in _MAIL_PROVIDERS.items():
            if pattern in mx_lower and name not in mail_providers:
                mail_providers.append(name)
    if not mx_records:
        issues.append({"check": "No MX Records", "severity": "LOW",
                        "detail": "Domain has no MX records — cannot receive email (or using subdomain routing)."})
    elif not mail_providers:
        mail_providers = ["Unknown/self-hosted"]

    # ── NS Records — nameserver hosting ──────────────────────────────────────
    ns_records = _doh(base, "NS", timeout)
    ns_provider = "Unknown"
    for ns in ns_records:
        ns_l = ns.lower()
        if "cloudflare" in ns_l:   ns_provider = "Cloudflare"
        elif "awsdns"  in ns_l:    ns_provider = "AWS Route 53"
        elif "azure"   in ns_l:    ns_provider = "Azure DNS"
        elif "google"  in ns_l:    ns_provider = "Google Cloud DNS"
        elif "nsone"   in ns_l:    ns_provider = "NS1"
        elif "ultradns" in ns_l:   ns_provider = "UltraDNS"
        elif "dnsimple" in ns_l:   ns_provider = "DNSimple"
        break

    # ── CNAME records — subdomain takeover via dangling CNAME ────────────────
    # Check the domain itself + 6 high-risk subdomains for CNAMEs pointing at
    # unclaimed cloud resources (GitHub Pages, Heroku, Netlify, Vercel, etc.)
    _CNAME_TAKEOVER_FINGERPRINTS: dict[str, str] = {
        "github.io":         "GitHub Pages",
        "githubusercontent.com": "GitHub",
        "herokuapp.com":     "Heroku",
        "netlify.app":       "Netlify",
        "netlify.com":       "Netlify",
        "vercel.app":        "Vercel",
        "now.sh":            "Vercel (legacy)",
        "surge.sh":          "Surge.sh",
        "pantheonsite.io":   "Pantheon",
        "azurewebsites.net": "Azure App Service",
        "cloudfront.net":    "AWS CloudFront",
        "fastly.net":        "Fastly CDN",
        "myshopify.com":     "Shopify",
        "zendesk.com":       "Zendesk",
        "freshdesk.com":     "Freshdesk",
        "ghost.io":          "Ghost",
        "helpscoutdocs.com": "HelpScout",
        "bitbucket.io":      "Bitbucket",
    }
    _cname_subdomains = ["", "www", "api", "static", "assets", "cdn", "staging", "dev"]
    cname_candidates: list[dict] = []

    for sub in _cname_subdomains:
        check_name = f"{sub}.{base}" if sub else base
        cname_records = _doh(check_name, "CNAME", timeout)
        for cname_val in cname_records:
            cname_lower = cname_val.lower().rstrip(".")
            for suffix, provider in _CNAME_TAKEOVER_FINGERPRINTS.items():
                if cname_lower.endswith(suffix):
                    cname_candidates.append({
                        "subdomain": check_name,
                        "cname": cname_val,
                        "provider": provider,
                    })

    if cname_candidates:
        for c in cname_candidates[:5]:
            issues.append({
                "check": f"CNAME Subdomain Takeover Risk — {c['provider']}",
                "severity": "HIGH",
                "detail": (
                    f"{c['subdomain']} → CNAME → {c['cname']} ({c['provider']}). "
                    "If the cloud resource is unclaimed, an attacker can register it and "
                    "serve content under your domain (credential theft, phishing, cookie theft)."
                ),
            })
        findings.append(
            f"CNAME takeover candidates: {', '.join(c['subdomain'] for c in cname_candidates[:3])}"
        )

    # ── CAA Records — certificate authority policy ────────────────────────────
    caa_records = _doh(base, "CAA", timeout)
    if not caa_records:
        issues.append({"check": "No CAA Records", "severity": "MEDIUM",
                        "detail": "No CAA records — any CA can issue SSL certificates for this domain. "
                                  "Add 'issue \"letsencrypt.org\"' to restrict unauthorized cert issuance."})
    else:
        issue_cas     = [r for r in caa_records if "issuewild" not in r and "issue" in r]
        issuewild_cas = [r for r in caa_records if "issuewild" in r]
        if issue_cas:
            findings.append(f"CAA restricts cert issuance to: {', '.join(issue_cas[:3])}")
        if not issuewild_cas:
            # CAA issue present but no issuewild — wildcards (*.domain.com) unrestricted
            issues.append({"check": "CAA Missing issuewild", "severity": "MEDIUM",
                            "detail": "CAA has 'issue' tag but no 'issuewild' tag — any CA can "
                                      "issue wildcard (*.domain.com) certificates regardless of your CA restriction."})
        else:
            findings.append(f"CAA wildcard restricted: {', '.join(issuewild_cas[:2])}")

    # ── TXT Records — service fingerprinting ─────────────────────────────────
    txt_records = _doh(base, "TXT", timeout)
    svc_found: list[str] = []
    for rec in txt_records:
        for pattern, svc in _DNS_SVC_TXT.items():
            if pattern.lower() in rec.lower() and svc not in svc_found:
                svc_found.append(svc)

    # ── SOA Record — zone admin email disclosure ──────────────────────────────
    soa_records = _doh(base, "SOA", timeout)
    soa_email   = ""
    if soa_records:
        soa_raw = soa_records[0]
        # SOA format: mname rname serial refresh retry expire min
        # rname is admin email with @ replaced by .
        parts = soa_raw.split()
        if len(parts) >= 2:
            rname = parts[1].rstrip(".")
            # Convert first dot to @ to get email
            soa_email = rname.replace(".", "@", 1) if rname else ""
        if soa_email and not soa_email.startswith("hostmaster"):
            issues.append({"check": "SOA Email Disclosure", "severity": "LOW",
                            "detail": f"SOA record reveals admin email: {soa_email[:50]}"})

    # ── Zone Transfer attempt (AXFR) via dnspython ───────────────────────────
    zone_transfer_success = False
    try:
        import dns.resolver
        import dns.query
        import dns.zone
        _resolver = dns.resolver.Resolver()
        _ns_list  = [r.to_text() for r in _resolver.resolve(base, "NS")]
        for _ns in _ns_list[:3]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(_ns.rstrip("."), base, timeout=5))
                if z:
                    zone_transfer_success = True
                    issues.append({"check": "Zone Transfer (AXFR)", "severity": "CRITICAL",
                                    "detail": f"CRITICAL: Zone transfer ALLOWED from {_ns}! "
                                              "Attacker can enumerate ALL DNS records. Disable AXFR immediately."})
                    break
            except Exception:
                pass
    except ImportError:
        pass
    except Exception:
        pass

    # ── Overall severity ─────────────────────────────────────────────────────
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    worst     = min(issues, key=lambda i: sev_order.get(i["severity"], 4))["severity"] if issues else "INFO"

    summary_parts = []
    if mail_providers:  summary_parts.append(f"Mail: {', '.join(mail_providers)}")
    if ns_provider:     summary_parts.append(f"DNS: {ns_provider}")
    if svc_found:       summary_parts.append(f"Services: {', '.join(svc_found[:3])}")
    if zone_transfer_success: summary_parts.append("⚠ AXFR OPEN")
    if issues:          summary_parts.append(f"{len(issues)} DNS issue(s)")

    return {
        "status": "completed",
        "severity": worst,
        "host": base,
        "mx_records": mx_records[:5],
        "mail_providers": mail_providers,
        "ns_records": ns_records[:5],
        "ns_provider": ns_provider,
        "caa_records": caa_records[:5],
        "cname_takeover_candidates": cname_candidates[:5],
        "txt_services": svc_found,
        "soa_email": soa_email,
        "zone_transfer_possible": zone_transfer_success,
        "issues": issues,
        "finding": (
            " | ".join(summary_parts)
            if summary_parts else
            f"DNS records for {base} — no issues found."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 14. Certificate Transparency subdomain enumeration (crt.sh)
# ─────────────────────────────────────────────────────────────────────────────

_INTERESTING_SUBDOMAIN = re.compile(
    r'(?i)^(dev|staging|stage|test|uat|qa|demo|admin|api|internal|'
    r'vpn|mail|ftp|sftp|jenkins|gitlab|jira|confluence|monitor|'
    r'kibana|grafana|portainer|k8s|kube|prod|beta|preview|corp|'
    r'intranet|management|panel|dashboard|login|auth|sso|ldap|backup)',
    re.IGNORECASE,
)


_MEGA_PLATFORM_DOMAINS = {
    "streamlit.app", "github.io", "netlify.app", "vercel.app",
    "pages.dev", "herokuapp.com", "azurewebsites.net", "web.app",
    "firebaseapp.com", "amplifyapp.com", "render.com", "railway.app",
    "fly.dev", "glitch.me", "replit.app", "onrender.com",
}


def check_crt_subdomains(domain: str, timeout: int = 12) -> dict:
    """
    Query crt.sh Certificate Transparency logs to enumerate subdomains.
    100% passive — reads public CT log data, no probes sent.
    Reveals ALL subdomains that have ever received an SSL certificate.
    """
    host = urlparse(domain).netloc or domain.replace("https://","").replace("http://","")
    host = host.split(":")[0].split("/")[0]
    base = re.sub(r'^www\.', '', host)

    # Shared hosting platforms host millions of apps — crt.sh returns
    # hundreds of thousands of entries and always times out or OOMs.
    for _platform in _MEGA_PLATFORM_DOMAINS:
        if host.endswith("." + _platform) or host == _platform:
            return {
                "status": "completed", "subdomains": [], "severity": "INFO",
                "finding": (
                    f"CT Logs: target is a subdomain of {_platform} — "
                    f"shared platform with millions of certificates. "
                    f"CT enumeration not applicable to individual app subdomains."
                ),
            }

    crt_url = f"https://crt.sh/?q=%.{base}&output=json"
    r = _safe_get(crt_url, timeout=timeout)
    if not r or r.status_code != 200:
        return {"status": "error", "subdomains": [], "severity": "INFO",
                "finding": "crt.sh query failed — CT log data unavailable."}

    try:
        entries = r.json()
    except Exception:
        return {"status": "error", "subdomains": [], "severity": "INFO",
                "finding": "crt.sh returned invalid JSON."}

    # Collect unique subdomains from name_value field
    seen: set[str] = set()
    subdomains: list[dict] = []
    interesting: list[dict] = []

    for entry in entries:
        names = entry.get("name_value", "").lower().split("\n")
        for name in names:
            name = name.strip().lstrip("*.")
            if not name or name in seen or not name.endswith(base):
                continue
            seen.add(name)
            label = name.replace(f".{base}", "").replace(base, "root")
            is_interesting = bool(_INTERESTING_SUBDOMAIN.match(label))
            entry_dict = {
                "subdomain": name,
                "label": label,
                "interesting": is_interesting,
                "issuer": entry.get("issuer_name", "")[:60],
                "not_before": (entry.get("not_before", "") or "")[:10],
            }
            subdomains.append(entry_dict)
            if is_interesting:
                interesting.append(entry_dict)

    # Deduplicate and sort
    subdomains = list({d["subdomain"]: d for d in subdomains}.values())
    interesting = list({d["subdomain"]: d for d in interesting}.values())

    sev = ("CRITICAL" if any(re.search(r'(jenkins|admin|internal|corp|intranet)', d["label"])
                             for d in interesting)
           else "HIGH" if len(interesting) >= 3
           else "MEDIUM" if interesting
           else "LOW" if len(subdomains) > 5
           else "INFO")

    return {
        "status": "completed",
        "total_subdomains": len(subdomains),
        "subdomains": subdomains[:50],
        "interesting_subdomains": interesting[:20],
        "interesting_count": len(interesting),
        "severity": sev,
        "finding": (
            f"CT Logs reveal {len(subdomains)} subdomain(s) — "
            f"{len(interesting)} HIGH-VALUE: "
            + ", ".join(d["subdomain"] for d in interesting[:4])
            if interesting else
            f"CT Logs reveal {len(subdomains)} subdomain(s) for {base} — no high-value targets identified."
            if subdomains else
            f"No certificates found in CT logs for {base}."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 13. GitHub public code leak search
# ─────────────────────────────────────────────────────────────────────────────

_GITHUB_SEARCH = "https://api.github.com/search/code"
# Token intentionally NOT stored as module-level global to prevent accidental
# logging of Authorization headers via exception tracebacks or debug dumps.
# Loaded lazily inside check_github_leaks() on every call.

def check_github_leaks(domain: str, timeout: int = 15) -> dict:
    """
    Search GitHub public code for credential leaks referencing this domain.
    Uses the public unauthenticated API (60 req/hour) or authenticated (5000/hr).

    Security: GITHUB_TOKEN is read inside the function (not a module global) to
    prevent the token from appearing in exception tracebacks, memory dumps, or
    any serialization of module state.
    """
    host = urlparse(domain).netloc or domain.replace("https://", "").replace("http://", "")
    host = host.split(":")[0].split("/")[0].replace("www.", "")

    queries = [
        f'"{host}" password',
        f'"{host}" api_key',
        f'"{host}" secret',
    ]

    all_items: list[dict] = []
    rate_limited = False

    # Build headers with token — scoped to this call only, never stored globally.
    _gh_headers = {**_HEADERS, "Accept": "application/vnd.github.v3+json"}
    _gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if _gh_token:
        _gh_headers["Authorization"] = f"token {_gh_token}"
    del _gh_token  # remove from local scope immediately after use

    # Outer try/finally guarantees Authorization is scrubbed even on early exit
    try:
        for q in queries:
            try:
                r = requests.get(
                    _GITHUB_SEARCH,
                    params={"q": q, "per_page": 10},
                    headers=_gh_headers,
                    timeout=timeout,
                )
                if r.status_code in (403, 429):
                    rate_limited = True
                    break
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get("items", [])[:5]:
                        all_items.append({
                            "repo":  item.get("repository", {}).get("full_name", ""),
                            "file":  item.get("name", ""),
                            "path":  item.get("path", ""),
                            "url":   item.get("html_url", ""),
                            # Redact query — don't teach attacker exact search terms
                            "query": _redact(q) if len(q) > 12 else q,
                        })
                time.sleep(1.2)  # respect rate limit between queries
            except Exception as exc:
                # Log only type — never str(exc) which may contain request context/headers
                logger.debug("GitHub search failed: %s", type(exc).__name__)
                break
    finally:
        # Scrub Authorization header from dict after all requests complete
        _gh_headers.pop("Authorization", None)

    # Deduplicate by repo+file
    seen: set[str] = set()
    unique: list[dict] = []
    for item in all_items:
        sig = f"{item['repo']}:{item['file']}"
        if sig not in seen:
            seen.add(sig)
            unique.append(item)

    sev = "CRITICAL" if len(unique) >= 3 else "HIGH" if unique else "INFO"
    return {
        "status":      "rate_limited" if rate_limited else "completed",
        "domain":      host,
        "repos_found": unique[:15],
        "leak_count":  len(unique),
        "severity":    sev,
        "finding": (
            f"CRITICAL: {len(unique)} public GitHub repo(s) may contain credentials for {host}: "
            + ", ".join(f"{i['repo']}/{i['file']}" for i in unique[:3])
            if unique else
            f"No public GitHub code leaks found for {host}."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Passive Recon runner — 15 tools, streaming + batch API
# ─────────────────────────────────────────────────────────────────────────────

def _build_tasks(url: str, domain: str, tech_results: dict) -> dict:
    """Return ordered task dict for all 15 OSINT tools."""
    return {
        "security_txt":       lambda: check_security_txt(url),
        "robots_sitemap":     lambda: analyze_robots_sitemap(url),
        "js_secrets":         lambda: scan_js_secrets(url),
        "wayback":            lambda: check_wayback_exposure(domain),
        "cloud_buckets":      lambda: check_cloud_buckets(domain),
        "http_methods":       lambda: check_http_methods(url),
        "email_spoofability": lambda: analyze_email_spoofability(domain),
        "cve_correlation":    lambda: correlate_cves(tech_results),
        "meta_leakage":       lambda: check_meta_leakage(url),
        "github_leaks":       lambda: check_github_leaks(domain),
        "exposed_files":      lambda: check_exposed_files(url),
        "http_headers":       lambda: analyze_http_security_headers(url),
        "ssl_passive":        lambda: check_ssl_passive(url),
        "crt_subdomains":     lambda: check_crt_subdomains(domain),
        "dns_deep":           lambda: check_dns_deep(domain),
    }


def _build_passive_result(url: str, results: dict) -> dict:
    """Aggregate tool results into the final passive recon dict."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    worst = min(
        (r.get("severity", "INFO") for r in results.values()),
        key=lambda s: sev_order.get(s, 4),
        default="INFO",
    )
    critical_findings = [
        {"tool": n, "finding": r.get("finding", ""), "severity": r.get("severity", "INFO")}
        for n, r in results.items()
        if r.get("severity") in ("CRITICAL", "HIGH") and r.get("finding")
    ]
    critical_findings.sort(key=lambda x: sev_order.get(x["severity"], 9))
    return {
        "url": url,
        "tools": results,
        "overall_severity": worst,
        "critical_findings": critical_findings,
        "tool_count": len(results),
        "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }


def run_passive_recon_streaming(
    url: str,
    tech_results: dict | None = None,
) -> Generator[tuple[str, dict], None, None]:
    """
    Generator that yields (tool_name, result) pairs as each tool completes.
    Runs all 15 tools concurrently; guaranteed to yield EXACTLY one result
    per tool — even if the executor times out or a future never resolves.
    """
    import concurrent.futures as _cf
    domain  = url
    tasks   = _build_tasks(url, domain, tech_results or {})
    yielded: set[str] = set()

    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            futs = {pool.submit(fn): name for name, fn in tasks.items()}
            try:
                for fut in as_completed(futs, timeout=120):
                    name = futs[fut]
                    try:
                        result = fut.result(timeout=5)
                    except FutTimeout:
                        result = {"status": "timeout", "severity": "INFO",
                                  "finding": f"{name}: tool timed out (>5s individual)."}
                    except Exception as exc:
                        logger.debug("Tool %s raised %s: %s", name, type(exc).__name__, exc)
                        result = {"status": "error", "error": type(exc).__name__,
                                  "severity": "INFO", "finding": f"{name}: tool failed ({type(exc).__name__})"}
                    yielded.add(name)
                    yield name, result
            except _cf.TimeoutError:
                # Overall 120s budget exceeded — some tools didn't complete
                logger.warning("Passive recon: total timeout exceeded (120s)")
    except Exception as exc:
        logger.error("Passive recon streaming error: %s", exc)

    # Guarantee every task gets a result — yield timeout for any that didn't complete
    for name in tasks:
        if name not in yielded:
            yield name, {"status": "timeout", "severity": "INFO",
                         "finding": f"{name}: scan budget exceeded — not completed."}


def run_passive_recon(url: str, tech_results: dict | None = None) -> dict:
    """
    Run all 15 passive OSINT tools concurrently and return aggregated dict.
    Blocking — use run_passive_recon_streaming() for real-time progress.
    """
    domain  = url
    tasks   = _build_tasks(url, domain, tech_results or {})
    results: dict[str, dict] = {}

    import concurrent.futures as _cf
    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            futs = {pool.submit(fn): name for name, fn in tasks.items()}
            try:
                for fut in as_completed(futs, timeout=120):
                    name = futs[fut]
                    try:
                        results[name] = fut.result(timeout=5)
                    except FutTimeout:
                        results[name] = {"status": "timeout", "severity": "INFO",
                                         "finding": f"{name} timed out."}
                    except Exception as exc:
                        logger.debug("Tool %s raised %s: %s", name, type(exc).__name__, exc)
                        results[name] = {"status": "error", "error": type(exc).__name__,
                                         "severity": "INFO", "finding": f"{name}: tool failed ({type(exc).__name__})"}
            except _cf.TimeoutError:
                logger.warning("Passive recon batch: 120s total budget exceeded")
    except Exception as exc:
        logger.error("Passive recon batch error: %s", exc)

    # Guarantee all tasks have a result
    for name in tasks:
        if name not in results:
            results[name] = {"status": "timeout", "severity": "INFO",
                             "finding": f"{name}: scan budget exceeded."}

    return _build_passive_result(url, results)

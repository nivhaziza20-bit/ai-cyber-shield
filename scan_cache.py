"""
Result caching layer — stores completed scan results in Supabase.
Same URL scanned within TTL returns cached result instantly (no GROQ call).
Paid users get longer TTL. Enterprise users can force-bust.

Cache key is tenant-scoped: different tenants, languages, or scan modes
always get independent cache entries to prevent cross-tenant data leakage.
"""
from __future__ import annotations
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta

import streamlit as st

_log = logging.getLogger(__name__)

# Cache TTL by tier (minutes)
_TTL: dict[str, int] = {
    "free":         60,    # 1 hour
    "starter":      360,   # 6 hours
    "professional": 1440,  # 24 hours
    "enterprise":   4320,  # 3 days
}
_ADMIN_TTL = 0  # admins always get fresh results by default


def _client():
    from auth.streamlit_auth import _client as auth_client
    return auth_client()


def _make_cache_key(
    url: str,
    scan_mode: str,
    tenant_id: str = "anonymous",
    lang: str = "en",
    compliance_mode: bool = False,
    pt_mode: bool = False,
) -> str:
    """
    Deterministic, tenant-scoped SHA-256 cache key.

    Every dimension that produces a meaningfully different result gets its
    own slot in the key, preventing cross-tenant or cross-language leakage.
    """
    raw = "|".join([
        tenant_id,
        url.lower().strip(),
        scan_mode,
        lang,
        str(compliance_mode),
        str(pt_mode),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


def get_cached_scan(
    url: str,
    scan_mode: str,
    tier: str,
    is_admin: bool,
    tenant_id: str = "anonymous",
    lang: str = "en",
    compliance_mode: bool = False,
    pt_mode: bool = False,
) -> dict | None:
    """Return cached scan result if fresh, else None.

    Callers that don't have tenant context (e.g. legacy Streamlit paths that
    haven't been updated yet) can omit the keyword arguments; they will fall
    into the "anonymous" bucket and still benefit from caching, just without
    tenant isolation.
    """
    if is_admin:
        return None  # admins always see fresh results

    ttl_minutes = _TTL.get(tier, 60)
    if ttl_minutes == 0:
        return None

    url_hash = _make_cache_key(url, scan_mode, tenant_id, lang, compliance_mode, pt_mode)
    c = _client()
    if c is None:
        return None

    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=ttl_minutes)).isoformat()
        resp = (c.table("scan_cache")
                .select("result_json,created_at")
                .eq("url_hash", url_hash)
                .gte("created_at", cutoff)
                .order("created_at", desc=True)
                .limit(1)
                .execute())
        if resp.data:
            row = resp.data[0]
            result = json.loads(row["result_json"])
            result["_cached"] = True
            result["_cached_at"] = row["created_at"]
            return result
    except Exception as exc:
        _log.debug("get_cached_scan: %s", exc)
    return None


def set_cached_scan(
    url: str,
    scan_mode: str,
    result: dict,
    tenant_id: str = "anonymous",
    lang: str = "en",
    compliance_mode: bool = False,
    pt_mode: bool = False,
) -> None:
    """Store a scan result in the tenant-scoped cache."""
    url_hash = _make_cache_key(url, scan_mode, tenant_id, lang, compliance_mode, pt_mode)
    c = _client()
    if c is None:
        return
    try:
        result_clean = {k: v for k, v in result.items() if not k.startswith("_")}
        c.table("scan_cache").upsert({
            "url_hash":    url_hash,
            "target_url":  url,
            "scan_mode":   scan_mode,
            "result_json": json.dumps(result_clean)[:200_000],
            "created_at":  datetime.now(timezone.utc).isoformat(),
        }, on_conflict="url_hash").execute()
    except Exception as exc:
        _log.debug("set_cached_scan: %s", exc)


def bust_cache(
    url: str,
    scan_mode: str,
    tenant_id: str = "anonymous",
    lang: str = "en",
    compliance_mode: bool = False,
    pt_mode: bool = False,
) -> bool:
    """Delete cache entry for a URL — Enterprise/admin feature."""
    url_hash = _make_cache_key(url, scan_mode, tenant_id, lang, compliance_mode, pt_mode)
    c = _client()
    if c is None:
        return False
    try:
        c.table("scan_cache").delete().eq("url_hash", url_hash).execute()
        return True
    except Exception as exc:
        _log.debug("bust_cache: %s", exc)
        return False

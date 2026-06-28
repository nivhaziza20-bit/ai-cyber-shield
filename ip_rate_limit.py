"""
ip_rate_limit.py — AI Cyber Shield v6
Multi-layer rate limiting: Cloudflare-aware IP, Supabase-backed, in-memory fallback.

Architecture
────────────
  Layer 1  Real client IP — CF-Connecting-IP (Cloudflare) → X-Forwarded-For → session ID
  Layer 2  Supabase rate_limits table — persistent across restarts and workers
  Layer 3  In-memory deque — used when Supabase is unavailable (dev mode)

Limits (production defaults)
────────────────────────────
  page:      30 requests / 60 s per IP    (lightweight bot protection)
  scan:       5 scans    / 60 s per IP    (protects Groq/Anthropic/Shodan quotas)
  guest:      3 scans    / day  per IP    (guest conversion funnel gate)

Why Supabase instead of in-memory?
  The previous in-memory implementation was per-process.  On Streamlit Cloud
  each browser tab may land on a different worker, giving each user N independent
  buckets.  Supabase upsert makes the counter globally consistent.

Required Supabase tables (run once in Supabase SQL editor):
──────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS rate_limits (
    key          TEXT PRIMARY KEY,
    count        INTEGER      NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS guest_quotas (
    ip_key    TEXT PRIMARY KEY,
    count     INTEGER NOT NULL DEFAULT 1,
    quota_day DATE    NOT NULL DEFAULT CURRENT_DATE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from datetime import datetime, date, timezone

import streamlit as st

try:
    from config import CONTACT_PHONE, CONTACT_EMAIL, GUEST_DAILY_LIMIT, SCAN_RATE_PER_MIN, PAGE_RATE_PER_MIN
except ImportError:
    CONTACT_PHONE    = "054-696-2565"
    CONTACT_EMAIL    = "nivhaziza20@gmail.com"
    GUEST_DAILY_LIMIT = 3
    SCAN_RATE_PER_MIN = 5
    PAGE_RATE_PER_MIN = 30

_log = logging.getLogger(__name__)

# ── Configuration (sourced from config.py / env vars) ─────────────────────────
_PAGE_LIMIT      = PAGE_RATE_PER_MIN
_SCAN_LIMIT      = SCAN_RATE_PER_MIN
_GUEST_DAY_LIMIT = GUEST_DAILY_LIMIT
_WINDOW_S        = 60    # sliding window duration in seconds


# ── Layer 1: Real IP extraction ───────────────────────────────────────────────

def _get_client_ip() -> str:
    """
    Extract the real client IP address.

    Priority order:
    1. CF-Connecting-IP  — set by Cloudflare, cannot be spoofed by client
    2. X-Forwarded-For   — first entry (closest to client)
    3. X-Real-IP         — nginx convention
    4. Session ID        — last-resort fallback (Streamlit-internal, unique per tab)
    """
    try:
        headers = st.context.headers          # Streamlit ≥ 1.37
        cf = headers.get("CF-Connecting-IP", "").strip()
        if cf:
            return cf
        xff = headers.get("X-Forwarded-For", "").strip()
        if xff:
            return xff.split(",")[0].strip()
        real = headers.get("X-Real-IP", "").strip()
        if real:
            return real
    except AttributeError:
        # Streamlit < 1.37 or running without a browser context (tests)
        pass
    except Exception as exc:
        _log.debug("ip extraction: %s", exc)
    return _session_key()


def _session_key() -> str:
    """Fallback: Streamlit session ID (unique per browser tab, not per IP)."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        ctx = get_script_run_ctx()
        if ctx:
            return f"sid:{ctx.session_id[:16]}"
    except Exception:
        pass
    return "unknown"


# ── Layer 3: In-memory fallback ───────────────────────────────────────────────

_memory_log: dict[str, deque] = defaultdict(deque)


def _memory_check(key: str, limit: int, window_s: int) -> bool:
    """Sliding-window check using in-process memory. Resets on restart."""
    now = time.monotonic()
    log = _memory_log[key]
    while log and log[0] < now - window_s:
        log.popleft()
    if len(log) >= limit:
        return False
    log.append(now)
    return True


# ── Layer 2: Supabase backend ─────────────────────────────────────────────────

def _supabase_client():
    """Return a live Supabase client or None (never raises)."""
    try:
        url = st.secrets.get("SUPABASE_URL", "")
        key = st.secrets.get("SUPABASE_KEY", "")
        if not url or not key or "PASTE_" in key:
            return None
        from supabase import create_client
        return create_client(url, key)
    except Exception:
        return None


def _supabase_rate_check(client, key: str, limit: int, window_s: int) -> bool:
    """
    Fixed-window rate check using Supabase.  Consistent across all workers.
    Returns True (allowed) or False (rate-limited).

    Race note: check-then-upsert has a small race window (~1-2 ms).
    For security tooling this is acceptable — we prefer availability over
    strict exactness.  A proper solution would use a Postgres function with
    row-level locking, but that requires a schema migration with RLS changes.
    """
    try:
        now = datetime.now(timezone.utc)
        resp = client.table("rate_limits").select("count,window_start").eq("key", key).maybe_single().execute()

        if resp.data:
            # Parse stored window start
            ws_str = resp.data["window_start"]
            # Handle both 'Z' and '+00:00' suffix
            ws_str = ws_str.replace("Z", "+00:00") if ws_str.endswith("Z") else ws_str
            window_start = datetime.fromisoformat(ws_str)
            elapsed = (now - window_start).total_seconds()

            if elapsed > window_s:
                # Window expired — reset counter
                client.table("rate_limits").upsert({
                    "key": key, "count": 1,
                    "window_start": now.isoformat(),
                    "updated_at":   now.isoformat(),
                }).execute()
                return True

            if resp.data["count"] >= limit:
                return False

            # Increment within current window
            client.table("rate_limits").update({
                "count":      resp.data["count"] + 1,
                "updated_at": now.isoformat(),
            }).eq("key", key).execute()
            return True

        else:
            # First request — insert fresh record
            client.table("rate_limits").upsert({
                "key": key, "count": 1,
                "window_start": now.isoformat(),
                "updated_at":   now.isoformat(),
            }).execute()
            return True

    except Exception as exc:
        _log.warning("rate_limit supabase error (%s): %s — using memory fallback", key, exc)
        return _memory_check(key, limit, window_s)


# ── Public API ────────────────────────────────────────────────────────────────

def _check(bucket: str, limit: int, window_s: int) -> bool:
    """Unified check: try Supabase first, fall back to in-memory."""
    ip  = _get_client_ip()
    key = f"{ip}:{bucket}"
    client = _supabase_client()
    if client:
        return _supabase_rate_check(client, key, limit, window_s)
    return _memory_check(key, limit, window_s)


def check_page_rate() -> bool:
    """Called on every page load — lightweight bot protection."""
    return _check("page", _PAGE_LIMIT, _WINDOW_S)


def check_scan_rate() -> bool:
    """Called before each scan — protects Groq / Anthropic / Shodan quotas."""
    return _check("scan", _SCAN_LIMIT, _WINDOW_S)


def enforce_rate_limit() -> None:
    """
    Call at the very top of the Streamlit app (before any auth).
    Shows an error and halts rendering if the IP is rate-limited.
    """
    if not check_page_rate():
        st.error(
            f"⚠️ Too many requests — please wait a moment and try again. "
            f"If you believe this is an error, contact **{CONTACT_PHONE}** or "
            f"**{CONTACT_EMAIL}**."
        )
        st.stop()


# ── Guest scan quota ──────────────────────────────────────────────────────────

def check_guest_quota() -> dict:
    """
    Check whether this IP has remaining guest scans for today (UTC).

    Returns:
        {"allowed": bool, "used": int, "limit": int, "remaining": int}
    """
    ip    = _get_client_ip()
    today = date.today().isoformat()
    key   = f"{ip}:guest"

    client = _supabase_client()

    # ── Supabase path ─────────────────────────────────────────────────────────
    if client:
        try:
            resp = (client.table("guest_quotas")
                    .select("count,quota_day")
                    .eq("ip_key", key)
                    .maybe_single()
                    .execute())

            if resp.data and resp.data["quota_day"][:10] == today:
                used = resp.data["count"]
            else:
                used = 0

            allowed = used < _GUEST_DAY_LIMIT
            return {
                "allowed":   allowed,
                "used":      used,
                "limit":     _GUEST_DAY_LIMIT,
                "remaining": max(0, _GUEST_DAY_LIMIT - used),
            }
        except Exception as exc:
            _log.warning("guest_quota check error: %s — allowing by default", exc)
            return {"allowed": True, "used": 0, "limit": _GUEST_DAY_LIMIT, "remaining": _GUEST_DAY_LIMIT}

    # ── In-memory path (dev / no Supabase) ───────────────────────────────────
    # Store in session state so it persists within a browser session
    _mem_key = f"_guest_quota_{key}_{today}"
    used = st.session_state.get(_mem_key, 0)
    allowed = used < _GUEST_DAY_LIMIT
    return {
        "allowed":   allowed,
        "used":      used,
        "limit":     _GUEST_DAY_LIMIT,
        "remaining": max(0, _GUEST_DAY_LIMIT - used),
    }


def increment_guest_quota() -> None:
    """Record one guest scan for the current IP (call after scan completes)."""
    ip    = _get_client_ip()
    today = date.today().isoformat()
    key   = f"{ip}:guest"
    now   = datetime.now(timezone.utc).isoformat()

    client = _supabase_client()

    if client:
        try:
            resp = (client.table("guest_quotas")
                    .select("count,quota_day")
                    .eq("ip_key", key)
                    .maybe_single()
                    .execute())

            if resp.data and resp.data["quota_day"][:10] == today:
                client.table("guest_quotas").update({
                    "count":      resp.data["count"] + 1,
                    "updated_at": now,
                }).eq("ip_key", key).execute()
            else:
                client.table("guest_quotas").upsert({
                    "ip_key":    key,
                    "count":     1,
                    "quota_day": today,
                    "updated_at": now,
                }).execute()
        except Exception as exc:
            _log.warning("guest_quota increment error: %s", exc)
            _mem_key = f"_guest_quota_{key}_{today}"
            st.session_state[_mem_key] = st.session_state.get(_mem_key, 0) + 1
    else:
        _mem_key = f"_guest_quota_{key}_{today}"
        st.session_state[_mem_key] = st.session_state.get(_mem_key, 0) + 1


def get_guest_quota_info() -> dict:
    """Convenience alias for display in UI."""
    return check_guest_quota()

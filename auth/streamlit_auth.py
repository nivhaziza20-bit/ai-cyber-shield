"""Supabase Auth wrapper for Streamlit — session, quota, profile."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

import streamlit as st

_log = logging.getLogger(__name__)

TIER_DAILY_LIMITS: dict[str, int] = {
    "free":         5,    # 5 scans/day
    "starter":      50,   # 50 scans/day  — $29/mo
    "professional": 200,  # 200 scans/day — $99/mo
    "enterprise":   -1,   # unlimited     — $299/mo
}


@dataclass
class UserSession:
    user_id: str
    email: str
    role: str = "user"
    pt_approved: bool = False
    subscription_tier: str = "free"
    stripe_customer_id: str = ""
    access_token: str = ""

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def daily_limit(self) -> int:
        return TIER_DAILY_LIMITS.get(self.subscription_tier, 5)

    @property
    def is_paid(self) -> bool:
        return self.subscription_tier != "free"


def _client():
    """Return a Supabase client or None if not configured."""
    url = st.secrets.get("SUPABASE_URL", "")
    key = st.secrets.get("SUPABASE_KEY", "")
    if not url or not key:
        return None
    try:
        from supabase import create_client
        return create_client(url, key)
    except Exception:
        return None


def _authed_client(session: UserSession):
    """Return a Supabase client authenticated as the given user."""
    url = st.secrets.get("SUPABASE_URL", "")
    key = st.secrets.get("SUPABASE_KEY", "")
    if not url or not key:
        return None
    try:
        from supabase import create_client
        from gotrue.types import Session as GotrueSession
        c = create_client(url, key)
        c.auth.set_session(session.access_token, "")
        return c
    except Exception:
        return _client()


# ── Auth operations ───────────────────────────────────────────────────────────

def sign_up(email: str, password: str) -> dict:
    c = _client()
    if c is None:
        return {"error": "Supabase not configured — add SUPABASE_URL and SUPABASE_KEY to Secrets"}
    try:
        resp = c.auth.sign_up({"email": email, "password": password})
        if resp.user:
            confirm_needed = resp.user.email_confirmed_at is None
            return {"ok": True, "confirm_required": confirm_needed}
        return {"error": "Registration failed — please try again"}
    except Exception as exc:
        msg = str(exc)
        if "already registered" in msg.lower() or "already been registered" in msg.lower():
            return {"error": "This email is already registered"}
        return {"error": msg}


def _check_brute_force(email: str) -> dict:
    """Returns {"blocked": True/False, "attempts": N}. Fails open on error."""
    c = _client()
    if c is None:
        return {"blocked": False}
    try:
        resp = c.rpc("check_login_attempts", {"p_email": email}).execute()
        return resp.data if resp.data else {"blocked": False}
    except Exception:
        return {"blocked": False}


def _record_attempt(email: str, success: bool) -> None:
    c = _client()
    if c is None:
        return
    try:
        c.rpc("record_login_attempt", {"p_email": email, "p_success": success}).execute()
    except Exception:
        pass


def _build_user_session(supabase_user, supabase_session) -> "UserSession":
    """Build a UserSession from a live Supabase auth user + session object."""
    c = _client()
    role, pt_approved, tier, stripe_cid = "user", False, "free", ""
    if c:
        try:
            profile_resp = (c.table("profiles")
                            .select("role,pt_approved,subscription_tier,stripe_customer_id")
                            .eq("id", supabase_user.id)
                            .maybe_single()
                            .execute())
            if profile_resp.data:
                role = profile_resp.data.get("role", "user")
                pt_approved = bool(profile_resp.data.get("pt_approved", False))
                tier = profile_resp.data.get("subscription_tier", "free")
                stripe_cid = profile_resp.data.get("stripe_customer_id") or ""
        except Exception:
            pass
    return UserSession(
        user_id=supabase_user.id,
        email=supabase_user.email or "",
        role=role,
        pt_approved=pt_approved,
        subscription_tier=tier,
        stripe_customer_id=stripe_cid,
        access_token=supabase_session.access_token if supabase_session else "",
    )


def sign_in(email: str, password: str) -> dict:
    c = _client()
    if c is None:
        return {"error": "Supabase not configured"}

    bf = _check_brute_force(email)
    if bf.get("blocked"):
        return {"error": "Too many failed attempts — account locked for 15 minutes. Try again later."}

    try:
        resp = c.auth.sign_in_with_password({"email": email, "password": password})
        if not resp.user:
            return {"error": "Invalid email or password"}
        session = _build_user_session(resp.user, resp.session)
        st.session_state["_user_session"] = session
        _record_attempt(email, success=True)
        return {"ok": True, "session": session}
    except Exception as exc:
        _log.warning("sign_in error: %s", exc)
        _record_attempt(email, success=False)
        return {"error": "Invalid email or password"}


def sign_out() -> None:
    c = _client()
    if c:
        try:
            c.auth.sign_out()
        except Exception:
            pass
    st.session_state.pop("_user_session", None)


def request_password_reset(email: str) -> dict:
    c = _client()
    if c is None:
        return {"error": "Supabase not configured"}
    try:
        c.auth.reset_password_email(email)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


def sign_in_with_google() -> dict:
    """Initiate Google OAuth via Supabase. Returns {"url": redirect_url} or {"error": ...}."""
    c = _client()
    if c is None:
        return {"error": "Supabase not configured"}
    try:
        site_url = st.secrets.get("SITE_URL", "")
        opts: dict = {"redirect_to": site_url} if site_url else {}
        resp = c.auth.sign_in_with_oauth({"provider": "google", "options": opts})
        if hasattr(resp, "url") and resp.url:
            return {"url": resp.url}
        return {"error": "Google OAuth is not enabled — configure it in Supabase → Auth → Providers → Google"}
    except Exception as exc:
        msg = str(exc)
        if "provider" in msg.lower() or "oauth" in msg.lower():
            return {"error": "Google OAuth is not enabled in Supabase yet. Enable it under Authentication → Providers."}
        return {"error": msg}


def sign_in_with_github() -> dict:
    """Initiate GitHub OAuth via Supabase. Returns {"url": redirect_url} or {"error": ...}."""
    c = _client()
    if c is None:
        return {"error": "Supabase not configured"}
    try:
        site_url = st.secrets.get("SITE_URL", "")
        opts: dict = {"redirect_to": site_url} if site_url else {}
        resp = c.auth.sign_in_with_oauth({"provider": "github", "options": opts})
        if hasattr(resp, "url") and resp.url:
            return {"url": resp.url}
        return {"error": "GitHub OAuth is not enabled — configure it in Supabase → Auth → Providers → GitHub"}
    except Exception as exc:
        msg = str(exc)
        if "provider" in msg.lower() or "oauth" in msg.lower():
            return {"error": "GitHub OAuth is not enabled in Supabase yet. Enable it under Authentication → Providers."}
        return {"error": msg}


# ── Session helpers ───────────────────────────────────────────────────────────

def get_current_user() -> Optional[UserSession]:
    return st.session_state.get("_user_session")


def require_auth() -> UserSession:
    """Call at top of page; stops rendering and shows auth UI if not logged in."""
    user = get_current_user()
    if user is None:
        from auth.auth_pages import show_auth_page
        show_auth_page()
        st.stop()
    return user


def supabase_available() -> bool:
    url = st.secrets.get("SUPABASE_URL", "")
    key = st.secrets.get("SUPABASE_KEY", "")
    return bool(url and key)


# ── Quota enforcement ─────────────────────────────────────────────────────────

def check_quota(user: UserSession) -> dict:
    """Check daily quota. Returns {"allowed": True/False, "used": N, "limit": N}."""
    if user.is_admin:
        return {"allowed": True, "used": 0, "limit": -1}
    c = _client()
    if c is None:
        return {"allowed": True, "used": 0, "limit": user.daily_limit}
    limit = user.daily_limit
    try:
        resp = (c.table("profiles")
                .select("scans_today,scans_today_reset")
                .eq("id", user.user_id)
                .maybe_single()
                .execute())
        if not resp.data:
            return {"allowed": True, "used": 0, "limit": limit}
        from datetime import date
        reset_date_str = (resp.data.get("scans_today_reset") or "")[:10]
        today_str = date.today().isoformat()
        used = resp.data.get("scans_today", 0) if reset_date_str == today_str else 0
        if limit >= 0 and used >= limit:
            return {"allowed": False, "used": used, "limit": limit}
        return {"allowed": True, "used": used, "limit": limit, "remaining": max(0, limit - used)}
    except Exception as exc:
        _log.debug("quota check: %s", exc)
        return {"allowed": True, "used": 0, "limit": limit}


def increment_quota(user: UserSession) -> None:
    """Atomically increment daily scan counter via Supabase RPC."""
    if user.is_admin:
        return
    c = _client()
    if c is None:
        return
    try:
        c.rpc("check_and_increment_daily_quota", {
            "p_user_id": user.user_id,
            "p_limit": user.daily_limit,
        }).execute()
    except Exception as exc:
        _log.debug("quota increment: %s", exc)


# ── Admin helpers ─────────────────────────────────────────────────────────────

def fetch_audit_logs(limit: int = 200) -> list[dict]:
    """Admin only — fetch recent audit logs."""
    user = get_current_user()
    if not user or not user.is_admin:
        return []
    c = _authed_client(user)
    if c is None:
        return []
    try:
        resp = (c.table("audit_logs")
                .select("*")
                .order("created_at", desc=True)
                .limit(limit)
                .execute())
        return resp.data or []
    except Exception as exc:
        _log.warning("fetch_audit_logs: %s", exc)
        return []


def fetch_all_users() -> list[dict]:
    """Admin only — fetch all user profiles."""
    user = get_current_user()
    if not user or not user.is_admin:
        return []
    c = _authed_client(user)
    if c is None:
        return []
    try:
        resp = c.table("profiles").select("*").order("created_at", desc=True).execute()
        return resp.data or []
    except Exception as exc:
        _log.warning("fetch_all_users: %s", exc)
        return []


def approve_pt_mode(target_user_id: str, admin: UserSession) -> bool:
    """Admin: grant PT mode to a user."""
    c = _authed_client(admin)
    if c is None:
        return False
    try:
        c.table("profiles").update({
            "pt_approved": True,
            "pt_approved_by": admin.email,
            "pt_approved_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", target_user_id).execute()
        return True
    except Exception as exc:
        _log.warning("approve_pt_mode: %s", exc)
        return False


def revoke_pt_mode(target_user_id: str, admin: UserSession) -> bool:
    """Admin: revoke PT mode from a user."""
    c = _authed_client(admin)
    if c is None:
        return False
    try:
        c.table("profiles").update({
            "pt_approved": False,
            "pt_approved_by": None,
            "pt_approved_at": None,
        }).eq("id", target_user_id).execute()
        return True
    except Exception as exc:
        _log.warning("revoke_pt_mode: %s", exc)
        return False

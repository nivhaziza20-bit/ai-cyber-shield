"""
auth/session_loader.py — AI Cyber Shield v6

Clean interface for loading authenticated session state and injecting it
into the scanner's HTTP layer via thread-local auth context.

Responsibilities:
  • ScanAuth dataclass — minimal (headers, cookies) container used by the pipeline
  • Loaders — convert ScanProfile / LoginSession / raw token / cookies → ScanAuth
  • Health check — quick request to verify the session is still alive
  • File loader — auto-detect JSON type and load from disk

Usage:
    from auth.session_loader import ScanAuth, load_from_file, check_session_health

    auth = load_from_file("sessions/prod-admin.json")
    healthy, reason = check_session_health(auth, "https://app.example.com/dashboard")

    # In pipeline worker threads:
    from tools.http_utils import set_scan_auth, clear_scan_auth
    set_scan_auth(auth.headers, auth.cookies)
    try:
        result = tool_func(url)
    finally:
        clear_scan_auth()
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auth.scan_profile import ScanProfile
    from auth.login_recorder import LoginSession

_log = logging.getLogger(__name__)

# Module-level imports from http_utils allow tests to patch
# auth.session_loader.safe_get / set_scan_auth / clear_scan_auth directly.
from tools.http_utils import safe_get, set_scan_auth, clear_scan_auth  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# ScanAuth — runtime auth container
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanAuth:
    """
    Extracted, ready-to-use authentication state for a scan run.

    Passed to _auth_wrapped() in the pipeline, which sets thread-local
    context so every safe_get() call in that thread inherits the auth.
    """
    headers:       dict[str, str] = field(default_factory=dict)
    cookies:       dict[str, str] = field(default_factory=dict)
    profile_name:  str = "unnamed"
    target_domain: str = ""
    source:        str = "manual"   # "profile" | "session" | "token" | "manual"
    expired:       bool = False     # True when JWT/session expiry was detected

    @property
    def is_empty(self) -> bool:
        return not self.headers and not self.cookies

    def summary(self) -> str:
        parts = []
        if self.cookies:
            parts.append(f"{len(self.cookies)} cookie(s)")
        if self.headers:
            auth_keys = [k for k in self.headers if k.lower() in ("authorization", "x-auth-token", "x-api-key")]
            parts.append(f"{len(self.headers)} header(s) [{', '.join(auth_keys)}]" if auth_keys else f"{len(self.headers)} header(s)")
        suffix = " [EXPIRED]" if self.expired else ""
        return f"[{self.profile_name}] " + (", ".join(parts) or "no credentials") + suffix


# ─────────────────────────────────────────────────────────────────────────────
# Loaders
# ─────────────────────────────────────────────────────────────────────────────

def from_scan_profile(profile: "ScanProfile") -> ScanAuth:
    """
    Extract auth state from a ScanProfile.

    Uses SessionInjector to migrate Playwright-recorded cookies into a plain
    dict, then merges profile-level custom_headers on top.
    """
    # Profiles without a recorded session only carry custom_headers
    if not profile.session_dict:
        return ScanAuth(
            headers=dict(profile.custom_headers),
            profile_name=profile.name,
            source="profile",
        )

    try:
        from auth.login_recorder import LoginSession
        from auth.session_injector import SessionInjector

        session = LoginSession.from_dict(profile.session_dict)
        injector = SessionInjector(session)

        # Warn if JWT/session has expired (let caller decide whether to abort)
        expired = session.is_expired() or injector.is_jwt_expired()
        if expired:
            _log.warning(
                "Session in profile '%s' appears expired (recorded: %s, expires: %s). "
                "Re-record with login_recorder to refresh.",
                profile.name, session.recorded_at, session.expires_at,
            )

        # Extract cookies for the target domain
        target_url = session.target_url or ""
        cookies = injector.to_cookie_dict(target_url)

        # Build headers: session extras + bearer token + profile overrides
        headers: dict[str, str] = {}
        if session.bearer_token:
            headers["Authorization"] = f"Bearer {session.bearer_token}"
        headers.update(session.extra_headers or {})
        headers.update(profile.custom_headers or {})   # profile wins

        return ScanAuth(
            headers=headers,
            cookies=cookies,
            profile_name=profile.name,
            target_domain=target_url,
            source="profile",
            expired=expired,
        )

    except Exception as exc:
        _log.error("Failed to extract auth from profile '%s': %s", profile.name, exc)
        # Graceful fallback — at least use custom_headers
        return ScanAuth(
            headers=dict(profile.custom_headers),
            profile_name=profile.name,
            source="profile",
        )


def from_login_session(session: "LoginSession") -> ScanAuth:
    """
    Extract auth state directly from a LoginSession (no ScanProfile wrapper).
    Used when loading a raw session JSON produced by login_recorder.
    """
    try:
        from auth.session_injector import SessionInjector

        injector = SessionInjector(session)
        expired  = session.is_expired() or injector.is_jwt_expired()

        if expired:
            _log.warning(
                "LoginSession '%s' has expired (recorded: %s). Consider re-recording.",
                session.profile_name, session.recorded_at,
            )

        cookies = injector.to_cookie_dict(session.target_url)

        headers: dict[str, str] = {}
        if session.bearer_token:
            headers["Authorization"] = f"Bearer {session.bearer_token}"
        headers.update(session.extra_headers or {})

        return ScanAuth(
            headers=headers,
            cookies=cookies,
            profile_name=session.profile_name,
            target_domain=session.target_url,
            source="session",
            expired=expired,
        )

    except Exception as exc:
        _log.error("Failed to extract auth from LoginSession: %s", exc)
        return ScanAuth(source="session")


def from_bearer_token(token: str, profile_name: str = "quick-token") -> ScanAuth:
    """
    Create auth state from a raw Bearer token string.
    Fastest path for API scanning: paste the token, start scanning.
    """
    if not token or not token.strip():
        raise ValueError("Bearer token cannot be empty")
    return ScanAuth(
        headers={"Authorization": f"Bearer {token.strip()}"},
        profile_name=profile_name,
        source="token",
    )


def from_cookies_dict(cookies: dict[str, str], profile_name: str = "manual") -> ScanAuth:
    """
    Create auth state from a raw name→value cookie dictionary.
    Used when the user pastes cookies from browser DevTools.
    """
    if not cookies:
        raise ValueError("Cookies dict cannot be empty")
    return ScanAuth(
        cookies=dict(cookies),
        profile_name=profile_name,
        source="manual",
    )


def from_headers_dict(headers: dict[str, str], profile_name: str = "manual") -> ScanAuth:
    """
    Create auth state from a raw headers dictionary.
    Used for API scanning where auth is entirely header-based.
    """
    if not headers:
        raise ValueError("Headers dict cannot be empty")
    return ScanAuth(
        headers=dict(headers),
        profile_name=profile_name,
        source="manual",
    )


# ─────────────────────────────────────────────────────────────────────────────
# File loader — auto-detects JSON type
# ─────────────────────────────────────────────────────────────────────────────

def load_from_file(path: str) -> ScanAuth:
    """
    Load a ScanAuth from a JSON file.

    Auto-detects the file type:
      - If JSON has "session_dict" key → ScanProfile
      - If JSON has "auth_pattern" key → LoginSession
      - If JSON has "Authorization" or "Bearer" key → headers dict
      - If JSON has all string values → cookies dict

    Args:
        path: Path to the JSON file.

    Returns:
        ScanAuth ready for use.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be parsed or recognised.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Auth file not found: {path}")

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in auth file '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Auth file must contain a JSON object, got {type(data).__name__}")

    # ── ScanProfile detection ─────────────────────────────────────────────────
    if "session_dict" in data or ("scope_rules" in data and "name" in data):
        from auth.scan_profile import ScanProfile
        profile = ScanProfile.from_dict(data)
        _log.info("Loaded ScanProfile '%s' from %s", profile.name, path)
        return from_scan_profile(profile)

    # ── LoginSession detection ────────────────────────────────────────────────
    if "auth_pattern" in data or "target_url" in data:
        from auth.login_recorder import LoginSession
        session = LoginSession.from_dict(data)
        _log.info("Loaded LoginSession '%s' from %s", session.profile_name, path)
        return from_login_session(session)

    # ── Raw headers dict {"Authorization": "Bearer ..."} ─────────────────────
    is_headers = any(
        k.lower() in ("authorization", "x-auth-token", "x-api-key", "cookie")
        for k in data
    )
    if is_headers:
        _log.info("Loaded raw auth headers from %s", path)
        return from_headers_dict(data, profile_name=p.stem)

    # ── Raw cookies dict {"session_id": "abc123", ...} ───────────────────────
    if all(isinstance(v, str) for v in data.values()):
        _log.info("Loaded raw cookies dict from %s (%d cookies)", path, len(data))
        return from_cookies_dict(data, profile_name=p.stem)

    raise ValueError(
        f"Cannot determine auth file type for '{path}'. "
        "Expected ScanProfile, LoginSession, headers dict, or cookies dict."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Session health check
# ─────────────────────────────────────────────────────────────────────────────

def check_session_health(
    auth: ScanAuth,
    target_url: str,
    timeout: int = 10,
) -> tuple[bool, str]:
    """
    Make a quick authenticated request to verify the session is still alive.

    Detects:
      - Redirect to login page → session expired
      - HTTP 401/403 → auth rejected
      - HTTP 200/2xx → session valid

    Args:
        auth:       ScanAuth to verify.
        target_url: URL to probe (should be an authenticated page, not a public endpoint).
        timeout:    Request timeout in seconds.

    Returns:
        (is_healthy: bool, reason: str)
    """
    if auth.is_empty:
        return False, "No credentials in ScanAuth — nothing to check"

    set_scan_auth(auth.headers, auth.cookies)
    try:
        resp = safe_get(target_url, timeout=timeout)

        # Check if we were silently redirected to a login page
        final_url = str(getattr(resp, "url", target_url)).lower()
        if any(kw in final_url for kw in ("login", "signin", "auth/login", "account/login")):
            return False, f"Redirected to login page ({final_url[:80]}) — session expired"

        if resp.status_code == 401:
            return False, "HTTP 401 Unauthorized — credentials rejected"
        if resp.status_code == 403:
            return False, "HTTP 403 Forbidden — credentials may be valid but insufficient scope"

        if 200 <= resp.status_code < 300:
            return True, f"Session valid (HTTP {resp.status_code})"

        return False, f"Unexpected HTTP {resp.status_code} — session state unclear"

    except Exception as exc:
        return False, f"Request failed: {type(exc).__name__}: {exc}"
    finally:
        clear_scan_auth()

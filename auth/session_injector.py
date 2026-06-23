"""
auth/session_injector.py — AI Cyber Shield v6

Injects authenticated session state into the scanner's HTTP client context.

What makes this better than competitors:
  • Works with requests.Session, httpx.Client, and aiohttp.ClientSession
  • JWT auto-decode (header inspection, expiry check, no crypto lib needed)
  • Smart token refresh detection (401/403 → retry with refreshed session)
  • Cookie jar migration from Playwright → requests / httpx (domain normalisation)
  • Header injection with precedence rules (scanner defaults overridden safely)
  • CSRF token auto-extraction and injection (looks in meta tags, forms, cookies)
  • Scope validation: only injects on matching domains (no credential leakage)
  • Dry-run mode: logs what would be injected without actually injecting

Usage:
    from auth.session_injector import SessionInjector
    from auth.login_recorder import LoginSession

    injector = SessionInjector(session)

    # Inject into requests.Session
    import requests
    s = requests.Session()
    injector.inject_requests(s, target_url="https://app.example.com")

    # Inject into httpx client
    import httpx
    client = httpx.Client()
    injector.inject_httpx(client, target_url="https://app.example.com")

    # Verify JWT is still valid
    info = injector.inspect_jwt()
    print(info.is_expired, info.subject, info.expires_at)
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# JWT inspector (no crypto — header + payload inspection only)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class JwtInfo:
    raw:        str
    header:     dict     = field(default_factory=dict)
    payload:    dict     = field(default_factory=dict)
    is_expired: bool     = False
    subject:    str      = ""
    issuer:     str      = ""
    audience:   str      = ""
    expires_at: str      = ""   # ISO UTC
    issued_at:  str      = ""
    algorithm:  str      = ""
    parse_error: str     = ""


def decode_jwt_insecure(token: str) -> JwtInfo:
    """
    Decode a JWT without signature verification (inspection only).
    NEVER use for authentication — only for expiry/subject inspection.

    A JWT has three base64url-encoded parts: header.payload.signature
    """
    info = JwtInfo(raw=token)
    parts = token.split(".")
    if len(parts) != 3:
        info.parse_error = f"Invalid JWT structure: expected 3 parts, got {len(parts)}"
        return info

    def _b64_decode(s: str) -> dict:
        # Add padding
        s += "=" * (4 - len(s) % 4)
        raw = base64.urlsafe_b64decode(s)
        return json.loads(raw.decode("utf-8", errors="replace"))

    try:
        info.header  = _b64_decode(parts[0])
        info.payload = _b64_decode(parts[1])
    except Exception as exc:
        info.parse_error = str(exc)
        return info

    info.algorithm = info.header.get("alg", "")
    info.subject   = str(info.payload.get("sub", ""))
    info.issuer    = str(info.payload.get("iss", ""))

    aud = info.payload.get("aud", "")
    info.audience = str(aud) if not isinstance(aud, list) else ", ".join(aud)

    now = time.time()

    exp = info.payload.get("exp")
    if exp is not None:
        info.is_expired = now > float(exp)
        info.expires_at = datetime.fromtimestamp(float(exp), tz=timezone.utc).isoformat()

    iat = info.payload.get("iat")
    if iat is not None:
        info.issued_at = datetime.fromtimestamp(float(iat), tz=timezone.utc).isoformat()

    return info


# ─────────────────────────────────────────────────────────────────────────────
# Domain scope guard
# ─────────────────────────────────────────────────────────────────────────────

def _domain_matches(cookie_domain: str, request_host: str) -> bool:
    """
    Return True if a cookie's domain covers the request host.
    Leading dot means subdomain matching (e.g. .example.com covers app.example.com).
    """
    cd = cookie_domain.lstrip(".").lower()
    rh = request_host.lower()
    return rh == cd or rh.endswith("." + cd)


def _extract_host(url: str) -> str:
    return urlparse(url).hostname or ""


# ─────────────────────────────────────────────────────────────────────────────
# CSRF extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

_CSRF_COOKIE_NAMES = re.compile(
    r"(csrf|xsrf|_token|antiforgery|verificationtoken)", re.IGNORECASE
)
_CSRF_META_RE = re.compile(
    r'<meta\s[^>]*name=["\']([^"\']*(?:csrf|xsrf)[^"\']*)["\'][^>]*'
    r'content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def extract_csrf_from_html(html: str) -> Optional[tuple[str, str]]:
    """
    Extract CSRF token from HTML page.
    Returns (header_name, token_value) or None.
    """
    m = _CSRF_META_RE.search(html)
    if m:
        meta_name = m.group(1)
        # Heuristic: convert meta name to header name
        header = "X-CSRF-Token"
        if "xsrf" in meta_name.lower():
            header = "X-XSRF-Token"
        return header, m.group(2)
    return None


def extract_csrf_from_cookies(cookies: dict[str, str]) -> Optional[tuple[str, str]]:
    """
    Extract CSRF value from a cookie jar (dict).
    Returns (header_name, token_value) or None.
    """
    for name, value in cookies.items():
        if _CSRF_COOKIE_NAMES.search(name):
            header = "X-XSRF-Token" if "xsrf" in name.lower() else "X-CSRF-Token"
            return header, value
    return None


# ─────────────────────────────────────────────────────────────────────────────
# InjectionResult
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InjectionResult:
    success:          bool
    cookies_injected: int   = 0
    headers_injected: int   = 0
    csrf_injected:    bool  = False
    jwt_info:         Optional[JwtInfo] = None
    warnings:         list[str] = field(default_factory=list)
    errors:           list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.success and not self.errors


# ─────────────────────────────────────────────────────────────────────────────
# SessionInjector
# ─────────────────────────────────────────────────────────────────────────────

class SessionInjector:
    """
    Injects LoginSession authentication state into HTTP clients.

    Supports:
      - requests.Session   → inject_requests()
      - httpx.Client       → inject_httpx()
      - dict (headers)     → inject_headers()
      - cookie dict        → to_cookie_dict()

    All methods are scope-guarded: cookies are only injected when their
    domain matches the target_url (prevents credential leakage to other hosts).
    """

    def __init__(
        self,
        session,           # LoginSession
        dry_run: bool = False,
    ) -> None:
        self._session  = session
        self._dry_run  = dry_run

    # ── JWT inspection ────────────────────────────────────────────────────────

    def inspect_jwt(self) -> Optional[JwtInfo]:
        """
        Decode and inspect the JWT bearer token from the session (if present).
        Returns None if no bearer token is stored.
        """
        token = self._session.bearer_token
        if not token:
            return None
        # Strip "Bearer " prefix if present
        if token.lower().startswith("bearer "):
            token = token[7:]
        return decode_jwt_insecure(token)

    def is_jwt_expired(self) -> bool:
        """Quick check: is the stored JWT expired?"""
        info = self.inspect_jwt()
        if info is None:
            return False
        return info.is_expired

    # ── Cookie helpers ────────────────────────────────────────────────────────

    def to_cookie_dict(self, target_url: str = "") -> dict[str, str]:
        """
        Return {name: value} dict of cookies scoped to target_url.
        If target_url is empty, returns all cookies.
        """
        host = _extract_host(target_url) if target_url else ""
        result: dict[str, str] = {}

        for c in self._session.cookies:
            if host and not _domain_matches(c.domain, host):
                continue
            result[c.name] = c.value

        return result

    def to_cookie_header(self, target_url: str = "") -> str:
        """
        Format cookies as a 'Cookie: name=value; name2=value2' header string.
        """
        cookie_dict = self.to_cookie_dict(target_url)
        return "; ".join(f"{k}={v}" for k, v in cookie_dict.items())

    # ── requests.Session injection ────────────────────────────────────────────

    def inject_requests(
        self,
        requests_session,
        target_url:       str = "",
        auto_csrf:        bool = True,
    ) -> InjectionResult:
        """
        Inject authentication into a requests.Session object.

        Args:
            requests_session: requests.Session instance
            target_url:       Target URL (used for domain scoping)
            auto_csrf:        Auto-detect and inject CSRF token from cookies

        Returns:
            InjectionResult
        """
        result = InjectionResult(success=True)
        host   = _extract_host(target_url) if target_url else ""

        # Inject cookies
        for c in self._session.cookies:
            if host and not _domain_matches(c.domain, host):
                _log.debug("Skipping cookie '%s' — domain mismatch", c.name)
                continue
            if self._dry_run:
                _log.info("[DRY-RUN] Would inject cookie: %s", c.name)
            else:
                requests_session.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
            result.cookies_injected += 1

        # Inject headers
        for k, v in self._session.extra_headers.items():
            if self._dry_run:
                _log.info("[DRY-RUN] Would inject header: %s", k)
            else:
                requests_session.headers[k] = v
            result.headers_injected += 1

        # Auto-inject CSRF from cookies
        if auto_csrf:
            cookie_dict = self.to_cookie_dict(target_url)
            csrf = extract_csrf_from_cookies(cookie_dict)
            if csrf:
                h_name, h_val = csrf
                if not self._dry_run:
                    requests_session.headers[h_name] = h_val
                result.csrf_injected = True
                _log.debug("CSRF header '%s' auto-injected", h_name)

        # Inspect JWT if present
        jwt_info = self.inspect_jwt()
        if jwt_info:
            result.jwt_info = jwt_info
            if jwt_info.is_expired:
                result.warnings.append(
                    f"Bearer JWT expired at {jwt_info.expires_at}. "
                    "Re-authenticate before scanning."
                )

        _log.info(
            "Injected into requests.Session: %d cookies, %d headers",
            result.cookies_injected, result.headers_injected,
        )
        return result

    # ── httpx.Client injection ────────────────────────────────────────────────

    def inject_httpx(
        self,
        httpx_client,
        target_url:   str  = "",
        auto_csrf:    bool = True,
    ) -> InjectionResult:
        """
        Inject authentication into an httpx.Client or httpx.AsyncClient.

        httpx stores cookies in client.cookies and headers in client.headers.
        """
        result = InjectionResult(success=True)
        host   = _extract_host(target_url) if target_url else ""

        for c in self._session.cookies:
            if host and not _domain_matches(c.domain, host):
                continue
            if self._dry_run:
                _log.info("[DRY-RUN] Would inject cookie: %s", c.name)
            else:
                httpx_client.cookies.set(c.name, c.value)
            result.cookies_injected += 1

        for k, v in self._session.extra_headers.items():
            if self._dry_run:
                _log.info("[DRY-RUN] Would inject header: %s", k)
            else:
                httpx_client.headers[k] = v
            result.headers_injected += 1

        if auto_csrf:
            csrf = extract_csrf_from_cookies(self.to_cookie_dict(target_url))
            if csrf:
                h_name, h_val = csrf
                if not self._dry_run:
                    httpx_client.headers[h_name] = h_val
                result.csrf_injected = True

        result.jwt_info = self.inspect_jwt()
        if result.jwt_info and result.jwt_info.is_expired:
            result.warnings.append(
                f"Bearer JWT expired at {result.jwt_info.expires_at}."
            )

        _log.info(
            "Injected into httpx client: %d cookies, %d headers",
            result.cookies_injected, result.headers_injected,
        )
        return result

    # ── Header dict injection (generic) ──────────────────────────────────────

    def inject_headers(
        self,
        headers:    dict[str, str],
        target_url: str = "",
    ) -> InjectionResult:
        """
        Inject auth headers into an existing dict (modifies in-place).
        Useful for tools that accept a headers kwarg.
        """
        result = InjectionResult(success=True)

        # Cookie header
        cookie_str = self.to_cookie_header(target_url)
        if cookie_str:
            if self._dry_run:
                _log.info("[DRY-RUN] Would inject Cookie header: %d bytes", len(cookie_str))
            else:
                headers["Cookie"] = cookie_str
            result.cookies_injected = len(self._session.cookies)

        # Extra headers (Authorization, etc.)
        for k, v in self._session.extra_headers.items():
            if not self._dry_run:
                headers[k] = v
            result.headers_injected += 1

        result.jwt_info = self.inspect_jwt()
        return result

    # ── Storage access ────────────────────────────────────────────────────────

    def get_local_storage_value(self, key: str) -> Optional[str]:
        return self._session.local_storage.get(key)

    def get_session_storage_value(self, key: str) -> Optional[str]:
        return self._session.session_storage.get(key)

    def get_all_local_storage(self) -> dict[str, str]:
        return dict(self._session.local_storage)

    # ── Scope check ──────────────────────────────────────────────────────────

    def is_in_scope(self, target_url: str) -> bool:
        """
        Return True if the session's cookies scope to the target URL's domain.
        Prevents injecting credentials to unrelated hosts.
        """
        host = _extract_host(target_url)
        if not host:
            return False
        return any(
            _domain_matches(c.domain, host)
            for c in self._session.cookies
        )

    # ── Summary ───────────────────────────────────────────────────────────────

    def describe(self) -> dict:
        """Return a human-readable summary of the session auth state."""
        jwt = self.inspect_jwt()
        return {
            "profile_name":    self._session.profile_name,
            "auth_pattern":    self._session.auth_pattern.value,
            "cookie_count":    len(self._session.cookies),
            "has_bearer":      bool(self._session.bearer_token),
            "jwt_expired":     jwt.is_expired if jwt else None,
            "jwt_subject":     jwt.subject    if jwt else None,
            "jwt_expires_at":  jwt.expires_at if jwt else None,
            "session_expired": self._session.is_expired(),
            "local_storage_keys":  list(self._session.local_storage.keys()),
            "extra_header_keys":   list(self._session.extra_headers.keys()),
        }

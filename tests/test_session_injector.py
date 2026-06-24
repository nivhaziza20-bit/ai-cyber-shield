"""
tests/test_session_injector.py — AI Cyber Shield v6

Test suite for auth/session_injector.py.

Tests cover:
  • decode_jwt_insecure:
    - valid JWT decodes header and payload
    - subject / issuer / audience extracted
    - exp → is_expired=True for past token
    - exp → is_expired=False for future token
    - no exp → is_expired=False
    - audience list converted to comma-separated string
    - algorithm extracted from header
    - issued_at ISO formatted
    - invalid base64 → parse_error set
    - non-3-part string → parse_error
  • extract_csrf_from_html:
    - detects csrf meta tag
    - detects xsrf meta tag → X-XSRF-Token header
    - returns None when no meta tag
  • extract_csrf_from_cookies:
    - detects csrftoken cookie
    - detects XSRF-TOKEN cookie → X-XSRF-Token
    - returns None for irrelevant cookies
  • _domain_matches:
    - exact match
    - leading-dot subdomain match
    - no match for unrelated domain
  • SessionInjector:
    - inspect_jwt returns JwtInfo
    - inspect_jwt returns None when no bearer
    - inspect_jwt strips "Bearer " prefix
    - is_jwt_expired True/False
    - to_cookie_dict: all cookies returned without target_url
    - to_cookie_dict: scoped to target_url (wrong domain excluded)
    - to_cookie_header: formatted correctly
    - inject_requests: cookies set in session
    - inject_requests: headers set in session
    - inject_requests: CSRF auto-injected from cookies
    - inject_requests: expired JWT → warning in result
    - inject_requests: dry_run=True → nothing injected
    - inject_httpx: cookies set
    - inject_httpx: headers set
    - inject_headers: Cookie header set
    - inject_headers: extra headers set
    - is_in_scope: True when cookie domain matches
    - is_in_scope: False when no cookies
    - is_in_scope: False for different domain
    - describe(): returns dict with expected keys
    - get_local_storage_value / get_session_storage_value
    - InjectionResult.ok property
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from auth.session_injector import (
    JwtInfo,
    InjectionResult,
    SessionInjector,
    decode_jwt_insecure,
    extract_csrf_from_html,
    extract_csrf_from_cookies,
    _domain_matches,
    _extract_host,
)
from auth.login_recorder import (
    LoginSession,
    SessionCookie,
    AuthPattern,
)


# ─────────────────────────────────────────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_jwt(payload: dict, header: Optional[dict] = None) -> str:
    """Build a fake JWT string (no real signature — for testing only)."""
    from typing import Optional
    h = header or {"alg": "HS256", "typ": "JWT"}

    def _b64(d: dict) -> str:
        raw = json.dumps(d).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64(h)}.{_b64(payload)}.fakesignature"


# ─────────────────────────────────────────────────────────────────────────────
# TestDecodeJwtInsecure
# ─────────────────────────────────────────────────────────────────────────────

class TestDecodeJwtInsecure:
    def test_valid_jwt_no_error(self):
        tok  = _make_jwt({"sub": "user123", "iss": "https://auth.example.com"})
        info = decode_jwt_insecure(tok)
        assert info.parse_error == ""

    def test_subject_extracted(self):
        tok  = _make_jwt({"sub": "user-abc"})
        info = decode_jwt_insecure(tok)
        assert info.subject == "user-abc"

    def test_issuer_extracted(self):
        tok  = _make_jwt({"iss": "https://auth.example.com"})
        info = decode_jwt_insecure(tok)
        assert info.issuer == "https://auth.example.com"

    def test_audience_string(self):
        tok  = _make_jwt({"aud": "api.example.com"})
        info = decode_jwt_insecure(tok)
        assert info.audience == "api.example.com"

    def test_audience_list_joined(self):
        tok  = _make_jwt({"aud": ["api.example.com", "admin.example.com"]})
        info = decode_jwt_insecure(tok)
        assert "api.example.com" in info.audience
        assert "admin.example.com" in info.audience

    def test_algorithm_from_header(self):
        tok  = _make_jwt({}, header={"alg": "RS256", "typ": "JWT"})
        info = decode_jwt_insecure(tok)
        assert info.algorithm == "RS256"

    def test_expired_token(self):
        past = int(time.time()) - 3600
        tok  = _make_jwt({"exp": past})
        info = decode_jwt_insecure(tok)
        assert info.is_expired is True

    def test_not_expired_token(self):
        future = int(time.time()) + 3600
        tok    = _make_jwt({"exp": future})
        info   = decode_jwt_insecure(tok)
        assert info.is_expired is False

    def test_no_exp_not_expired(self):
        tok  = _make_jwt({"sub": "user"})
        info = decode_jwt_insecure(tok)
        assert info.is_expired is False
        assert info.expires_at == ""

    def test_expires_at_iso_format(self):
        future = int(time.time()) + 7200
        tok    = _make_jwt({"exp": future})
        info   = decode_jwt_insecure(tok)
        assert "T" in info.expires_at

    def test_issued_at_extracted(self):
        iat  = int(time.time()) - 60
        tok  = _make_jwt({"iat": iat})
        info = decode_jwt_insecure(tok)
        assert "T" in info.issued_at

    def test_invalid_not_3_parts(self):
        info = decode_jwt_insecure("not.a.jwt.at.all")
        assert info.parse_error != ""

    def test_invalid_base64(self):
        info = decode_jwt_insecure("!!invalid!!.!!base64!!.sig")
        assert info.parse_error != ""

    def test_raw_token_preserved(self):
        tok  = _make_jwt({"sub": "u"})
        info = decode_jwt_insecure(tok)
        assert info.raw == tok

    def test_header_decoded(self):
        tok  = _make_jwt({}, header={"alg": "HS256", "typ": "JWT", "kid": "key-01"})
        info = decode_jwt_insecure(tok)
        assert info.header["kid"] == "key-01"


# ─────────────────────────────────────────────────────────────────────────────
# TestExtractCsrf
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractCsrfFromHtml:
    def test_csrf_meta_tag(self):
        html = '<meta name="csrf-token" content="abc123"/>'
        result = extract_csrf_from_html(html)
        assert result is not None
        header, value = result
        assert value == "abc123"
        assert "CSRF" in header.upper() or "XSRF" in header.upper()

    def test_xsrf_meta_tag_returns_xsrf_header(self):
        html = '<meta name="xsrf-token" content="xyz789"/>'
        result = extract_csrf_from_html(html)
        assert result is not None
        header, value = result
        assert "XSRF" in header.upper()
        assert value == "xyz789"

    def test_no_csrf_meta_returns_none(self):
        html = '<html><head><title>App</title></head></html>'
        assert extract_csrf_from_html(html) is None

    def test_double_quote_meta(self):
        html = '<meta name="csrf-token" content="tok-double"/>'
        result = extract_csrf_from_html(html)
        assert result is not None
        assert result[1] == "tok-double"


class TestExtractCsrfFromCookies:
    def test_csrftoken_cookie(self):
        result = extract_csrf_from_cookies({"csrftoken": "tok-csrf"})
        assert result is not None
        header, value = result
        assert value == "tok-csrf"

    def test_xsrf_token_cookie(self):
        result = extract_csrf_from_cookies({"XSRF-TOKEN": "tok-xsrf"})
        assert result is not None
        header, value = result
        assert "XSRF" in header.upper()

    def test_no_csrf_cookie_returns_none(self):
        result = extract_csrf_from_cookies({"session": "abc", "lang": "en"})
        assert result is None

    def test_empty_dict_returns_none(self):
        assert extract_csrf_from_cookies({}) is None

    def test_antiforgery_cookie_detected(self):
        result = extract_csrf_from_cookies({"__RequestVerificationToken": "tok"})
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# TestDomainMatches
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainMatches:
    def test_exact_match(self):
        assert _domain_matches("example.com", "example.com") is True

    def test_leading_dot_subdomain(self):
        assert _domain_matches(".example.com", "app.example.com") is True

    def test_leading_dot_exact(self):
        assert _domain_matches(".example.com", "example.com") is True

    def test_different_domain_no_match(self):
        assert _domain_matches(".example.com", "other.com") is False

    def test_partial_match_no_match(self):
        assert _domain_matches("example.com", "notexample.com") is False

    def test_case_insensitive(self):
        assert _domain_matches(".Example.COM", "APP.example.com") is True


# ─────────────────────────────────────────────────────────────────────────────
# Test fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_session(
    bearer_token: str = "",
    cookies: Optional[list] = None,
    extra_headers: Optional[dict] = None,
    local_storage: Optional[dict] = None,
    session_storage: Optional[dict] = None,
) -> LoginSession:
    from typing import Optional
    return LoginSession(
        profile_name    = "test",
        target_url      = "https://app.example.com/login",
        auth_pattern    = AuthPattern.FORM,
        cookies         = cookies or [],
        bearer_token    = bearer_token,
        extra_headers   = extra_headers or {},
        local_storage   = local_storage or {},
        session_storage = session_storage or {},
    )


# ─────────────────────────────────────────────────────────────────────────────
# TestSessionInjectorJwt
# ─────────────────────────────────────────────────────────────────────────────

class TestSessionInjectorJwt:
    def test_inspect_jwt_returns_none_when_no_token(self):
        inj = SessionInjector(_make_session())
        assert inj.inspect_jwt() is None

    def test_inspect_jwt_returns_info(self):
        tok = _make_jwt({"sub": "alice"})
        inj = SessionInjector(_make_session(bearer_token=tok))
        info = inj.inspect_jwt()
        assert info is not None
        assert info.subject == "alice"

    def test_inspect_jwt_strips_bearer_prefix(self):
        tok = _make_jwt({"sub": "bob"})
        inj = SessionInjector(_make_session(bearer_token=f"Bearer {tok}"))
        info = inj.inspect_jwt()
        assert info is not None
        assert info.subject == "bob"

    def test_is_jwt_expired_false_when_no_token(self):
        inj = SessionInjector(_make_session())
        assert inj.is_jwt_expired() is False

    def test_is_jwt_expired_true_for_past(self):
        past = int(time.time()) - 3600
        tok  = _make_jwt({"exp": past})
        inj  = SessionInjector(_make_session(bearer_token=tok))
        assert inj.is_jwt_expired() is True

    def test_is_jwt_expired_false_for_future(self):
        future = int(time.time()) + 3600
        tok    = _make_jwt({"exp": future})
        inj    = SessionInjector(_make_session(bearer_token=tok))
        assert inj.is_jwt_expired() is False


# ─────────────────────────────────────────────────────────────────────────────
# TestCookieHelpers
# ─────────────────────────────────────────────────────────────────────────────

class TestCookieHelpers:
    def _session_with_cookies(self):
        return _make_session(cookies=[
            SessionCookie("session", "abc123", ".example.com"),
            SessionCookie("csrf", "tok-csrf", ".example.com"),
            SessionCookie("other", "xyz", ".other.com"),
        ])

    def test_to_cookie_dict_no_url_returns_all(self):
        inj    = SessionInjector(self._session_with_cookies())
        result = inj.to_cookie_dict()
        assert "session" in result
        assert "csrf"    in result
        assert "other"   in result

    def test_to_cookie_dict_scoped(self):
        inj    = SessionInjector(self._session_with_cookies())
        result = inj.to_cookie_dict("https://app.example.com")
        assert "session" in result
        assert "csrf"    in result
        assert "other"   not in result

    def test_to_cookie_header_format(self):
        inj    = SessionInjector(self._session_with_cookies())
        header = inj.to_cookie_header("https://app.example.com")
        assert "session=abc123" in header
        assert "=" in header

    def test_to_cookie_dict_empty_when_no_cookies(self):
        inj = SessionInjector(_make_session())
        assert inj.to_cookie_dict() == {}


# ─────────────────────────────────────────────────────────────────────────────
# TestInjectRequests
# ─────────────────────────────────────────────────────────────────────────────

class TestInjectRequests:
    def _make_requests_session(self):
        """Return a mock that behaves like requests.Session."""
        mock = MagicMock()
        mock.cookies = MagicMock()
        mock.headers = {}
        return mock

    def _session_full(self):
        future_jwt = _make_jwt({"sub": "user", "exp": int(time.time()) + 7200})
        return _make_session(
            cookies      = [SessionCookie("sid", "abc", ".example.com")],
            bearer_token = future_jwt,
            extra_headers= {"Authorization": f"Bearer {future_jwt}"},
        )

    def test_cookies_set(self):
        inj     = SessionInjector(self._session_full())
        rs      = self._make_requests_session()
        result  = inj.inject_requests(rs, "https://app.example.com")
        assert result.cookies_injected == 1
        rs.cookies.set.assert_called_once()

    def test_headers_set(self):
        inj    = SessionInjector(self._session_full())
        rs     = self._make_requests_session()
        result = inj.inject_requests(rs, "https://app.example.com")
        assert result.headers_injected == 1
        assert "Authorization" in rs.headers

    def test_csrf_auto_injected(self):
        session = _make_session(
            cookies = [
                SessionCookie("sid", "abc", ".example.com"),
                SessionCookie("csrftoken", "csrf-val", ".example.com"),
            ]
        )
        inj    = SessionInjector(session)
        rs     = self._make_requests_session()
        result = inj.inject_requests(rs, "https://app.example.com")
        assert result.csrf_injected is True
        assert "X-CSRF-Token" in rs.headers or "X-XSRF-Token" in rs.headers

    def test_expired_jwt_produces_warning(self):
        past_jwt = _make_jwt({"exp": int(time.time()) - 3600})
        session  = _make_session(bearer_token=past_jwt)
        inj      = SessionInjector(session)
        rs       = self._make_requests_session()
        result   = inj.inject_requests(rs)
        assert len(result.warnings) > 0
        assert "expired" in result.warnings[0].lower()

    def test_dry_run_no_cookies_set(self):
        inj    = SessionInjector(self._session_full(), dry_run=True)
        rs     = self._make_requests_session()
        result = inj.inject_requests(rs, "https://app.example.com")
        # dry_run: cookies_injected counter still increments but set is NOT called
        rs.cookies.set.assert_not_called()
        assert result.cookies_injected == 1  # count still accurate

    def test_wrong_domain_cookie_excluded(self):
        session = _make_session(
            cookies = [
                SessionCookie("sid", "abc", ".example.com"),
                SessionCookie("other", "xyz", ".other.com"),
            ]
        )
        inj    = SessionInjector(session)
        rs     = self._make_requests_session()
        result = inj.inject_requests(rs, "https://app.example.com")
        assert result.cookies_injected == 1   # only .example.com cookie

    def test_result_ok_property(self):
        inj    = SessionInjector(self._session_full())
        rs     = self._make_requests_session()
        result = inj.inject_requests(rs, "https://app.example.com")
        assert result.ok is True


# ─────────────────────────────────────────────────────────────────────────────
# TestInjectHttpx
# ─────────────────────────────────────────────────────────────────────────────

class TestInjectHttpx:
    def _make_httpx_client(self):
        mock = MagicMock()
        mock.cookies = MagicMock()
        mock.headers = {}
        return mock

    def test_cookies_set(self):
        session = _make_session(
            cookies = [SessionCookie("tok", "val", ".example.com")]
        )
        inj    = SessionInjector(session)
        client = self._make_httpx_client()
        result = inj.inject_httpx(client, "https://app.example.com")
        client.cookies.set.assert_called_once_with("tok", "val")
        assert result.cookies_injected == 1

    def test_headers_set(self):
        future = int(time.time()) + 3600
        tok    = _make_jwt({"exp": future})
        session = _make_session(
            bearer_token = tok,
            extra_headers = {"Authorization": f"Bearer {tok}"},
        )
        inj    = SessionInjector(session)
        client = self._make_httpx_client()
        inj.inject_httpx(client, "https://app.example.com")
        assert "Authorization" in client.headers


# ─────────────────────────────────────────────────────────────────────────────
# TestInjectHeaders
# ─────────────────────────────────────────────────────────────────────────────

class TestInjectHeaders:
    def test_cookie_header_set(self):
        session = _make_session(
            cookies = [SessionCookie("sid", "abc", ".example.com")]
        )
        inj     = SessionInjector(session)
        headers = {}
        result  = inj.inject_headers(headers, "https://app.example.com")
        assert "Cookie" in headers
        assert "sid=abc" in headers["Cookie"]
        assert result.cookies_injected == 1

    def test_extra_headers_injected(self):
        session = _make_session(extra_headers={"X-API-Key": "key-abc"})
        inj     = SessionInjector(session)
        headers = {}
        inj.inject_headers(headers)
        assert headers.get("X-API-Key") == "key-abc"

    def test_no_cookies_no_cookie_header(self):
        inj     = SessionInjector(_make_session())
        headers = {}
        inj.inject_headers(headers)
        assert "Cookie" not in headers


# ─────────────────────────────────────────────────────────────────────────────
# TestScopeCheck
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeCheck:
    def test_in_scope_matching_domain(self):
        session = _make_session(
            cookies = [SessionCookie("s", "v", ".example.com")]
        )
        inj = SessionInjector(session)
        assert inj.is_in_scope("https://app.example.com/dashboard") is True

    def test_not_in_scope_different_domain(self):
        session = _make_session(
            cookies = [SessionCookie("s", "v", ".example.com")]
        )
        inj = SessionInjector(session)
        assert inj.is_in_scope("https://other.com/path") is False

    def test_not_in_scope_no_cookies(self):
        inj = SessionInjector(_make_session())
        assert inj.is_in_scope("https://example.com") is False

    def test_not_in_scope_empty_url(self):
        session = _make_session(cookies=[SessionCookie("s", "v", ".example.com")])
        inj     = SessionInjector(session)
        assert inj.is_in_scope("") is False


# ─────────────────────────────────────────────────────────────────────────────
# TestStorageAccess
# ─────────────────────────────────────────────────────────────────────────────

class TestStorageAccess:
    def test_get_local_storage_value(self):
        session = _make_session(local_storage={"auth_token": "jwt-abc"})
        inj     = SessionInjector(session)
        assert inj.get_local_storage_value("auth_token") == "jwt-abc"

    def test_get_local_storage_missing_returns_none(self):
        inj = SessionInjector(_make_session())
        assert inj.get_local_storage_value("nonexistent") is None

    def test_get_session_storage_value(self):
        session = _make_session(session_storage={"csrf": "tok-xyz"})
        inj     = SessionInjector(session)
        assert inj.get_session_storage_value("csrf") == "tok-xyz"

    def test_get_all_local_storage(self):
        session = _make_session(local_storage={"a": "1", "b": "2"})
        inj     = SessionInjector(session)
        assert inj.get_all_local_storage() == {"a": "1", "b": "2"}


# ─────────────────────────────────────────────────────────────────────────────
# TestDescribe
# ─────────────────────────────────────────────────────────────────────────────

class TestDescribe:
    def test_returns_dict(self):
        inj    = SessionInjector(_make_session())
        result = inj.describe()
        assert isinstance(result, dict)

    def test_contains_required_keys(self):
        inj  = SessionInjector(_make_session())
        desc = inj.describe()
        for key in ("profile_name", "auth_pattern", "cookie_count",
                    "has_bearer", "jwt_expired", "session_expired"):
            assert key in desc

    def test_profile_name_correct(self):
        inj  = SessionInjector(_make_session())
        desc = inj.describe()
        assert desc["profile_name"] == "test"

    def test_has_bearer_false(self):
        inj  = SessionInjector(_make_session())
        desc = inj.describe()
        assert desc["has_bearer"] is False

    def test_has_bearer_true(self):
        future = int(time.time()) + 3600
        tok    = _make_jwt({"exp": future})
        inj    = SessionInjector(_make_session(bearer_token=tok))
        desc   = inj.describe()
        assert desc["has_bearer"] is True

    def test_cookie_count(self):
        session = _make_session(cookies=[
            SessionCookie("a", "1", ".ex.com"),
            SessionCookie("b", "2", ".ex.com"),
        ])
        inj  = SessionInjector(session)
        desc = inj.describe()
        assert desc["cookie_count"] == 2


# ─────────────────────────────────────────────────────────────────────────────
# TestInjectionResult
# ─────────────────────────────────────────────────────────────────────────────

class TestInjectionResult:
    def test_ok_true_when_success_no_errors(self):
        r = InjectionResult(success=True)
        assert r.ok is True

    def test_ok_false_when_not_success(self):
        r = InjectionResult(success=False)
        assert r.ok is False

    def test_ok_false_when_errors_present(self):
        r = InjectionResult(success=True, errors=["something went wrong"])
        assert r.ok is False


# ─────────────────────────────────────────────────────────────────────────────
# Optional helper
# ─────────────────────────────────────────────────────────────────────────────

from typing import Optional

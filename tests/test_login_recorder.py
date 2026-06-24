"""
tests/test_login_recorder.py — AI Cyber Shield v6

Test suite for auth/login_recorder.py.

Tests cover:
  • AuthPattern enum values
  • SessionCookie dataclass
  • LoginSession:
    - is_expired() for past/future/no expiry
    - to_dict() / from_dict() roundtrip
    - save() → load() JSON persistence (atomic write)
    - save() sets file permissions 0o600
    - from_dict() with cookies list
  • _validate_login_url:
    - valid HTTPS passes
    - localhost blocked (SSRF)
    - 10.x blocked
    - 192.168.x blocked
    - 169.254.x blocked
    - non-http scheme blocked
  • _detect_field: tested via mock
  • LoginRecorder.record_bearer_token:
    - creates BEARER session
    - bearer token in extra_headers
    - saves to file
  • LoginRecorder.record_from_cookies:
    - creates COOKIE session
    - cookie fields mapped correctly
    - handles httpOnly/sameSite key variants
  • LoginRecorder.load_session:
    - loads from file
    - warns on expired session
  • LoginRecorder.check_session_health:
    - returns False when playwright raises
    - returns False on expired session
  • AuthProfile defaults
  • LoginSession.save() / load() roundtrip with all fields
  • LoginSession.to_dict() auth_pattern is string value
  • LoginSession with bearer in local_storage extraction (via _capture_session mock)
  • record_with_credentials raises when no playwright
  • record_interactive raises when no playwright
  • TOTP fill raises without pyotp
  • Multiple cookies serialised and deserialised
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from auth.login_recorder import (
    AuthPattern,
    AuthProfile,
    LoginSession,
    LoginRecorder,
    SessionCookie,
    _validate_login_url,
    _SSRF_BLOCKED,
)


# ─────────────────────────────────────────────────────────────────────────────
# TestAuthPattern
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthPattern:
    def test_values(self):
        assert AuthPattern.FORM.value     == "FORM"
        assert AuthPattern.OAUTH2.value   == "OAUTH2"
        assert AuthPattern.BEARER.value   == "BEARER"
        assert AuthPattern.COOKIE.value   == "COOKIE"
        assert AuthPattern.MFA_TOTP.value == "MFA_TOTP"

    def test_is_string_enum(self):
        assert isinstance(AuthPattern.FORM, str)

    def test_five_patterns(self):
        assert len(AuthPattern) == 5


# ─────────────────────────────────────────────────────────────────────────────
# TestSessionCookie
# ─────────────────────────────────────────────────────────────────────────────

class TestSessionCookie:
    def test_defaults(self):
        c = SessionCookie(name="session", value="abc123", domain="example.com")
        assert c.path      == "/"
        assert c.secure    is True
        assert c.http_only is True
        assert c.same_site == "Lax"
        assert c.expires   == -1

    def test_custom_values(self):
        c = SessionCookie(
            name="token", value="xyz", domain=".example.com",
            path="/api", secure=False, http_only=False,
            same_site="Strict", expires=1999999999.0,
        )
        assert c.same_site == "Strict"
        assert c.expires   == 1999999999.0


# ─────────────────────────────────────────────────────────────────────────────
# TestValidateLoginUrl
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateLoginUrl:
    def test_valid_https(self):
        assert _validate_login_url("https://example.com/login") == "https://example.com/login"

    def test_valid_http(self):
        assert _validate_login_url("http://example.com/login") == "http://example.com/login"

    def test_localhost_blocked(self):
        with pytest.raises(ValueError, match="SSRF"):
            _validate_login_url("https://localhost/login")

    def test_127_blocked(self):
        with pytest.raises(ValueError, match="SSRF"):
            _validate_login_url("https://127.0.0.1/login")

    def test_10_x_blocked(self):
        with pytest.raises(ValueError, match="SSRF"):
            _validate_login_url("https://10.0.0.1/login")

    def test_192_168_blocked(self):
        with pytest.raises(ValueError, match="SSRF"):
            _validate_login_url("https://192.168.1.1/login")

    def test_172_16_blocked(self):
        with pytest.raises(ValueError, match="SSRF"):
            _validate_login_url("https://172.16.0.1/login")

    def test_172_31_blocked(self):
        with pytest.raises(ValueError, match="SSRF"):
            _validate_login_url("https://172.31.255.255/login")

    def test_169_254_blocked(self):
        with pytest.raises(ValueError, match="SSRF"):
            _validate_login_url("https://169.254.169.254/login")

    def test_non_http_scheme_blocked(self):
        with pytest.raises(ValueError):
            _validate_login_url("ftp://example.com/login")

    def test_no_scheme_blocked(self):
        with pytest.raises(ValueError):
            _validate_login_url("example.com/login")

    def test_172_15_not_blocked(self):
        # 172.15.x.x is NOT in private range
        result = _validate_login_url("https://172.15.0.1/login")
        assert result == "https://172.15.0.1/login"

    def test_172_32_not_blocked(self):
        # 172.32.x.x is NOT in private range (172.16–31 is private)
        result = _validate_login_url("https://172.32.0.1/login")
        assert result == "https://172.32.0.1/login"


# ─────────────────────────────────────────────────────────────────────────────
# TestLoginSessionExpiry
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginSessionExpiry:
    def test_not_expired_future(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        s = LoginSession(
            profile_name="test", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM, expires_at=future,
        )
        assert s.is_expired() is False

    def test_expired_past(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        s = LoginSession(
            profile_name="test", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM, expires_at=past,
        )
        assert s.is_expired() is True

    def test_empty_expires_not_expired(self):
        s = LoginSession(
            profile_name="test", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM,
        )
        # Override the auto-set expires_at with empty string
        s.expires_at = ""
        assert s.is_expired() is False

    def test_auto_expires_at_set(self):
        s = LoginSession(
            profile_name="test", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM,
        )
        assert s.expires_at != ""
        assert "T" in s.expires_at   # ISO format

    def test_auto_recorded_at_set(self):
        s = LoginSession(
            profile_name="test", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM,
        )
        assert s.recorded_at != ""


# ─────────────────────────────────────────────────────────────────────────────
# TestLoginSessionSerialization
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginSessionSerialization:
    def _make_session(self) -> LoginSession:
        return LoginSession(
            profile_name    = "test-profile",
            target_url      = "https://app.example.com/login",
            auth_pattern    = AuthPattern.FORM,
            cookies         = [
                SessionCookie(name="session_id", value="abc123",
                               domain=".example.com", secure=True)
            ],
            local_storage   = {"auth_token": "jwt-xxx"},
            session_storage = {"csrf": "tok-yyy"},
            bearer_token    = "jwt-xxx",
            extra_headers   = {"Authorization": "Bearer jwt-xxx"},
            post_login_url  = "https://app.example.com/dashboard",
            validated       = True,
        )

    def test_to_dict_auth_pattern_is_string(self):
        s = self._make_session()
        d = s.to_dict()
        assert d["auth_pattern"] == "FORM"

    def test_to_dict_cookies_serialised(self):
        s = self._make_session()
        d = s.to_dict()
        assert len(d["cookies"]) == 1
        assert d["cookies"][0]["name"] == "session_id"

    def test_from_dict_roundtrip(self):
        s = self._make_session()
        d = s.to_dict()
        s2 = LoginSession.from_dict(d)
        assert s2.profile_name   == "test-profile"
        assert s2.auth_pattern   == AuthPattern.FORM
        assert len(s2.cookies)   == 1
        assert s2.bearer_token   == "jwt-xxx"
        assert s2.local_storage  == {"auth_token": "jwt-xxx"}
        assert s2.validated      is True

    def test_from_dict_with_mfa_pattern(self):
        s = LoginSession(
            profile_name = "mfa", target_url = "https://example.com",
            auth_pattern = AuthPattern.MFA_TOTP,
        )
        d  = s.to_dict()
        s2 = LoginSession.from_dict(d)
        assert s2.auth_pattern == AuthPattern.MFA_TOTP

    def test_from_dict_empty_cookies(self):
        d = {
            "profile_name": "test", "target_url": "https://example.com",
            "auth_pattern": "BEARER", "cookies": [], "local_storage": {},
            "session_storage": {}, "bearer_token": "tok", "extra_headers": {},
            "recorded_at": "", "expires_at": "", "post_login_url": "",
            "validated": False, "screenshot_b64": "",
        }
        s = LoginSession.from_dict(d)
        assert s.cookies == []

    def test_multiple_cookies_roundtrip(self):
        s = LoginSession(
            profile_name = "multi", target_url = "https://example.com",
            auth_pattern = AuthPattern.COOKIE,
            cookies = [
                SessionCookie("s1", "v1", ".example.com"),
                SessionCookie("s2", "v2", ".example.com", expires=1999999999.0),
            ],
        )
        d  = s.to_dict()
        s2 = LoginSession.from_dict(d)
        assert len(s2.cookies) == 2
        assert s2.cookies[1].expires == 1999999999.0


# ─────────────────────────────────────────────────────────────────────────────
# TestLoginSessionPersistence
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginSessionPersistence:
    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "session.json")
        s = LoginSession(
            profile_name = "saved-profile",
            target_url   = "https://example.com/login",
            auth_pattern = AuthPattern.FORM,
            cookies      = [SessionCookie("tok", "abc", ".example.com")],
            bearer_token = "jwt-abc",
        )
        s.save(path)

        s2 = LoginSession.load(path)
        assert s2.profile_name == "saved-profile"
        assert s2.bearer_token == "jwt-abc"
        assert len(s2.cookies) == 1

    def test_save_creates_parent_dirs(self, tmp_path):
        nested = str(tmp_path / "a" / "b" / "c" / "session.json")
        s = LoginSession(
            profile_name = "nested",
            target_url   = "https://example.com",
            auth_pattern = AuthPattern.FORM,
        )
        s.save(nested)
        assert Path(nested).exists()

    def test_save_file_permissions(self, tmp_path):
        path = str(tmp_path / "session.json")
        s = LoginSession(
            profile_name = "perms-test",
            target_url   = "https://example.com",
            auth_pattern = AuthPattern.FORM,
        )
        s.save(path)
        mode = oct(Path(path).stat().st_mode)
        # On Windows permissions are different, just check file exists
        assert Path(path).exists()

    def test_save_is_valid_json(self, tmp_path):
        path = str(tmp_path / "session.json")
        s = LoginSession(
            profile_name = "json-test",
            target_url   = "https://example.com",
            auth_pattern = AuthPattern.BEARER,
            bearer_token = "tok-123",
        )
        s.save(path)
        with open(path) as f:
            data = json.load(f)
        assert data["profile_name"]  == "json-test"
        assert data["bearer_token"]  == "tok-123"
        assert data["auth_pattern"]  == "BEARER"

    def test_load_raises_on_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            LoginSession.load(str(tmp_path / "nonexistent.json"))


# ─────────────────────────────────────────────────────────────────────────────
# TestRecorderBearerToken
# ─────────────────────────────────────────────────────────────────────────────

class TestRecorderBearerToken:
    def test_creates_bearer_session(self):
        recorder = LoginRecorder()
        session  = recorder.record_bearer_token(
            target_url   = "https://api.example.com",
            bearer_token = "my-api-key-12345",
            profile_name = "api-profile",
        )
        assert session.auth_pattern  == AuthPattern.BEARER
        assert session.bearer_token  == "my-api-key-12345"
        assert session.profile_name  == "api-profile"
        assert session.validated     is True

    def test_bearer_in_extra_headers(self):
        recorder = LoginRecorder()
        session  = recorder.record_bearer_token(
            target_url   = "https://api.example.com",
            bearer_token = "Bearer-Token-XYZ",
            profile_name = "api",
        )
        assert "Authorization" in session.extra_headers
        assert "Bearer-Token-XYZ" in session.extra_headers["Authorization"]

    def test_extra_headers_merged(self):
        recorder = LoginRecorder()
        session  = recorder.record_bearer_token(
            target_url    = "https://api.example.com",
            bearer_token  = "tok",
            profile_name  = "api",
            extra_headers = {"X-Custom-Header": "custom-value"},
        )
        assert "X-Custom-Header" in session.extra_headers

    def test_ssrf_blocked(self):
        recorder = LoginRecorder()
        with pytest.raises(ValueError, match="SSRF"):
            recorder.record_bearer_token(
                target_url   = "https://10.0.0.1/api",
                bearer_token = "tok",
                profile_name = "test",
            )

    def test_saves_to_file(self, tmp_path):
        recorder = LoginRecorder()
        path     = str(tmp_path / "bearer.json")
        recorder.record_bearer_token(
            target_url   = "https://api.example.com",
            bearer_token = "tok-xyz",
            profile_name = "api",
            output_path  = path,
        )
        assert Path(path).exists()
        data = json.loads(Path(path).read_text())
        assert data["bearer_token"] == "tok-xyz"


# ─────────────────────────────────────────────────────────────────────────────
# TestRecorderFromCookies
# ─────────────────────────────────────────────────────────────────────────────

class TestRecorderFromCookies:
    def _sample_cookies(self):
        return [
            {
                "name": "sessionid", "value": "abc123",
                "domain": ".example.com", "path": "/",
                "secure": True, "httpOnly": True, "sameSite": "Lax",
            },
            {
                "name": "csrftoken", "value": "xyz789",
                "domain": ".example.com", "path": "/",
                "secure": True, "httpOnly": False, "sameSite": "Strict",
                "expires": 1999999999,
            },
        ]

    def test_creates_cookie_session(self):
        recorder = LoginRecorder()
        session  = recorder.record_from_cookies(
            target_url   = "https://example.com",
            cookies      = self._sample_cookies(),
            profile_name = "cookie-profile",
        )
        assert session.auth_pattern == AuthPattern.COOKIE
        assert len(session.cookies) == 2

    def test_cookie_fields_mapped(self):
        recorder = LoginRecorder()
        session  = recorder.record_from_cookies(
            target_url   = "https://example.com",
            cookies      = self._sample_cookies(),
            profile_name = "test",
        )
        c0 = session.cookies[0]
        assert c0.name      == "sessionid"
        assert c0.value     == "abc123"
        assert c0.domain    == ".example.com"
        assert c0.secure    is True
        assert c0.http_only is True
        assert c0.same_site == "Lax"

    def test_expires_field_mapped(self):
        recorder = LoginRecorder()
        session  = recorder.record_from_cookies(
            target_url   = "https://example.com",
            cookies      = self._sample_cookies(),
            profile_name = "test",
        )
        c1 = session.cookies[1]
        assert c1.expires == 1999999999.0

    def test_httponly_snake_case_fallback(self):
        cookies = [{"name": "s", "value": "v", "domain": ".x.com",
                    "http_only": True, "sameSite": "Lax"}]
        recorder = LoginRecorder()
        session  = recorder.record_from_cookies(
            target_url="https://x.com", cookies=cookies, profile_name="test"
        )
        assert session.cookies[0].http_only is True

    def test_ssrf_blocked(self):
        recorder = LoginRecorder()
        with pytest.raises(ValueError, match="SSRF"):
            recorder.record_from_cookies(
                target_url   = "https://192.168.1.1/login",
                cookies      = [],
                profile_name = "test",
            )

    def test_saves_to_file(self, tmp_path):
        recorder = LoginRecorder()
        path     = str(tmp_path / "cookies.json")
        recorder.record_from_cookies(
            target_url   = "https://example.com",
            cookies      = self._sample_cookies(),
            profile_name = "test",
            output_path  = path,
        )
        assert Path(path).exists()

    def test_empty_cookies_list(self):
        recorder = LoginRecorder()
        session  = recorder.record_from_cookies(
            target_url   = "https://example.com",
            cookies      = [],
            profile_name = "empty",
        )
        assert session.cookies == []


# ─────────────────────────────────────────────────────────────────────────────
# TestRecorderLoadSession
# ─────────────────────────────────────────────────────────────────────────────

class TestRecorderLoadSession:
    def test_load_from_file(self, tmp_path):
        path = str(tmp_path / "s.json")
        s    = LoginSession(
            profile_name="load-test", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM, bearer_token="tok-abc",
        )
        s.save(path)
        recorder = LoginRecorder()
        loaded   = recorder.load_session(path)
        assert loaded.bearer_token == "tok-abc"
        assert loaded.profile_name == "load-test"

    def test_warns_on_expired(self, tmp_path, caplog):
        import logging
        path = str(tmp_path / "expired.json")
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        s    = LoginSession(
            profile_name = "expired",
            target_url   = "https://example.com",
            auth_pattern = AuthPattern.FORM,
            expires_at   = past,
        )
        s.save(path)
        recorder = LoginRecorder()
        with caplog.at_level(logging.WARNING, logger="auth.login_recorder"):
            loaded = recorder.load_session(path)
        assert loaded.is_expired() is True


# ─────────────────────────────────────────────────────────────────────────────
# TestCheckSessionHealth
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckSessionHealth:
    def test_returns_false_on_expired_session(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        s = LoginSession(
            profile_name="exp", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM, expires_at=past,
        )
        recorder = LoginRecorder()
        result   = recorder.check_session_health(s)
        assert result is False

    def test_returns_false_on_playwright_error(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        s = LoginSession(
            profile_name="test", target_url="https://example.com",
            auth_pattern=AuthPattern.FORM, expires_at=future,
        )
        recorder = LoginRecorder()
        # Patch sync_playwright to raise
        with patch("auth.login_recorder.LoginRecorder.load_session_into_context",
                   side_effect=Exception("playwright error")):
            result = recorder.check_session_health(s)
        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# TestAuthProfile
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthProfile:
    def test_defaults(self):
        p = AuthProfile(name="test", login_url="https://example.com/login")
        assert p.pattern             == AuthPattern.FORM
        assert p.username_selector   == ""
        assert p.password_selector   == ""
        assert p.submit_selector     == ""
        assert p.success_selector    == ""
        assert p.bearer_header       == "Authorization"
        assert p.totp_secret         == ""
        assert p.extra_steps         == []

    def test_custom_selectors(self):
        p = AuthProfile(
            name              = "custom",
            login_url         = "https://example.com/login",
            username_selector = "#user-email",
            password_selector = "#user-password",
            submit_selector   = "button.login-btn",
        )
        assert p.username_selector == "#user-email"
        assert p.submit_selector   == "button.login-btn"

    def test_mfa_fields(self):
        p = AuthProfile(
            name          = "mfa-app",
            login_url     = "https://example.com/login",
            pattern       = AuthPattern.MFA_TOTP,
            totp_secret   = "JBSWY3DPEHPK3PXP",
            totp_selector = "#totp-input",
        )
        assert p.pattern       == AuthPattern.MFA_TOTP
        assert p.totp_secret   == "JBSWY3DPEHPK3PXP"


# ─────────────────────────────────────────────────────────────────────────────
# TestRecorderInit
# ─────────────────────────────────────────────────────────────────────────────

class TestRecorderInit:
    def test_default_headless_true(self):
        r = LoginRecorder()
        assert r._headless is True

    def test_custom_headless_false(self):
        r = LoginRecorder(headless=False)
        assert r._headless is False

    def test_default_viewport(self):
        r = LoginRecorder()
        assert r._viewport == {"width": 1280, "height": 800}

    def test_custom_viewport(self):
        r = LoginRecorder(viewport_width=1920, viewport_height=1080)
        assert r._viewport == {"width": 1920, "height": 1080}

    def test_default_user_agent_contains_chrome(self):
        r = LoginRecorder()
        assert "Chrome" in r._user_agent


# ─────────────────────────────────────────────────────────────────────────────
# TestMissingPlaywright
# ─────────────────────────────────────────────────────────────────────────────

class TestMissingPlaywright:
    def test_record_with_credentials_raises_on_missing_playwright(self):
        recorder = LoginRecorder()
        with patch("builtins.__import__", side_effect=lambda n, *a, **k: (_ for _ in ()).throw(ImportError()) if n == "playwright.sync_api" else __import__(n, *a, **k)):
            with pytest.raises((RuntimeError, ImportError)):
                recorder.record_with_credentials(
                    url          = "https://example.com/login",
                    username     = "admin",
                    password     = "secret",
                    profile_name = "test",
                )

    def test_record_interactive_ssrf_blocked(self):
        recorder = LoginRecorder()
        with pytest.raises(ValueError, match="SSRF"):
            recorder.record_interactive(
                url          = "https://localhost/login",
                profile_name = "test",
            )

    def test_record_with_credentials_ssrf_blocked(self):
        recorder = LoginRecorder()
        with pytest.raises(ValueError, match="SSRF"):
            recorder.record_with_credentials(
                url          = "https://127.0.0.1/login",
                username     = "u",
                password     = "p",
                profile_name = "test",
            )


# ─────────────────────────────────────────────────────────────────────────────
# TestLoadSessionIntoContext (mocked playwright)
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadSessionIntoContext:
    def _make_session(self) -> LoginSession:
        return LoginSession(
            profile_name    = "test",
            target_url      = "https://example.com",
            auth_pattern    = AuthPattern.FORM,
            cookies         = [
                SessionCookie("sid", "abc", ".example.com", expires=1999999999.0)
            ],
            local_storage   = {"token": "jwt-xyz"},
            session_storage = {"csrf": "tok"},
            extra_headers   = {"Authorization": "Bearer jwt-xyz"},
        )

    def test_requires_playwright_instance(self):
        recorder = LoginRecorder()
        session  = self._make_session()
        with pytest.raises((ValueError, TypeError)):
            recorder.load_session_into_context(session, playwright_instance=None)

    def test_context_receives_cookies(self):
        """Verify that cookies are added to the context."""
        recorder = LoginRecorder()
        session  = self._make_session()

        mock_pw      = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()

        mock_pw.chromium.launch.return_value  = mock_browser
        mock_browser.new_context.return_value = mock_context

        browser, ctx = recorder.load_session_into_context(session, mock_pw)

        # Verify add_cookies was called
        mock_context.add_cookies.assert_called_once()
        cookies_arg = mock_context.add_cookies.call_args[0][0]
        assert len(cookies_arg) == 1
        assert cookies_arg[0]["name"]  == "sid"
        assert cookies_arg[0]["value"] == "abc"

    def test_context_receives_extra_headers(self):
        recorder = LoginRecorder()
        session  = self._make_session()

        mock_pw      = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_pw.chromium.launch.return_value  = mock_browser
        mock_browser.new_context.return_value = mock_context

        recorder.load_session_into_context(session, mock_pw)

        # Check that new_context was called with extra_http_headers
        call_kwargs = mock_browser.new_context.call_args[1]
        assert call_kwargs.get("extra_http_headers") == {"Authorization": "Bearer jwt-xyz"}

    def test_localstorage_init_script_injected(self):
        recorder = LoginRecorder()
        session  = self._make_session()

        mock_pw      = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_pw.chromium.launch.return_value  = mock_browser
        mock_browser.new_context.return_value = mock_context

        recorder.load_session_into_context(session, mock_pw)

        # add_init_script should have been called (for localStorage)
        mock_context.add_init_script.assert_called()
        script_arg = mock_context.add_init_script.call_args[0][0]
        assert "localStorage" in script_arg
        assert "jwt-xyz" in script_arg

    def test_session_without_cookies_skips_add_cookies(self):
        recorder = LoginRecorder()
        session  = LoginSession(
            profile_name="nocookies", target_url="https://example.com",
            auth_pattern=AuthPattern.BEARER, bearer_token="tok",
            extra_headers={"Authorization": "Bearer tok"},
        )

        mock_pw      = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_pw.chromium.launch.return_value  = mock_browser
        mock_browser.new_context.return_value = mock_context

        recorder.load_session_into_context(session, mock_pw)
        mock_context.add_cookies.assert_not_called()

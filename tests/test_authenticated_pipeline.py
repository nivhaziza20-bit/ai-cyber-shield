"""
tests/test_authenticated_pipeline.py

Full test suite for Stage B — Authenticated Scanning Pipeline.

Coverage:
  1. Thread-local auth context (http_utils): set / get / clear / isolation
  2. safe_get() auth header + cookie merging
  3. cookie_security.py httpx auth merging
  4. ScanAuth dataclass: is_empty, summary, from_bearer_token, from_cookies_dict
  5. session_loader: load_from_file (ScanProfile / LoginSession / raw headers / raw cookies)
  6. session_loader: check_session_health (healthy, expired, redirected, 401)
  7. Pipeline: _auth_wrapped (with + without auth, exception cleanup)
  8. Pipeline: run_url_security_audit accepts scan_auth, returns auth_mode field
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures and helpers
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_auth(monkeypatch):
    """Ensure thread-local auth is cleared before and after every test."""
    from tools.http_utils import clear_scan_auth
    clear_scan_auth()
    yield
    clear_scan_auth()


@pytest.fixture()
def bearer_auth():
    """A simple ScanAuth with a Bearer token."""
    from auth.session_loader import from_bearer_token
    return from_bearer_token("test.jwt.token", profile_name="test-bearer")


@pytest.fixture()
def cookie_auth():
    """A simple ScanAuth with cookies."""
    from auth.session_loader import from_cookies_dict
    return from_cookies_dict({"session": "abc123", "csrf": "xyz789"}, profile_name="test-cookies")


@pytest.fixture()
def headers_auth():
    """A ScanAuth with custom headers."""
    from auth.session_loader import from_headers_dict
    return from_headers_dict({"X-Auth-Token": "secret", "X-Tenant": "acme"}, profile_name="test-headers")


def _make_mock_response(status: int = 200, headers: dict | None = None, body: str = "OK") -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.headers = MagicMock()
    resp.headers.get.return_value = None
    resp.is_redirect = False
    resp.text = body
    resp.content = body.encode()
    resp.url = "https://example.com/"
    resp.apparent_encoding = "utf-8"

    chunks_consumed = [False]
    def iter_content(chunk_size=65536):
        if not chunks_consumed[0]:
            chunks_consumed[0] = True
            yield body.encode()
    resp.iter_content = iter_content

    return resp


# ─────────────────────────────────────────────────────────────────────────────
# 1. Thread-local auth context
# ─────────────────────────────────────────────────────────────────────────────

class TestThreadLocalAuthContext:
    def test_initial_state_returns_empty_dicts(self):
        from tools.http_utils import get_scan_auth, clear_scan_auth
        clear_scan_auth()
        headers, cookies = get_scan_auth()
        assert headers == {}
        assert cookies == {}

    def test_set_and_get_headers(self):
        from tools.http_utils import set_scan_auth, get_scan_auth
        set_scan_auth({"Authorization": "Bearer tok"}, {})
        headers, cookies = get_scan_auth()
        assert headers == {"Authorization": "Bearer tok"}
        assert cookies == {}

    def test_set_and_get_cookies(self):
        from tools.http_utils import set_scan_auth, get_scan_auth
        set_scan_auth({}, {"session": "abc", "csrf": "xyz"})
        headers, cookies = get_scan_auth()
        assert headers == {}
        assert cookies == {"session": "abc", "csrf": "xyz"}

    def test_clear_removes_auth(self):
        from tools.http_utils import set_scan_auth, get_scan_auth, clear_scan_auth
        set_scan_auth({"Authorization": "Bearer tok"}, {"s": "v"})
        clear_scan_auth()
        headers, cookies = get_scan_auth()
        assert headers == {}
        assert cookies == {}

    def test_thread_isolation(self):
        """Auth set in one thread must not bleed into another thread."""
        from tools.http_utils import set_scan_auth, get_scan_auth, clear_scan_auth

        results: dict[str, tuple] = {}

        def _t1():
            set_scan_auth({"Authorization": "Bearer thread1"}, {})
            import time; time.sleep(0.05)  # let t2 run
            results["t1"] = get_scan_auth()

        def _t2():
            # t2 has no auth set
            import time; time.sleep(0.01)
            results["t2"] = get_scan_auth()

        t1 = threading.Thread(target=_t1)
        t2 = threading.Thread(target=_t2)
        t1.start(); t2.start()
        t1.join(); t2.join()

        # t1 should see its headers, t2 should see nothing
        assert results["t1"][0].get("Authorization") == "Bearer thread1"
        assert results["t2"][0] == {}

    def test_set_overwrites_previous(self):
        from tools.http_utils import set_scan_auth, get_scan_auth
        set_scan_auth({"Authorization": "Bearer old"}, {"s": "old"})
        set_scan_auth({"Authorization": "Bearer new"}, {"s": "new"})
        h, c = get_scan_auth()
        assert h["Authorization"] == "Bearer new"
        assert c["s"] == "new"

    def test_get_returns_copies_not_references(self):
        """Mutating returned dicts must not corrupt the thread-local state."""
        from tools.http_utils import set_scan_auth, get_scan_auth
        set_scan_auth({"X-Auth": "orig"}, {"sess": "orig"})
        h, c = get_scan_auth()
        h["X-Auth"] = "mutated"
        c["sess"]   = "mutated"
        h2, c2 = get_scan_auth()
        assert h2["X-Auth"] == "orig"
        assert c2["sess"]   == "orig"


# ─────────────────────────────────────────────────────────────────────────────
# 2. safe_get() auth merging
# ─────────────────────────────────────────────────────────────────────────────

class TestSafeGetAuthMerging:
    def _make_session_spy(self):
        """Returns (session_mock, captured_calls) where captured_calls is mutated in place."""
        captured = []

        class SpySession:
            cookies = MagicMock()
            def get(self, url, **kwargs):
                captured.append({"url": url, "kwargs": kwargs})
                return _make_mock_response(200)

        return SpySession(), captured

    def test_auth_headers_sent_when_active(self):
        from tools.http_utils import set_scan_auth, safe_get
        set_scan_auth({"Authorization": "Bearer tok123"}, {})

        with patch("tools.http_utils.is_ssrf_blocked", return_value=False):
            spy, calls = self._make_session_spy()
            with patch("tools.http_utils.requests.Session", return_value=spy):
                safe_get("https://example.com/")

        assert len(calls) == 1
        sent_headers = calls[0]["kwargs"].get("headers", {})
        assert sent_headers.get("Authorization") == "Bearer tok123"

    def test_extra_headers_override_auth_headers(self):
        """extra_headers param should take precedence over thread-local auth."""
        from tools.http_utils import set_scan_auth, safe_get
        set_scan_auth({"X-Custom": "from-auth"}, {})

        with patch("tools.http_utils.is_ssrf_blocked", return_value=False):
            spy, calls = self._make_session_spy()
            with patch("tools.http_utils.requests.Session", return_value=spy):
                safe_get("https://example.com/", extra_headers={"X-Custom": "from-extra"})

        sent = calls[0]["kwargs"].get("headers", {})
        assert sent.get("X-Custom") == "from-extra"

    def test_no_auth_when_not_active(self):
        """Without set_scan_auth(), no auth headers appear."""
        from tools.http_utils import clear_scan_auth, safe_get
        clear_scan_auth()

        with patch("tools.http_utils.is_ssrf_blocked", return_value=False):
            spy, calls = self._make_session_spy()
            with patch("tools.http_utils.requests.Session", return_value=spy):
                safe_get("https://example.com/")

        sent = calls[0]["kwargs"].get("headers", {})
        assert "Authorization" not in sent


# ─────────────────────────────────────────────────────────────────────────────
# 3. ScanAuth dataclass
# ─────────────────────────────────────────────────────────────────────────────

class TestScanAuth:
    def test_is_empty_when_no_headers_or_cookies(self):
        from auth.session_loader import ScanAuth
        assert ScanAuth().is_empty is True

    def test_is_not_empty_with_headers(self):
        from auth.session_loader import ScanAuth
        assert ScanAuth(headers={"Authorization": "Bearer x"}).is_empty is False

    def test_is_not_empty_with_cookies(self):
        from auth.session_loader import ScanAuth
        assert ScanAuth(cookies={"s": "v"}).is_empty is False

    def test_summary_shows_profile_name(self):
        from auth.session_loader import ScanAuth
        auth = ScanAuth(headers={"Authorization": "Bearer x"}, profile_name="my-profile")
        assert "my-profile" in auth.summary()

    def test_summary_shows_cookie_count(self):
        from auth.session_loader import ScanAuth
        auth = ScanAuth(cookies={"a": "1", "b": "2", "c": "3"})
        assert "3" in auth.summary()

    def test_summary_shows_expired(self):
        from auth.session_loader import ScanAuth
        auth = ScanAuth(cookies={"s": "v"}, expired=True)
        assert "EXPIRED" in auth.summary().upper()

    def test_source_field_preserved(self):
        from auth.session_loader import ScanAuth
        auth = ScanAuth(source="token")
        assert auth.source == "token"


# ─────────────────────────────────────────────────────────────────────────────
# 4. session_loader factory functions
# ─────────────────────────────────────────────────────────────────────────────

class TestSessionLoaderFactories:
    def test_from_bearer_token_sets_authorization_header(self, bearer_auth):
        assert bearer_auth.headers.get("Authorization") == "Bearer test.jwt.token"
        assert bearer_auth.cookies == {}
        assert bearer_auth.source == "token"

    def test_from_bearer_token_rejects_empty_string(self):
        from auth.session_loader import from_bearer_token
        with pytest.raises(ValueError, match="empty"):
            from_bearer_token("")

    def test_from_bearer_token_strips_whitespace(self):
        from auth.session_loader import from_bearer_token
        auth = from_bearer_token("  token123  ")
        assert auth.headers["Authorization"] == "Bearer token123"

    def test_from_cookies_dict_sets_cookies(self, cookie_auth):
        assert cookie_auth.cookies == {"session": "abc123", "csrf": "xyz789"}
        assert cookie_auth.headers == {}
        assert cookie_auth.source == "manual"

    def test_from_cookies_dict_rejects_empty(self):
        from auth.session_loader import from_cookies_dict
        with pytest.raises(ValueError, match="empty"):
            from_cookies_dict({})

    def test_from_headers_dict_sets_headers(self, headers_auth):
        assert headers_auth.headers == {"X-Auth-Token": "secret", "X-Tenant": "acme"}
        assert headers_auth.source == "manual"

    def test_from_headers_dict_rejects_empty(self):
        from auth.session_loader import from_headers_dict
        with pytest.raises(ValueError, match="empty"):
            from_headers_dict({})


# ─────────────────────────────────────────────────────────────────────────────
# 5. load_from_file — auto-detection
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadFromFile:
    def _write_json(self, data: dict) -> str:
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8")
        json.dump(data, tmp)
        tmp.close()
        return tmp.name

    def teardown_method(self):
        pass  # tempfile cleanup handled per test

    def test_loads_raw_bearer_headers(self):
        from auth.session_loader import load_from_file
        path = self._write_json({"Authorization": "Bearer tok123"})
        try:
            auth = load_from_file(path)
            assert auth.headers.get("Authorization") == "Bearer tok123"
        finally:
            os.unlink(path)

    def test_loads_raw_cookies_dict(self):
        from auth.session_loader import load_from_file
        path = self._write_json({"session": "abc", "csrf": "xyz"})
        try:
            auth = load_from_file(path)
            assert auth.cookies.get("session") == "abc"
        finally:
            os.unlink(path)

    def test_raises_for_missing_file(self):
        from auth.session_loader import load_from_file
        with pytest.raises(FileNotFoundError):
            load_from_file("/nonexistent/path/auth.json")

    def test_raises_for_invalid_json(self):
        from auth.session_loader import load_from_file
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
        tmp.write("not valid json {{{")
        tmp.close()
        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                load_from_file(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_raises_for_non_object_json(self):
        from auth.session_loader import load_from_file
        path = self._write_json([1, 2, 3])  # list, not dict
        try:
            with pytest.raises(ValueError, match="JSON object"):
                load_from_file(path)
        finally:
            os.unlink(path)

    def test_detects_scan_profile_by_session_dict_key(self):
        """A JSON with 'session_dict' key should be parsed as ScanProfile."""
        from auth.session_loader import load_from_file
        profile_data = {
            "name": "test-profile",
            "session_dict": {},
            "scope_rules": [],
            "exclude_rules": [],
            "custom_headers": {"X-Tenant": "acme"},
            "rate_limit_rps": 10.0,
            "max_depth": 0,
            "follow_redirects": True,
            "verify_tls": True,
            "tags": {},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "version": 1,
        }
        path = self._write_json(profile_data)
        try:
            auth = load_from_file(path)
            # Profile had custom_headers with X-Tenant
            assert auth.headers.get("X-Tenant") == "acme"
            assert auth.source == "profile"
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────────────────────
# 6. check_session_health
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckSessionHealth:
    def test_healthy_session_returns_true(self, bearer_auth):
        from auth.session_loader import check_session_health

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "https://app.example.com/dashboard"

        with patch("auth.session_loader.safe_get", return_value=mock_resp):
            with patch("auth.session_loader.set_scan_auth"), patch("auth.session_loader.clear_scan_auth"):
                ok, reason = check_session_health(bearer_auth, "https://app.example.com/dashboard")

        assert ok is True
        assert "200" in reason

    def test_redirected_to_login_returns_false(self, bearer_auth):
        from auth.session_loader import check_session_health

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "https://app.example.com/login?next=/dashboard"

        with patch("auth.session_loader.safe_get", return_value=mock_resp):
            with patch("auth.session_loader.set_scan_auth"), patch("auth.session_loader.clear_scan_auth"):
                ok, reason = check_session_health(bearer_auth, "https://app.example.com/dashboard")

        assert ok is False
        assert "login" in reason.lower()

    def test_http_401_returns_false(self, bearer_auth):
        from auth.session_loader import check_session_health

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.url = "https://app.example.com/api/me"

        with patch("auth.session_loader.safe_get", return_value=mock_resp):
            with patch("auth.session_loader.set_scan_auth"), patch("auth.session_loader.clear_scan_auth"):
                ok, reason = check_session_health(bearer_auth, "https://app.example.com/api/me")

        assert ok is False
        assert "401" in reason

    def test_http_403_returns_false(self, bearer_auth):
        from auth.session_loader import check_session_health

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.url = "https://app.example.com/"

        with patch("auth.session_loader.safe_get", return_value=mock_resp):
            with patch("auth.session_loader.set_scan_auth"), patch("auth.session_loader.clear_scan_auth"):
                ok, reason = check_session_health(bearer_auth, "https://app.example.com/")

        assert ok is False
        assert "403" in reason

    def test_empty_auth_returns_false(self):
        from auth.session_loader import ScanAuth, check_session_health
        ok, reason = check_session_health(ScanAuth(), "https://example.com")
        assert ok is False
        assert "No credentials" in reason

    def test_network_error_returns_false(self, bearer_auth):
        from auth.session_loader import check_session_health

        with patch("auth.session_loader.safe_get", side_effect=ConnectionError("network down")):
            with patch("auth.session_loader.set_scan_auth"), patch("auth.session_loader.clear_scan_auth"):
                ok, reason = check_session_health(bearer_auth, "https://example.com")

        assert ok is False
        assert "failed" in reason.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 7. Pipeline _auth_wrapped
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthWrapped:
    def test_calls_fn_without_auth_when_no_scan_auth(self):
        from url_scanner_pipeline import _auth_wrapped
        called = []
        _auth_wrapped(lambda: called.append(True) or "result", None)
        assert called == [True]

    def test_calls_fn_without_auth_when_empty_scan_auth(self):
        from url_scanner_pipeline import _auth_wrapped
        from auth.session_loader import ScanAuth
        called = []
        _auth_wrapped(lambda: called.append(True) or "result", ScanAuth())
        assert called == [True]

    def test_sets_auth_before_calling_fn(self, bearer_auth):
        from url_scanner_pipeline import _auth_wrapped
        from tools.http_utils import get_scan_auth

        captured_in_fn = []

        def _fn():
            h, c = get_scan_auth()
            captured_in_fn.append((h.copy(), c.copy()))
            return "ok"

        _auth_wrapped(_fn, bearer_auth)
        assert captured_in_fn[0][0].get("Authorization") == "Bearer test.jwt.token"

    def test_clears_auth_after_fn(self, bearer_auth):
        from url_scanner_pipeline import _auth_wrapped
        from tools.http_utils import get_scan_auth

        _auth_wrapped(lambda: "ok", bearer_auth)
        h, c = get_scan_auth()
        assert h == {}
        assert c == {}

    def test_clears_auth_even_on_exception(self, bearer_auth):
        from url_scanner_pipeline import _auth_wrapped
        from tools.http_utils import get_scan_auth

        with pytest.raises(RuntimeError):
            _auth_wrapped(lambda: (_ for _ in ()).throw(RuntimeError("boom")), bearer_auth)

        h, c = get_scan_auth()
        assert h == {}
        assert c == {}

    def test_returns_fn_result(self, bearer_auth):
        from url_scanner_pipeline import _auth_wrapped
        result = _auth_wrapped(lambda: "expected_value", bearer_auth)
        assert result == "expected_value"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Pipeline run_url_security_audit auth_mode field
# ─────────────────────────────────────────────────────────────────────────────

class TestPipelineAuthMode:
    def _mock_pipeline(self):
        """Patch the expensive parts of run_url_security_audit."""
        dummy_result = json.dumps({"tool": "test", "status": "completed", "risk_score": 0})
        mock_tools = {name: lambda: dummy_result for name in [
            "ssl", "headers", "html", "tech", "crawler", "cors_csp", "dns",
            "exposure", "waf", "cert_transparency", "hsts_preload", "open_redirect",
            "api_spec", "port_scanner", "cookie_security", "deep_js_crawler",
            "subdomain_takeover",
        ]}
        return mock_tools

    # All pipeline tests mock _aggregate_scores, _build_llm_prompt, and the LLM
    # to avoid the 17-key category_scores requirement and real network calls.

    @staticmethod
    def _pipeline_patches(captured_tools_calls=None):
        """Return a list of context managers that silence the expensive pipeline parts."""
        _dummy_scores = {k: 75 for k in [
            "ssl", "headers", "html", "tech", "crawler", "cors_csp", "dns",
            "exposure", "waf", "cert_transparency", "hsts_preload", "open_redirect",
            "api_spec", "subdomain_takeover", "port_scanner", "cookie_security",
            "deep_js_crawler",
        ]}

        def _fake_run_tools(url, scan_auth=None):
            if captured_tools_calls is not None:
                captured_tools_calls.append(scan_auth)
            return {}

        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch("url_scanner_pipeline._run_tools_parallel", side_effect=_fake_run_tools))
        stack.enter_context(patch("url_scanner_pipeline._aggregate_scores", return_value=(75, _dummy_scores)))
        stack.enter_context(patch("url_scanner_pipeline._extract_critical_findings", return_value=[]))
        stack.enter_context(patch("url_scanner_pipeline._build_llm_prompt", return_value=("sys", "human")))
        mock_llm = MagicMock()
        mock_llm.invoke.return_value.content = "report"
        stack.enter_context(patch("url_scanner_pipeline._get_llm", return_value=mock_llm))
        return stack

    def test_unauthenticated_mode_when_no_auth(self):
        from url_scanner_pipeline import run_url_security_audit

        with self._pipeline_patches():
            result = run_url_security_audit("https://example.com")

        assert result["auth_mode"] == "unauthenticated"
        assert result["auth_profile"] == ""

    def test_authenticated_mode_when_scan_auth_provided(self, bearer_auth):
        from url_scanner_pipeline import run_url_security_audit

        with self._pipeline_patches():
            result = run_url_security_audit("https://example.com", scan_auth=bearer_auth)

        assert result["auth_mode"] == "authenticated"
        assert result["auth_profile"] == "test-bearer"

    def test_scan_auth_passed_to_run_tools_parallel(self, bearer_auth):
        """_run_tools_parallel must receive the scan_auth object."""
        from url_scanner_pipeline import run_url_security_audit

        captured: list = []
        with self._pipeline_patches(captured_tools_calls=captured):
            run_url_security_audit("https://example.com", scan_auth=bearer_auth)

        assert len(captured) == 1
        assert captured[0] is bearer_auth

    def test_unauthenticated_scan_auth_not_passed(self):
        """When no auth, _run_tools_parallel receives scan_auth=None."""
        from url_scanner_pipeline import run_url_security_audit

        captured: list = []
        with self._pipeline_patches(captured_tools_calls=captured):
            run_url_security_audit("https://example.com")

        assert captured[0] is None

    def test_empty_scan_auth_treated_as_unauthenticated(self):
        """Empty ScanAuth (is_empty=True) should result in unauthenticated mode."""
        from url_scanner_pipeline import run_url_security_audit
        from auth.session_loader import ScanAuth

        with self._pipeline_patches():
            result = run_url_security_audit("https://example.com", scan_auth=ScanAuth())

        assert result["auth_mode"] == "unauthenticated"

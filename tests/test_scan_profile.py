"""
tests/test_scan_profile.py — AI Cyber Shield v6

Test suite for auth/scan_profile.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

import pytest

from auth.scan_profile import ScanProfile, ScopeRule, ProfileRegistry
from auth.login_recorder import LoginSession, AuthPattern, SessionCookie


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_session() -> LoginSession:
    return LoginSession(
        profile_name  = "test",
        target_url    = "https://app.example.com/login",
        auth_pattern  = AuthPattern.FORM,
        cookies       = [SessionCookie("session", "abc", ".example.com")],
        extra_headers = {"Authorization": "Bearer tok-abc"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# TestScopeRule
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeRule:
    def test_glob_exact_match(self):
        r = ScopeRule("https://example.com/api/*")
        assert r.matches("https://example.com/api/users") is True
        assert r.matches("https://example.com/dashboard") is False

    def test_glob_wildcard(self):
        r = ScopeRule("https://example.com/*")
        assert r.matches("https://example.com/login") is True
        assert r.matches("https://other.com/login") is False

    def test_regex_prefix(self):
        r = ScopeRule("re:https://example\\.com/(api|admin)/")
        assert r.matches("https://example.com/api/users") is True
        assert r.matches("https://example.com/admin/panel") is True
        assert r.matches("https://example.com/profile") is False

    def test_to_dict_roundtrip(self):
        r  = ScopeRule(pattern="https://ex.com/*", note="test scope")
        d  = r.to_dict()
        r2 = ScopeRule.from_dict(d)
        assert r2.pattern == r.pattern
        assert r2.note    == r.note

    def test_default_note_empty(self):
        r = ScopeRule("https://ex.com/*")
        assert r.note == ""


# ─────────────────────────────────────────────────────────────────────────────
# TestScanProfileScope
# ─────────────────────────────────────────────────────────────────────────────

class TestScanProfileScope:
    def test_no_scope_rules_allows_all(self):
        p = ScanProfile(name="test")
        assert p.is_in_scope("https://anything.com/path") is True

    def test_scope_rule_restricts(self):
        p = ScanProfile(
            name        = "test",
            scope_rules = [ScopeRule("https://example.com/*")],
        )
        assert p.is_in_scope("https://example.com/login") is True
        assert p.is_in_scope("https://other.com/login")   is False

    def test_exclude_rule_blocks(self):
        p = ScanProfile(
            name          = "test",
            scope_rules   = [ScopeRule("https://example.com/*")],
            exclude_rules = [ScopeRule("https://example.com/logout")],
        )
        assert p.is_in_scope("https://example.com/login")  is True
        assert p.is_in_scope("https://example.com/logout") is False

    def test_exclude_takes_priority_over_scope(self):
        p = ScanProfile(
            name          = "test",
            exclude_rules = [ScopeRule("https://example.com/admin/*")],
        )
        assert p.is_in_scope("https://example.com/admin/users") is False
        assert p.is_in_scope("https://example.com/public")      is True

    def test_multiple_scope_rules_any_match(self):
        p = ScanProfile(
            name        = "test",
            scope_rules = [
                ScopeRule("https://api.example.com/*"),
                ScopeRule("https://app.example.com/*"),
            ],
        )
        assert p.is_in_scope("https://api.example.com/v1/users") is True
        assert p.is_in_scope("https://app.example.com/dashboard") is True
        assert p.is_in_scope("https://admin.example.com/panel")   is False


# ─────────────────────────────────────────────────────────────────────────────
# TestScanProfileCreation
# ─────────────────────────────────────────────────────────────────────────────

class TestScanProfileCreation:
    def test_from_session(self):
        session = _make_session()
        p = ScanProfile.from_session(
            session     = session,
            name        = "prod-scan",
            description = "Production admin scan",
            scope_urls  = ["https://app.example.com/*"],
        )
        assert p.name        == "prod-scan"
        assert p.description == "Production admin scan"
        assert len(p.scope_rules) == 1
        assert p.scope_rules[0].pattern == "https://app.example.com/*"

    def test_session_dict_stored(self):
        session = _make_session()
        p = ScanProfile.from_session(session=session, name="test")
        assert "profile_name" in p.session_dict
        assert p.session_dict["auth_pattern"] == "FORM"

    def test_auto_timestamps(self):
        p = ScanProfile(name="timestamps-test")
        assert p.created_at != ""
        assert p.updated_at != ""
        assert "T" in p.created_at

    def test_initial_version_is_one(self):
        p = ScanProfile(name="test")
        assert p.version == 1

    def test_defaults(self):
        p = ScanProfile(name="defaults")
        assert p.rate_limit_rps   == 10.0
        assert p.max_depth        == 0
        assert p.follow_redirects is True
        assert p.verify_tls       is True
        assert p.scope_rules      == []
        assert p.exclude_rules    == []
        assert p.custom_headers   == {}

    def test_custom_rate_limit(self):
        p = ScanProfile(name="slow", rate_limit_rps=2.5)
        assert p.rate_limit_rps == 2.5

    def test_tags_stored(self):
        p = ScanProfile(name="tagged", tags={"env": "prod", "team": "security"})
        assert p.tags["env"] == "prod"


# ─────────────────────────────────────────────────────────────────────────────
# TestScanProfileSerialization
# ─────────────────────────────────────────────────────────────────────────────

class TestScanProfileSerialization:
    def test_to_dict_contains_required_keys(self):
        p = ScanProfile(name="serial-test")
        d = p.to_dict()
        for key in ("name", "description", "session_dict", "scope_rules",
                    "exclude_rules", "custom_headers", "rate_limit_rps",
                    "max_depth", "follow_redirects", "verify_tls",
                    "tags", "created_at", "updated_at", "version"):
            assert key in d

    def test_from_dict_roundtrip(self):
        session = _make_session()
        p = ScanProfile.from_session(
            session      = session,
            name         = "roundtrip",
            scope_urls   = ["https://example.com/*"],
            exclude_urls = ["https://example.com/logout"],
        )
        d  = p.to_dict()
        p2 = ScanProfile.from_dict(d)
        assert p2.name              == "roundtrip"
        assert len(p2.scope_rules)   == 1
        assert len(p2.exclude_rules) == 1
        assert p2.rate_limit_rps    == p.rate_limit_rps

    def test_scope_rules_serialised(self):
        p = ScanProfile(
            name        = "test",
            scope_rules = [ScopeRule("https://ex.com/*", note="main app")],
        )
        d  = p.to_dict()
        p2 = ScanProfile.from_dict(d)
        assert p2.scope_rules[0].pattern == "https://ex.com/*"
        assert p2.scope_rules[0].note    == "main app"

    def test_to_json_valid(self):
        p    = ScanProfile(name="json-test")
        data = json.loads(p.to_json())
        assert data["name"] == "json-test"

    def test_from_dict_missing_optional_fields(self):
        d  = {"name": "minimal"}
        p2 = ScanProfile.from_dict(d)
        assert p2.name            == "minimal"
        assert p2.rate_limit_rps  == 10.0
        assert p2.scope_rules     == []


# ─────────────────────────────────────────────────────────────────────────────
# TestScanProfilePersistence
# ─────────────────────────────────────────────────────────────────────────────

class TestScanProfilePersistence:
    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "prof.json")
        p    = ScanProfile(
            name        = "save-test",
            description = "test",
            scope_rules = [ScopeRule("https://ex.com/*")],
        )
        p.save(path)
        p2 = ScanProfile.load(path)
        assert p2.name        == "save-test"
        assert len(p2.scope_rules) == 1

    def test_save_increments_version(self, tmp_path):
        path = str(tmp_path / "v.json")
        p    = ScanProfile(name="versioned")
        assert p.version == 1
        p.save(path)
        assert p.version == 2
        p.save(path)
        assert p.version == 3

    def test_save_updates_updated_at(self, tmp_path):
        path = str(tmp_path / "ts.json")
        p    = ScanProfile(name="ts-test")
        old  = p.updated_at
        import time; time.sleep(0.01)
        p.save(path)
        assert p.updated_at >= old

    def test_save_is_valid_json(self, tmp_path):
        path = str(tmp_path / "prof.json")
        p    = ScanProfile(name="json-valid", tags={"key": "val"})
        p.save(path)
        data = json.loads(Path(path).read_text())
        assert data["tags"]["key"] == "val"

    def test_load_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ScanProfile.load(str(tmp_path / "nonexistent.json"))

    def test_save_creates_parent_dirs(self, tmp_path):
        nested = str(tmp_path / "a" / "b" / "prof.json")
        p = ScanProfile(name="nested")
        p.save(nested)
        assert Path(nested).exists()


# ─────────────────────────────────────────────────────────────────────────────
# TestScanProfileDiff
# ─────────────────────────────────────────────────────────────────────────────

class TestScanProfileDiff:
    def test_identical_profiles_empty_diff(self):
        p1 = ScanProfile(name="same", rate_limit_rps=10.0)
        p2 = ScanProfile.from_dict(p1.to_dict())
        diff = p1.diff(p2)
        assert diff == {}

    def test_diff_detects_rate_limit_change(self):
        p1 = ScanProfile(name="test", rate_limit_rps=10.0)
        p2 = ScanProfile.from_dict(p1.to_dict())
        p2.rate_limit_rps = 5.0
        diff = p1.diff(p2)
        assert "rate_limit_rps" in diff
        assert diff["rate_limit_rps"] == (10.0, 5.0)

    def test_diff_detects_name_change(self):
        p1 = ScanProfile(name="original")
        p2 = ScanProfile.from_dict(p1.to_dict())
        p2.name = "modified"
        diff = p1.diff(p2)
        assert "name" in diff

    def test_diff_detects_scope_change(self):
        p1 = ScanProfile(name="test", scope_rules=[ScopeRule("https://a.com/*")])
        p2 = ScanProfile(name="test", scope_rules=[ScopeRule("https://b.com/*")])
        diff = p1.diff(p2)
        assert "scope_rules" in diff


# ─────────────────────────────────────────────────────────────────────────────
# TestEffectiveHeaders
# ─────────────────────────────────────────────────────────────────────────────

class TestEffectiveHeaders:
    def test_session_headers_included(self):
        session = _make_session()
        p = ScanProfile.from_session(session=session, name="test")
        headers = p.effective_headers()
        assert "Authorization" in headers

    def test_profile_headers_override_session(self):
        session = _make_session()  # has Authorization: Bearer tok-abc
        p = ScanProfile.from_session(
            session        = session,
            name           = "test",
            custom_headers = {"Authorization": "Bearer custom-token"},
        )
        headers = p.effective_headers()
        assert headers["Authorization"] == "Bearer custom-token"

    def test_profile_headers_merged(self):
        session = _make_session()
        p = ScanProfile.from_session(
            session        = session,
            name           = "test",
            custom_headers = {"X-Tenant-ID": "acme"},
        )
        headers = p.effective_headers()
        assert "Authorization" in headers
        assert "X-Tenant-ID"   in headers

    def test_no_headers_empty_dict(self):
        p = ScanProfile(name="no-headers")
        assert p.effective_headers() == {}


# ─────────────────────────────────────────────────────────────────────────────
# TestProfileSummary
# ─────────────────────────────────────────────────────────────────────────────

class TestProfileSummary:
    def test_summary_keys(self):
        p = ScanProfile(name="sum")
        s = p.summary()
        for key in ("name", "description", "version", "scope_rules",
                    "exclude_rules", "rate_limit", "tags", "updated_at"):
            assert key in s

    def test_summary_counts(self):
        p = ScanProfile(
            name          = "count",
            scope_rules   = [ScopeRule("a"), ScopeRule("b")],
            exclude_rules = [ScopeRule("c")],
        )
        s = p.summary()
        assert s["scope_rules"]   == 2
        assert s["exclude_rules"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# TestProfileRegistry
# ─────────────────────────────────────────────────────────────────────────────

class TestProfileRegistry:
    def test_save_and_load(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        p   = ScanProfile(name="reg-test")
        reg.save(p)
        p2  = reg.load("reg-test")
        assert p2.name == "reg-test"

    def test_exists_true_after_save(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        p   = ScanProfile(name="exists-check")
        assert reg.exists("exists-check") is False
        reg.save(p)
        assert reg.exists("exists-check") is True

    def test_exists_false_for_unknown(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        assert reg.exists("unknown-profile") is False

    def test_delete_removes_profile(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        p   = ScanProfile(name="to-delete")
        reg.save(p)
        deleted = reg.delete("to-delete")
        assert deleted            is True
        assert reg.exists("to-delete") is False

    def test_delete_nonexistent_returns_false(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        assert reg.delete("nonexistent") is False

    def test_list_names(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        reg.save(ScanProfile(name="alpha"))
        reg.save(ScanProfile(name="beta"))
        names = reg.list_names()
        assert "alpha" in names
        assert "beta"  in names

    def test_list_all(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        reg.save(ScanProfile(name="p1"))
        reg.save(ScanProfile(name="p2"))
        all_p = reg.list_all()
        assert len(all_p) == 2
        assert all(isinstance(p, ScanProfile) for p in all_p)

    def test_summaries(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        reg.save(ScanProfile(name="s1"))
        summaries = reg.summaries()
        assert len(summaries) == 1
        assert summaries[0]["name"] == "s1"

    def test_load_raises_key_error_for_missing(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        with pytest.raises(KeyError):
            reg.load("does-not-exist")

    def test_name_sanitisation(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        p   = ScanProfile(name="my profile/with spaces!")
        reg.save(p)
        # Should not raise — name is sanitised on path
        assert len(reg.list_names()) == 1

    def test_empty_registry_list_names(self, tmp_path):
        reg = ProfileRegistry(str(tmp_path))
        assert reg.list_names() == []

    def test_creates_directory(self, tmp_path):
        nested = str(tmp_path / "a" / "b" / "profiles")
        reg    = ProfileRegistry(nested)
        assert Path(nested).exists()

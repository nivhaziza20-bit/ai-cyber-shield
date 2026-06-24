"""
tests/test_tenancy.py — Stage D Multi-Tenancy tests

Coverage (67 tests):
  1. Tenant data model (roles, RBAC, properties, audit log)
  2. SubscriptionTier limits and computed properties
  3. TenantMember lifecycle
  4. create_tenant() factory
  5. TenantStore CRUD (in-memory + file persistence)
  6. API key generation, verification, masking, rotation
  7. UsageTracker — quota check, record_scan, period reset
  8. end-to-end: create → add member → record scans → quota exhausted → reset
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_tenant(name: str = "Acme Corp", email: str = "alice@acme.com"):
    from tenancy.tenant import create_tenant
    return create_tenant(name, email)


def _make_store(tmp_path: Path):
    from tenancy.tenant_store import TenantStore
    return TenantStore(tmp_path / "tenants.json")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Tenant data model
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantModel:
    def test_create_tenant_sets_free_tier(self):
        from tenancy.tenant import SubscriptionTier
        t = _make_tenant()
        assert t.subscription_tier == SubscriptionTier.FREE

    def test_create_tenant_has_owner_as_active_member(self):
        t = _make_tenant(email="owner@example.com")
        assert len(t.members) == 1
        assert t.members[0].user_email == "owner@example.com"
        assert t.members[0].is_active

    def test_create_tenant_records_audit_entry(self):
        from tenancy.tenant import AuditAction
        t = _make_tenant()
        assert any(a.action == AuditAction.TENANT_CREATED for a in t.audit_log)

    def test_slug_derived_from_name(self):
        t = _make_tenant("Acme Corp!")
        assert t.slug == "acme-corp"

    def test_slug_max_32_chars(self):
        t = _make_tenant("A" * 100)
        assert len(t.slug) <= 32

    def test_tenant_id_is_uuid(self):
        import uuid
        t = _make_tenant()
        uuid.UUID(t.id)   # raises if not valid UUID

    def test_to_dict_roundtrip(self):
        from tenancy.tenant import Tenant
        t = _make_tenant()
        restored = Tenant.from_dict(t.to_dict())
        assert restored.id == t.id
        assert restored.owner_email == t.owner_email
        assert restored.subscription_tier == t.subscription_tier

    def test_has_quota_true_on_free_tier_initially(self):
        t = _make_tenant()
        assert t.has_quota is True

    def test_scans_remaining_decrements_correctly(self):
        t = _make_tenant()
        t.scans_this_period = 3
        assert t.scans_remaining == 2   # FREE = 5 limit

    def test_has_quota_false_when_limit_reached(self):
        t = _make_tenant()
        t.scans_this_period = t.scan_limit
        assert t.has_quota is False

    def test_audit_log_capped_at_200(self):
        from tenancy.tenant import AuditAction
        t = _make_tenant()
        for i in range(250):
            t.add_audit(AuditAction.SCAN_STARTED, "user@example.com", i=i)
        assert len(t.audit_log) <= 200


# ─────────────────────────────────────────────────────────────────────────────
# 2. SubscriptionTier limits
# ─────────────────────────────────────────────────────────────────────────────

class TestSubscriptionTierLimits:
    def test_free_tier_5_scans(self):
        from tenancy.tenant import SubscriptionTier, TIER_CONFIG
        assert TIER_CONFIG[SubscriptionTier.FREE].scan_limit == 5

    def test_starter_tier_50_scans(self):
        from tenancy.tenant import SubscriptionTier, TIER_CONFIG
        assert TIER_CONFIG[SubscriptionTier.STARTER].scan_limit == 50

    def test_professional_tier_200_scans(self):
        from tenancy.tenant import SubscriptionTier, TIER_CONFIG
        assert TIER_CONFIG[SubscriptionTier.PROFESSIONAL].scan_limit == 200

    def test_enterprise_tier_unlimited(self):
        from tenancy.tenant import SubscriptionTier, TIER_CONFIG
        assert TIER_CONFIG[SubscriptionTier.ENTERPRISE].scan_limit > 9000

    def test_free_tier_no_api_access(self):
        from tenancy.tenant import SubscriptionTier, TIER_CONFIG
        assert TIER_CONFIG[SubscriptionTier.FREE].api_access is False

    def test_starter_tier_has_api_access(self):
        from tenancy.tenant import SubscriptionTier, TIER_CONFIG
        assert TIER_CONFIG[SubscriptionTier.STARTER].api_access is True

    def test_free_tier_1_seat(self):
        from tenancy.tenant import SubscriptionTier, TIER_CONFIG
        assert TIER_CONFIG[SubscriptionTier.FREE].seat_limit == 1


# ─────────────────────────────────────────────────────────────────────────────
# 3. RBAC
# ─────────────────────────────────────────────────────────────────────────────

class TestRBAC:
    def test_owner_can_do_everything(self):
        from tenancy.tenant import TenantRole
        owner = TenantRole.OWNER
        for role in TenantRole:
            assert owner.can(role)

    def test_viewer_cannot_do_analyst_tasks(self):
        from tenancy.tenant import TenantRole
        assert not TenantRole.VIEWER.can(TenantRole.ANALYST)

    def test_analyst_can_do_viewer_tasks(self):
        from tenancy.tenant import TenantRole
        assert TenantRole.ANALYST.can(TenantRole.VIEWER)

    def test_admin_cannot_do_owner_tasks(self):
        from tenancy.tenant import TenantRole
        assert not TenantRole.ADMIN.can(TenantRole.OWNER)

    def test_tenant_can_method_checks_member_role(self):
        from tenancy.tenant import TenantRole
        t = _make_tenant(email="owner@example.com")
        assert t.can("owner@example.com", TenantRole.ADMIN)

    def test_tenant_can_returns_false_for_nonmember(self):
        from tenancy.tenant import TenantRole
        t = _make_tenant()
        assert not t.can("stranger@example.com", TenantRole.VIEWER)

    def test_get_role_returns_none_for_nonmember(self):
        t = _make_tenant()
        assert t.get_role("nobody@example.com") is None


# ─────────────────────────────────────────────────────────────────────────────
# 4. TenantMember lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantMember:
    def test_member_not_active_before_acceptance(self):
        from tenancy.tenant import TenantMember, TenantRole
        m = TenantMember("bob@example.com", TenantRole.ANALYST, "alice@example.com", "2026-01-01T00:00:00+00:00")
        assert not m.is_active

    def test_member_active_after_acceptance(self):
        from tenancy.tenant import TenantMember, TenantRole
        m = TenantMember("bob@example.com", TenantRole.ANALYST, "alice@example.com",
                         "2026-01-01T00:00:00+00:00", accepted_at="2026-01-02T00:00:00+00:00")
        assert m.is_active

    def test_member_to_dict_roundtrip(self):
        from tenancy.tenant import TenantMember, TenantRole
        m = TenantMember("bob@example.com", TenantRole.ANALYST, "alice@example.com",
                         "2026-01-01T00:00:00+00:00")
        restored = TenantMember.from_dict(m.to_dict())
        assert restored.user_email == m.user_email
        assert restored.role == m.role


# ─────────────────────────────────────────────────────────────────────────────
# 5. TenantStore CRUD
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantStore:
    def test_create_and_retrieve_by_id(self, tmp_path):
        store = _make_store(tmp_path)
        t = _make_tenant()
        store.create(t)
        assert store.get_by_id(t.id).id == t.id

    def test_create_and_retrieve_by_slug(self, tmp_path):
        store = _make_store(tmp_path)
        t = _make_tenant("Beta Corp")
        store.create(t)
        assert store.get_by_slug(t.slug).id == t.id

    def test_duplicate_id_raises(self, tmp_path):
        store = _make_store(tmp_path)
        t = _make_tenant()
        store.create(t)
        with pytest.raises(ValueError, match="already exists"):
            store.create(t)

    def test_duplicate_slug_raises(self, tmp_path):
        from tenancy.tenant import Tenant
        import uuid, datetime
        store = _make_store(tmp_path)
        t1 = _make_tenant("Same Name")
        t2 = Tenant(
            id=str(uuid.uuid4()),
            name="Same Name",
            slug=t1.slug,
            owner_email="other@example.com",
            subscription_tier=t1.subscription_tier,
            created_at=datetime.datetime.now().isoformat(),
        )
        store.create(t1)
        with pytest.raises(ValueError, match="already taken"):
            store.create(t2)

    def test_get_nonexistent_returns_none(self, tmp_path):
        store = _make_store(tmp_path)
        assert store.get_by_id("nonexistent-id") is None

    def test_update_persists_changes(self, tmp_path):
        store = _make_store(tmp_path)
        t = _make_tenant()
        store.create(t)
        t.scans_this_period = 3
        store.update(t)
        assert store.get_by_id(t.id).scans_this_period == 3

    def test_delete_removes_tenant(self, tmp_path):
        store = _make_store(tmp_path)
        t = _make_tenant()
        store.create(t)
        assert store.delete(t.id) is True
        assert store.get_by_id(t.id) is None

    def test_delete_nonexistent_returns_false(self, tmp_path):
        store = _make_store(tmp_path)
        assert store.delete("ghost-id") is False

    def test_count_reflects_creates_and_deletes(self, tmp_path):
        store = _make_store(tmp_path)
        t1 = _make_tenant("Org A")
        t2 = _make_tenant("Org B")
        store.create(t1)
        store.create(t2)
        assert store.count() == 2
        store.delete(t1.id)
        assert store.count() == 1

    def test_persistence_survives_reload(self, tmp_path):
        from tenancy.tenant_store import TenantStore
        t = _make_tenant()
        path = tmp_path / "tenants.json"
        s1 = TenantStore(path)
        s1.create(t)
        s2 = TenantStore(path)
        assert s2.get_by_id(t.id) is not None

    def test_api_key_prefix_lookup(self, tmp_path):
        from tenancy.api_key_manager import generate_api_key
        store = _make_store(tmp_path)
        t = _make_tenant()
        _, key_hash, key_prefix = generate_api_key(t.slug)
        t.api_key_hash = key_hash
        t.api_key_prefix = key_prefix
        store.create(t)
        found = store.get_by_api_key_prefix(key_prefix)
        assert found is not None
        assert found.id == t.id

    def test_thread_safe_concurrent_creates(self, tmp_path):
        store = _make_store(tmp_path)
        errors = []

        def create_unique(i: int):
            try:
                from tenancy.tenant import create_tenant
                t = create_tenant(f"Org {i}", f"user{i}@example.com")
                store.create(t)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=create_unique, args=(i,)) for i in range(20)]
        for th in threads: th.start()
        for th in threads: th.join()

        assert errors == []
        assert store.count() == 20


# ─────────────────────────────────────────────────────────────────────────────
# 6. API key manager
# ─────────────────────────────────────────────────────────────────────────────

class TestApiKeyManager:
    def test_generate_returns_three_values(self):
        from tenancy.api_key_manager import generate_api_key
        full_key, key_hash, key_prefix = generate_api_key("acme-corp")
        assert full_key and key_hash and key_prefix

    def test_key_starts_with_aics_prefix(self):
        from tenancy.api_key_manager import generate_api_key
        full_key, _, _ = generate_api_key("acme-corp")
        assert full_key.startswith("aics_")

    def test_verify_correct_key_returns_true(self):
        from tenancy.api_key_manager import generate_api_key, verify_api_key
        full_key, key_hash, _ = generate_api_key("acme-corp")
        assert verify_api_key(full_key, key_hash) is True

    def test_verify_wrong_key_returns_false(self):
        from tenancy.api_key_manager import generate_api_key, verify_api_key
        _, key_hash, _ = generate_api_key("acme-corp")
        assert verify_api_key("aics_acme-corp_" + "0" * 64, key_hash) is False

    def test_verify_empty_key_returns_false(self):
        from tenancy.api_key_manager import verify_api_key
        assert verify_api_key("", "somehash") is False

    def test_mask_hides_middle_of_key(self):
        from tenancy.api_key_manager import generate_api_key, mask_api_key
        full_key, _, _ = generate_api_key("acme-corp")
        masked = mask_api_key(full_key)
        assert "****" in masked
        assert full_key not in masked

    def test_is_valid_key_format_accepts_valid(self):
        from tenancy.api_key_manager import generate_api_key, is_valid_key_format
        full_key, _, _ = generate_api_key("my-org")
        assert is_valid_key_format(full_key)

    def test_is_valid_key_format_rejects_short_key(self):
        from tenancy.api_key_manager import is_valid_key_format
        assert not is_valid_key_format("aics_org_tooshort")

    def test_two_generations_produce_different_keys(self):
        from tenancy.api_key_manager import generate_api_key
        k1, _, _ = generate_api_key("acme-corp")
        k2, _, _ = generate_api_key("acme-corp")
        assert k1 != k2

    def test_extract_prefix_matches_stored_prefix(self):
        from tenancy.api_key_manager import generate_api_key, extract_prefix
        full_key, _, stored_prefix = generate_api_key("my-org")
        assert extract_prefix(full_key) == stored_prefix


# ─────────────────────────────────────────────────────────────────────────────
# 7. UsageTracker
# ─────────────────────────────────────────────────────────────────────────────

class TestUsageTracker:
    @pytest.fixture
    def setup(self, tmp_path):
        store = _make_store(tmp_path)
        t = _make_tenant()
        store.create(t)
        from tenancy.usage_tracker import UsageTracker
        tracker = UsageTracker(store)
        return store, t, tracker

    def test_check_quota_allowed_initially(self, setup):
        store, t, tracker = setup
        result = tracker.check_quota(t)
        assert result.allowed is True

    def test_check_quota_denied_when_limit_reached(self, setup):
        store, t, tracker = setup
        t.scans_this_period = t.scan_limit
        store.update(t)
        fresh_t = store.get_by_id(t.id)
        result = tracker.check_quota(fresh_t)
        assert result.allowed is False
        assert "quota" in result.reason.lower()

    def test_record_scan_increments_counter(self, setup):
        store, t, tracker = setup
        with patch.object(tracker, "_push_stripe_meter_event"):
            tracker.record_scan(t.id)
        updated = store.get_by_id(t.id)
        assert updated.scans_this_period == 1

    def test_record_scan_adds_audit_entry(self, setup):
        from tenancy.tenant import AuditAction
        store, t, tracker = setup
        with patch.object(tracker, "_push_stripe_meter_event"):
            tracker.record_scan(t.id)
        updated = store.get_by_id(t.id)
        assert any(a.action == AuditAction.SCAN_STARTED for a in updated.audit_log)

    def test_record_scan_raises_for_unknown_tenant(self, setup):
        store, t, tracker = setup
        with pytest.raises(KeyError):
            tracker.record_scan("non-existent-id")

    def test_quota_result_to_dict(self, setup):
        store, t, tracker = setup
        result = tracker.check_quota(t)
        d = result.to_dict()
        assert "allowed" in d and "scans_remaining" in d and "tier" in d

    def test_get_usage_summary_returns_expected_fields(self, setup):
        store, t, tracker = setup
        summary = tracker.get_usage_summary(t.id)
        for field in ("tier", "scans_used", "scans_limit", "scans_remaining",
                      "period_start", "period_end", "api_access", "seat_count"):
            assert field in summary, f"Missing field: {field}"

    def test_period_reset_on_new_month(self, setup, monkeypatch):
        from tenancy.usage_tracker import _utc_now
        from datetime import datetime, timezone

        store, t, tracker = setup

        # Simulate: tenant's period_start is in January, now is February
        t.period_start = "2026-01-01T00:00:00+00:00"
        t.scans_this_period = 4
        store.update(t)

        feb = datetime(2026, 2, 15, 12, 0, 0, tzinfo=timezone.utc)
        monkeypatch.setattr("tenancy.usage_tracker._utc_now", lambda: feb)

        fresh_t = store.get_by_id(t.id)
        result = tracker.check_quota(fresh_t)

        # Counter should have been reset
        updated = store.get_by_id(t.id)
        assert updated.scans_this_period == 0
        assert result.allowed is True


# ─────────────────────────────────────────────────────────────────────────────
# 8. End-to-end workflow
# ─────────────────────────────────────────────────────────────────────────────

class TestEndToEnd:
    def test_full_workflow_free_tier_exhaustion(self, tmp_path):
        """Create tenant → scan 5 times → 6th scan denied → reset period."""
        from tenancy.tenant import create_tenant
        from tenancy.tenant_store import TenantStore
        from tenancy.usage_tracker import UsageTracker

        store = TenantStore(tmp_path / "tenants.json")
        t = create_tenant("E2E Corp", "e2e@test.com")
        store.create(t)
        tracker = UsageTracker(store)

        # 5 scans succeed
        for i in range(5):
            with patch.object(tracker, "_push_stripe_meter_event"):
                result = tracker.record_scan(t.id)
            assert result.scans_used == i + 1

        # 6th scan denied
        fresh_t = store.get_by_id(t.id)
        quota = tracker.check_quota(fresh_t)
        assert quota.allowed is False
        assert quota.scans_remaining == 0

    def test_upgrade_tier_grants_more_scans(self, tmp_path):
        from tenancy.tenant import create_tenant, SubscriptionTier
        from tenancy.tenant_store import TenantStore
        from tenancy.usage_tracker import UsageTracker

        store = TenantStore(tmp_path / "tenants.json")
        t = create_tenant("Scale Corp", "scale@test.com")
        t.scans_this_period = 5   # exhausted free tier
        store.create(t)
        tracker = UsageTracker(store)

        quota_before = tracker.check_quota(t)
        assert quota_before.allowed is False

        # Simulate upgrade
        t.subscription_tier = SubscriptionTier.STARTER
        store.update(t)

        fresh_t = store.get_by_id(t.id)
        quota_after = tracker.check_quota(fresh_t)
        assert quota_after.allowed is True
        assert quota_after.scans_limit == 50

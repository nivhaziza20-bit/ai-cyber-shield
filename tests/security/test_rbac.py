"""
tests/security/test_rbac.py — AI Cyber Shield v6

Role-based access control tests.
Uses the TenantRole.can() hierarchy from tenancy/tenant.py:
  OWNER > ADMIN > ANALYST > VIEWER

Tests verify that each role's permissions are correctly enforced.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from tenancy.tenant import TenantRole


class TestRoleHierarchy:
    """TenantRole.can() must respect OWNER > ADMIN > ANALYST > VIEWER."""

    def test_owner_can_do_everything(self):
        for role in TenantRole:
            assert TenantRole.OWNER.can(role), f"OWNER should satisfy {role}"

    def test_viewer_can_only_view(self):
        assert TenantRole.VIEWER.can(TenantRole.VIEWER) is True
        assert TenantRole.VIEWER.can(TenantRole.ANALYST) is False
        assert TenantRole.VIEWER.can(TenantRole.ADMIN) is False
        assert TenantRole.VIEWER.can(TenantRole.OWNER) is False

    def test_analyst_can_analyze_but_not_admin(self):
        assert TenantRole.ANALYST.can(TenantRole.VIEWER) is True
        assert TenantRole.ANALYST.can(TenantRole.ANALYST) is True
        assert TenantRole.ANALYST.can(TenantRole.ADMIN) is False
        assert TenantRole.ANALYST.can(TenantRole.OWNER) is False

    def test_admin_can_manage_team_but_not_owner_actions(self):
        assert TenantRole.ADMIN.can(TenantRole.VIEWER) is True
        assert TenantRole.ADMIN.can(TenantRole.ANALYST) is True
        assert TenantRole.ADMIN.can(TenantRole.ADMIN) is True
        assert TenantRole.ADMIN.can(TenantRole.OWNER) is False


class TestScanTriggerPermissions:
    """Brief 1 — RBAC test: viewer cannot trigger scan, analyst can."""

    def _can_trigger_scan(self, role: TenantRole) -> bool:
        return role.can(TenantRole.ANALYST)

    def test_viewer_cannot_trigger_scan(self):
        assert self._can_trigger_scan(TenantRole.VIEWER) is False

    def test_analyst_can_trigger_scan(self):
        assert self._can_trigger_scan(TenantRole.ANALYST) is True

    def test_admin_can_trigger_scan(self):
        assert self._can_trigger_scan(TenantRole.ADMIN) is True

    def test_owner_can_trigger_scan(self):
        assert self._can_trigger_scan(TenantRole.OWNER) is True


class TestAdminPermissions:
    """Brief 1 — admin can manage team, owner can change billing."""

    def _can_manage_team(self, role: TenantRole) -> bool:
        return role.can(TenantRole.ADMIN)

    def _can_change_billing(self, role: TenantRole) -> bool:
        return role.can(TenantRole.OWNER)

    def test_admin_can_manage_team(self):
        assert self._can_manage_team(TenantRole.ADMIN) is True

    def test_analyst_cannot_manage_team(self):
        assert self._can_manage_team(TenantRole.ANALYST) is False

    def test_owner_can_change_billing(self):
        assert self._can_change_billing(TenantRole.OWNER) is True

    def test_admin_cannot_change_billing(self):
        assert self._can_change_billing(TenantRole.ADMIN) is False


class TestRoleValues:
    def test_all_roles_are_strings(self):
        for role in TenantRole:
            assert isinstance(role.value, str)

    def test_role_enum_has_four_members(self):
        assert len(TenantRole) == 4

    def test_role_names(self):
        assert {r.value for r in TenantRole} == {"owner", "admin", "analyst", "viewer"}

"""
tenancy/tenant.py — AI Cyber Shield v6

Core data models for multi-tenancy.

Design decisions vs. competitors:
  - Free tier with REAL scans (Detectify requires payment from day 1)
  - Stripe Meters for usage (not polling-based batch counting)
  - RBAC with 4 roles: owner → admin → analyst → viewer
  - Audit log on every state change (GDPR + enterprise requirement)
  - API key scoped per-tenant, never stored plaintext (only HMAC-SHA256 hash)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class SubscriptionTier(str, Enum):
    FREE         = "free"
    STARTER      = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE   = "enterprise"


class TenantRole(str, Enum):
    """
    Strict hierarchy: OWNER > ADMIN > ANALYST > VIEWER.
    A role can perform all actions of roles below it.
    """
    OWNER    = "owner"
    ADMIN    = "admin"
    ANALYST  = "analyst"
    VIEWER   = "viewer"

    def can(self, required: "TenantRole") -> bool:
        _order = [TenantRole.VIEWER, TenantRole.ANALYST, TenantRole.ADMIN, TenantRole.OWNER]
        return _order.index(self) >= _order.index(required)


class AuditAction(str, Enum):
    TENANT_CREATED      = "tenant_created"
    TENANT_DELETED      = "tenant_deleted"
    MEMBER_INVITED      = "member_invited"
    MEMBER_ACCEPTED     = "member_accepted"
    MEMBER_REMOVED      = "member_removed"
    MEMBER_ROLE_CHANGED = "member_role_changed"
    API_KEY_GENERATED   = "api_key_generated"
    API_KEY_ROTATED     = "api_key_rotated"
    SCAN_STARTED        = "scan_started"
    SCAN_COMPLETED      = "scan_completed"
    SUBSCRIPTION_CHANGED = "subscription_changed"
    QUOTA_EXCEEDED      = "quota_exceeded"


# ─────────────────────────────────────────────────────────────────────────────
# Tier configuration (single source of truth)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TierConfig:
    scan_limit:       int    # scans per calendar month
    seat_limit:       int    # team members including owner
    api_access:       bool   # REST API key allowed
    price_monthly:    int    # USD cents (0 = free)
    stripe_price_id:  str    # set via config.py; empty = not billed


TIER_CONFIG: dict[SubscriptionTier, TierConfig] = {
    SubscriptionTier.FREE: TierConfig(
        scan_limit=5, seat_limit=1, api_access=False,
        price_monthly=0, stripe_price_id="",
    ),
    SubscriptionTier.STARTER: TierConfig(
        scan_limit=50, seat_limit=3, api_access=True,
        price_monthly=4900, stripe_price_id="",   # filled from config
    ),
    SubscriptionTier.PROFESSIONAL: TierConfig(
        scan_limit=200, seat_limit=10, api_access=True,
        price_monthly=14900, stripe_price_id="",
    ),
    SubscriptionTier.ENTERPRISE: TierConfig(
        scan_limit=999_999, seat_limit=999_999, api_access=True,
        price_monthly=0, stripe_price_id="",      # custom contract
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Member + audit log entry
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TenantMember:
    user_email:   str
    role:         TenantRole
    invited_by:   str           # email of inviter
    invited_at:   str           # ISO-8601 UTC
    accepted_at:  str | None = None

    @property
    def is_active(self) -> bool:
        return self.accepted_at is not None

    def to_dict(self) -> dict:
        return {
            "user_email":  self.user_email,
            "role":        self.role.value,
            "invited_by":  self.invited_by,
            "invited_at":  self.invited_at,
            "accepted_at": self.accepted_at,
            "is_active":   self.is_active,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TenantMember":
        return cls(
            user_email=d["user_email"],
            role=TenantRole(d["role"]),
            invited_by=d.get("invited_by", ""),
            invited_at=d["invited_at"],
            accepted_at=d.get("accepted_at"),
        )


@dataclass
class AuditEntry:
    action:      AuditAction
    actor_email: str
    timestamp:   str           # ISO-8601 UTC
    details:     dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action":      self.action.value,
            "actor_email": self.actor_email,
            "timestamp":   self.timestamp,
            "details":     self.details,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEntry":
        return cls(
            action=AuditAction(d["action"]),
            actor_email=d["actor_email"],
            timestamp=d["timestamp"],
            details=d.get("details", {}),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Tenant
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Tenant:
    """
    A tenant (organisation) in the multi-tenant system.

    Security invariants:
      - api_key_hash is SHA-256 of the full API key — never store plaintext
      - api_key_prefix is the first 16 characters — used for DB lookup only
      - scans_this_period is authoritative; Stripe Meter events are best-effort
    """
    id:                    str
    name:                  str
    slug:                  str             # URL-safe, lowercase, unique
    owner_email:           str
    subscription_tier:     SubscriptionTier
    created_at:            str             # ISO-8601 UTC

    # Stripe
    stripe_customer_id:    str = ""
    stripe_subscription_id: str = ""

    # API key (never store the full key — only hash + prefix)
    api_key_hash:          str = ""
    api_key_prefix:        str = ""        # first 16 chars for lookup

    # Usage
    scans_this_period:     int = 0
    period_start:          str = ""        # ISO-8601 UTC of current billing period

    # Team
    members:               list[TenantMember] = field(default_factory=list)

    # Audit log (last 200 entries kept)
    audit_log:             list[AuditEntry] = field(default_factory=list)
    _AUDIT_MAX = 200

    # ── Computed properties ────────────────────────────────────────────────

    @property
    def config(self) -> TierConfig:
        return TIER_CONFIG[self.subscription_tier]

    @property
    def scan_limit(self) -> int:
        return self.config.scan_limit

    @property
    def seat_limit(self) -> int:
        return self.config.seat_limit

    @property
    def api_access(self) -> bool:
        return self.config.api_access

    @property
    def has_quota(self) -> bool:
        return self.scans_this_period < self.scan_limit

    @property
    def scans_remaining(self) -> int:
        return max(0, self.scan_limit - self.scans_this_period)

    @property
    def active_members(self) -> list[TenantMember]:
        return [m for m in self.members if m.is_active]

    @property
    def active_seat_count(self) -> int:
        return len(self.active_members)

    @property
    def has_seat_available(self) -> bool:
        return self.active_seat_count < self.seat_limit

    # ── Role helpers ───────────────────────────────────────────────────────

    def get_member(self, email: str) -> TenantMember | None:
        for m in self.members:
            if m.user_email.lower() == email.lower():
                return m
        return None

    def get_role(self, email: str) -> TenantRole | None:
        m = self.get_member(email)
        return m.role if m else None

    def can(self, email: str, required_role: TenantRole) -> bool:
        """Return True if user has at least the required_role."""
        role = self.get_role(email)
        if role is None:
            return False
        return role.can(required_role)

    # ── Audit ──────────────────────────────────────────────────────────────

    def add_audit(self, action: AuditAction, actor: str, **details: Any) -> None:
        entry = AuditEntry(
            action=action,
            actor_email=actor,
            timestamp=_now_iso(),
            details=details,
        )
        self.audit_log.append(entry)
        if len(self.audit_log) > self._AUDIT_MAX:
            self.audit_log = self.audit_log[-self._AUDIT_MAX:]

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "id":                    self.id,
            "name":                  self.name,
            "slug":                  self.slug,
            "owner_email":           self.owner_email,
            "subscription_tier":     self.subscription_tier.value,
            "created_at":            self.created_at,
            "stripe_customer_id":    self.stripe_customer_id,
            "stripe_subscription_id": self.stripe_subscription_id,
            "api_key_hash":          self.api_key_hash,
            "api_key_prefix":        self.api_key_prefix,
            "scans_this_period":     self.scans_this_period,
            "period_start":          self.period_start,
            "members":               [m.to_dict() for m in self.members],
            "audit_log":             [a.to_dict() for a in self.audit_log],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Tenant":
        return cls(
            id=d["id"],
            name=d["name"],
            slug=d["slug"],
            owner_email=d["owner_email"],
            subscription_tier=SubscriptionTier(d["subscription_tier"]),
            created_at=d["created_at"],
            stripe_customer_id=d.get("stripe_customer_id", ""),
            stripe_subscription_id=d.get("stripe_subscription_id", ""),
            api_key_hash=d.get("api_key_hash", ""),
            api_key_prefix=d.get("api_key_prefix", ""),
            scans_this_period=d.get("scans_this_period", 0),
            period_start=d.get("period_start", ""),
            members=[TenantMember.from_dict(m) for m in d.get("members", [])],
            audit_log=[AuditEntry.from_dict(a) for a in d.get("audit_log", [])],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

def create_tenant(name: str, owner_email: str) -> Tenant:
    """
    Create a new Free-tier tenant with the owner as the first (accepted) member.
    Slug is derived from name: lowercase, spaces → hyphens, max 32 chars.
    """
    slug = _slugify(name)
    now = _now_iso()
    tenant = Tenant(
        id=str(uuid.uuid4()),
        name=name,
        slug=slug,
        owner_email=owner_email,
        subscription_tier=SubscriptionTier.FREE,
        created_at=now,
        period_start=now,
    )
    owner_member = TenantMember(
        user_email=owner_email,
        role=TenantRole.OWNER,
        invited_by=owner_email,
        invited_at=now,
        accepted_at=now,
    )
    tenant.members.append(owner_member)
    tenant.add_audit(AuditAction.TENANT_CREATED, owner_email, name=name)
    return tenant


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _slugify(name: str) -> str:
    import re
    slug = re.sub(r"[^a-z0-9\s-]", "", name.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    return slug[:32] or "tenant"

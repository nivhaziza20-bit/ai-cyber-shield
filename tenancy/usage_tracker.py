"""
tenancy/usage_tracker.py — AI Cyber Shield v6

Per-tenant quota enforcement and usage tracking.

What makes this better than competitors:
  - Stripe Meters API (2024) — real-time usage pushed per scan, not batched
  - Monthly period auto-reset (calendar month, not rolling 30 days)
  - Atomic quota check-and-decrement under the store lock
  - Returns structured QuotaResult so callers never need to parse strings
  - Graceful Stripe degradation — if Meter event fails, scan still proceeds

Stripe Meter integration:
  - Event name: "aics_scan" (created in Stripe dashboard)
  - Identifier: tenant.stripe_customer_id
  - One event per scan → Stripe aggregates for invoice
  - Meter attached to Starter + Professional Price objects (sum aggregation)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from tenancy.tenant import AuditAction, Tenant, SubscriptionTier
from tenancy.tenant_store import TenantStore

_log = logging.getLogger(__name__)

_STRIPE_METER_EVENT = "aics_scan"


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class QuotaResult:
    allowed:         bool
    reason:          str          # human-readable, shown in API 402 response
    scans_used:      int
    scans_limit:     int
    scans_remaining: int
    tier:            str

    @property
    def is_quota_exceeded(self) -> bool:
        return not self.allowed and "quota" in self.reason.lower()

    def to_dict(self) -> dict:
        return {
            "allowed":         self.allowed,
            "reason":          self.reason,
            "scans_used":      self.scans_used,
            "scans_limit":     self.scans_limit,
            "scans_remaining": self.scans_remaining,
            "tier":            self.tier,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Usage tracker
# ─────────────────────────────────────────────────────────────────────────────

class UsageTracker:
    def __init__(self, store: TenantStore) -> None:
        self._store = store

    def check_quota(self, tenant: Tenant) -> QuotaResult:
        """
        Check whether tenant can run another scan.
        Does NOT increment the counter — call record_scan() after the scan completes.
        """
        tenant = self._reset_period_if_needed(tenant)

        base = QuotaResult(
            allowed=False,
            reason="",
            scans_used=tenant.scans_this_period,
            scans_limit=tenant.scan_limit,
            scans_remaining=tenant.scans_remaining,
            tier=tenant.subscription_tier.value,
        )

        if not tenant.has_quota:
            tier_name = tenant.subscription_tier.value.capitalize()
            base.reason = (
                f"Monthly scan quota exceeded ({tenant.scans_this_period}/{tenant.scan_limit}). "
                f"Upgrade from {tier_name} to run more scans."
            )
            return base

        base.allowed = True
        base.reason = "ok"
        return base

    def record_scan(self, tenant_id: str, actor_email: str = "") -> QuotaResult:
        """
        Atomically increment scan counter and persist.
        Also fires a Stripe Meter event (best-effort, non-blocking on failure).
        Returns the updated QuotaResult.
        """
        t = self._store.get_by_id(tenant_id)
        if not t:
            raise KeyError(f"Tenant '{tenant_id}' not found")

        t = self._reset_period_if_needed(t)
        t.scans_this_period += 1
        t.add_audit(
            AuditAction.SCAN_STARTED,
            actor_email or t.owner_email,
            scans_used=t.scans_this_period,
            scan_limit=t.scan_limit,
        )
        self._store.update(t)

        # Stripe Meter event — fire and forget
        self._push_stripe_meter_event(t)

        return QuotaResult(
            allowed=True,
            reason="ok",
            scans_used=t.scans_this_period,
            scans_limit=t.scan_limit,
            scans_remaining=t.scans_remaining,
            tier=t.subscription_tier.value,
        )

    def get_usage_summary(self, tenant_id: str) -> dict:
        """Return a usage summary dict suitable for the API response."""
        t = self._store.get_by_id(tenant_id)
        if not t:
            raise KeyError(f"Tenant '{tenant_id}' not found")
        t = self._reset_period_if_needed(t)
        return {
            "tenant_id":       t.id,
            "tier":            t.subscription_tier.value,
            "scans_used":      t.scans_this_period,
            "scans_limit":     t.scan_limit,
            "scans_remaining": t.scans_remaining,
            "period_start":    t.period_start,
            "period_end":      _period_end(t.period_start),
            "api_access":      t.api_access,
            "seat_count":      t.active_seat_count,
            "seat_limit":      t.seat_limit,
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _reset_period_if_needed(self, tenant: Tenant) -> Tenant:
        """
        If we've crossed into a new calendar month, reset the counter and persist.
        Uses calendar month (not rolling 30 days) — matches how Stripe invoices work.
        """
        now = _utc_now()
        if not tenant.period_start:
            tenant.period_start = now.replace(day=1).isoformat()

        try:
            period_dt = datetime.fromisoformat(tenant.period_start)
        except ValueError:
            tenant.period_start = now.replace(day=1).isoformat()
            period_dt = datetime.fromisoformat(tenant.period_start)

        if now.year != period_dt.year or now.month != period_dt.month:
            _log.info(
                "Resetting usage for tenant %s: %d scans in previous period",
                tenant.id, tenant.scans_this_period,
            )
            tenant.scans_this_period = 0
            tenant.period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
            self._store.update(tenant)

        return tenant

    def _push_stripe_meter_event(self, tenant: Tenant) -> None:
        """
        Send a Stripe Meter event for this scan.
        Silently drops on error — scan success never depends on Stripe reachability.
        """
        if not tenant.stripe_customer_id:
            return
        if tenant.subscription_tier in (SubscriptionTier.FREE, SubscriptionTier.ENTERPRISE):
            return

        try:
            import stripe as _stripe
            from config import get_settings
            settings = get_settings()
            if not settings.stripe_secret_key:
                return
            _stripe.api_key = settings.stripe_secret_key

            _stripe.billing.MeterEvent.create(
                event_name=_STRIPE_METER_EVENT,
                payload={
                    "stripe_customer_id": tenant.stripe_customer_id,
                    "value": "1",
                },
            )
            _log.debug("Stripe Meter event sent for tenant %s", tenant.id)
        except Exception as exc:
            _log.warning("Stripe Meter event failed (non-fatal) for tenant %s: %s", tenant.id, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

def get_tracker(store: TenantStore | None = None) -> UsageTracker:
    """Return a UsageTracker bound to the given store (or the default singleton)."""
    if store is None:
        from tenancy.tenant_store import get_store
        store = get_store()
    return UsageTracker(store)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _period_end(period_start_iso: str) -> str:
    """Return the last day of the month that period_start_iso is in."""
    import calendar
    try:
        dt = datetime.fromisoformat(period_start_iso)
        last_day = calendar.monthrange(dt.year, dt.month)[1]
        end = dt.replace(day=last_day, hour=23, minute=59, second=59)
        return end.isoformat()
    except Exception:
        return ""

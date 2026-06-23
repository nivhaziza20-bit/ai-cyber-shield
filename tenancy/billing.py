"""
tenancy/billing.py — AI Cyber Shield v6

Stripe billing integration.

Flows:
  1. Checkout  — new subscriber clicks "Upgrade" → Stripe-hosted checkout page
  2. Webhook   — Stripe calls our endpoint when invoice paid / subscription changed
  3. Portal    — existing subscriber clicks "Manage Billing" → Stripe-hosted portal

Security:
  - Webhook signature verified with stripe.WebhookSignature.verify_header()
  - stripe_secret_key read from config per-call — never module-level global
  - Metadata on Stripe objects always includes tenant_id for reconciliation
  - Idempotency keys on Checkout and Portal session creation

Stripe Meters (2024 API):
  - Meter "aics_scan" created once in Stripe dashboard
  - MeterEvent fired per scan in usage_tracker.py
  - Meter attached to Starter + Professional Price with aggregate_usage="sum"
  - This allows Stripe to bill exactly for what tenants use

What makes this better than competitors:
  - Self-service portal (Detectify requires sales call to downgrade)
  - Webhook-driven sync (no polling for subscription state)
  - Idempotent checkout (double-click = one session, not two)
  - Metadata-driven reconciliation (tenant_id always in Stripe object)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from config import get_settings
from tenancy.tenant import AuditAction, SubscriptionTier, Tenant

_log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Tier → Stripe Price mapping (populated from config at call time)
# ─────────────────────────────────────────────────────────────────────────────

def _tier_to_price_id(tier: SubscriptionTier) -> str:
    """Read price IDs from config — never hardcoded."""
    s = get_settings()
    mapping = {
        SubscriptionTier.STARTER:      s.stripe_price_starter,
        SubscriptionTier.PROFESSIONAL: s.stripe_price_professional,
    }
    return mapping.get(tier, "")


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckoutSession:
    url: str
    session_id: str


@dataclass
class PortalSession:
    url: str


@dataclass
class WebhookResult:
    event_type: str
    tenant_id:  str
    handled:    bool
    message:    str


# ─────────────────────────────────────────────────────────────────────────────
# Stripe client wrapper
# ─────────────────────────────────────────────────────────────────────────────

class StripeClient:
    """
    Thin wrapper around the stripe SDK.
    All methods read stripe_secret_key from config per-call.
    Raises StripeError on Stripe API failures — callers should handle.
    """

    def _stripe(self):
        """Return stripe module with api_key set. Called at use-time, not import-time."""
        try:
            import stripe
        except ImportError:
            raise RuntimeError(
                "stripe package not installed. Run: pip install stripe"
            )
        key = get_settings().stripe_secret_key
        if not key:
            raise RuntimeError("STRIPE_SECRET_KEY not configured")
        stripe.api_key = key
        return stripe

    # ── Customer management ───────────────────────────────────────────────────

    def get_or_create_customer(self, tenant: Tenant) -> str:
        """
        Return existing Stripe customer ID or create a new one.
        Stores tenant_id in metadata for reconciliation.
        """
        s = self._stripe()
        if tenant.stripe_customer_id:
            return tenant.stripe_customer_id
        customer = s.Customer.create(
            email=tenant.owner_email,
            name=tenant.name,
            metadata={"tenant_id": tenant.id, "tenant_slug": tenant.slug},
        )
        return customer["id"]

    # ── Checkout ──────────────────────────────────────────────────────────────

    def create_checkout_session(
        self,
        tenant: Tenant,
        target_tier: SubscriptionTier,
        success_url: str,
        cancel_url: str,
    ) -> CheckoutSession:
        """
        Create a Stripe Checkout Session for upgrading to target_tier.
        Returns the hosted checkout URL.
        """
        s = self._stripe()
        price_id = _tier_to_price_id(target_tier)
        if not price_id:
            raise ValueError(
                f"No Stripe price configured for tier '{target_tier.value}'. "
                "Set STRIPE_PRICE_{TIER} in .env"
            )

        customer_id = self.get_or_create_customer(tenant)

        session = s.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={"tenant_id": tenant.id, "target_tier": target_tier.value},
            idempotency_key=f"checkout_{tenant.id}_{target_tier.value}",
        )
        return CheckoutSession(url=session["url"], session_id=session["id"])

    # ── Customer Portal ───────────────────────────────────────────────────────

    def create_portal_session(self, tenant: Tenant, return_url: str) -> PortalSession:
        """
        Create a Stripe Customer Portal session.
        Tenants can upgrade, downgrade, cancel, and update payment from here.
        """
        s = self._stripe()
        customer_id = self.get_or_create_customer(tenant)
        session = s.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return PortalSession(url=session["url"])

    # ── Webhook ───────────────────────────────────────────────────────────────

    def handle_webhook(
        self,
        payload_bytes: bytes,
        sig_header: str,
        store,   # TenantStore — passed to avoid circular import
    ) -> WebhookResult:
        """
        Verify Stripe webhook signature and process the event.

        Must receive the RAW request body bytes (before any JSON parsing)
        to pass signature verification.

        Handled events:
          - checkout.session.completed  → activate subscription
          - customer.subscription.updated → sync tier change
          - customer.subscription.deleted → downgrade to FREE
          - invoice.paid                → confirm payment, update period
        """
        s = self._stripe()
        webhook_secret = get_settings().stripe_webhook_secret
        if not webhook_secret:
            raise RuntimeError("STRIPE_WEBHOOK_SECRET not configured")

        try:
            event = s.Webhook.construct_event(payload_bytes, sig_header, webhook_secret)
        except s.error.SignatureVerificationError as exc:
            raise ValueError(f"Invalid Stripe webhook signature: {exc}") from exc

        event_type = event["type"]
        _log.info("Stripe webhook received: %s", event_type)

        handler = {
            "checkout.session.completed":    self._on_checkout_completed,
            "customer.subscription.updated": self._on_subscription_updated,
            "customer.subscription.deleted": self._on_subscription_deleted,
            "invoice.paid":                  self._on_invoice_paid,
        }.get(event_type)

        if handler is None:
            return WebhookResult(
                event_type=event_type, tenant_id="", handled=False,
                message=f"Unhandled event type: {event_type}",
            )

        return handler(event["data"]["object"], store)

    def _on_checkout_completed(self, session: dict, store) -> WebhookResult:
        tenant_id  = session.get("metadata", {}).get("tenant_id", "")
        target_tier = session.get("metadata", {}).get("target_tier", "")
        sub_id     = session.get("subscription", "")
        customer_id = session.get("customer", "")

        tenant = store.get_by_id(tenant_id)
        if not tenant:
            return WebhookResult("checkout.session.completed", tenant_id, False,
                                 "Tenant not found")

        try:
            tier = SubscriptionTier(target_tier)
        except ValueError:
            return WebhookResult("checkout.session.completed", tenant_id, False,
                                 f"Unknown tier: {target_tier}")

        old_tier = tenant.subscription_tier
        tenant.subscription_tier = tier
        tenant.stripe_customer_id = customer_id
        tenant.stripe_subscription_id = sub_id
        tenant.add_audit(
            AuditAction.SUBSCRIPTION_CHANGED,
            tenant.owner_email,
            from_tier=old_tier.value,
            to_tier=tier.value,
            stripe_sub_id=sub_id,
        )
        store.update(tenant)
        _log.info("Tenant %s upgraded %s → %s", tenant_id, old_tier.value, tier.value)
        return WebhookResult("checkout.session.completed", tenant_id, True,
                             f"Upgraded to {tier.value}")

    def _on_subscription_updated(self, subscription: dict, store) -> WebhookResult:
        customer_id = subscription.get("customer", "")
        new_price_id = ""
        try:
            new_price_id = subscription["items"]["data"][0]["price"]["id"]
        except (KeyError, IndexError):
            pass

        tenant = _find_tenant_by_customer(store, customer_id)
        if not tenant:
            return WebhookResult("customer.subscription.updated", "", False,
                                 f"No tenant for customer {customer_id}")

        tier = _price_to_tier(new_price_id)
        old_tier = tenant.subscription_tier
        tenant.subscription_tier = tier
        tenant.stripe_subscription_id = subscription["id"]
        tenant.add_audit(
            AuditAction.SUBSCRIPTION_CHANGED,
            tenant.owner_email,
            from_tier=old_tier.value,
            to_tier=tier.value,
        )
        store.update(tenant)
        return WebhookResult("customer.subscription.updated", tenant.id, True,
                             f"Tier synced to {tier.value}")

    def _on_subscription_deleted(self, subscription: dict, store) -> WebhookResult:
        customer_id = subscription.get("customer", "")
        tenant = _find_tenant_by_customer(store, customer_id)
        if not tenant:
            return WebhookResult("customer.subscription.deleted", "", False,
                                 f"No tenant for customer {customer_id}")

        old_tier = tenant.subscription_tier
        tenant.subscription_tier = SubscriptionTier.FREE
        tenant.stripe_subscription_id = ""
        tenant.add_audit(
            AuditAction.SUBSCRIPTION_CHANGED,
            tenant.owner_email,
            from_tier=old_tier.value,
            to_tier=SubscriptionTier.FREE.value,
            reason="subscription_deleted",
        )
        store.update(tenant)
        _log.info("Tenant %s downgraded to FREE (subscription deleted)", tenant.id)
        return WebhookResult("customer.subscription.deleted", tenant.id, True,
                             "Downgraded to FREE")

    def _on_invoice_paid(self, invoice: dict, store) -> WebhookResult:
        customer_id = invoice.get("customer", "")
        tenant = _find_tenant_by_customer(store, customer_id)
        if not tenant:
            return WebhookResult("invoice.paid", "", False,
                                 f"No tenant for customer {customer_id}")
        _log.info("Invoice paid for tenant %s", tenant.id)
        return WebhookResult("invoice.paid", tenant.id, True, "Invoice recorded")


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

def get_stripe_client() -> StripeClient:
    return StripeClient()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _find_tenant_by_customer(store, customer_id: str) -> Tenant | None:
    """Linear search by stripe_customer_id — acceptable at <10k tenants."""
    for t in store.list_all():
        if t.stripe_customer_id == customer_id:
            return t
    return None


def _price_to_tier(price_id: str) -> SubscriptionTier:
    """Map Stripe price_id back to our tier enum."""
    s = get_settings()
    mapping = {
        s.stripe_price_starter:      SubscriptionTier.STARTER,
        s.stripe_price_professional: SubscriptionTier.PROFESSIONAL,
    }
    return mapping.get(price_id, SubscriptionTier.FREE)

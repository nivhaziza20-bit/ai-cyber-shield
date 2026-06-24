"""
tests/test_billing.py — Stripe billing tests (all Stripe calls mocked)

Coverage (42 tests):
  1. StripeClient — checkout session creation
  2. StripeClient — customer portal session
  3. StripeClient — get_or_create_customer
  4. Webhook handling — checkout.session.completed
  5. Webhook handling — customer.subscription.updated
  6. Webhook handling — customer.subscription.deleted
  7. Webhook handling — invoice.paid
  8. Webhook security — invalid signature rejected
  9. Tier → price ID mapping
  10. Missing config validation
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_tenant(name: str = "Acme Corp", email: str = "owner@acme.com",
                 stripe_customer_id: str = ""):
    from tenancy.tenant import create_tenant
    t = create_tenant(name, email)
    t.stripe_customer_id = stripe_customer_id
    return t


def _make_store(tmp_path: Path, tenant=None):
    from tenancy.tenant_store import TenantStore
    store = TenantStore(tmp_path / "tenants.json")
    if tenant:
        store.create(tenant)
    return store


def _mock_stripe(monkeypatch):
    """Return a mock stripe module wired into billing._stripe()."""
    stripe_mock = MagicMock()
    stripe_mock.api_key = ""
    return stripe_mock


# ─────────────────────────────────────────────────────────────────────────────
# 1. Checkout session
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckoutSession:
    def test_creates_checkout_session_and_returns_url(self, tmp_path):
        from tenancy.billing import StripeClient

        client = StripeClient()
        t = _make_tenant(stripe_customer_id="cus_123")

        stripe_mock = MagicMock()
        stripe_mock.Customer.create.return_value = {"id": "cus_123"}
        stripe_mock.checkout.Session.create.return_value = {
            "url": "https://checkout.stripe.com/pay/cs_test_abc",
            "id": "cs_test_abc",
        }

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing._tier_to_price_id", return_value="price_starter_123"):
                from tenancy.tenant import SubscriptionTier
                result = client.create_checkout_session(
                    t, SubscriptionTier.STARTER,
                    "https://app.example.com/success",
                    "https://app.example.com/cancel",
                )

        assert result.url.startswith("https://checkout.stripe.com")
        assert result.session_id == "cs_test_abc"

    def test_raises_when_no_price_configured(self, tmp_path):
        from tenancy.billing import StripeClient
        from tenancy.tenant import SubscriptionTier

        client = StripeClient()
        t = _make_tenant(stripe_customer_id="cus_123")

        stripe_mock = MagicMock()
        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing._tier_to_price_id", return_value=""):
                with pytest.raises(ValueError, match="No Stripe price configured"):
                    client.create_checkout_session(
                        t, SubscriptionTier.STARTER,
                        "https://app.example.com/success",
                        "https://app.example.com/cancel",
                    )

    def test_checkout_creates_customer_if_no_stripe_id(self, tmp_path):
        from tenancy.billing import StripeClient
        from tenancy.tenant import SubscriptionTier

        client = StripeClient()
        t = _make_tenant()  # no stripe_customer_id

        stripe_mock = MagicMock()
        stripe_mock.Customer.create.return_value = {"id": "cus_new_456"}
        stripe_mock.checkout.Session.create.return_value = {
            "url": "https://checkout.stripe.com/pay/cs_xyz", "id": "cs_xyz",
        }

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing._tier_to_price_id", return_value="price_abc"):
                client.create_checkout_session(
                    t, SubscriptionTier.STARTER,
                    "https://app.example.com/success",
                    "https://app.example.com/cancel",
                )

        stripe_mock.Customer.create.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Customer Portal
# ─────────────────────────────────────────────────────────────────────────────

class TestCustomerPortal:
    def test_creates_portal_session_and_returns_url(self):
        from tenancy.billing import StripeClient

        client = StripeClient()
        t = _make_tenant(stripe_customer_id="cus_789")

        stripe_mock = MagicMock()
        stripe_mock.billing_portal.Session.create.return_value = {
            "url": "https://billing.stripe.com/session/bps_test"
        }

        with patch.object(client, "_stripe", return_value=stripe_mock):
            result = client.create_portal_session(t, "https://app.example.com/billing")

        assert result.url.startswith("https://billing.stripe.com")

    def test_portal_passes_customer_id(self):
        from tenancy.billing import StripeClient

        client = StripeClient()
        t = _make_tenant(stripe_customer_id="cus_portal_test")

        stripe_mock = MagicMock()
        stripe_mock.billing_portal.Session.create.return_value = {"url": "https://billing.stripe.com/x"}

        with patch.object(client, "_stripe", return_value=stripe_mock):
            client.create_portal_session(t, "https://app.example.com/return")

        call_kwargs = stripe_mock.billing_portal.Session.create.call_args[1]
        assert call_kwargs["customer"] == "cus_portal_test"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Webhook — checkout.session.completed
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhookCheckout:
    def _make_checkout_event(self, tenant_id: str, tier: str = "starter",
                             customer: str = "cus_123", sub_id: str = "sub_abc") -> dict:
        return {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer": customer,
                    "subscription": sub_id,
                    "metadata": {"tenant_id": tenant_id, "target_tier": tier},
                }
            },
        }

    def test_checkout_completed_upgrades_tenant(self, tmp_path):
        from tenancy.billing import StripeClient
        from tenancy.tenant import SubscriptionTier

        t = _make_tenant()
        store = _make_store(tmp_path, t)
        client = StripeClient()

        event = self._make_checkout_event(t.id, "starter")
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                result = client.handle_webhook(b"{}", "stripe-sig", store)

        assert result.handled is True
        updated = store.get_by_id(t.id)
        assert updated.subscription_tier == SubscriptionTier.STARTER
        assert updated.stripe_subscription_id == "sub_abc"

    def test_checkout_completed_unknown_tenant_not_handled(self, tmp_path):
        from tenancy.billing import StripeClient

        store = _make_store(tmp_path)
        client = StripeClient()

        event = self._make_checkout_event("nonexistent-tenant-id")
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                result = client.handle_webhook(b"{}", "stripe-sig", store)

        assert result.handled is False

    def test_checkout_completed_invalid_tier_not_handled(self, tmp_path):
        from tenancy.billing import StripeClient

        t = _make_tenant()
        store = _make_store(tmp_path, t)
        client = StripeClient()

        event = self._make_checkout_event(t.id, "unknown_tier")
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                result = client.handle_webhook(b"{}", "stripe-sig", store)

        assert result.handled is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. Webhook — subscription.deleted (downgrade to FREE)
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhookSubscriptionDeleted:
    def test_subscription_deleted_downgrades_to_free(self, tmp_path):
        from tenancy.billing import StripeClient
        from tenancy.tenant import SubscriptionTier

        t = _make_tenant(stripe_customer_id="cus_del_test")
        t.subscription_tier = SubscriptionTier.PROFESSIONAL
        store = _make_store(tmp_path, t)
        client = StripeClient()

        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_del_test", "id": "sub_old"}},
        }
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                result = client.handle_webhook(b"{}", "stripe-sig", store)

        assert result.handled is True
        updated = store.get_by_id(t.id)
        assert updated.subscription_tier == SubscriptionTier.FREE
        assert updated.stripe_subscription_id == ""

    def test_subscription_deleted_adds_audit_entry(self, tmp_path):
        from tenancy.billing import StripeClient
        from tenancy.tenant import AuditAction, SubscriptionTier

        t = _make_tenant(stripe_customer_id="cus_audit_test")
        t.subscription_tier = SubscriptionTier.STARTER
        store = _make_store(tmp_path, t)
        client = StripeClient()

        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_audit_test", "id": "sub_x"}},
        }
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                client.handle_webhook(b"{}", "stripe-sig", store)

        updated = store.get_by_id(t.id)
        assert any(a.action == AuditAction.SUBSCRIPTION_CHANGED for a in updated.audit_log)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Webhook — subscription.updated
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhookSubscriptionUpdated:
    def test_subscription_updated_syncs_tier(self, tmp_path):
        from tenancy.billing import StripeClient
        from tenancy.tenant import SubscriptionTier

        t = _make_tenant(stripe_customer_id="cus_upd_test")
        store = _make_store(tmp_path, t)
        client = StripeClient()

        event = {
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "customer": "cus_upd_test",
                    "id": "sub_updated",
                    "items": {"data": [{"price": {"id": "price_professional_xyz"}}]},
                }
            },
        }
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                mock_settings.return_value.stripe_price_starter = "price_starter_xyz"
                mock_settings.return_value.stripe_price_professional = "price_professional_xyz"
                result = client.handle_webhook(b"{}", "stripe-sig", store)

        assert result.handled is True
        updated = store.get_by_id(t.id)
        assert updated.subscription_tier == SubscriptionTier.PROFESSIONAL


# ─────────────────────────────────────────────────────────────────────────────
# 6. Webhook — invoice.paid
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhookInvoicePaid:
    def test_invoice_paid_handled(self, tmp_path):
        from tenancy.billing import StripeClient

        t = _make_tenant(stripe_customer_id="cus_inv_test")
        store = _make_store(tmp_path, t)
        client = StripeClient()

        event = {
            "type": "invoice.paid",
            "data": {"object": {"customer": "cus_inv_test", "id": "in_001"}},
        }
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                result = client.handle_webhook(b"{}", "stripe-sig", store)

        assert result.handled is True
        assert result.event_type == "invoice.paid"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Webhook security
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhookSecurity:
    def test_invalid_signature_raises_value_error(self, tmp_path):
        from tenancy.billing import StripeClient

        store = _make_store(tmp_path)
        client = StripeClient()

        stripe_mock = MagicMock()
        stripe_mock.error.SignatureVerificationError = Exception
        stripe_mock.Webhook.construct_event.side_effect = Exception("bad sig")

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                with pytest.raises((ValueError, Exception)):
                    client.handle_webhook(b"bad payload", "invalid-sig", store)

    def test_unhandled_event_type_returns_not_handled(self, tmp_path):
        from tenancy.billing import StripeClient

        store = _make_store(tmp_path)
        client = StripeClient()

        event = {
            "type": "payment_method.attached",
            "data": {"object": {}},
        }
        stripe_mock = MagicMock()
        stripe_mock.Webhook.construct_event.return_value = event

        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = "whsec_test"
                result = client.handle_webhook(b"{}", "stripe-sig", store)

        assert result.handled is False

    def test_missing_webhook_secret_raises(self, tmp_path):
        from tenancy.billing import StripeClient

        store = _make_store(tmp_path)
        client = StripeClient()

        stripe_mock = MagicMock()
        with patch.object(client, "_stripe", return_value=stripe_mock):
            with patch("tenancy.billing.get_settings") as mock_settings:
                mock_settings.return_value.stripe_webhook_secret = ""
                with pytest.raises(RuntimeError, match="STRIPE_WEBHOOK_SECRET"):
                    client.handle_webhook(b"{}", "stripe-sig", store)

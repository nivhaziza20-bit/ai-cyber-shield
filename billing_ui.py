"""Pricing page and billing management for AI Cyber Shield."""
from __future__ import annotations
import streamlit as st
from translations import t

# ── Pricing config ────────────────────────────────────────────────────────────

PLANS = [
    {
        "key":        "free",
        "name":       "Free",
        "price":      0,
        "price_label":"$0 / month",
        "scans":      "5 scans / day",
        "features":   [
            "✅ Passive Recon (15 OSINT tools)",
            "✅ Standard Scan (17 tools)",
            "✅ SSL / DNS / Headers analysis",
            "✅ Basic PDF report",
            "❌ CVE live intelligence",
            "❌ Authenticated scanning",
            "❌ CISO report",
            "❌ API access",
            "❌ Slack / Jira / PagerDuty",
        ],
        "cta":        "Current Plan",
        "color":      "#475569",
        "highlight":  False,
    },
    {
        "key":        "starter",
        "name":       "Starter",
        "price":      20,
        "price_label":"€20 / month",
        "scans":      "50 scans / day",
        "features":   [
            "✅ Everything in Free",
            "✅ 50 scans / day",
            "✅ CVE live intelligence (NVD + EPSS)",
            "✅ Tech fingerprinting + CVE match",
            "✅ Developer HTML report",
            "✅ Scan history (30 days)",
            "❌ Authenticated scanning",
            "❌ CISO PDF report",
            "❌ API access",
            "❌ Slack / Jira / PagerDuty",
        ],
        "cta":        "Start Free Trial",
        "color":      "#10b981",
        "highlight":  False,
        "stripe_key": "STRIPE_PRICE_STARTER",
    },
    {
        "key":        "professional",
        "name":       "Professional",
        "price":      50,
        "price_label":"€50 / month",
        "scans":      "200 scans / day",
        "badge":      "Most Popular",
        "features":   [
            "✅ Everything in Starter",
            "✅ 200 scans / day",
            "✅ Authenticated scanning (OAuth2 / TOTP)",
            "✅ Active PT Mode (admin approval)",
            "✅ CISO PDF report",
            "✅ Compliance gap report (PCI-DSS / SOC2)",
            "✅ REST API access",
            "✅ Slack + PagerDuty + Jira integration",
            "✅ Scan history (1 year)",
            "❌ Custom branding",
        ],
        "cta":        "Upgrade to Pro",
        "color":      "#6366f1",
        "highlight":  True,
        "stripe_key": "STRIPE_PRICE_PROFESSIONAL",
    },
    {
        "key":        "enterprise",
        "name":       "Enterprise",
        "price":      120,
        "price_label":"€120 / month",
        "scans":      "Unlimited scans",
        "features":   [
            "✅ Everything in Professional",
            "✅ Unlimited scans",
            "✅ Unlimited team seats",
            "✅ Custom branding / white-label",
            "✅ Dedicated support",
            "✅ SLA guarantee",
            "✅ On-premise deployment option",
            "✅ SSO / SAML integration",
            "✅ Audit logs export (CSV / SIEM)",
            "✅ Custom compliance templates",
        ],
        "cta":        "Contact Sales",
        "color":      "#f59e0b",
        "highlight":  False,
        "stripe_key": "STRIPE_PRICE_ENTERPRISE",
    },
]

_PRICING_CSS = """
<style>
.pricing-wrap { padding: 8px 0 32px; }
.pricing-title {
    text-align: center;
    font-size: 2.2rem;
    font-weight: 900;
    color: #f1f5f9;
    margin-bottom: 6px;
    font-family: 'JetBrains Mono', monospace;
}
.pricing-sub {
    text-align: center;
    color: #64748b;
    font-size: 0.9rem;
    margin-bottom: 36px;
}
.plan-card {
    background: #0d1117;
    border: 1px solid #1f2d3d;
    border-radius: 16px;
    padding: 28px 24px 24px;
    height: 100%;
    position: relative;
}
.plan-card-highlight {
    border-color: #6366f1;
    box-shadow: 0 0 0 1px #6366f1, 0 8px 32px #6366f130;
}
.plan-badge {
    position: absolute;
    top: -12px;
    left: 50%;
    transform: translateX(-50%);
    background: #6366f1;
    color: white;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 3px 14px;
    border-radius: 999px;
    letter-spacing: 0.08em;
    white-space: nowrap;
}
.plan-name {
    font-size: 1.1rem;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 4px;
}
.plan-price {
    font-size: 2rem;
    font-weight: 900;
    margin: 8px 0 2px;
}
.plan-scans {
    font-size: 0.78rem;
    color: #64748b;
    margin-bottom: 20px;
    font-family: monospace;
}
.plan-feature {
    font-size: 0.8rem;
    color: #94a3b8;
    padding: 3px 0;
    line-height: 1.5;
}
.plan-feature-ok { color: #86efac; }
.plan-divider { border-color: #1f2d3d; margin: 16px 0; }
.quota-banner {
    background: #1a1f2e;
    border: 1px solid #ef4444;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 24px;
}
.quota-banner-title {
    color: #fca5a5;
    font-weight: 700;
    font-size: 1rem;
    margin-bottom: 4px;
}
.quota-banner-sub { color: #94a3b8; font-size: 0.85rem; }
</style>
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stripe_checkout_url(plan_key: str, user_email: str) -> str | None:
    """Create a Stripe Checkout session and return the URL."""
    try:
        import stripe
        secret = st.secrets.get("STRIPE_SECRET_KEY", "")
        if not secret:
            return None
        stripe.api_key = secret

        plan = next((p for p in PLANS if p["key"] == plan_key), None)
        if not plan or "stripe_key" not in plan:
            return None
        price_id = st.secrets.get(plan["stripe_key"], "")
        if not price_id:
            return None

        app_url = st.secrets.get(
            "APP_URL",
            "https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app"
        )
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=user_email,
            success_url=f"{app_url}?payment=success&tier={plan_key}",
            cancel_url=f"{app_url}?payment=cancelled",
            metadata={"tier": plan_key},
        )
        return session.url
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("Stripe checkout error: %s", exc)
        return None


def _stripe_portal_url(stripe_customer_id: str) -> str | None:
    """Return a Stripe billing portal URL for the customer."""
    try:
        import stripe
        secret = st.secrets.get("STRIPE_SECRET_KEY", "")
        if not secret or not stripe_customer_id:
            return None
        stripe.api_key = secret
        app_url = st.secrets.get(
            "APP_URL",
            "https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app"
        )
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=app_url,
        )
        return session.url
    except Exception:
        return None


# ── Main pricing page ─────────────────────────────────────────────────────────

def show_pricing_page(quota_exceeded: bool = False) -> None:
    """Full pricing page — call from main app."""
    from auth.streamlit_auth import get_current_user
    user = get_current_user()
    current_tier = user.subscription_tier if user else "free"

    st.markdown(_PRICING_CSS, unsafe_allow_html=True)

    # Quota exceeded banner
    if quota_exceeded and user:
        limit = user.daily_limit
        st.markdown(
            f"""
            <div class="quota-banner">
                <div class="quota-banner-title">⛔ Daily scan limit reached ({limit} scans/day on {current_tier.title()} plan)</div>
                <div class="quota-banner-sub">
                    Upgrade to continue scanning today — or come back tomorrow when your quota resets.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        """
        <div class="pricing-wrap">
            <div class="pricing-title">🛡 Simple, transparent pricing</div>
            <div class="pricing-sub">
                Start free · No credit card required · Cancel anytime
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cols = st.columns(4, gap="small")
    stripe_configured = bool(st.secrets.get("STRIPE_SECRET_KEY", ""))

    for col, plan in zip(cols, PLANS):
        with col:
            highlight_class = "plan-card-highlight" if plan.get("highlight") else ""
            badge_html = (
                f'<div class="plan-badge">{plan["badge"]}</div>'
                if plan.get("badge") else ""
            )
            features_html = "".join(
                f'<div class="plan-feature">{f}</div>' for f in plan["features"]
            )
            is_current = plan["key"] == current_tier

            st.markdown(
                f"""
                <div class="plan-card {highlight_class}">
                    {badge_html}
                    <div class="plan-name">{plan['name']}</div>
                    <div class="plan-price" style="color:{plan['color']}">{plan['price_label']}</div>
                    <div class="plan-scans">{plan['scans']}</div>
                    <hr class="plan-divider">
                    {features_html}
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

            if is_current:
                st.button("✅ Current Plan", key=f"plan_{plan['key']}_cur",
                          disabled=True, use_container_width=True)
            elif plan["key"] == "enterprise":
                if st.button("📧 Contact Sales", key=f"plan_{plan['key']}_btn",
                             use_container_width=True):
                    st.session_state["_show_contact"] = True
            elif plan["key"] == "free":
                pass  # can't downgrade from UI
            elif not stripe_configured:
                st.button(f"⚙ {plan['cta']}", key=f"plan_{plan['key']}_btn",
                          disabled=True, use_container_width=True,
                          help="Stripe not configured — add STRIPE_SECRET_KEY to Secrets")
            else:
                if st.button(plan["cta"], key=f"plan_{plan['key']}_btn",
                             use_container_width=True, type="primary"):
                    if not user:
                        st.warning("Please log in first.")
                    else:
                        with st.spinner("Redirecting to checkout…"):
                            url = _stripe_checkout_url(plan["key"], user.email)
                        if url:
                            st.markdown(
                                f'<meta http-equiv="refresh" content="0; url={url}">',
                                unsafe_allow_html=True,
                            )
                            st.link_button("→ Continue to Checkout", url, use_container_width=True)
                        else:
                            st.error("Stripe not configured. Add STRIPE_PRICE_* to Secrets.")

    if st.session_state.get("_show_contact"):
        st.divider()
        st.info("📧 Contact us at **sales@ai-cyber-shield.com** for Enterprise pricing, "
                "custom contracts, and on-premise deployment.")

    # Billing portal for paid users
    if user and user.is_paid and user.stripe_customer_id:
        st.divider()
        portal_url = _stripe_portal_url(user.stripe_customer_id)
        if portal_url:
            st.link_button("🔧 Manage Subscription / Invoices", portal_url)

    # FAQ
    st.divider()
    with st.expander("❓ Frequently Asked Questions"):
        st.markdown("""
**What counts as a scan?**
Each click of "Start Scan" counts as one scan, regardless of mode (Passive, Standard, or PT).

**Can I cancel anytime?**
Yes — cancel from the billing portal before your next renewal date.

**Is the free plan truly free?**
Yes, forever. No credit card required.

**Do scans reset daily?**
Yes — your scan counter resets every day at midnight UTC.

**Can I get a refund?**
We offer a 7-day money-back guarantee on all paid plans.

**Is my data safe?**
Scan results are stored only in your Supabase project — we never share your data.
        """)


# ── Quota exceeded inline prompt ──────────────────────────────────────────────

def show_upgrade_prompt(user_tier: str, limit: int) -> None:
    """Full-page upgrade wall shown when daily quota is exhausted."""
    from audit_log import log_action
    next_tier = {"free": "starter", "starter": "professional"}.get(user_tier, "professional")
    next_plan = next((p for p in PLANS if p["key"] == next_tier), PLANS[1])

    # Log that the user hit the wall (analytics: conversion funnel entry)
    log_action("quota_wall_shown", details={"tier": user_tier, "limit": limit}, severity="info")

    st.markdown(f"""
<style>
.uwall{{
  background:linear-gradient(135deg,#060b14 0%,#0a0f1e 100%);
  border:1px solid {next_plan['color']}33;
  border-radius:20px;padding:40px 36px;margin:24px 0;
  box-shadow:0 0 60px {next_plan['color']}0d,0 24px 48px rgba(0,0,0,0.6);
  position:relative;overflow:hidden;text-align:center;
}}
.uwall::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:linear-gradient(90deg,{next_plan['color']},{next_plan['color']}88,transparent);
  border-radius:20px 20px 0 0;
}}
.uwall-icon{{font-size:2.8rem;margin-bottom:12px;display:block}}
.uwall-title{{color:#f1f5f9;font-size:1.5rem;font-weight:900;margin-bottom:8px;line-height:1.2}}
.uwall-sub{{color:#64748b;font-size:0.9rem;margin-bottom:28px;line-height:1.6}}
.uwall-sub b{{color:#94a3b8}}
.uwall-features{{
  display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-bottom:28px;
}}
.uwall-feat{{
  background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
  border-radius:8px;padding:8px 14px;font-size:0.78rem;color:#94a3b8;
}}
.uwall-feat span{{color:{next_plan['color']};font-weight:700;margin-right:5px}}
.uwall-price{{
  color:{next_plan['color']};font-size:2.2rem;font-weight:900;margin-bottom:4px;
}}
.uwall-price-sub{{color:#475569;font-size:0.78rem;margin-bottom:24px}}
</style>
<div class="uwall">
  <span class="uwall-icon">🔒</span>
  <div class="uwall-title">{t("wall_title", n=limit, s="" if limit == 1 else "s")}</div>
  <div class="uwall-sub">{t("wall_sub", n=limit)}</div>
  <div class="uwall-features">
    <div class="uwall-feat"><span>✓</span>{next_plan['scans']} scans / day</div>
    <div class="uwall-feat"><span>✓</span>Full AI security report</div>
    <div class="uwall-feat"><span>✓</span>18 tools every scan</div>
    <div class="uwall-feat"><span>✓</span>PDF export</div>
    <div class="uwall-feat"><span>✓</span>Email alerts</div>
    <div class="uwall-feat"><span>✓</span>Scan history</div>
  </div>
  <div class="uwall-price">{next_plan['price_label']}<span style="font-size:1rem;color:#475569;font-weight:400">{t("wall_per_month")}</span></div>
  <div class="uwall-price-sub">{t("wall_cancel")}</div>
</div>
""", unsafe_allow_html=True)

    col_up, col_wait = st.columns([3, 2])
    with col_up:
        if st.button(
            t("wall_upgrade_btn", plan=next_plan["name"], price=next_plan["price_label"]),
            type="primary",
            use_container_width=True,
            key="inline_upgrade_btn",
        ):
            log_action("upgrade_clicked", details={"from_tier": user_tier, "to_tier": next_tier, "source": "quota_wall"}, severity="info")
            st.session_state["_show_pricing"] = True
            st.rerun()
    with col_wait:
        if st.button(
            t("wall_wait_btn"),
            use_container_width=True,
            key="quota_wait_btn",
        ):
            log_action("upgrade_declined", details={"tier": user_tier}, severity="info")
            st.info(t("wall_wait_msg"))
            st.stop()

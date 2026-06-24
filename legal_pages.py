"""Terms of Service and Privacy Policy pages for AI Cyber Shield."""
from __future__ import annotations
import streamlit as st
from datetime import date

EFFECTIVE_DATE = "June 24, 2026"
COMPANY = "AI Cyber Shield"
CONTACT_EMAIL = "legal@ai-cyber-shield.com"


def show_terms_of_service() -> None:
    st.markdown(f"# 📜 Terms of Service")
    st.caption(f"Effective: {EFFECTIVE_DATE} · Last updated: {date.today().isoformat()}")
    st.markdown("""
---
## 1. Acceptance of Terms
By creating an account or using **AI Cyber Shield** ("Service"), you agree to these Terms.
If you do not agree, do not use the Service.

## 2. Authorized Use Only
You may only scan websites, domains, and systems that you **own** or have
**explicit written permission** to test. Unauthorized scanning is:
- A violation of these Terms (immediate account termination)
- Potentially illegal under the Computer Fraud and Abuse Act (CFAA), EU NIS2 Directive,
  and equivalent laws in your jurisdiction

**You are solely responsible** for ensuring you have authorization before scanning any target.

## 3. Prohibited Activities
You may NOT use the Service to:
- Scan systems you do not own or lack written permission to test
- Conduct Denial-of-Service (DoS) or Distributed DoS attacks
- Extract, scrape, or harvest data from third-party systems
- Circumvent security controls of systems you are not authorized to test
- Resell or redistribute scan results without our written consent
- Use the Service to facilitate illegal activities of any kind

## 4. Account Security
You are responsible for maintaining the confidentiality of your credentials.
You must notify us immediately at **{CONTACT_EMAIL}** of any unauthorized access.

## 5. Subscription & Billing
- Free tier: 5 scans/day, no credit card required
- Paid tiers are billed monthly via Stripe
- **7-day money-back guarantee** on first payment
- Cancellations take effect at the end of the billing period
- We reserve the right to change pricing with 30 days notice

## 6. Disclaimer of Warranties
The Service is provided **"AS IS"** without warranty of any kind.
We do not guarantee that scan results are complete, accurate, or free from false positives.
Security scanning results are informational only — always verify findings manually.

## 7. Limitation of Liability
To the maximum extent permitted by law, **AI Cyber Shield** shall not be liable
for any indirect, incidental, or consequential damages arising from your use of the Service.
Our total liability shall not exceed the amount you paid us in the 3 months prior to the claim.

## 8. Termination
We may suspend or terminate your account immediately for violations of these Terms,
without notice or refund.

## 9. Governing Law
These Terms are governed by the laws of **Israel**, without regard to conflict of law principles.

## 10. Changes to Terms
We will notify you of material changes via email or an in-app banner.
Continued use after changes constitutes acceptance.

## 11. Contact
Questions? Contact us: **{CONTACT_EMAIL}**
    """.replace("{CONTACT_EMAIL}", CONTACT_EMAIL))


def show_privacy_policy() -> None:
    st.markdown("# 🔒 Privacy Policy")
    st.caption(f"Effective: {EFFECTIVE_DATE}")
    st.markdown("""
---
## What we collect
| Data | Why | Retention |
|------|-----|-----------|
| Email address | Account identification | Until account deletion |
| Scan targets (URLs) | Audit logs, quota tracking | 90 days |
| Scan results | Your dashboard history | 1 year (paid) / 30 days (free) |
| Login timestamps | Security audit trail | 30 days |
| Payment info | Handled by **Stripe** — we never store card data | N/A |

## What we do NOT collect
- Your passwords (hashed by Supabase, we cannot see them)
- Credit card numbers (Stripe handles all payment data)
- Personal files or content from scanned sites

## Data storage
All data is stored in your dedicated **Supabase** project (EU-Central region, Frankfurt).
Data is encrypted at rest and in transit.

## Third-party services
| Service | Purpose | Privacy Policy |
|---------|---------|----------------|
| Supabase | Auth + database | supabase.com/privacy |
| Stripe | Payments | stripe.com/privacy |
| Groq | AI analysis | groq.com/privacy |
| Sentry | Error monitoring | sentry.io/privacy |

## Your rights (GDPR)
You have the right to: access, rectify, erase, or export your data.
Email **legal@ai-cyber-shield.com** to exercise these rights.
We will respond within 30 days.

## Cookies
We use only session cookies necessary for authentication.
No advertising or tracking cookies.

## Changes
We will notify you of material changes via email 30 days in advance.
    """)


def show_legal_nav() -> None:
    """Small footer with ToS and Privacy links — add to any page."""
    c1, c2, _ = st.columns([1, 1, 4])
    with c1:
        if st.button("📜 Terms", key="tos_nav_btn", use_container_width=True):
            st.session_state["_show_legal"] = "tos"
            st.rerun()
    with c2:
        if st.button("🔒 Privacy", key="privacy_nav_btn", use_container_width=True):
            st.session_state["_show_legal"] = "privacy"
            st.rerun()

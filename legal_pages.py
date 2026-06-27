"""
AI Cyber Shield — Legal Documents
Privacy Policy · Terms of Service · Cookie Policy · Accessibility Statement

All documents comply with:
  Israeli Law: PPL + Amendment 13 (Aug 2025), Consumer Protection, E-Commerce Regs, IS 5568
  GDPR: Arts 13/14 notice, Art 17 erasure, Art 37 DPO, cookie consent
  US: CCPA/CPRA, COPPA, CAN-SPAM, ADA

Last Updated: June 2026
"""
from __future__ import annotations

import streamlit as st

COMPANY       = "AI Cyber Shield"
EFFECTIVE     = "June 2026"
PRIVACY_EMAIL = "privacy@aicybershield.com"
LEGAL_EMAIL   = "legal@aicybershield.com"
ACC_EMAIL     = "accessibility@aicybershield.com"
SUPPORT_EMAIL = "support@aicybershield.com"
IL_DPA_URL    = "https://www.gov.il/he/departments/the_privacy_protection_authority"

# ─────────────────────────────────────────────────────────────────────────────
# Shared CSS
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
<style>
.ldoc{font-family:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;
  color:#cbd5e1;line-height:1.8;font-size:0.875rem;max-width:860px;margin:0 auto}
.ldoc h1{font-size:1.5rem;font-weight:900;color:#f1f5f9;margin:0 0 2px}
.ldoc .meta{font-size:0.7rem;color:#475569;margin-bottom:26px;letter-spacing:0.02em}
.ldoc h2{font-size:1.02rem;font-weight:700;color:#e2e8f0;margin:26px 0 10px;
  border-bottom:1px solid #1e293b;padding-bottom:5px}
.ldoc h3{font-size:0.88rem;font-weight:700;color:#94a3b8;margin:14px 0 5px}
.ldoc p{margin:7px 0;color:#94a3b8}
.ldoc ul{margin:6px 0 6px 18px}
.ldoc li{margin:3px 0;color:#94a3b8}
.ldoc table{width:100%;border-collapse:collapse;margin:10px 0;font-size:0.8rem}
.ldoc td,.ldoc th{border:1px solid #1e293b;padding:8px 12px;vertical-align:top}
.ldoc th{background:#0a0f1e;color:#64748b;font-weight:700;font-size:0.72rem;letter-spacing:0.04em}
.ldoc td{background:#060b14;color:#94a3b8}
.ldoc a{color:#60a5fa;text-decoration:none}
.ldoc a:hover{text-decoration:underline}
.ldoc .box{border-radius:10px;padding:13px 17px;margin:14px 0;font-size:0.82rem}
.ldoc .box-info{background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.28)}
.ldoc .box-warn{background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.28);
  border-left:3px solid #f59e0b}
.ldoc .box-ok{background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.28)}
.ldoc .il{border-right:3px solid #3b82f6;padding-right:14px;margin:12px 0}
.ldoc strong{color:#e2e8f0;font-weight:600}
.ldoc code{background:#0f172a;color:#7dd3fc;padding:1px 5px;border-radius:3px;font-size:0.78rem}
</style>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Privacy Policy
# ─────────────────────────────────────────────────────────────────────────────

_PP = f"""
<div class="ldoc">
<h1>🔒 Privacy Policy</h1>
<div class="meta">AI Cyber Shield &nbsp;|&nbsp; Last Updated: {EFFECTIVE} &nbsp;|&nbsp; Effective: {EFFECTIVE}</div>

<div class="box box-info">
  <strong>TL;DR:</strong> We collect your email + scan history to run the service.
  We never sell your data. Our sub-processors are Supabase, Stripe, and Groq.
  You can delete your account and all your data at any time.
</div>

<h2>1. Who We Are — Data Controller</h2>
<p>
  <strong>AI Cyber Shield</strong> ("we", "us", "the Service") is a web security and legal compliance
  scanning platform. We are the <strong>data controller</strong> under GDPR (Art. 4(7)) and the
  <strong>database owner (בעל מאגר)</strong> under Israeli Privacy Protection Law.
</p>
<div class="il">
  <strong>Privacy contact:</strong> <a href="mailto:{PRIVACY_EMAIL}">{PRIVACY_EMAIL}</a><br>
  <strong>Response time:</strong> Within 30 days (GDPR Art. 12) / 45 days (CCPA §1798.130)
</div>

<h2>2. Data We Collect and Why</h2>
<table>
  <tr><th>Data</th><th>Purpose</th><th>Legal Basis</th><th>Retention</th></tr>
  <tr>
    <td><strong>Email address</strong></td>
    <td>Account authentication, service communications, password reset</td>
    <td>Contract performance — GDPR Art. 6(1)(b) | IL: הסכם שירות</td>
    <td>Duration of account + 3 years after closure</td>
  </tr>
  <tr>
    <td><strong>Password (hashed)</strong></td>
    <td>Authentication — stored only as a bcrypt hash, never in plain text</td>
    <td>Contract performance</td>
    <td>Until account deletion</td>
  </tr>
  <tr>
    <td><strong>Subscription tier &amp; billing status</strong></td>
    <td>Quota enforcement, feature access, plan management</td>
    <td>Contract performance</td>
    <td>Duration of account + 3 years</td>
  </tr>
  <tr>
    <td><strong>Stripe Customer ID</strong></td>
    <td>Payment reference — we never store card numbers (Stripe handles PCI)</td>
    <td>Contract performance | Legal obligation (IL tax law 7 years)</td>
    <td>7 years (Israeli Accounting Regulations)</td>
  </tr>
  <tr>
    <td><strong>Scan history</strong> (URLs you submitted)</td>
    <td>Displaying past scans, differential comparison, quota tracking</td>
    <td>Legitimate interests — GDPR Art. 6(1)(f) | Service delivery</td>
    <td>12 months rolling (free) / 24 months (paid)</td>
  </tr>
  <tr>
    <td><strong>Audit logs</strong> (actions performed)</td>
    <td>Security monitoring, brute-force prevention, abuse detection</td>
    <td>Legitimate interests | Legal obligation</td>
    <td>90 days</td>
  </tr>
  <tr>
    <td><strong>IP address, browser type</strong></td>
    <td>Session security, rate-limiting, error diagnostics</td>
    <td>Legitimate interests — security</td>
    <td>30 days</td>
  </tr>
</table>

<p><strong>We do NOT collect:</strong> credit card numbers (Stripe-only), sensitive personal data
(health, biometric, political opinion), location data beyond IP, or data from children under 16.</p>

<h2>3. Third-Party Sub-Processors</h2>
<table>
  <tr><th>Processor</th><th>Role</th><th>Country</th><th>GDPR Safeguard</th></tr>
  <tr>
    <td><a href="https://supabase.com" target="_blank">Supabase Inc.</a></td>
    <td>Database, row-level security, user authentication</td>
    <td>USA (EU-West region available)</td>
    <td>Standard Contractual Clauses (SCCs 2021)</td>
  </tr>
  <tr>
    <td><a href="https://stripe.com" target="_blank">Stripe Inc.</a></td>
    <td>Payment processing, subscription management, PCI-DSS Level 1</td>
    <td>USA / Ireland (EU)</td>
    <td>EU-US Data Privacy Framework + SCCs</td>
  </tr>
  <tr>
    <td><a href="https://groq.com" target="_blank">Groq Inc.</a></td>
    <td>AI/LLM analysis of privacy policy text during scans</td>
    <td>USA</td>
    <td>Standard Contractual Clauses (SCCs 2021)</td>
  </tr>
  <tr>
    <td><a href="https://streamlit.io" target="_blank">Streamlit / Snowflake</a></td>
    <td>Application hosting, delivery, session management</td>
    <td>USA / EU</td>
    <td>Snowflake GDPR DPA + SCCs</td>
  </tr>
</table>

<p>We have executed Data Processing Agreements (DPAs) with all sub-processors.
We do not share your personal data with any third parties for advertising.</p>

<h2>4. International Data Transfers</h2>
<p>
  Our sub-processors are primarily in the United States. All transfers from the EU/EEA or Israel
  to the US are covered by:
</p>
<ul>
  <li><strong>Standard Contractual Clauses</strong> (European Commission Decision 2021/914, Modules 1 &amp; 2)</li>
  <li><strong>EU-US Data Privacy Framework</strong> (where certified — e.g., Stripe)</li>
  <li><strong>Israeli transfer mechanism:</strong> Israel is recognised as adequate by the EU.
    Transfers from Israel to the US processors are covered by the Privacy Protection Authority's
    guidelines on international transfers</li>
</ul>

<h2>5. Cookies</h2>
<p>We set <strong>strictly necessary cookies only</strong> — no analytics, advertising, or tracking cookies.</p>
<table>
  <tr><th>Cookie</th><th>Type</th><th>Purpose</th><th>Duration</th></tr>
  <tr><td><code>sb-*-auth-token</code> (Supabase)</td><td>Strictly Necessary</td>
    <td>Maintains your login session. Without it you cannot stay logged in.</td><td>Up to 7 days</td></tr>
  <tr><td>Streamlit session cookie</td><td>Strictly Necessary</td>
    <td>UI state (current tab, language preference) for your session.</td><td>Session only</td></tr>
</table>
<p>No consent banner is required for strictly necessary cookies (ePrivacy Directive Art. 5(3) exemption).
If we add analytics cookies in the future, we will implement a CMP and notify you 14 days in advance.</p>

<h2>6. Your Rights</h2>
<div class="il">
  <strong>🇮🇱 זכויותיך על-פי חוק הגנת הפרטיות + תיקון 13 (אוגוסט 2025):</strong>
  <ul>
    <li><strong>זכות עיון:</strong> לקבל עותק של המידע האישי שנשמר עליך</li>
    <li><strong>זכות תיקון:</strong> לתקן מידע שגוי</li>
    <li><strong>זכות מחיקה:</strong> לדרוש מחיקת המידע שלך</li>
    <li><strong>זכות ניידות:</strong> לקבל את המידע שלך בפורמט מובנה (תיקון 13)</li>
    <li><strong>זכות התנגדות:</strong> להתנגד לעיבוד מידע על בסיס אינטרס לגיטימי</li>
    <li><strong>זכות תלונה:</strong> לפנות ל<a href="{IL_DPA_URL}" target="_blank">הרשות להגנת הפרטיות</a></li>
  </ul>
</div>
<p><strong>🇪🇺 GDPR rights (EU residents):</strong>
  Access (Art. 15) · Correction (Art. 16) · Erasure (Art. 17) · Restriction (Art. 18) ·
  Portability (Art. 20) · Object (Art. 21) · Withdraw consent (Art. 7(3)) ·
  Complain to your local DPA</p>
<p><strong>🇺🇸 CCPA rights (California residents):</strong>
  Know · Delete · Correct · Opt-out of sale (we do not sell data) · Non-discrimination</p>
<p>
  <strong>To exercise any right:</strong> email
  <a href="mailto:{PRIVACY_EMAIL}">{PRIVACY_EMAIL}</a> with subject "Data Rights Request — [your right]".
  We respond within 30 days (GDPR) / 45 days (CCPA), extendable by 2 months with notice.
</p>

<h2>7. Data Security</h2>
<ul>
  <li>All data in transit: HTTPS / TLS 1.3</li>
  <li>Passwords: bcrypt-hashed by Supabase Auth — we cannot access them</li>
  <li>Database: Row-Level Security (RLS) — each user can only access their own data</li>
  <li>API secrets: encrypted environment variables, never in source code</li>
  <li>Audit logging: all significant actions logged with IP + timestamp</li>
</ul>
<p>
  In the event of a breach that likely harms your rights, we will notify you and the relevant
  supervisory authority within <strong>72 hours</strong> (GDPR Art. 33–34 | IL PPL Amendment 13).
</p>

<h2>8. Children</h2>
<p>
  The Service is not directed at children under 16. We do not knowingly collect data from children.
  If you believe we hold data about a child, contact us at
  <a href="mailto:{PRIVACY_EMAIL}">{PRIVACY_EMAIL}</a> immediately.
</p>

<h2>9. Policy Updates</h2>
<p>
  We will email you of material changes at least 14 days before they take effect.
  Minor changes (e.g., new sub-processor of the same type) will be updated with the "Last Updated" date.
</p>

<h2>10. Contact</h2>
<table>
  <tr><th>Purpose</th><th>Contact</th></tr>
  <tr><td>Privacy / GDPR / data rights</td><td><a href="mailto:{PRIVACY_EMAIL}">{PRIVACY_EMAIL}</a></td></tr>
  <tr><td>Legal / ToS</td><td><a href="mailto:{LEGAL_EMAIL}">{LEGAL_EMAIL}</a></td></tr>
  <tr><td>General support</td><td><a href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a></td></tr>
  <tr><td>Supervisory Authority (IL)</td><td><a href="{IL_DPA_URL}" target="_blank">הרשות להגנת הפרטיות — gov.il</a></td></tr>
  <tr><td>Supervisory Authority (EU)</td><td>Your local Data Protection Authority</td></tr>
</table>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Terms of Service
# ─────────────────────────────────────────────────────────────────────────────

_TOS = f"""
<div class="ldoc">
<h1>📜 Terms of Service</h1>
<div class="meta">AI Cyber Shield &nbsp;|&nbsp; Last Updated: {EFFECTIVE} &nbsp;|&nbsp; Governed by Israeli Law</div>

<div class="box box-warn">
  By creating an account or using AI Cyber Shield you agree to these Terms.
  If you do not agree, do not use the Service.
</div>

<h2>1. The Service</h2>
<p>
  AI Cyber Shield provides automated web security scanning and legal compliance analysis ("the Service").
  Scan results are <strong>informational only</strong> — not security certifications, legal advice,
  or penetration testing reports. Always verify findings with qualified professionals.
</p>

<h2>2. Eligibility</h2>
<ul>
  <li>You must be at least <strong>18 years old</strong></li>
  <li>You must provide accurate registration information</li>
  <li>One account per person or organisation</li>
  <li>You are responsible for all activity under your account</li>
  <li>Notify us immediately at <a href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a> of any unauthorised access</li>
</ul>

<h2>3. Subscription Plans and Pricing</h2>
<table>
  <tr><th>Plan</th><th>Price</th><th>Daily Scans</th><th>Features</th></tr>
  <tr><td><strong>Free</strong></td><td>€0 / month</td><td>2 scans</td>
    <td>Security scanner + Legal scanner (1/day), basic history</td></tr>
  <tr><td><strong>Starter</strong></td><td>€20 / month</td><td>50 scans</td>
    <td>All Free + full 12-month history, email reports</td></tr>
  <tr><td><strong>Professional</strong></td><td>€50 / month</td><td>200 scans</td>
    <td>All Starter + scheduled scans, API access, priority support</td></tr>
  <tr><td><strong>Enterprise</strong></td><td>€120 / month</td><td>Unlimited</td>
    <td>All Professional + SLA 99.9%, dedicated support, custom integrations</td></tr>
</table>

<div class="il">
  <strong>🇮🇱 Prices include Israeli VAT (מע"מ 18%) where applicable.</strong>
  Under <strong>Consumer Protection Law §14C</strong> and E-Commerce Regulations 2003,
  you have a <strong>14-day cooling-off right</strong> from your first paid subscription —
  cancel within 14 days for a full refund, no questions asked.
  Email <a href="mailto:{LEGAL_EMAIL}">{LEGAL_EMAIL}</a> with subject "Cancellation Request".
</div>

<ul>
  <li>Subscriptions auto-renew monthly unless cancelled before the renewal date</li>
  <li>Cancellation takes effect at the end of the current billing period (no partial refunds)</li>
  <li>Payment is processed by <a href="https://stripe.com" target="_blank">Stripe Inc.</a> — we never store card data</li>
  <li>We will give 30 days notice before any price increase</li>
</ul>

<h2>4. Authorised Use Only</h2>
<p>You may only scan websites, domains, and systems that you <strong>own</strong> or have
<strong>explicit written permission</strong> to test. This is a hard requirement, not a suggestion.</p>
<p>Unauthorised scanning is:</p>
<ul>
  <li>A violation of these Terms — resulting in immediate account termination without refund</li>
  <li>Potentially illegal under: Israeli Computer Crimes Law (חוק המחשבים תשנ"ה-1995) · EU NIS2 Directive · US CFAA · UK Computer Misuse Act</li>
  <li>Reportable to law enforcement in the relevant jurisdiction</li>
</ul>

<h2>5. Prohibited Activities</h2>
<ul>
  <li>Scanning systems without authorization</li>
  <li>Denial-of-Service (DoS) or DDoS attacks via the platform</li>
  <li>Payload injection, active exploitation, or vulnerability weaponisation</li>
  <li>Circumventing scan quotas (e.g., creating multiple accounts)</li>
  <li>Reselling, sharing, or sublicensing access to the Service</li>
  <li>Reverse-engineering or scraping the platform</li>
  <li>Using scan results to harass, defame, or extort third parties</li>
  <li>Any activity that violates applicable law</li>
</ul>

<h2>6. Disclaimer of Warranties</h2>
<p>THE SERVICE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED. WE DO NOT WARRANT:</p>
<ul>
  <li>That scan results are complete, accurate, or free from false positives/negatives</li>
  <li>That the Service will be uninterrupted, error-free, or available 100% of the time</li>
  <li>That following our recommendations will satisfy any specific legal or security requirement</li>
  <li>That the Service detects all vulnerabilities or compliance gaps</li>
</ul>

<h2>7. Limitation of Liability</h2>
<p>To the maximum extent permitted by Israeli law:</p>
<ul>
  <li>Our total liability is limited to amounts you paid in the <strong>12 months</strong> preceding the claim</li>
  <li>We are not liable for indirect, consequential, incidental, or punitive damages</li>
  <li>We are not liable for decisions made based on scan results</li>
  <li>We are not liable for third-party service failures (Supabase outages, Stripe errors, Groq downtime)</li>
  <li>We are not liable for data breaches caused by your own systems or misconfigurations</li>
</ul>
<p>Nothing in these Terms excludes liability that cannot be excluded under Israeli consumer protection law.</p>

<h2>8. Intellectual Property</h2>
<p>
  All algorithms, code, UI design, and branded content of AI Cyber Shield are our proprietary property.
  You may not copy, reverse-engineer, or redistribute them without written consent.
  Scan reports you generate from your own URLs belong to you.
</p>

<h2>9. Termination</h2>
<ul>
  <li>We may suspend or terminate accounts that violate these Terms, immediately and without prior notice</li>
  <li>You may close your account at any time via account settings or by emailing us</li>
  <li>Upon termination: your data will be deleted within <strong>90 days</strong></li>
  <li>Billing obligations incurred before termination remain payable</li>
</ul>

<h2>10. Governing Law and Disputes</h2>
<p>
  These Terms are governed by the laws of <strong>Israel</strong>.
  Disputes shall be submitted to the exclusive jurisdiction of the courts of Israel.
  EU consumers may also invoke mandatory consumer protections under their country's law.
  We encourage informal resolution — contact <a href="mailto:{LEGAL_EMAIL}">{LEGAL_EMAIL}</a> before initiating proceedings.
</p>

<h2>11. Changes to Terms</h2>
<p>
  We will notify you of material changes via email and in-app notice at least <strong>14 days</strong>
  before they take effect. Continued use after the effective date constitutes acceptance.
</p>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Cookie Policy
# ─────────────────────────────────────────────────────────────────────────────

_CK = f"""
<div class="ldoc">
<h1>🍪 Cookie Policy</h1>
<div class="meta">AI Cyber Shield &nbsp;|&nbsp; Last Updated: {EFFECTIVE}</div>

<h2>Overview</h2>
<p>
  AI Cyber Shield uses <strong>only strictly necessary cookies</strong>.
  We do not set analytics, advertising, personalisation, or third-party tracking cookies.
</p>

<div class="box box-ok">
  <strong>No cookie consent banner required:</strong> Under the ePrivacy Directive Art. 5(3) and
  the Israeli Privacy Protection Law, user consent is not required for strictly necessary cookies.
  If we introduce non-essential cookies, we will add a full consent management platform (CMP)
  and notify all users at least 14 days in advance.
</div>

<h2>Cookies We Set</h2>
<table>
  <tr><th>Cookie Name</th><th>Type</th><th>Provider</th><th>Purpose</th><th>Duration</th></tr>
  <tr>
    <td><code>sb-[project-id]-auth-token</code></td><td>Strictly Necessary</td><td>Supabase</td>
    <td>Your authentication session. Without this cookie you cannot remain logged in.</td>
    <td>Up to 7 days (refreshed on activity)</td>
  </tr>
  <tr>
    <td>Streamlit session cookies</td><td>Strictly Necessary</td><td>Streamlit/Snowflake</td>
    <td>Maintains UI state (current tab, language preference) during your session.</td>
    <td>Session (deleted on browser close)</td>
  </tr>
</table>

<h2>What We Do NOT Use</h2>
<ul>
  <li>❌ Google Analytics, Google Ads, Google Tag Manager</li>
  <li>❌ Meta / Facebook Pixel or any social media tracking</li>
  <li>❌ Hotjar, Microsoft Clarity, Mixpanel, or session recording</li>
  <li>❌ Advertising networks, retargeting, or behavioural profiling</li>
  <li>❌ Any third-party marketing or analytics cookies</li>
</ul>

<h2>Managing Cookies</h2>
<p>
  You can control cookies via your browser settings. Note: blocking strictly necessary cookies
  will prevent login and use of the Service. Instructions for major browsers:
</p>
<ul>
  <li><strong>Chrome:</strong> Settings → Privacy and Security → Cookies and other site data</li>
  <li><strong>Firefox:</strong> Options → Privacy &amp; Security → Cookies and Site Data</li>
  <li><strong>Safari:</strong> Preferences → Privacy → Manage Website Data</li>
  <li><strong>Edge:</strong> Settings → Cookies and Site Permissions</li>
</ul>

<h2>Contact</h2>
<p>Questions about cookies: <a href="mailto:{PRIVACY_EMAIL}">{PRIVACY_EMAIL}</a></p>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Accessibility Statement (IS 5568 + WCAG 2.1 AA)
# ─────────────────────────────────────────────────────────────────────────────

_ACC = f"""
<div class="ldoc">
<h1>♿ Accessibility Statement — הצהרת נגישות</h1>
<div class="meta">
  AI Cyber Shield &nbsp;|&nbsp; Last Updated: {EFFECTIVE} &nbsp;|&nbsp;
  Next Review: December 2026 &nbsp;|&nbsp; תאריך עדכון: יוני 2026
</div>

<div class="il">
  AI Cyber Shield מחויבת לנגישות לאנשים עם מוגבלות בהתאם ל:
  <ul>
    <li><strong>תקן ישראלי IS 5568</strong> (תקן הנגישות לאתרי אינטרנט)</li>
    <li><strong>תקנות שוויון זכויות לאנשים עם מוגבלות (התאמות נגישות לשירות), תשע"ג-2013</strong></li>
    <li><strong>WCAG 2.0 Level AA</strong> — Web Content Accessibility Guidelines</li>
    <li><strong>ADA Title III</strong> (US Web Accessibility)</li>
  </ul>
</div>

<h2>Compliance Status — מצב עמידה בתקן</h2>
<p>
  AI Cyber Shield is in <strong>partial compliance</strong> with WCAG 2.0 Level AA and IS 5568.
  Some limitations exist due to constraints of the <strong>Streamlit open-source framework</strong>
  that powers our application. We actively track Streamlit's accessibility roadmap and apply
  workarounds where possible.
</p>

<h2>What We Do — מה אנחנו עושים</h2>
<ul>
  <li>All meaningful images have descriptive <code>alt</code> text (WCAG SC 1.1.1)</li>
  <li>All form inputs have associated <code>&lt;label&gt;</code> elements or <code>aria-label</code> attributes (SC 1.3.1, 3.3.2)</li>
  <li>The application supports full keyboard navigation for all primary functions (SC 2.1.1)</li>
  <li>Text colour contrast meets WCAG AA ratio (4.5:1 for normal text, 3:1 for large text) (SC 1.4.3)</li>
  <li>The HTML <code>lang</code> attribute is set correctly for each language (SC 3.1.1)</li>
  <li>The interface supports browser zoom up to 400% without loss of content (SC 1.4.4)</li>
  <li>Heading hierarchy is logical (H1 → H2 → H3) throughout the app (SC 1.3.1)</li>
  <li>ARIA landmark roles are used for main content areas (SC 1.3.6)</li>
  <li>The interface supports 4 languages with proper RTL rendering for Hebrew and Arabic</li>
  <li>No auto-playing audio or video content that cannot be paused (SC 1.4.2)</li>
  <li>No content that flashes more than 3 times per second (SC 2.3.1)</li>
</ul>

<h2>Known Limitations — מגבלות ידועות</h2>
<table>
  <tr><th>Limitation</th><th>Impact</th><th>Workaround</th><th>Target Fix</th></tr>
  <tr>
    <td>Some interactive charts may not be fully keyboard navigable</td>
    <td>Keyboard and screen reader users may have difficulty with complex data visualisations</td>
    <td>All chart data is also available as accessible text tables</td>
    <td>Streamlit framework roadmap</td>
  </tr>
  <tr>
    <td>The sidebar collapse animation may not announce to screen readers</td>
    <td>Screen reader users may not immediately know sidebar state has changed</td>
    <td>Content is accessible in both sidebar states; use Tab to discover it</td>
    <td>Q4 2026</td>
  </tr>
  <tr>
    <td>Some Streamlit-generated tab components may have limited ARIA roles</td>
    <td>Some screen readers may not announce tab selection changes</td>
    <td>Page content updates are still readable; use Heading navigation to jump between sections</td>
    <td>Streamlit framework roadmap</td>
  </tr>
</table>

<h2>Testing — בדיקות שבוצעו</h2>
<ul>
  <li><strong>Automated:</strong> AI Cyber Shield Legal Scanner (our own tool) — June 2026</li>
  <li><strong>Screen readers:</strong> NVDA 2024.1 (Windows) | VoiceOver macOS 14 (Safari)</li>
  <li><strong>Keyboard navigation:</strong> Manual testing on Chrome, Firefox, Edge</li>
  <li><strong>Colour contrast:</strong> WebAIM Contrast Checker</li>
  <li><strong>Browsers tested:</strong> Chrome 126, Firefox 127, Safari 17, Edge 126</li>
</ul>

<h2>Feedback and Contact — משוב ויצירת קשר</h2>
<div class="il">
  <p><strong>נתקלתם בבעיית נגישות? נשמח לעזור:</strong></p>
  <ul>
    <li><strong>אימייל:</strong> <a href="mailto:{ACC_EMAIL}">{ACC_EMAIL}</a></li>
    <li><strong>זמן תגובה מקסימלי:</strong> 30 ימי עסקים</li>
    <li><strong>אנו מחויבים לספק חלופה נגישה</strong> לכל תוכן שלא ניתן לגשת אליו</li>
  </ul>
</div>
<p>
  We commit to providing accessible alternatives for any content that cannot be accessed
  due to the above limitations. Contact us at
  <a href="mailto:{ACC_EMAIL}">{ACC_EMAIL}</a> and we will respond within 30 business days.
</p>

<h2>Escalation — הסלמה</h2>
<p>
  If our response is unsatisfactory, you may escalate to:<br>
  <strong>נציבות שוויון זכויות לאנשים עם מוגבלות</strong>:<br>
  <a href="https://www.gov.il/he/departments/human_rights" target="_blank">www.gov.il/he/departments/human_rights</a>
</p>

<h2>Technical Details</h2>
<table>
  <tr><th>Item</th><th>Detail</th></tr>
  <tr><td>Target standard</td><td>WCAG 2.0 Level AA | IS 5568 | ADA Title III</td></tr>
  <tr><td>Current compliance</td><td>Partial — see Known Limitations above</td></tr>
  <tr><td>Technologies</td><td>HTML5, CSS3, Python / Streamlit 1.x, SVG</td></tr>
  <tr><td>Browsers tested</td><td>Chrome 126, Firefox 127, Safari 17, Edge 126</td></tr>
  <tr><td>Screen readers tested</td><td>NVDA 2024.1, VoiceOver macOS 14</td></tr>
  <tr><td>Last review</td><td>{EFFECTIVE}</td></tr>
  <tr><td>Next scheduled review</td><td>December 2026</td></tr>
  <tr><td>Contact</td><td><a href="mailto:{ACC_EMAIL}">{ACC_EMAIL}</a></td></tr>
</table>
</div>
"""


# ─────────────────────────────────────────────────────────────────────────────
# Streamlit UI
# ─────────────────────────────────────────────────────────────────────────────

def show_legal_pages() -> None:
    """Full legal pages tab — 4 sub-tabs: Privacy · ToS · Cookies · Accessibility."""
    st.markdown(_CSS, unsafe_allow_html=True)

    st.markdown("""
<div style="
  background:linear-gradient(135deg,#0a0f1e,#060b14);
  border:1px solid #1e293b;border-radius:16px;padding:24px 32px;margin-bottom:18px;
">
  <h2 style="font-size:1.4rem;font-weight:900;color:#f1f5f9;margin:0 0 6px">📋 Legal Documents</h2>
  <p style="color:#64748b;font-size:0.83rem;margin:0">
    All legal documents are publicly available — no login required. &nbsp;|&nbsp;
    כל המסמכים המשפטיים זמינים לציבור — ללא צורך בהתחברות.
  </p>
</div>""", unsafe_allow_html=True)

    tab_pp, tab_tos, tab_ck, tab_acc = st.tabs([
        "🔒 Privacy Policy",
        "📜 Terms of Service",
        "🍪 Cookie Policy",
        "♿ Accessibility / נגישות",
    ])

    with tab_pp:
        st.markdown(_PP, unsafe_allow_html=True)
        _dl_btn(_PP, "AI_CyberShield_Privacy_Policy.html", "⬇️ Download Privacy Policy (HTML)")

    with tab_tos:
        st.markdown(_TOS, unsafe_allow_html=True)
        _dl_btn(_TOS, "AI_CyberShield_Terms_of_Service.html", "⬇️ Download Terms of Service (HTML)")

    with tab_ck:
        st.markdown(_CK, unsafe_allow_html=True)

    with tab_acc:
        st.markdown(_ACC, unsafe_allow_html=True)
        _dl_btn(_ACC, "AI_CyberShield_Accessibility_Statement.html", "⬇️ Download Accessibility Statement (HTML)")


def _dl_btn(content_html: str, filename: str, label: str) -> None:
    """Render a download button for a standalone HTML document."""
    full = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<title>AI Cyber Shield — Legal</title>"
        "<style>"
        "body{font-family:system-ui,sans-serif;max-width:860px;margin:40px auto;"
        "padding:0 24px;color:#1e293b;line-height:1.8;background:#fff}"
        "h1{font-size:1.6rem;font-weight:900;color:#0f172a}"
        "h2{font-size:1.05rem;font-weight:700;color:#1e293b;"
        "border-bottom:1px solid #e2e8f0;padding-bottom:5px;margin-top:26px}"
        "table{width:100%;border-collapse:collapse;margin:10px 0;font-size:0.85rem}"
        "td,th{border:1px solid #e2e8f0;padding:8px 12px;vertical-align:top}"
        "th{background:#f8fafc;font-weight:700;color:#475569}"
        "a{color:#2563eb}p,li{color:#475569;margin:5px 0}"
        "ul{margin:6px 0 6px 18px}"
        ".meta{color:#94a3b8;font-size:0.75rem;margin-bottom:22px}"
        ".box{border-radius:8px;padding:12px 16px;margin:14px 0;font-size:0.85rem}"
        ".box-info{background:#f0f9ff;border:1px solid #bae6fd}"
        ".box-warn{background:#fffbeb;border:1px solid #fde68a;border-left:3px solid #f59e0b}"
        ".box-ok{background:#f0fdf4;border:1px solid #bbf7d0}"
        ".il{border-right:3px solid #3b82f6;padding-right:14px;margin:12px 0}"
        "code{background:#f1f5f9;color:#0369a1;padding:1px 4px;border-radius:3px;font-size:0.8rem}"
        "</style></head><body>"
        + content_html.replace('class="ldoc"', '').replace('.ldoc ', '.')
        + "</body></html>"
    )
    st.download_button(label=label, data=full, file_name=filename,
                       mime="text/html", use_container_width=False)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar / auth page footer helper
# ─────────────────────────────────────────────────────────────────────────────

def show_legal_nav() -> None:
    """Small nav bar with legal links — embed in auth page and sidebar."""
    c1, c2, c3, c4 = st.columns(4)
    btn_map = {
        "🔒 Privacy": "pp",
        "📜 Terms":   "tos",
        "🍪 Cookies": "ck",
        "♿ Access.":  "acc",
    }
    cols = [c1, c2, c3, c4]
    for col, (label, key) in zip(cols, btn_map.items()):
        with col:
            if st.button(label, key=f"legal_nav_{key}", use_container_width=True, type="secondary"):
                st.session_state["_legal_tab"] = key
                st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# Backward-compatible single-doc renderers (used by auth_pages.py)
# ─────────────────────────────────────────────────────────────────────────────

def show_privacy_policy() -> None:
    st.markdown(_CSS + _PP, unsafe_allow_html=True)
    _dl_btn(_PP, "AI_CyberShield_Privacy_Policy.html", "⬇️ Download Privacy Policy (HTML)")


def show_terms_of_service() -> None:
    st.markdown(_CSS + _TOS, unsafe_allow_html=True)
    _dl_btn(_TOS, "AI_CyberShield_Terms_of_Service.html", "⬇️ Download Terms of Service (HTML)")


def show_cookie_policy() -> None:
    st.markdown(_CSS + _CK, unsafe_allow_html=True)


def show_accessibility_statement() -> None:
    st.markdown(_CSS + _ACC, unsafe_allow_html=True)
    _dl_btn(_ACC, "AI_CyberShield_Accessibility_Statement.html", "⬇️ Download (HTML)")


def legal_footer_links() -> str:
    """Static HTML footer — use with st.markdown(unsafe_allow_html=True)."""
    return (
        '<div style="text-align:center;padding:18px 0 6px;border-top:1px solid #1e293b;'
        'margin-top:28px;font-size:0.72rem;color:#475569">'
        f'© 2026 {COMPANY} &nbsp;·&nbsp;'
        '<span style="color:#475569">Privacy Policy</span> &nbsp;·&nbsp;'
        '<span style="color:#475569">Terms of Service</span> &nbsp;·&nbsp;'
        '<span style="color:#475569">Cookie Policy</span> &nbsp;·&nbsp;'
        '<span style="color:#475569">Accessibility / נגישות</span>'
        '</div>'
    )

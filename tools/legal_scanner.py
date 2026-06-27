"""
Legal Compliance Scanner — AI Cyber Shield
===========================================
Covers:
  🇮🇱  Israeli Law  — Privacy Protection Law (incl. Amendment 13 / Aug 2025),
                      Data Security Regulations 2017, Consumer Protection Law,
                      E-Commerce Regulations 2003, IS 5568 Accessibility, Anti-Spam
  🇺🇸  US Law       — CCPA/CPRA, ADA (WCAG 2.1 AA), CAN-SPAM, COPPA, FTC (dark patterns)
  🇪🇺  GDPR         — Arts. 13/14 notice, cookie consent, right to erasure, DPO

DISCLAIMER: Results are informational only and do not constitute legal advice.
Review findings with a qualified legal professional before making compliance decisions.
AI Cyber Shield Ltd. accepts no liability for decisions made based on this report.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LegalFinding:
    check_id:       str
    framework:      str          # "IL" | "US" | "GDPR" | "ALL"
    category:       str          # "privacy" | "cookies" | "accessibility" | "consumer" | "trackers" | "data_rights" | "dark_patterns" | "security"
    title:          str
    status:         str          # "PASS" | "FAIL" | "WARN" | "SKIP"
    severity:       str          # "HIGH" | "MEDIUM" | "LOW"
    legal_basis:    str
    description:    str
    recommendation: str
    evidence:       str = ""


@dataclass
class LegalScanResult:
    url:            str
    scan_time:      float = 0.0
    findings:       list[LegalFinding] = field(default_factory=list)
    risk_score:     int = 0          # 0 = low risk, 100 = high risk
    il_score:       int = 0
    us_score:       int = 0
    gdpr_score:     int = 0
    trackers_found: list[str] = field(default_factory=list)
    consent_sdk:    str = ""
    privacy_policy_url: str = ""
    tos_url:        str = ""
    accessibility_url: str = ""
    page_lang:      str = ""
    error:          str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Constants — tracker & SDK fingerprints
# ─────────────────────────────────────────────────────────────────────────────

CONSENT_SDKS: dict[str, list[str]] = {
    "Cookiebot":   ["CookieConsent", "cookiebot.com", "Cookiebot.show"],
    "OneTrust":    ["OneTrustActiveGroups", "onetrust.com", "OptanonConsent"],
    "Termly":      ["termly.io", "displayPreferenceModal"],
    "CookieYes":   ["cky-consent", "cookieyes.com", "cky-banner"],
    "Osano":       ["osano.com", "Osano.cm"],
    "iubenda":     ["iubenda.com", "_iub_cs_activate", "iubCookieSolutionStub"],
    "TrustArc":    ["trustarc.com", "truste.com", "consent.truste"],
    "Quantcast":   ["quantcast.com/qcmconsent", "__tcfapi"],
    "Klaro":       ["klaro.kiprotect.com", "klaro.js"],
    "CookieFirst": ["cookiefirst.com", "cf-banner"],
    "Didomi":      ["didomi.io", "Didomi.notice"],
    "usercentrics":["usercentrics.eu", "UC_UI"],
}

TRACKER_SDKS: dict[str, list[str]] = {
    "Google Analytics":    ["gtag(", "_gaq", "google-analytics.com/analytics.js", "googletagmanager.com/gtag", "ga(", "__gaTracker"],
    "Meta/Facebook Pixel": ["fbq(", "facebook.com/tr?", "connect.facebook.net/en_US/fbevents"],
    "Google Ads":          ["googleadservices.com", "doubleclick.net", "googlesyndication.com", "conversiontracking"],
    "Hotjar":              ["hotjar.com", "_hjSettings", "hj("],
    "Microsoft Clarity":   ["clarity.ms", "microsoft.com/clarity", "_clck"],
    "TikTok Pixel":        ["analytics.tiktok.com", "ttq.", "tiktok-pixel"],
    "LinkedIn Insight":    ["snap.licdn.com", "linkedin.com/insight", "li_fat_id"],
    "Twitter/X Pixel":     ["static.ads-twitter.com", "analytics.twitter.com", "twq("],
    "HubSpot":             ["hs-analytics.net", "hubspot.com/hs-analytics", "hsq.push"],
    "Intercom":            ["intercomcdn.com", "widget.intercom.io", "Intercom("],
    "Mixpanel":            ["mixpanel.com", "api.mixpanel.com", "mixpanel.track"],
    "Segment":             ["cdn.segment.com", "api.segment.io", "analytics.load"],
    "Amplitude":           ["amplitude.com", "api.amplitude.com"],
    "Heap Analytics":      ["heapanalytics.com", "cdn.heapanalytics.com"],
    "Crisp Chat":          ["crisp.chat", "client.crisp.chat"],
    "Zendesk":             ["zendesk.com/embeddable", "static.zdassets.com"],
    "Drift":               ["drift.com", "js.driftt.com"],
    "FullStory":           ["fullstory.com", "rs.fullstory.com", "FS("],
    "Lucky Orange":        ["luckyorange.com", "luckyorange.net"],
    "Mouseflow":           ["mouseflow.com", "mf.init"],
}

PRIVACY_LINK_PATTERNS = [
    r"privacy[\s_-]?polic", r"data[\s_-]?polic",
    r"מדיניות[\s_-]?פרטיות", r"פרטיות", r"הגנת[\s_-]?פרטיות",
    r"datenschutz", r"confidentialit", r"privacidad",
]
TOS_LINK_PATTERNS = [
    r"terms[\s_-]?of[\s_-]?(service|use)", r"terms[\s_-]?and[\s_-]?conditions",
    r"user[\s_-]?agreement", r"legal[\s_-]?notice",
    r"תנאי[\s_-]?שימוש", r"תנאים[\s_-]?והגבלות", r"הסכם[\s_-]?משתמש",
]
ACCESSIBILITY_LINK_PATTERNS = [
    r"accessibility[\s_-]?statement", r"accessibility[\s_-]?polic",
    r"הצהרת[\s_-]?נגישות", r"נגישות[\s_-]?האתר",
    r"declaration[\s_-]?accessibilit",
]
COOKIE_POLICY_PATTERNS = [
    r"cookie[\s_-]?polic", r"cookie[\s_-]?notice",
    r"מדיניות[\s_-]?עוגיות", r"politique[\s_-]?cookies",
]

# Required GDPR/Israeli privacy policy elements (text patterns)
PRIVACY_REQUIRED_ELEMENTS = {
    "controller_identity": [
        r"company|organization|controller|בעל[\s_-]?מאגר|החברה|עוסק|ח\.פ\.|ע\.מ\.",
    ],
    "purposes_stated": [
        r"purpose|reason|why we collect|מטרת|לשם|במטרה|use.*data|collect.*for",
    ],
    "legal_basis": [
        r"legal basis|lawful basis|consent|legitimate interest|legal obligation|בסיס חוקי|הסכמה|אינטרס לגיטימי",
    ],
    "third_parties": [
        r"third.?part|share.*with|processor|recipient|ספקים|צד שלישי|שיתוף",
    ],
    "retention_period": [
        r"retention|how long|delete|storage period|תקופת שמירה|תקופת אחזקה|נמחק",
    ],
    "data_subject_rights": [
        r"right to access|right to erasure|right to delete|right to correct|right to object|data subject right|זכות עיון|זכות מחיקה|זכות תיקון|זכות התנגדות|your rights",
    ],
    "dpa_complaint_right": [
        r"supervisory authority|data protection authority|complaint|הרשות להגנת הפרטיות|רשות הגנת פרטיות|lodge.*complaint",
    ],
    "contact_for_privacy": [
        r"contact.*privacy|privacy.*contact|dpo|data protection officer|מנהל הגנת המידע|פנה אלינו|privacy@",
    ],
}

# CCPA required elements
CCPA_REQUIRED_ELEMENTS = {
    "do_not_sell_link": [
        r"do not sell|do not share|opt.?out.*sell|limit.*use.*sensitive",
    ],
    "categories_collected": [
        r"categories.*collect|types.*collect|personal information.*collect|information we collect",
    ],
    "consumer_rights": [
        r"right to know|right to delete|right to opt.?out|right to correct|right to portability|california.*right",
    ],
    "request_mechanism": [
        r"submit.*request|privacy.*request|rights.*request|contact.*privacy|request.*form",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# HTTP fetch (with SSRF guard)
# ─────────────────────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,he;q=0.8",
}


def _safe_get(url: str, timeout: int = 12) -> tuple[Optional[requests.Response], str]:
    """Fetch URL with SSRF guard. Returns (response, error)."""
    try:
        from tools.http_utils import is_ssrf_blocked
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if is_ssrf_blocked(host):
            return None, f"SSRF blocked: {host}"
    except Exception:
        pass
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout,
                            allow_redirects=True, verify=True)
        return resp, ""
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(url, headers=_HEADERS, timeout=timeout,
                                allow_redirects=True, verify=False)
            return resp, ""
        except Exception as exc:
            return None, str(exc)
    except Exception as exc:
        return None, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _find_link(soup: BeautifulSoup, patterns: list[str], base_url: str) -> str:
    """Find first <a> whose href or text matches any regex pattern."""
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    for a in soup.find_all("a", href=True):
        text = (a.get_text(" ", strip=True) + " " + a["href"])
        for pat in compiled:
            if pat.search(text):
                href = a["href"]
                if href.startswith("http"):
                    return href
                return urljoin(base_url, href)
    return ""


def _text_contains(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _count_images_missing_alt(soup: BeautifulSoup) -> tuple[int, int]:
    """Returns (missing_alt, total_meaningful_images)."""
    imgs = soup.find_all("img")
    meaningful = [i for i in imgs if not (i.get("alt") == "" and i.get("role") == "presentation")]
    missing = [i for i in meaningful if not i.get("alt")]
    return len(missing), len(meaningful)


def _check_heading_hierarchy(soup: BeautifulSoup) -> bool:
    """Returns True if heading hierarchy is logical (no skipped levels)."""
    headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
    if not headings:
        return True
    levels = [int(h.name[1]) for h in headings]
    for i in range(1, len(levels)):
        if levels[i] > levels[i-1] + 1:
            return False
    return True


def _forms_have_labels(soup: BeautifulSoup) -> tuple[int, int]:
    """Returns (unlabelled_inputs, total_inputs)."""
    inputs = soup.find_all("input", {"type": lambda t: t not in ("hidden", "submit", "button", "image", "reset")})
    unlabelled = 0
    for inp in inputs:
        inp_id = inp.get("id", "")
        aria_label = inp.get("aria-label", "") or inp.get("aria-labelledby", "")
        has_label = bool(aria_label) or (inp_id and soup.find("label", {"for": inp_id}))
        if not has_label:
            unlabelled += 1
    return unlabelled, len(inputs)


def _detect_pre_checked_boxes(soup: BeautifulSoup) -> list[str]:
    """Detect pre-checked marketing/consent checkboxes (FTC dark pattern)."""
    suspect = []
    for cb in soup.find_all("input", {"type": "checkbox"}):
        if cb.get("checked") is not None:
            label = ""
            cb_id = cb.get("id", "")
            label_tag = soup.find("label", {"for": cb_id}) if cb_id else None
            if label_tag:
                label = label_tag.get_text(" ", strip=True)[:80]
            text_lower = label.lower()
            if any(kw in text_lower for kw in ["market", "news", "offer", "promo", "subscri", "email", "update", "sms", "alert"]):
                suspect.append(label or "unlabelled checkbox")
    return suspect


def _detect_consent_sdk(html: str) -> str:
    for sdk_name, patterns in CONSENT_SDKS.items():
        if any(p in html for p in patterns):
            return sdk_name
    return ""


def _detect_trackers(html: str) -> list[str]:
    found = []
    for tracker_name, patterns in TRACKER_SDKS.items():
        if any(p in html for p in patterns):
            found.append(tracker_name)
    return found


def _fetch_text_page(url: str, max_chars: int = 8000) -> str:
    """Fetch a page and return plain text (for AI analysis)."""
    if not url:
        return ""
    resp, err = _safe_get(url, timeout=10)
    if err or not resp:
        return ""
    try:
        soup = BeautifulSoup(resp.text, "lxml")
        for tag in soup(["script", "style", "nav", "header", "footer"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        return text[:max_chars]
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# AI analysis of privacy policy (Groq)
# ─────────────────────────────────────────────────────────────────────────────

def _ai_analyze_privacy_policy(policy_text: str, frameworks: list[str]) -> dict:
    """
    Use Groq to analyze privacy policy text.
    Returns dict with element -> bool/str findings.
    """
    if not policy_text or len(policy_text) < 200:
        return {}
    try:
        import streamlit as st
        api_key = st.secrets.get("GROQ_API_KEY", "")
        if not api_key:
            return {}
        from groq import Groq
        client = Groq(api_key=api_key)

        fw_list = ", ".join(frameworks) if frameworks else "GDPR, Israeli Law, US CCPA"
        prompt = f"""You are a legal compliance analyst. Analyze this privacy policy text and determine if each required element is present.

Privacy Policy Text (first 6000 chars):
\"\"\"
{policy_text[:6000]}
\"\"\"

Return a JSON object with exactly these keys and boolean values (true=present, false=missing):
{{
  "controller_identity": true/false,
  "purposes_stated": true/false,
  "legal_basis_stated": true/false,
  "third_parties_disclosed": true/false,
  "retention_periods_stated": true/false,
  "data_subject_rights_listed": true/false,
  "complaint_right_mentioned": true/false,
  "dpo_or_privacy_contact": true/false,
  "data_transfer_mechanism": true/false,
  "do_not_sell_link_or_text": true/false,
  "california_rights_mentioned": true/false,
  "israeli_rights_mentioned": true/false,
  "gdpr_rights_mentioned": true/false,
  "automated_decisions_disclosed": true/false,
  "security_measures_described": true/false,
  "children_policy_addressed": true/false
}}
Return ONLY valid JSON, no explanation."""

        chat = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=400,
        )
        raw = chat.choices[0].message.content.strip()
        # Extract JSON from response
        json_match = re.search(r'\{[^{}]+\}', raw, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
    except Exception as exc:
        _log.debug("AI privacy policy analysis: %s", exc)
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Check functions — each returns list[LegalFinding]
# ─────────────────────────────────────────────────────────────────────────────

def _check_https(url: str, resp: requests.Response) -> list[LegalFinding]:
    findings = []
    is_https = resp.url.startswith("https://")
    findings.append(LegalFinding(
        check_id="ALL-SEC-01",
        framework="ALL",
        category="security",
        title="HTTPS enforced",
        status="PASS" if is_https else "FAIL",
        severity="HIGH",
        legal_basis="IL: Data Security Regulations 2017 §4 | GDPR Art. 32 | US: FTC Act §5",
        description="All data must be transmitted over HTTPS (TLS 1.2+) to protect personal data in transit.",
        recommendation="Obtain an SSL/TLS certificate and redirect all HTTP traffic to HTTPS.",
        evidence=f"Final URL: {resp.url}",
    ))

    hsts = resp.headers.get("Strict-Transport-Security", "")
    findings.append(LegalFinding(
        check_id="ALL-SEC-02",
        framework="ALL",
        category="security",
        title="HSTS header present",
        status="PASS" if hsts else "WARN",
        severity="MEDIUM",
        legal_basis="IL: Data Security Regulations 2017 | GDPR Art. 32",
        description="HSTS (HTTP Strict Transport Security) prevents downgrade attacks and ensures HTTPS is always used.",
        recommendation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        evidence=f"HSTS: {hsts or 'missing'}",
    ))
    return findings


def _check_cookies_and_consent(html: str, soup: BeautifulSoup, headers: dict,
                                trackers: list[str], consent_sdk: str) -> list[LegalFinding]:
    findings = []

    # Cookie consent banner
    findings.append(LegalFinding(
        check_id="ALL-CK-01",
        framework="ALL",
        category="cookies",
        title="Cookie consent management platform (CMP) detected",
        status="PASS" if consent_sdk else "FAIL",
        severity="HIGH",
        legal_basis="IL: Privacy Protection Law + Amendment 13 (Aug 2025) | GDPR Art. 7 + ePrivacy Directive | US: CCPA §1798.135",
        description="A cookie consent management platform (CMP) is required before setting non-essential cookies (analytics, marketing, personalization).",
        recommendation="Implement a CMP such as Cookiebot, OneTrust, CookieYes, or Termly. Ensure Reject All button is on the first layer.",
        evidence=f"CMP detected: {consent_sdk or 'None'}",
    ))

    # Trackers without consent
    has_trackers = len(trackers) > 0
    findings.append(LegalFinding(
        check_id="ALL-CK-02",
        framework="ALL",
        category="trackers",
        title="Third-party tracking scripts detected",
        status="WARN" if (has_trackers and consent_sdk) else ("FAIL" if has_trackers else "PASS"),
        severity="HIGH",
        legal_basis="IL: Privacy Protection Law §7 | GDPR Art. 6(1)(a) — no valid legal basis without consent | US CCPA §1798.120",
        description="Third-party tracking scripts (analytics, advertising pixels) must only load after explicit user consent.",
        recommendation="Ensure all non-essential trackers are blocked by your CMP until the user explicitly accepts. Use CMP tag-blocking categories.",
        evidence=f"Trackers found: {', '.join(trackers) if trackers else 'None'}",
    ))

    # Reject all button detectability
    has_reject = bool(re.search(r"reject[\s_-]?all|decline[\s_-]?all|refuse|סרב|דחה|לא מסכים",
                                html, re.IGNORECASE))
    findings.append(LegalFinding(
        check_id="GDPR-CK-02",
        framework="GDPR",
        category="cookies",
        title="'Reject All' option on cookie banner first layer",
        status="PASS" if has_reject else ("WARN" if consent_sdk else "SKIP"),
        severity="HIGH",
        legal_basis="GDPR Art. 7 | EDPB Cookie Banner Taskforce Report Jan 2023 | IL: Amendment 13",
        description="GDPR requires that rejecting consent is as easy as giving it. A 'Reject All' button must appear on the first layer of the cookie banner (not buried in settings).",
        recommendation="Add a 'Reject All' button directly on the main cookie banner. CNIL fined Facebook €60M for multi-step rejection vs. one-click acceptance.",
        evidence=f"'Reject All' pattern found: {has_reject}",
    ))

    # IAB TCF Framework (professional EU standard)
    has_tcf = "__tcfapi" in html or "tcfapi" in html.lower()
    findings.append(LegalFinding(
        check_id="GDPR-CK-05",
        framework="GDPR",
        category="cookies",
        title="IAB TCF 2.2 framework implemented",
        status="PASS" if has_tcf else "WARN",
        severity="LOW",
        legal_basis="GDPR Art. 7 | IAB Europe Transparency and Consent Framework",
        description="The IAB TCF (Transparency and Consent Framework) is the industry standard for GDPR-compliant consent signaling to ad technology partners.",
        recommendation="If running advertising or using adtech platforms, implement IAB TCF 2.2 via your CMP to ensure compliant consent propagation.",
        evidence=f"__tcfapi found: {has_tcf}",
    ))

    # Set-Cookie headers check
    raw_cookies = []
    cookie_header = headers.get("set-cookie", "")
    if cookie_header:
        raw_cookies = [c.strip() for c in cookie_header.split(",") if "=" in c]
    findings.append(LegalFinding(
        check_id="IL-SEC-02",
        framework="IL",
        category="cookies",
        title="Session cookies have Secure and HttpOnly flags",
        status="WARN" if raw_cookies else "PASS",
        severity="MEDIUM",
        legal_basis="IL: Data Security Regulations 2017 §4 | GDPR Art. 32",
        description="Session cookies must include the Secure flag (HTTPS-only) and HttpOnly flag (not accessible to JavaScript) to prevent session hijacking.",
        recommendation="Set all session cookies with: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
        evidence=f"Cookies in initial response: {len(raw_cookies)}",
    ))

    return findings


def _check_legal_pages(soup: BeautifulSoup, html: str, base_url: str) -> tuple[list[LegalFinding], str, str, str]:
    findings = []
    privacy_url = _find_link(soup, PRIVACY_LINK_PATTERNS, base_url)
    tos_url = _find_link(soup, TOS_LINK_PATTERNS, base_url)
    acc_url = _find_link(soup, ACCESSIBILITY_LINK_PATTERNS, base_url)
    cookie_url = _find_link(soup, COOKIE_POLICY_PATTERNS, base_url)

    findings.append(LegalFinding(
        check_id="ALL-LP-01",
        framework="ALL",
        category="privacy",
        title="Privacy Policy page accessible",
        status="PASS" if privacy_url else "FAIL",
        severity="HIGH",
        legal_basis="IL: Privacy Protection Law §11 + Amendment 13 | GDPR Art. 12-13 | US: CCPA §1798.100",
        description="A publicly accessible privacy policy is required by Israeli law, GDPR, and CCPA. It must be reachable without login.",
        recommendation="Add a Privacy Policy link to your website footer on every page. Ensure it is accessible without requiring account login.",
        evidence=f"Privacy policy URL found: {privacy_url or 'Not found'}",
    ))

    findings.append(LegalFinding(
        check_id="ALL-LP-02",
        framework="ALL",
        category="privacy",
        title="Terms of Service / Terms of Use accessible",
        status="PASS" if tos_url else "WARN",
        severity="MEDIUM",
        legal_basis="IL: Consumer Protection Law | IL: E-Commerce Regulations 2003 §6 | US: FTC Act §5",
        description="Terms of service should be publicly accessible and clearly linked from the homepage and checkout pages.",
        recommendation="Add a Terms of Service link to your footer. Ensure users must acknowledge Terms before completing a purchase.",
        evidence=f"ToS URL found: {tos_url or 'Not found'}",
    ))

    findings.append(LegalFinding(
        check_id="IL-ACC-01",
        framework="IL",
        category="accessibility",
        title="Accessibility Statement (הצהרת נגישות) present",
        status="PASS" if acc_url else "FAIL",
        severity="HIGH",
        legal_basis="IL: Equal Rights for Persons with Disabilities Regulations 2013 (IS 5568) | תקנות שוויון זכויות לאנשים עם מוגבלות",
        description="Israeli law requires any website serving the public to publish an Accessibility Statement (הצהרת נגישות) that includes: compliance level, last review date, and accessibility contact.",
        recommendation="Create an accessibility statement page and link it from the footer. Include: WCAG compliance level, date of last accessibility review, contact for accessibility issues.",
        evidence=f"Accessibility statement URL: {acc_url or 'Not found'}",
    ))

    findings.append(LegalFinding(
        check_id="ALL-LP-04",
        framework="ALL",
        category="cookies",
        title="Cookie Policy accessible",
        status="PASS" if cookie_url else "WARN",
        severity="MEDIUM",
        legal_basis="IL: Privacy Protection Law | GDPR Recital 30 | CCPA",
        description="A separate cookie policy (or detailed cookie section in the privacy policy) should disclose what cookies are used, why, and by which third parties.",
        recommendation="Create a cookie policy page or add a dedicated cookie section to your privacy policy. Link it from the cookie consent banner.",
        evidence=f"Cookie policy URL: {cookie_url or 'Not found'}",
    ))

    return findings, privacy_url, tos_url, acc_url


def _check_privacy_policy_content(policy_text: str, ai_analysis: dict) -> list[LegalFinding]:
    findings = []
    if not policy_text:
        return findings

    text = policy_text.lower()

    checks = [
        ("ALL-PP-01", "ALL", "privacy",  "HIGH",
         "Controller / data owner identity stated",
         "IL: PPL §11 + Amend.13 | GDPR Art. 13(1)(a) | CCPA §1798.100",
         "The privacy policy must identify the organization that controls/owns the data — including legal name and contact details.",
         "Add your company's full legal name, registered number (ח.פ./ע.מ.), and contact address to the privacy policy.",
         "controller_identity"),

        ("ALL-PP-02", "ALL", "privacy",  "HIGH",
         "Purposes of data collection clearly stated",
         "IL: PPL + Amend.13 §11(a) | GDPR Art. 13(1)(c) | CCPA §1798.100(a)(1)",
         "The policy must explain specifically WHY personal data is collected — not just 'to improve services' in vague terms.",
         "List specific purposes: account management, service delivery, marketing (with opt-in), analytics (with consent), etc.",
         "purposes_stated"),

        ("ALL-PP-03", "GDPR", "privacy", "HIGH",
         "Legal basis for processing stated for each purpose",
         "GDPR Art. 13(1)(c) — most cited violation category in enforcement",
         "For each processing purpose, the specific legal basis must be stated: consent, contract performance, legal obligation, or legitimate interests.",
         "Add a table or list mapping each purpose to its legal basis (e.g., 'Analytics — Legal basis: Consent').",
         "legal_basis_stated"),

        ("ALL-PP-04", "ALL", "privacy",  "HIGH",
         "Third-party recipients / data sharing disclosed",
         "IL: PPL + Amend.13 | GDPR Art. 13(1)(e) | CCPA §1798.100",
         "The policy must name (or describe categories of) third parties who receive personal data. Vague 'trusted partners' is non-compliant per GDPR.",
         "List specific third-party categories or names: payment processors, analytics providers, email marketing services, cloud hosting.",
         "third_parties_disclosed"),

        ("ALL-PP-05", "ALL", "privacy",  "HIGH",
         "Data retention periods stated",
         "GDPR Art. 13(2)(a) | IL: Amend.13 | CCPA §1798.100(a)(3)",
         "The policy must state how long each category of data is retained, or the criteria used to determine retention period.",
         "Add a retention schedule: e.g., 'Account data: retained for 3 years after account closure; analytics data: 13 months rolling window.'",
         "retention_periods_stated"),

        ("ALL-PP-06", "ALL", "privacy",  "HIGH",
         "Data subject rights enumerated (access, deletion, correction, portability)",
         "IL: PPL Amend.13 — rights of access/correction/deletion effective Aug 2025 | GDPR Arts. 15-21 | CCPA §1798.100",
         "The policy must list all data subject rights: right to access, correct, delete, object, port data, and withdraw consent.",
         "Add a 'Your Rights' section listing each right, with instructions on how to exercise them and expected response time (1 month for GDPR, 45 days for CCPA).",
         "data_subject_rights_listed"),

        ("GDPR-PP-08", "GDPR", "privacy", "MEDIUM",
         "Right to complain to supervisory authority stated",
         "GDPR Art. 13(2)(d) | IL: Amend.13 — right to complain to Privacy Protection Authority",
         "Data subjects must be informed of their right to lodge a complaint with a data protection supervisory authority.",
         "Add: 'You have the right to file a complaint with your local data protection authority (e.g., the Privacy Protection Authority in Israel, or the relevant EU DPA).'",
         "complaint_right_mentioned"),

        ("ALL-PP-07", "ALL", "privacy",  "HIGH",
         "Privacy contact / DPO contact information provided",
         "IL: PPL Amend.13 §17B — DPO mandatory for large processors | GDPR Art. 37-39 | CCPA §1798.135",
         "Users must be able to contact a designated privacy contact or DPO for data-related requests.",
         "Add a privacy contact email (e.g., privacy@yourcompany.com) to the policy. If required, appoint and publish a Data Protection Officer.",
         "dpo_or_privacy_contact"),

        ("GDPR-PP-05", "GDPR", "privacy", "HIGH",
         "International data transfer safeguards stated",
         "GDPR Art. 13(1)(f) + Art. 46 | IL: PPL — transfers to non-adequate countries",
         "If personal data is transferred outside the EU/EEA or Israel, the destination country and safeguard mechanism (Standard Contractual Clauses, adequacy decision) must be stated.",
         "Add a section on international transfers, naming destination countries and citing the transfer mechanism (e.g., 'EU-US Data Privacy Framework', 'Standard Contractual Clauses').",
         "data_transfer_mechanism"),
    ]

    for (cid, fw, cat, sev, title, basis, desc, rec, ai_key) in checks:
        # Use AI result if available, otherwise check text patterns
        if ai_key in ai_analysis:
            present = bool(ai_analysis[ai_key])
        else:
            key_patterns = PRIVACY_REQUIRED_ELEMENTS.get(ai_key, [])
            present = _text_contains(text, key_patterns) if key_patterns else None

        if present is None:
            status = "SKIP"
        else:
            status = "PASS" if present else "FAIL"

        findings.append(LegalFinding(
            check_id=cid, framework=fw, category=cat, title=title,
            status=status, severity=sev, legal_basis=basis,
            description=desc, recommendation=rec,
            evidence=f"AI analysis: {present}" if ai_key in ai_analysis else "Text pattern matching",
        ))

    return findings


def _check_ccpa(html: str, soup: BeautifulSoup, privacy_text: str, ai_analysis: dict) -> list[LegalFinding]:
    findings = []
    text = html.lower()

    # "Do Not Sell" link
    has_dns = bool(re.search(r"do not sell|do not share|opt.out.*sell|opt.out.*share|limit.*sensitive", text, re.IGNORECASE))
    findings.append(LegalFinding(
        check_id="US-CA-02",
        framework="US",
        category="privacy",
        title='"Do Not Sell or Share My Personal Information" link present (CCPA/CPRA)',
        status="PASS" if has_dns else "WARN",
        severity="HIGH",
        legal_basis="CCPA §1798.135(a) | CPRA — required for businesses meeting CCPA thresholds",
        description="California businesses that sell or share personal information must provide a 'Do Not Sell or Share My Personal Information' link on the homepage and in the privacy policy.",
        recommendation="Add a 'Do Not Sell or Share My Personal Information' link to your website footer. Link it to an opt-out form or preference center.",
        evidence=f"DNS link/text found: {has_dns}",
    ))

    # GPC signal support
    gpc_js = "navigator.globalPrivacyControl" in html or "globalPrivacyControl" in html
    findings.append(LegalFinding(
        check_id="US-CA-04",
        framework="US",
        category="privacy",
        title="Global Privacy Control (GPC) signal supported",
        status="PASS" if gpc_js else "WARN",
        severity="HIGH",
        legal_basis="CA CPRA (effective 2023) | CO CPA (mandatory July 2024) | TX TDPSA (mandatory Jan 2025)",
        description="California, Colorado, and Texas require websites to honor the GPC opt-out signal (browser-sent Sec-GPC header). Failure to honor GPC is treated as a CCPA/CPA violation.",
        recommendation="Implement GPC signal detection: check for navigator.globalPrivacyControl === true in JavaScript and honor it as an opt-out of data sale/sharing.",
        evidence=f"GPC implementation found in JS: {gpc_js}",
    ))

    # California rights in privacy policy
    ca_rights = bool(ai_analysis.get("california_rights_mentioned")) or bool(
        re.search(r"california|ccpa|cpra|california consumer privacy", privacy_text, re.IGNORECASE))
    findings.append(LegalFinding(
        check_id="US-CA-01",
        framework="US",
        category="privacy",
        title="California-specific rights disclosed in Privacy Policy",
        status="PASS" if ca_rights else "WARN",
        severity="HIGH",
        legal_basis="CCPA §1798.100 | CPRA | California businesses or those processing CA residents' data",
        description="Businesses subject to CCPA must include California-specific disclosures: categories of PI collected, consumer rights, how to submit requests, and retention periods.",
        recommendation="Add a California Privacy Rights section to your policy covering: categories of PI, purposes, rights (know, delete, correct, opt-out, non-discrimination), and how to submit requests (within 45 days).",
        evidence=f"California rights mention found: {ca_rights}",
    ))

    # COPPA — child-directed signals
    child_signals = bool(re.search(r"children|child|kid|teen|under[\s_-]?13|coppa|minors", html, re.IGNORECASE))
    findings.append(LegalFinding(
        check_id="US-COPPA-01",
        framework="US",
        category="privacy",
        title="COPPA compliance signals (if child-directed site)",
        status="WARN" if child_signals else "PASS",
        severity="HIGH",
        legal_basis="COPPA 16 CFR §312 | FTC — fines up to $53,088/violation/day",
        description="Sites directed at children under 13 must obtain verifiable parental consent before collecting any personal information. COPPA violations result in major FTC fines (Google/YouTube: $170M, TikTok: $5.7M).",
        recommendation="If your site targets or knowingly collects data from children under 13: implement an age gate, obtain verifiable parental consent, and add COPPA-compliant disclosures to your privacy policy.",
        evidence=f"Child-directed content signals: {child_signals}",
    ))

    # ADA / FTC — dark patterns
    pre_checked = _detect_pre_checked_boxes(soup)
    findings.append(LegalFinding(
        check_id="US-FTC-03",
        framework="US",
        category="dark_patterns",
        title="Pre-checked consent / marketing checkboxes (dark pattern)",
        status="FAIL" if pre_checked else "PASS",
        severity="HIGH",
        legal_basis="FTC Act §5 — Deceptive Design (2022 FTC Dark Patterns Report) | GDPR Art. 7(2) | IL: PPL",
        description="Pre-ticked checkboxes for marketing consent, data sharing, or subscriptions are classified as deceptive design (dark patterns) and constitute invalid consent under GDPR and FTC guidelines.",
        recommendation="Remove the 'checked' attribute from all marketing/consent checkboxes. Users must actively opt in.",
        evidence=f"Pre-checked boxes found: {pre_checked or 'None'}",
    ))

    return findings


def _check_consumer_law(soup: BeautifulSoup, html: str) -> list[LegalFinding]:
    findings = []
    text = html.lower()

    # Business identity
    business_signals = bool(re.search(
        r"ח\.פ\.|ע\.מ\.|company\s+no|registered\s+number|vat\s+number|inc\.|ltd\.|llc\.|corp\.|gmbh|אחראי|בעל\s+האתר",
        html, re.IGNORECASE
    ))
    has_contact_email = bool(re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", html))
    has_contact_phone = bool(re.search(r"(\+\d{1,3}[\s.-])?(\(?\d{1,4}\)?[\s.-]){1,4}\d{4}", html))

    findings.append(LegalFinding(
        check_id="IL-EC-01",
        framework="IL",
        category="consumer",
        title="Business identity and contact details visible",
        status="PASS" if (business_signals or (has_contact_email and has_contact_phone)) else "FAIL",
        severity="HIGH",
        legal_basis="IL: E-Commerce Regulations 2003 §2 | Consumer Protection Law 1981 | US: FTC Act §5",
        description="Israeli law requires every commercial website to display: business legal name, registered business number (ח.פ./ע.מ.), physical address, and contact information (email + phone).",
        recommendation="Add to your website footer: company legal name, business registration number, physical address, phone number, and email address.",
        evidence=f"Biz registration number: {business_signals} | Email: {has_contact_email} | Phone: {has_contact_phone}",
    ))

    # Return / cancellation policy
    has_return = bool(re.search(
        r"return\s+polic|refund\s+polic|cancell?ation|מדיניות\s+ביטול|זכות\s+ביטול|14\s+day|14\s+ימ",
        html, re.IGNORECASE
    ))
    findings.append(LegalFinding(
        check_id="IL-EC-03",
        framework="IL",
        category="consumer",
        title="Cancellation / return policy accessible (14-day right)",
        status="PASS" if has_return else "WARN",
        severity="HIGH",
        legal_basis="IL: Consumer Protection Law §14C — 14-day cooling-off period for distance transactions | E-Commerce Regulations 2003 §3",
        description="Israeli law grants consumers a 14-day right to cancel distance transactions without penalty. This right must be disclosed before the transaction.",
        recommendation="Add a clearly accessible return/cancellation policy. State the 14-day cancellation right explicitly for all transactions made remotely.",
        evidence=f"Return/cancellation policy found: {has_return}",
    ))

    # VAT/price transparency
    has_vat = bool(re.search(r"vat|מע\"מ|מס ערך מוסף|incl?\s*tax|tax[\s_-]?includ|כולל מע", html, re.IGNORECASE))
    findings.append(LegalFinding(
        check_id="IL-EC-02",
        framework="IL",
        category="consumer",
        title="Prices include VAT / all fees disclosed",
        status="PASS" if has_vat else "WARN",
        severity="HIGH",
        legal_basis="IL: Consumer Protection Law + E-Commerce Regulations 2003 §3 — total price including all taxes must be shown",
        description="Israeli law requires that all prices displayed include VAT (מע\"מ) and any mandatory fees. Surprise fees added at checkout are prohibited.",
        recommendation="Display all prices inclusive of VAT (מע\"מ 17%). Label prices clearly as 'כולל מע\"מ' or 'including VAT'. Disclose any shipping or service fees upfront.",
        evidence=f"VAT/tax mention found: {has_vat}",
    ))

    # Terms acceptance before purchase
    has_terms_checkbox = bool(soup.find("input", {"type": "checkbox"}))
    has_terms_link = bool(re.search(r"i agree|terms|agree\s+to|מסכים|קרא\s+ואישר", html, re.IGNORECASE))
    findings.append(LegalFinding(
        check_id="IL-EC-06",
        framework="IL",
        category="consumer",
        title="Terms acceptance mechanism before transactions",
        status="PASS" if (has_terms_checkbox and has_terms_link) else "WARN",
        severity="MEDIUM",
        legal_basis="IL: E-Commerce Regulations 2003 §6 | GDPR Art. 7 | US: FTC dark patterns guidance",
        description="Users should actively acknowledge Terms of Service before completing a transaction. Passive acceptance (e.g., fine print 'by using this site you agree') does not satisfy Israeli e-commerce regulations.",
        recommendation="Add an unchecked 'I agree to the Terms of Service [link]' checkbox at checkout or registration. Store acceptance records with timestamp.",
        evidence=f"Agreement checkbox: {has_terms_checkbox} | Terms text: {has_terms_link}",
    ))

    return findings


def _check_accessibility(soup: BeautifulSoup, html: str) -> list[LegalFinding]:
    findings = []

    # HTML lang attribute
    html_tag = soup.find("html")
    lang = html_tag.get("lang", "") if html_tag else ""
    findings.append(LegalFinding(
        check_id="IL-ACC-06",
        framework="IL",
        category="accessibility",
        title="HTML lang attribute set (WCAG 3.1.1)",
        status="PASS" if lang else "FAIL",
        severity="MEDIUM",
        legal_basis="IL: IS 5568 / WCAG 2.0 AA — Success Criterion 3.1.1 | ADA WCAG 2.1 AA",
        description="The <html> tag must have a lang attribute identifying the page language. Screen readers use this to select the correct voice profile.",
        recommendation=f"Add lang attribute to <html> tag: <html lang=\"he\"> for Hebrew, <html lang=\"en\"> for English.",
        evidence=f"lang=\"{lang}\"" if lang else "lang attribute missing",
    ))

    # Alt text on images
    missing_alt, total_imgs = _count_images_missing_alt(soup)
    alt_pass = missing_alt == 0
    findings.append(LegalFinding(
        check_id="IL-ACC-02",
        framework="IL",
        category="accessibility",
        title=f"Images have alt text ({total_imgs - missing_alt}/{total_imgs} compliant)",
        status="PASS" if alt_pass else ("WARN" if missing_alt <= 2 else "FAIL"),
        severity="HIGH",
        legal_basis="IL: IS 5568 / WCAG 2.0 AA — SC 1.1.1 | ADA Title III | GDPR Art. 5 (data minimisation principle does not apply here, but accessibility does)",
        description="All meaningful images must have descriptive alt text so screen readers can convey their content to visually impaired users.",
        recommendation="Add descriptive alt text to all meaningful images. For decorative images, use alt=\"\" (empty, not missing). Avoid generic text like 'image' or 'photo'.",
        evidence=f"{missing_alt} images missing alt text out of {total_imgs} total",
    ))

    # Heading hierarchy
    good_headings = _check_heading_hierarchy(soup)
    h1_count = len(soup.find_all("h1"))
    findings.append(LegalFinding(
        check_id="IL-ACC-07",
        framework="IL",
        category="accessibility",
        title=f"Heading hierarchy is logical (H1→H2→H3) — {h1_count} H1 found",
        status="PASS" if (good_headings and h1_count == 1) else "WARN",
        severity="MEDIUM",
        legal_basis="IL: IS 5568 / WCAG 2.0 AA — SC 1.3.1 | ADA WCAG 2.1 AA",
        description="Pages must have exactly one H1 and a logical heading hierarchy (no skipped levels, e.g., H1→H3 without H2). Screen readers use headings for navigation.",
        recommendation="Ensure exactly one H1 per page. Use headings in sequential order (H1 → H2 → H3). Do not use headings for styling — use CSS classes instead.",
        evidence=f"Heading hierarchy logical: {good_headings} | H1 count: {h1_count}",
    ))

    # Form labels
    unlabelled, total_inputs = _forms_have_labels(soup)
    findings.append(LegalFinding(
        check_id="IL-ACC-05",
        framework="IL",
        category="accessibility",
        title=f"Form inputs have labels ({total_inputs - unlabelled}/{total_inputs} labelled)",
        status="PASS" if unlabelled == 0 else ("WARN" if unlabelled <= 2 else "FAIL"),
        severity="HIGH",
        legal_basis="IL: IS 5568 / WCAG 2.0 AA — SC 1.3.1, 3.3.2 | ADA WCAG 2.1 AA",
        description="Every form input field must have an associated <label> element, aria-label, or aria-labelledby attribute. Missing labels make forms unusable with screen readers.",
        recommendation=f"Fix {unlabelled} unlabelled input(s). Use <label for=\"input-id\"> or add aria-label attributes. Test with a screen reader.",
        evidence=f"{unlabelled} unlabelled inputs out of {total_inputs} total",
    ))

    # Skip navigation link
    has_skip = bool(re.search(r"skip[\s_-]?(to[\s_-])?main|skip[\s_-]?nav|דלג\s+לתוכן", html, re.IGNORECASE))
    findings.append(LegalFinding(
        check_id="IL-ACC-08",
        framework="IL",
        category="accessibility",
        title="Skip navigation link present",
        status="PASS" if has_skip else "WARN",
        severity="LOW",
        legal_basis="IL: IS 5568 / WCAG 2.1 — SC 2.4.1 | ADA WCAG 2.1 AA",
        description="A 'Skip to main content' link should be the first focusable element on the page, allowing keyboard users to bypass repetitive navigation menus.",
        recommendation="Add a visually hidden 'Skip to main content' link as the first element in the <body>: <a href='#main-content' class='skip-link'>Skip to main content</a>",
        evidence=f"Skip nav link found: {has_skip}",
    ))

    # Viewport meta (mobile accessibility)
    viewport = soup.find("meta", {"name": "viewport"})
    viewport_content = viewport.get("content", "") if viewport else ""
    bad_viewport = "user-scalable=no" in viewport_content or "maximum-scale=1" in viewport_content
    findings.append(LegalFinding(
        check_id="IL-ACC-09",
        framework="IL",
        category="accessibility",
        title="Viewport allows user scaling (zoom accessible)",
        status="FAIL" if bad_viewport else "PASS",
        severity="MEDIUM",
        legal_basis="IL: IS 5568 / WCAG 2.1 — SC 1.4.4 Resize Text | ADA WCAG 2.1 AA",
        description="The viewport meta tag must not prevent users from zooming (user-scalable=no or maximum-scale=1 are accessibility violations). Many users with low vision rely on zoom.",
        recommendation="Remove user-scalable=no and maximum-scale=1 from your viewport meta tag. Use: <meta name='viewport' content='width=device-width, initial-scale=1'>",
        evidence=f"Viewport: {viewport_content or 'missing'} | Bad zoom restriction: {bad_viewport}",
    ))

    return findings


def _check_data_rights(soup: BeautifulSoup, html: str, privacy_url: str) -> list[LegalFinding]:
    findings = []

    # Data deletion request mechanism
    has_delete_mechanism = bool(re.search(
        r"delete.*account|remove.*data|erase.*data|data.*deletion|right.*erase|request.*delete|מחיקת\s+נתונים|מחיקת\s+חשבון",
        html, re.IGNORECASE
    ))
    findings.append(LegalFinding(
        check_id="GDPR-ER-01",
        framework="GDPR",
        category="data_rights",
        title="Data deletion / erasure request mechanism visible",
        status="PASS" if has_delete_mechanism else "FAIL",
        severity="HIGH",
        legal_basis="GDPR Art. 17 — Right to Erasure ('Right to be Forgotten') | IL: PPL Amend.13 — right to deletion | CCPA §1798.105",
        description="Users must be able to request deletion of their personal data. The mechanism (form, email, or settings) must be accessible and clearly described.",
        recommendation="Add a data deletion request form or clear instructions (e.g., 'Email privacy@yoursite.com with subject Delete my data'). Must respond within 30 days (GDPR) / 45 days (CCPA).",
        evidence=f"Deletion mechanism found: {has_delete_mechanism}",
    ))

    # Data access request
    has_access = bool(re.search(
        r"access.*data|data.*access|request.*data|subject.*access|זכות\s+עיון|בקשת\s+מידע",
        html, re.IGNORECASE
    ))
    findings.append(LegalFinding(
        check_id="GDPR-DR-02",
        framework="GDPR",
        category="data_rights",
        title="Data access request mechanism visible",
        status="PASS" if has_access else "WARN",
        severity="MEDIUM",
        legal_basis="GDPR Art. 15 — Right of Access | IL: PPL Amend.13 | CCPA §1798.100",
        description="Users have the right to request a copy of their personal data. This right must be exercisable and the mechanism must be described.",
        recommendation="Add a data access request form or instructions. State the response time (30 days for GDPR, 45 days for CCPA, extendable by 2 months for complexity).",
        evidence=f"Access mechanism found: {has_access}",
    ))

    # Email unsubscribe / marketing opt-out
    has_unsub = bool(re.search(
        r"unsubscribe|opt.out.*email|remove.*email.*list|הסרה\s+מרשימת|הסרת\s+מינוי|ביטול\s+הרשמה",
        html, re.IGNORECASE
    ))
    findings.append(LegalFinding(
        check_id="IL-SPAM-02",
        framework="IL",
        category="data_rights",
        title="Email marketing opt-out / unsubscribe mechanism",
        status="PASS" if has_unsub else "WARN",
        severity="HIGH",
        legal_basis="IL: Telecommunications Law (Anti-Spam) §30A | US: CAN-SPAM Act §5(a)(5) — processed within 10 business days",
        description="Any site that sends marketing emails must provide a clear unsubscribe mechanism, both on the website and in every marketing email. Israeli law requires opt-in for marketing (not just opt-out).",
        recommendation="Add an unsubscribe page linked from your footer and from every marketing email. Ensure opt-out requests are processed within 10 business days.",
        evidence=f"Unsubscribe mechanism found: {has_unsub}",
    ))

    # Explicit opt-in checkboxes (not pre-checked) for marketing
    forms = soup.find_all("form")
    has_newsletter_form = any(
        re.search(r"newsletter|subscribe|subscrib|עדכונים|רשימת\s+תפוצה|email.*list", f.get_text(), re.IGNORECASE)
        for f in forms
    )
    findings.append(LegalFinding(
        check_id="IL-SPAM-01",
        framework="IL",
        category="data_rights",
        title="Newsletter/marketing subscription uses explicit opt-in",
        status="WARN" if has_newsletter_form else "PASS",
        severity="HIGH",
        legal_basis="IL: Telecommunications Law (Anti-Spam) §30A — opt-in required (not opt-out) | GDPR Art. 7",
        description="Israeli anti-spam law requires explicit prior consent (opt-in) before sending commercial messages. Consent must be a clear affirmative action — not pre-ticked boxes, not implied from sign-up.",
        recommendation="Ensure all newsletter signup forms use an unchecked explicit consent checkbox (not pre-ticked). Clearly state what emails the user will receive.",
        evidence=f"Newsletter signup form detected: {has_newsletter_form}",
    ))

    return findings


def _check_security_headers(headers: dict) -> list[LegalFinding]:
    findings = []
    hd = {k.lower(): v for k, v in headers.items()}

    # CSP
    csp = hd.get("content-security-policy", "")
    findings.append(LegalFinding(
        check_id="ALL-SEC-03",
        framework="ALL",
        category="security",
        title="Content-Security-Policy header present",
        status="PASS" if csp else "WARN",
        severity="MEDIUM",
        legal_basis="IL: Data Security Regulations 2017 | GDPR Art. 32 — appropriate technical measures | OWASP",
        description="A Content-Security-Policy header prevents XSS attacks that could lead to unauthorized data collection and privacy violations.",
        recommendation="Add a Content-Security-Policy header restricting script sources to known domains. Start with: Content-Security-Policy: default-src 'self'; script-src 'self' [trusted domains]",
        evidence=f"CSP: {csp[:100] if csp else 'missing'}",
    ))

    # X-Frame-Options
    xfo = hd.get("x-frame-options", "")
    findings.append(LegalFinding(
        check_id="ALL-SEC-04",
        framework="ALL",
        category="security",
        title="X-Frame-Options / frame-ancestors CSP set",
        status="PASS" if (xfo or "frame-ancestors" in csp) else "WARN",
        severity="MEDIUM",
        legal_basis="IL: Data Security Regulations 2017 | GDPR Art. 32",
        description="Without clickjacking protection, attackers can overlay your site in an iframe to steal user credentials or manipulate actions.",
        recommendation="Add header: X-Frame-Options: SAMEORIGIN or use CSP: frame-ancestors 'self'",
        evidence=f"X-Frame-Options: {xfo or 'missing'}",
    ))

    # X-Content-Type-Options
    xcto = hd.get("x-content-type-options", "")
    findings.append(LegalFinding(
        check_id="ALL-SEC-05",
        framework="ALL",
        category="security",
        title="X-Content-Type-Options: nosniff set",
        status="PASS" if xcto else "WARN",
        severity="LOW",
        legal_basis="IL: Data Security Regulations 2017 | GDPR Art. 32",
        description="Prevents browsers from MIME-sniffing responses, which can lead to XSS vulnerabilities.",
        recommendation="Add header: X-Content-Type-Options: nosniff",
        evidence=f"X-Content-Type-Options: {xcto or 'missing'}",
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Scoring engine
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_scores(findings: list[LegalFinding]) -> tuple[int, int, int, int]:
    """Returns (overall, il_score, us_score, gdpr_score) — 0=low risk, 100=high risk."""
    sev_weight = {"HIGH": 10, "MEDIUM": 5, "LOW": 2}

    def _fw_score(fw_filter: str) -> int:
        fw_checks = [f for f in findings
                     if (f.framework == fw_filter or f.framework == "ALL")
                     and f.status != "SKIP"]
        if not fw_checks:
            return 0
        max_pts = sum(sev_weight.get(f.severity, 5) for f in fw_checks)
        fail_pts = sum(sev_weight.get(f.severity, 5) for f in fw_checks if f.status == "FAIL")
        warn_pts = sum(sev_weight.get(f.severity, 5) * 0.4 for f in fw_checks if f.status == "WARN")
        return min(100, round(((fail_pts + warn_pts) / max_pts) * 100)) if max_pts else 0

    il = _fw_score("IL")
    us = _fw_score("US")
    gdpr = _fw_score("GDPR")
    overall = min(100, round((il * 0.35 + us * 0.30 + gdpr * 0.35)))
    return overall, il, us, gdpr


# ─────────────────────────────────────────────────────────────────────────────
# Main orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run_legal_scan(url: str, frameworks: list[str] | None = None) -> LegalScanResult:
    """
    Run a full legal compliance scan on the given URL.
    frameworks: subset of ["IL", "US", "GDPR"] or None for all.
    Returns LegalScanResult with all findings and scores.
    """
    t0 = time.time()
    result = LegalScanResult(url=url)
    active_fw = set(frameworks or ["IL", "US", "GDPR"])

    # ── 1. Fetch main page ──────────────────────────────────────────────────
    resp, err = _safe_get(url, timeout=15)
    if err or resp is None:
        result.error = f"Failed to fetch URL: {err}"
        return result

    html = resp.text
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    base_url = resp.url
    headers = dict(resp.headers)
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # ── 2. Detect trackers & consent SDK ───────────────────────────────────
    result.trackers_found = _detect_trackers(html)
    result.consent_sdk    = _detect_consent_sdk(html)

    # ── 3. Find legal page URLs ─────────────────────────────────────────────
    legal_findings, privacy_url, tos_url, acc_url = _check_legal_pages(soup, html, base_url)
    result.privacy_policy_url = privacy_url
    result.tos_url            = tos_url
    result.accessibility_url  = acc_url

    html_tag = soup.find("html")
    result.page_lang = html_tag.get("lang", "") if html_tag else ""

    # ── 4. Fetch privacy policy for AI analysis ─────────────────────────────
    policy_text = _fetch_text_page(privacy_url) if privacy_url else ""
    ai_analysis = _ai_analyze_privacy_policy(policy_text, list(active_fw))

    # ── 5. Run all checks ────────────────────────────────────────────────────
    all_findings: list[LegalFinding] = []

    all_findings += _check_https(url, resp)
    all_findings += _check_security_headers(headers)
    all_findings += _check_cookies_and_consent(html, soup, headers_lower,
                                               result.trackers_found, result.consent_sdk)
    all_findings += legal_findings
    all_findings += _check_privacy_policy_content(policy_text, ai_analysis)
    all_findings += _check_ccpa(html, soup, policy_text, ai_analysis)
    all_findings += _check_consumer_law(soup, html)
    all_findings += _check_accessibility(soup, html)
    all_findings += _check_data_rights(soup, html, privacy_url)

    # Filter by selected frameworks
    filtered = [
        f for f in all_findings
        if f.framework == "ALL" or f.framework in active_fw
    ]
    result.findings = filtered

    # ── 6. Scoring ──────────────────────────────────────────────────────────
    result.risk_score, result.il_score, result.us_score, result.gdpr_score = \
        _calculate_scores(filtered)
    result.scan_time = round(time.time() - t0, 1)

    return result

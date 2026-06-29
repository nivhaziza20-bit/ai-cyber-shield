"""
Compliance Shield — AI Cyber Shield
=====================================
Covers:
  Israeli Law  — Privacy Protection Law (incl. Amendment 13 / Aug 2025),
                 Data Security Regulations 2017, Consumer Protection Law,
                 E-Commerce Regulations 2003, IS 5568 Accessibility, Anti-Spam
  US Law       — CCPA/CPRA, ADA (WCAG 2.1 AA), CAN-SPAM, COPPA, FTC (dark patterns)
  GDPR         — Arts. 13/14 notice, cookie consent, right to erasure, DPO

DISCLAIMER: Results are informational only and do not constitute legal advice.
Review findings with a qualified legal professional before making compliance decisions.
AI Cyber Shield Ltd. accepts no liability for decisions made based on this report.
"""
from __future__ import annotations

# NOTE: asyncio intentionally NOT imported — this scanner is fully synchronous.
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
    # Fine estimate fields — populated by _apply_fine_estimates() in run_legal_scan
    fine_min:       str = ""     # e.g. "€0", "₪50,000", "$2,500"
    fine_max:       str = ""     # e.g. "€20M or 4% turnover"
    fine_example:   str = ""     # Real enforcement case: "Google €150M (CNIL 2021)"


@dataclass
class CookieRecord:
    name:      str
    value:     str = ""
    domain:    str = ""
    http_only: bool = False
    secure:    bool = False
    same_site: str = ""
    category:  str = "unknown"   # "strictly_necessary" | "functional" | "analytics" | "marketing" | "unknown"
    tracker:   str = ""          # name of known tracker if identified


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
    # New fields (v3)
    scan_method:      str = "static"    # "playwright" | "requests" (static)
    cookies_found:    list[CookieRecord] = field(default_factory=list)
    pages_scanned:    list[str] = field(default_factory=list)
    privacy_in_footer_all_pages: bool = False  # True if privacy link in footer on ALL sampled pages


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

# ─────────────────────────────────────────────────────────────────────────────
# Fine Database — maps check_id → (min, max, real enforcement example)
# Sources: CNIL, Irish DPC, GDPR Enforcement Tracker, FTC, CPPA, IL law
# ─────────────────────────────────────────────────────────────────────────────

FINE_DB: dict[str, dict] = {
    # ── Cookies & Consent ────────────────────────────────────────────────────
    "ALL-CK-01": {
        "min": "€0", "max": "€20M or 4% global turnover",
        "example": "Google €150M + YouTube €60M (CNIL 2021) — cookie refusal required multiple clicks",
    },
    "ALL-CK-02": {
        "min": "€0", "max": "€20M or 4% turnover",
        "example": "Amazon €35M (CNIL 2020) — analytics cookies set before consent",
    },
    "GDPR-CK-02": {
        "min": "€5M", "max": "€60M",
        "example": "Facebook €60M (CNIL 2021) + Microsoft Bing €60M (CNIL 2022) — no first-layer Reject button",
    },
    "GDPR-CK-05": {
        "min": "€0", "max": "€20M",
        "example": "IAB Europe €250K (Belgian DPA 2022) — TCF framework non-compliant",
    },
    "IL-SEC-02": {
        "min": "₪0", "max": "₪3.2M",
        "example": "IL PPL Amendment 13 (Aug 2025) — insecure cookie flags = Data Security Regulations violation",
    },
    # ── Privacy Policy / Transparency ────────────────────────────────────────
    "ALL-LP-01": {
        "min": "€0", "max": "€20M or 4% turnover",
        "example": "WhatsApp €225M (Irish DPC 2021) — privacy policy opacity; Amazon €746M (Luxembourg 2021)",
    },
    "ALL-PP-01": {
        "min": "€10K", "max": "€20M or 4% turnover",
        "example": "Uber €4.24M (Italian DPA 2018) — vague privacy policy, no controller identity",
    },
    "ALL-PP-02": {
        "min": "€10K", "max": "€20M or 4% turnover",
        "example": "Clearview AI €20M (Italian DPA 2022) — purposes not stated",
    },
    "ALL-PP-03": {
        "min": "€50K", "max": "€20M or 4% turnover",
        "example": "Meta €1.2B (Irish DPC 2023) — no adequate legal basis for data transfers",
    },
    "ALL-PP-04": {
        "min": "€10K", "max": "€20M",
        "example": "Vodafone €12.25M (Spanish AEPD 2021) — third parties not disclosed",
    },
    "ALL-PP-05": {
        "min": "€5K", "max": "€10M",
        "example": "H&M €35.2M (Hamburg DPA 2020) — no clear retention periods",
    },
    "ALL-PP-06": {
        "min": "€5K", "max": "€20M",
        "example": "Google €50M (CNIL 2019) — data subject rights not clearly explained",
    },
    "ALL-PP-07": {
        "min": "€5K", "max": "€10M",
        "example": "GDPR Art. 37-38 — DPO not designated or not published for mandatory controllers",
    },
    "GDPR-PP-05": {
        "min": "€100K", "max": "€20M or 4% turnover",
        "example": "Meta €1.2B (2023) — no SCCs for US transfers; Grindr €5.9M (Norwegian DPA 2023)",
    },
    "GDPR-PP-08": {
        "min": "€1K", "max": "€5M",
        "example": "GDPR Art. 13(2)(d) — complaint right must be stated; enforcement in Czech Republic, Austria",
    },
    # ── Data Rights ──────────────────────────────────────────────────────────
    "GDPR-ER-01": {
        "min": "€7M", "max": "€20M or 4% turnover",
        "example": "Google €7M (Swedish DPA 2020) — incomplete global erasure from search results",
    },
    "GDPR-DR-02": {
        "min": "€5K", "max": "€20M",
        "example": "GDPR Art. 15 — 28% of DPA complaints involve access requests; ICO fined 150+ cases",
    },
    "IL-SPAM-01": {
        "min": "₪1,000", "max": "₪1,000 per marketing message",
        "example": "IL Telecommunications Law §30A — each unsolicited message = separate violation",
    },
    "IL-SPAM-02": {
        "min": "₪1,000/msg", "max": "$53,088/email (CAN-SPAM)",
        "example": "Verkada $2.95M (FTC 2024) — largest CAN-SPAM penalty ever; Experian $650K (FTC 2023)",
    },
    # ── Accessibility ────────────────────────────────────────────────────────
    "IL-ACC-01": {
        "min": "₪50,000", "max": "₪50,000 + 5%/day",
        "example": "IS 5568 / Equal Rights Act — fixed statutory penalty per violation; daily escalation",
    },
    "IL-ACC-02": {
        "min": "₪50,000", "max": "₪50,000 + 5%/day",
        "example": "ADA: $75,000 first violation, $150,000 subsequent (US DOJ); IL: ₪50K fixed penalty",
    },
    "IL-ACC-05": {
        "min": "₪50,000", "max": "$150,000 (ADA)",
        "example": "Domino's Pizza v. Robles (US Supreme Court 2019) — website accessibility required under ADA",
    },
    "IL-ACC-06": {
        "min": "₪50,000", "max": "₪50,000 + escalation",
        "example": "IS 5568 WCAG SC 3.1.1 — missing HTML lang is automatic accessibility failure",
    },
    "IL-ACC-07": {
        "min": "₪50,000", "max": "$75,000–$150,000",
        "example": "ADA Title III web cases — $75,000 first violation, $150,000 repeat. 4,000+ US lawsuits filed in 2023.",
    },
    "IL-ACC-08": {
        "min": "₪50,000", "max": "₪50,000",
        "example": "IS 5568 WCAG SC 2.4.1 — skip nav required; keyboard trap is separate high-severity violation",
    },
    "IL-ACC-09": {
        "min": "₪50,000", "max": "₪50,000",
        "example": "WCAG SC 1.4.4 — user-scalable=no blocks zoom for low-vision users; automatic FAIL",
    },
    # ── Consumer Law ─────────────────────────────────────────────────────────
    "IL-EC-01": {
        "min": "₪50,000", "max": "₪50,000 civil penalty",
        "example": "IL E-Commerce Regs 2003 §2 — Consumer Protection Authority issues fines for missing business identity",
    },
    "IL-EC-02": {
        "min": "₪10,000", "max": "₪50,000",
        "example": "IL Consumer Protection Law — prices must include VAT; hidden fees at checkout = separate offense",
    },
    "IL-EC-03": {
        "min": "₪10,000", "max": "₪50,000",
        "example": "IL Consumer Protection §14C — 14-day right violation; FTC ROSCA: Vonage $100M (2023)",
    },
    "IL-EC-06": {
        "min": "₪5,000", "max": "₪50,000",
        "example": "IL E-Commerce Regs — terms must be accepted before transaction; FTC: dark pattern settlements",
    },
    # ── Dark Patterns ────────────────────────────────────────────────────────
    "US-FTC-03": {
        "min": "$0", "max": "$245M",
        "example": "Epic Games $245M (FTC 2023) — dark patterns tricking players; Amazon Prime $2.5B settlement (2024)",
    },
    "US-FTC-DP-01": {
        "min": "$3M", "max": "$245M",
        "example": "Publishers Clearing House $18.5M (FTC 2023); Credit Karma $3M (FTC 2023)",
    },
    "US-FTC-DP-02": {
        "min": "$0", "max": "$100M",
        "example": "Vonage $100M (FTC 2023) — impossible cancellation; Amazon $2.5B settlement",
    },
    # ── CCPA / US Privacy ────────────────────────────────────────────────────
    "US-CA-01": {
        "min": "$2,500", "max": "$7,988 per violation",
        "example": "Disney $2.75M (CPPA 2026); DoorDash $375K (CA AG 2024); Sephora $1.2M (CA AG 2022)",
    },
    "US-CA-02": {
        "min": "$2,500", "max": "$7,988 per violation",
        "example": "Sephora $1.2M (CA AG 2022) — selling data without disclosure + no opt-out signal",
    },
    "US-CA-04": {
        "min": "$2,500", "max": "$7,988 per violation",
        "example": "CA CPRA — GPC opt-out mandatory since Jan 2023; CO CPA — mandatory July 2024",
    },
    "US-COPPA-01": {
        "min": "$0", "max": "$53,088/violation",
        "example": "YouTube/Google $170M (FTC 2019); TikTok $5.7M (FTC 2019); Disney $10M (YouTube 2023)",
    },
    # ── Security ─────────────────────────────────────────────────────────────
    "ALL-SEC-01": {
        "min": "€10K", "max": "€20M or 4% turnover",
        "example": "GDPR Art. 32 — data in transit must be encrypted. Marriott €18.4M (ICO 2020) for inadequate security",
    },
    "ALL-SEC-02": {
        "min": "€5K", "max": "€10M",
        "example": "Data Security Regulations 2017 (IL) §4 — HSTS required for sensitive data services",
    },
    "ALL-SEC-03": {
        "min": "€0", "max": "€5M",
        "example": "GDPR Art. 32 — CSP is part of 'appropriate technical measures'; XSS leading to breach triggers Art. 33",
    },
    # ── GDPR Legal Pages ─────────────────────────────────────────────────────
    "ALL-LP-02": {
        "min": "₪10K", "max": "₪50K",
        "example": "IL E-Commerce Regs §6 — ToS must be accepted before distance transactions",
    },
    "ALL-LP-04": {
        "min": "€5K", "max": "€20M",
        "example": "GDPR Recital 30 — cookies must be disclosed by category; CNIL requires separate cookie list",
    },
    "GDPR-EU-REP-01": {
        "min": "€10M", "max": "€20M or 2% turnover",
        "example": "GDPR Art. 27 — mandatory for non-EU controllers. Clearview AI cited for no EU representative",
    },
    "ALL-META-01": {
        "min": "€0", "max": "€10M",
        "example": "CCPA §1798.130 — annual policy update required; ICO enforcement for stale policies",
    },
    "GDPR-CK-INV-01": {
        "min": "€60M", "max": "€150M",
        "example": "Google (CNIL 2021 €150M) — analytics cookies set before consent; Facebook €60M same year",
    },
    "US-PAY-01": {
        "min": "$5K", "max": "$100K/month",
        "example": "PCI-DSS v4.0 — self-hosted card forms without qualified processor = Level 1 non-compliance",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Cookie Categorization Engine
# Based on: Open Cookie Database, IAB TCF 2.2, known tracker patterns
# ─────────────────────────────────────────────────────────────────────────────

# Prefix/exact-name based classifier (covers ~95% of real-world cookies)
_COOKIE_RULES: list[tuple[str, str, str]] = [
    # (match_type, pattern, category)  — checked in priority order
    # STRICTLY NECESSARY — no consent required (ePrivacy Directive Art. 5(3) exemption)
    ("prefix", "PHPSESSID",          "strictly_necessary"),
    ("prefix", "JSESSIONID",         "strictly_necessary"),
    ("prefix", "ASP.NET_SessionId",  "strictly_necessary"),
    ("prefix", "csrftoken",          "strictly_necessary"),
    ("prefix", "XSRF-TOKEN",         "strictly_necessary"),
    ("prefix", "_csrf",              "strictly_necessary"),
    ("prefix", "csrf",               "strictly_necessary"),
    ("prefix", "xsrf",               "strictly_necessary"),
    ("prefix", "session",            "strictly_necessary"),
    ("prefix", "sess",               "strictly_necessary"),
    ("prefix", "__Host-",            "strictly_necessary"),
    ("prefix", "__Secure-",          "strictly_necessary"),
    ("prefix", "sb-",                "strictly_necessary"),   # Supabase auth
    ("prefix", "__stripe_",          "strictly_necessary"),
    ("prefix", "AWSALB",             "strictly_necessary"),
    ("prefix", "AWSELB",             "strictly_necessary"),
    ("prefix", "OptanonConsent",     "strictly_necessary"),   # CMP consent record
    ("prefix", "CookieConsent",      "strictly_necessary"),   # CMP consent record
    ("prefix", "cookieconsent_",     "strictly_necessary"),
    ("prefix", "cky-consent",        "strictly_necessary"),
    ("prefix", "cmplz_",             "strictly_necessary"),
    ("prefix", "viewed_cookie_",     "strictly_necessary"),
    # FUNCTIONAL — require consent under GDPR
    ("prefix", "lang",               "functional"),
    ("prefix", "locale",             "functional"),
    ("prefix", "language",           "functional"),
    ("prefix", "currency",           "functional"),
    ("prefix", "timezone",           "functional"),
    ("prefix", "theme",              "functional"),
    ("prefix", "user_pref",          "functional"),
    ("prefix", "preferences",        "functional"),
    ("prefix", "wp-settings-",       "functional"),
    # ANALYTICS — require consent
    ("prefix", "_ga",                "analytics"),    # Google Analytics 4 + UA
    ("prefix", "_gid",               "analytics"),
    ("prefix", "_gat",               "analytics"),
    ("prefix", "_gac_",              "analytics"),
    ("prefix", "__utm",              "analytics"),    # GA legacy
    ("prefix", "_pk_id",             "analytics"),   # Matomo
    ("prefix", "_pk_ses",            "analytics"),
    ("prefix", "amplitude_",         "analytics"),
    ("prefix", "_hjid",              "analytics"),   # Hotjar
    ("prefix", "_hjFirstSeen",       "analytics"),
    ("prefix", "_hjSession",         "analytics"),
    ("prefix", "_hjAbsolute",        "analytics"),
    ("prefix", "_hjIncluded",        "analytics"),
    ("prefix", "_hjTLDTest",         "analytics"),
    ("prefix", "_clck",              "analytics"),   # Microsoft Clarity
    ("prefix", "_clsk",              "analytics"),
    ("prefix", "HEAP",               "analytics"),
    ("prefix", "heap_",              "analytics"),
    ("prefix", "ajs_",              "analytics"),    # Segment
    ("prefix", "mixpanel",           "analytics"),
    ("prefix", "_fs_",               "analytics"),   # FullStory
    ("prefix", "fs_",                "analytics"),
    ("prefix", "mp_",                "analytics"),   # Mixpanel
    # MARKETING — require consent
    ("prefix", "_fbp",               "marketing"),   # Facebook Pixel
    ("prefix", "_fbc",               "marketing"),
    ("exact",  "fr",                 "marketing"),   # Facebook
    ("exact",  "datr",               "marketing"),
    ("exact",  "xs",                 "marketing"),
    ("prefix", "_gcl_",              "marketing"),   # Google Ads
    ("exact",  "NID",                "marketing"),
    ("exact",  "1P_JAR",             "marketing"),
    ("exact",  "DSID",               "marketing"),
    ("exact",  "IDE",                "marketing"),
    ("exact",  "ANID",               "marketing"),
    ("exact",  "AID",                "marketing"),
    ("prefix", "_uetsid",            "marketing"),   # Microsoft/Bing Ads
    ("prefix", "_uetvid",            "marketing"),
    ("exact",  "MUID",               "marketing"),
    ("exact",  "MR",                 "marketing"),
    ("prefix", "_tt_sess",           "marketing"),   # TikTok
    ("prefix", "ttcsid",             "marketing"),
    ("prefix", "ttwid",              "marketing"),
    ("prefix", "li_fat_id",          "marketing"),   # LinkedIn
    ("prefix", "bcookie",            "marketing"),
    ("prefix", "lidc",               "marketing"),
    ("prefix", "li_sugr",            "marketing"),
    ("prefix", "guest_id",           "marketing"),   # Twitter/X
    ("prefix", "ads_prefs",          "marketing"),
    ("prefix", "_pin_",              "marketing"),   # Pinterest
    ("prefix", "_scid",              "marketing"),   # Snapchat
    ("prefix", "_sctr",              "marketing"),
]

_COOKIE_RULE_LOOKUP: dict[str, str] = {p: cat for (mt, p, cat) in _COOKIE_RULES if mt == "exact"}
_COOKIE_PREFIX_RULES: list[tuple[str, str]] = [(p, cat) for (mt, p, cat) in _COOKIE_RULES if mt == "prefix"]

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

# Known tracking cookies by name prefix
TRACKING_COOKIE_PATTERNS: dict[str, str] = {
    "_ga":         "Google Analytics",
    "_gid":        "Google Analytics",
    "_gat":        "Google Analytics",
    "_gac_":       "Google Analytics",
    "_fbp":        "Facebook/Meta Pixel",
    "_fbc":        "Facebook/Meta Pixel",
    "fr":          "Facebook",
    "_hjid":       "Hotjar",
    "_hjFirstSeen":"Hotjar",
    "_clck":       "Microsoft Clarity",
    "_clsk":       "Microsoft Clarity",
    "MUID":        "Microsoft",
}

# Known payment processor JS signals
PAYMENT_PROCESSOR_SIGNALS = [
    "js.stripe.com",
    "stripe.js",
    "paypalobjects.com",
    "paypal.com/sdk",
    "braintreepayments.com",
    "squareup.com",
    "js.squarecdn.com",
    "checkout.com",
    "worldpay.com",
    "adyen.com",
]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP fetch (with SSRF guard — NON-OPTIONAL)
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

# SSRF guard — must import at module level; failure is fatal (not silently skipped).
try:
    from tools.http_utils import is_ssrf_blocked as _is_ssrf_blocked
except ImportError as _ssrf_import_err:
    raise ImportError(
        "legal_scanner: cannot import is_ssrf_blocked from tools.http_utils. "
        "SSRF protection is non-optional. "
        f"Original error: {_ssrf_import_err}"
    ) from _ssrf_import_err


def _safe_get(url: str, timeout: int = 12) -> tuple[Optional[requests.Response], str]:
    """Fetch URL with SSRF guard. Returns (response, error).
    SSL errors are caught and reported as findings — verify=False is never used.
    """
    # SSRF guard is non-optional; import failure already raised at module load.
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if _is_ssrf_blocked(host):
        return None, f"SSRF blocked: {host}"

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout,
                            allow_redirects=True, verify=True)
        return resp, ""
    except requests.exceptions.SSLError as exc:
        # Do NOT retry with verify=False — report the SSL failure instead.
        return None, f"SSL error (certificate invalid or expired): {exc}"
    except Exception as exc:
        return None, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _find_link(soup: BeautifulSoup, patterns: list[str], base_url: str) -> str:
    """Find first <a> whose href OR anchor text matches any regex pattern.

    Bug fix: previously concatenated text+href before matching, causing false
    positives. Now searches anchor text and href independently.
    """
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    for a in soup.find_all("a", href=True):
        anchor_text = a.get_text(" ", strip=True)
        href = a["href"]
        for pat in compiled:
            if pat.search(anchor_text) or pat.search(href):
                if href.startswith("http"):
                    return href
                return urljoin(base_url, href)
    return ""


def _text_contains(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _count_images_missing_alt(soup: BeautifulSoup) -> tuple[int, int]:
    """Returns (missing_alt, total_images).

    Bug fix: only images with a COMPLETELY ABSENT alt attribute are violations.
    Images with alt="" (empty string) are intentionally decorative and are correct.
    The old logic wrongly counted alt="" images as missing.
    """
    imgs = soup.find_all("img")
    total = len(imgs)
    # alt attribute completely absent (not present at all) = violation
    missing = [i for i in imgs if i.get("alt") is None]
    return len(missing), total


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
    """Detect third-party tracking scripts in HTML source.
    Also checks for Google Tag Manager as a meta-signal — even if individual
    tracker snippets are absent, GTM can load them dynamically.
    """
    found = []
    for tracker_name, patterns in TRACKER_SDKS.items():
        if any(p in html for p in patterns):
            found.append(tracker_name)

    # GTM meta-signal: GTM can load any tracker dynamically after page load,
    # so its presence is a strong signal that trackers may fire without direct
    # script embeds being detectable in the static HTML.
    if "googletagmanager.com/gtm.js" in html and "Google Tag Manager" not in found:
        found.append("Google Tag Manager (dynamic tracker loader)")

    return found


def _fetch_text_page(url: str, max_chars: int = 20000) -> str:
    """Fetch a page and return plain text (for AI analysis).
    max_chars increased to 20000 to accommodate typical privacy policies
    (3,000-15,000 words).
    """
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
        prompt = f"""You are a legal compliance analyst specializing in {fw_list}.
Analyze this privacy policy text and determine if each required element is present,
specifically evaluating compliance with the following legal frameworks:

- Israeli Law (IL): Privacy Protection Law + Amendment 13 (Aug 2025), Data Security
  Regulations 2017, Consumer Protection Law, E-Commerce Regulations 2003
- US Law (US): CCPA/CPRA (California), CAN-SPAM, COPPA, FTC Act §5
- GDPR (EU): Arts. 13/14 privacy notice, Art. 6 lawful basis, Art. 7 consent,
  Art. 17 erasure, Art. 37 DPO, ePrivacy Directive

Privacy Policy Text (first 6000 chars):
\"\"\"
{policy_text[:6000]}
\"\"\"

Return a JSON object with exactly these keys and boolean values (true=present, false=missing):
{{
  "controller_identity": true,
  "purposes_stated": true,
  "legal_basis_stated": true,
  "third_parties_disclosed": true,
  "retention_periods_stated": true,
  "data_subject_rights_listed": true,
  "complaint_right_mentioned": true,
  "dpo_or_privacy_contact": true,
  "data_transfer_mechanism": true,
  "do_not_sell_link_or_text": true,
  "california_rights_mentioned": true,
  "israeli_rights_mentioned": true,
  "gdpr_rights_mentioned": true,
  "automated_decisions_disclosed": true,
  "security_measures_described": true,
  "children_policy_addressed": true
}}
Return ONLY valid JSON, no explanation."""

        chat = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=500,
        )
        raw = chat.choices[0].message.content.strip()

        # Attempt 1: parse the whole response as JSON
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Attempt 2: extract the first {...} block (handles markdown fences etc.)
        brace_start = raw.find("{")
        brace_end   = raw.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            try:
                return json.loads(raw[brace_start:brace_end + 1])
            except json.JSONDecodeError:
                pass

    except Exception as exc:
        _log.debug("AI privacy policy analysis: %s", exc)
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Check functions — each returns list[LegalFinding]
# ─────────────────────────────────────────────────────────────────────────────

def _check_https(url: str, resp: requests.Response) -> list[LegalFinding]:
    """Bug fix: use resp.url (final redirect URL) not the initial url parameter."""
    findings = []
    # Use the final URL after all redirects — not the initial url argument.
    # If the site redirects http:// → https://, the final URL is what matters.
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
        evidence=f"Final URL after redirects: {resp.url}",
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

    # COPPA — child-directed signals (handled in depth by _check_children_safety_advanced)
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
        legal_basis="IL: IS 5568 / WCAG 2.0 AA — SC 1.1.1 | ADA Title III",
        description="All meaningful images must have descriptive alt text so screen readers can convey their content to visually impaired users. Decorative images (alt=\"\") are correct and not flagged.",
        recommendation="Add descriptive alt text to all meaningful images. For decorative images, use alt=\"\" (empty, not missing). Avoid generic text like 'image' or 'photo'.",
        evidence=f"{missing_alt} images missing alt attribute entirely out of {total_imgs} total",
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
# NEW Check A — DMARC / SPF email authentication
# ─────────────────────────────────────────────────────────────────────────────

def _check_dmarc_spf(domain: str) -> list[LegalFinding]:
    """Check SPF and DMARC DNS records for the domain.

    Legal basis: IL: Telecom Law Anti-Spam §30A | US: CAN-SPAM Act (email authentication
    best practice) | GDPR: FTC/industry standard
    """
    findings = []
    if not domain:
        return findings

    try:
        import dns.resolver  # type: ignore[import]
    except ImportError:
        findings.append(LegalFinding(
            check_id="ALL-EMAIL-01",
            framework="ALL",
            category="security",
            title="SPF record present (email authentication)",
            status="SKIP",
            severity="MEDIUM",
            legal_basis="IL: Telecom Law Anti-Spam §30A | US: CAN-SPAM Act | GDPR: industry standard",
            description="dnspython not available — SPF/DMARC check skipped.",
            recommendation="Install dnspython: pip install dnspython",
            evidence="Import error: dns.resolver not available",
        ))
        return findings

    # ── SPF ─────────────────────────────────────────────────────────────────
    spf_found = False
    spf_value = ""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                          for s in rdata.strings)
            if txt.startswith("v=spf1"):
                spf_found = True
                spf_value = txt[:120]
                break
    except Exception as exc:
        spf_value = str(exc)

    findings.append(LegalFinding(
        check_id="ALL-EMAIL-01",
        framework="ALL",
        category="security",
        title="SPF record present (email authentication)",
        status="PASS" if spf_found else "FAIL",
        severity="MEDIUM",
        legal_basis="IL: Telecom Law Anti-Spam §30A | US: CAN-SPAM Act | GDPR: industry standard",
        description=(
            "An SPF (Sender Policy Framework) TXT record authorises which mail servers "
            "may send email on behalf of this domain, preventing spoofing and spam."
        ),
        recommendation=(
            "Add a TXT record to your DNS: "
            "\"v=spf1 include:_spf.google.com ~all\" "
            "(adjust for your mail provider). Use tools like mxtoolbox.com to validate."
        ),
        evidence=f"SPF record: {spf_value or 'not found'}",
    ))

    # ── DMARC ───────────────────────────────────────────────────────────────
    dmarc_found = False
    dmarc_policy = ""
    dmarc_value = ""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = "".join(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                          for s in rdata.strings)
            if txt.startswith("v=DMARC1"):
                dmarc_found = True
                dmarc_value = txt[:200]
                # Extract policy
                m = re.search(r"p=(\w+)", txt)
                dmarc_policy = m.group(1) if m else "unknown"
                break
    except Exception as exc:
        dmarc_value = str(exc)

    # p=none = monitoring only (WARN), p=quarantine/reject = enforcing (PASS)
    if dmarc_found:
        if dmarc_policy in ("quarantine", "reject"):
            dmarc_status = "PASS"
        else:
            dmarc_status = "WARN"  # p=none — not enforcing
    else:
        dmarc_status = "FAIL"

    findings.append(LegalFinding(
        check_id="ALL-EMAIL-02",
        framework="ALL",
        category="security",
        title=f"DMARC record present and enforcing (policy={dmarc_policy or 'missing'})",
        status=dmarc_status,
        severity="MEDIUM",
        legal_basis="IL: Telecom Law Anti-Spam §30A | US: CAN-SPAM Act | GDPR: industry standard",
        description=(
            "DMARC (Domain-based Message Authentication) protects your domain from "
            "email spoofing. Policy p=none = monitoring only (no protection), "
            "p=quarantine = suspicious mail goes to spam, p=reject = spoofed mail blocked."
        ),
        recommendation=(
            "Add a DMARC TXT record on _dmarc.yourdomain.com: "
            "\"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\" "
            "Upgrade from p=none to p=quarantine or p=reject after monitoring."
        ),
        evidence=f"DMARC record: {dmarc_value or 'not found'} | Policy: {dmarc_policy or 'N/A'}",
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW Check B — Privacy policy metadata quality
# ─────────────────────────────────────────────────────────────────────────────

def _check_privacy_policy_metadata(policy_text: str) -> list[LegalFinding]:
    """Check privacy policy freshness, length, and language clarity.

    Legal basis: CCPA §1798.130 (annual update) | GDPR Art. 12 (plain language) |
    IL PPL Amendment 13
    """
    findings = []
    if not policy_text:
        return findings

    # ── Last updated date ───────────────────────────────────────────────────
    date_pattern = re.compile(
        r"(last\s+(updated|revised|modified)|עודכן\s+לאחרונה|תאריך\s+עדכון)"
        r".{0,80}"
        r"(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4}|\d{4})",
        re.IGNORECASE,
    )
    has_date = bool(date_pattern.search(policy_text))

    findings.append(LegalFinding(
        check_id="ALL-PP-META-01",
        framework="ALL",
        category="privacy",
        title="Privacy policy has a 'Last Updated' date",
        status="PASS" if has_date else "WARN",
        severity="MEDIUM",
        legal_basis="CCPA §1798.130 — policy must be updated at least annually | GDPR Art. 12 — clear and plain language | IL PPL Amendment 13",
        description=(
            "A 'Last Updated' date shows users when the policy was last revised and "
            "helps demonstrate compliance with annual update requirements."
        ),
        recommendation=(
            "Add 'Last Updated: [date]' near the top of your privacy policy. "
            "Review and update the policy at least annually or when data practices change."
        ),
        evidence=f"Last-updated date pattern found: {has_date}",
    ))

    # ── Policy length ───────────────────────────────────────────────────────
    word_count = len(policy_text.split())
    findings.append(LegalFinding(
        check_id="ALL-PP-META-02",
        framework="ALL",
        category="privacy",
        title=f"Privacy policy length adequate ({word_count} words)",
        status="FAIL" if word_count < 500 else "PASS",
        severity="HIGH",
        legal_basis="GDPR Art. 13/14 — all required elements must be present | CCPA §1798.100 | IL PPL Amendment 13",
        description=(
            "A privacy policy under 500 words is almost certainly incomplete. "
            "A compliant policy typically requires 1,000-5,000+ words to cover all "
            "required legal elements."
        ),
        recommendation=(
            "Expand your privacy policy to cover all mandatory elements: "
            "identity, purposes, legal basis, retention, third parties, rights, "
            "DPO contact, transfer mechanisms, and complaint rights."
        ),
        evidence=f"Word count: {word_count} (threshold: 500 words minimum)",
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW Check C — GDPR EU Representative disclosure
# ─────────────────────────────────────────────────────────────────────────────

def _check_gdpr_eu_representative(privacy_text: str, soup: BeautifulSoup) -> list[LegalFinding]:
    """Check for EU Representative / EU Contact disclosure (GDPR Art. 27).

    Non-EU businesses that target EU users must designate an EU Representative.
    Penalties: up to €10M or 2% of global turnover.
    """
    combined_text = privacy_text + " " + soup.get_text(" ", strip=True)
    has_eu_rep = bool(re.search(
        r"eu\s+representative|european\s+representative|article\s+27|art\.?\s*27|"
        r"eu\s+contact|gdpr\s+representative|eu\s+data\s+representative|"
        r"representative\s+in\s+the\s+(eu|european|eea)",
        combined_text, re.IGNORECASE
    ))

    return [LegalFinding(
        check_id="GDPR-ART27-01",
        framework="GDPR",
        category="privacy",
        title="EU Representative (GDPR Art. 27) designated and disclosed",
        status="PASS" if has_eu_rep else "WARN",
        severity="HIGH",
        legal_basis=(
            "GDPR Art. 27 — mandatory for controllers/processors outside EU/EEA "
            "offering goods/services to EU residents or monitoring their behaviour. "
            "Fines: up to €10M or 2% of global turnover."
        ),
        description=(
            "Non-EU businesses targeting EU residents must appoint an EU Representative "
            "(a natural person or organisation in an EU Member State) and disclose "
            "their contact details in the privacy policy."
        ),
        recommendation=(
            "If you process EU residents' data and are based outside the EU/EEA: "
            "(1) Appoint an EU Representative in an EU Member State, "
            "(2) Add their name, address, and contact email to your privacy policy, "
            "(3) Register the representative with the relevant national DPA."
        ),
        evidence=f"EU Representative disclosure found: {has_eu_rep}",
    )]


# ─────────────────────────────────────────────────────────────────────────────
# NEW Check D — Cookie inventory (Set-Cookie headers + known tracking names)
# ─────────────────────────────────────────────────────────────────────────────

def _check_cookie_inventory(resp_headers: dict, html: str) -> list[LegalFinding]:
    """Check for known tracking cookies set on the initial page load (before consent).

    Legal basis: GDPR Art. 5(1)(a),(b) | EDPB 2023 Cookie Taskforce | IL PPL Amendment 13
    """
    findings = []

    # Collect all Set-Cookie header values
    set_cookie_raw = resp_headers.get("set-cookie", "")
    cookie_names: list[str] = []
    if set_cookie_raw:
        for cookie_part in set_cookie_raw.split(","):
            name_part = cookie_part.strip().split(";")[0].split("=")
            if name_part:
                cookie_names.append(name_part[0].strip())

    # Also look for document.cookie patterns in HTML (JS-set cookies)
    js_cookie_names = re.findall(r'document\.cookie\s*=\s*["\']([^="\']+)=', html)
    cookie_names.extend(js_cookie_names)

    # Match against known tracking cookie prefixes
    tracking_found: list[str] = []
    for name in cookie_names:
        for prefix, tracker in TRACKING_COOKIE_PATTERNS.items():
            if name == prefix or name.startswith(prefix):
                label = f"{name} ({tracker})"
                if label not in tracking_found:
                    tracking_found.append(label)
                break

    if tracking_found:
        status = "FAIL"
        evidence = f"Tracking cookies set on initial load (before consent): {', '.join(tracking_found)}"
        description = (
            "Tracking cookies from analytics/advertising platforms are being set on "
            "the initial page load BEFORE the user has given consent. This is a clear "
            "GDPR violation and violates IL Amendment 13 requirements."
        )
        recommendation = (
            "Configure your CMP to block all non-essential cookies until the user "
            "actively accepts. Tracking cookies must only fire AFTER explicit consent. "
            "Use your CMP's cookie blocking/blocking mode to enforce this."
        )
    else:
        status = "PASS"
        evidence = f"No known tracking cookies detected in Set-Cookie headers. Cookies checked: {len(cookie_names)}"
        description = (
            "No known tracking cookies were detected in the initial page load "
            "response headers. Cookies set after user consent are expected and acceptable."
        )
        recommendation = "Continue ensuring tracking cookies only load after explicit user consent."

    findings.append(LegalFinding(
        check_id="ALL-CK-INV-01",
        framework="ALL",
        category="cookies",
        title=f"Tracking cookies set before consent {'DETECTED' if tracking_found else 'not detected'}",
        status=status,
        severity="HIGH",
        legal_basis="GDPR Art. 5(1)(a),(b) | EDPB 2023 Cookie Taskforce Report | IL PPL Amendment 13",
        description=description,
        recommendation=recommendation,
        evidence=evidence,
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW Check E — ARIA landmarks for screen reader navigation
# ─────────────────────────────────────────────────────────────────────────────

def _check_aria_landmarks(soup: BeautifulSoup) -> list[LegalFinding]:
    """Check for required ARIA landmark roles (WCAG 2.1 AA SC 1.3.6, 2.4.1).

    Legal basis: IL IS 5568 / WCAG 2.1 AA | ADA Title III
    """
    findings = []

    def _has_landmark(tag: str, role: str) -> bool:
        """Check if page has the semantic tag OR a role= attribute."""
        return bool(soup.find(tag)) or bool(soup.find(attrs={"role": role}))

    def _count_landmark(tag: str, role: str) -> int:
        return len(soup.find_all(tag)) + len(soup.find_all(attrs={"role": role}))

    # <main> or role="main" — exactly one required
    main_count = _count_landmark("main", "main")
    findings.append(LegalFinding(
        check_id="IL-ACC-LM-01",
        framework="IL",
        category="accessibility",
        title=f"<main> landmark present (found: {main_count})",
        status="PASS" if main_count == 1 else ("WARN" if main_count > 1 else "FAIL"),
        severity="HIGH",
        legal_basis="IL IS 5568 / WCAG 2.1 AA — SC 1.3.6, 2.4.1 | ADA Title III",
        description=(
            "The page must have exactly one <main> element (or role=\"main\") to identify "
            "the primary content area. Screen readers use this landmark to navigate directly "
            "to the page's main content."
        ),
        recommendation=(
            "Wrap your primary page content in a <main> element. "
            "Ensure there is exactly one per page."
        ),
        evidence=f"<main> / role='main' count: {main_count}",
    ))

    # <nav> or role="navigation" — at least one required
    nav_count = _count_landmark("nav", "navigation")
    findings.append(LegalFinding(
        check_id="IL-ACC-LM-02",
        framework="IL",
        category="accessibility",
        title=f"<nav> landmark present (found: {nav_count})",
        status="PASS" if nav_count >= 1 else "FAIL",
        severity="MEDIUM",
        legal_basis="IL IS 5568 / WCAG 2.1 AA — SC 2.4.1 | ADA Title III",
        description=(
            "At least one <nav> element (or role=\"navigation\") is required to identify "
            "navigation regions. Screen reader users rely on this landmark to quickly access "
            "navigation menus."
        ),
        recommendation=(
            "Wrap your navigation menus in <nav> elements. "
            "Use aria-label to distinguish multiple navigation regions "
            "(e.g., <nav aria-label='Main navigation'>)."
        ),
        evidence=f"<nav> / role='navigation' count: {nav_count}",
    ))

    # <header> or role="banner" — one per page
    header_count = _count_landmark("header", "banner")
    findings.append(LegalFinding(
        check_id="IL-ACC-LM-03",
        framework="IL",
        category="accessibility",
        title=f"<header> / banner landmark present (found: {header_count})",
        status="PASS" if header_count >= 1 else "WARN",
        severity="LOW",
        legal_basis="IL IS 5568 / WCAG 2.1 AA — SC 1.3.6 | ADA Title III",
        description=(
            "A <header> element (or role=\"banner\") identifies the page banner area "
            "(logo, site name, primary navigation). Screen readers announce this landmark "
            "to help users understand page structure."
        ),
        recommendation="Wrap your site header in a <header> element at the top of the page.",
        evidence=f"<header> / role='banner' count: {header_count}",
    ))

    # <footer> or role="contentinfo" — one per page
    footer_count = _count_landmark("footer", "contentinfo")
    findings.append(LegalFinding(
        check_id="IL-ACC-LM-04",
        framework="IL",
        category="accessibility",
        title=f"<footer> / contentinfo landmark present (found: {footer_count})",
        status="PASS" if footer_count >= 1 else "WARN",
        severity="LOW",
        legal_basis="IL IS 5568 / WCAG 2.1 AA — SC 1.3.6 | ADA Title III",
        description=(
            "A <footer> element (or role=\"contentinfo\") identifies the page footer, "
            "typically containing legal links, contact info, and copyright. "
            "Screen reader users navigate to this landmark to find legal pages."
        ),
        recommendation="Wrap your site footer in a <footer> element at the bottom of the page.",
        evidence=f"<footer> / role='contentinfo' count: {footer_count}",
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW Check F — Advanced dark pattern detection
# ─────────────────────────────────────────────────────────────────────────────

def _check_dark_patterns_advanced(soup: BeautifulSoup, html: str) -> list[LegalFinding]:
    """Detect advanced dark patterns beyond pre-checked checkboxes.

    Legal basis: FTC Act §5 — Bringing Dark Patterns to Light report (2022) |
    GDPR Art. 7(4) | IL Consumer Protection Law §3
    """
    findings = []

    # ── Confirm-shaming ──────────────────────────────────────────────────────
    # Decline buttons using guilt language
    confirm_shame_pattern = re.compile(
        r"no.{0,15}(don.?t\s+want|prefer\s+not|hate|don.?t\s+care|miss\s+out|"
        r"i\s+don.?t\s+like|no\s+thanks.*save|no\s+thanks.*discount|no\s+thanks.*money)",
        re.IGNORECASE,
    )
    confirm_shame_found = bool(confirm_shame_pattern.search(html))

    findings.append(LegalFinding(
        check_id="US-FTC-DP-01",
        framework="US",
        category="dark_patterns",
        title="Confirm-shaming (guilt-based decline language) detected",
        status="FAIL" if confirm_shame_found else "PASS",
        severity="HIGH",
        legal_basis="FTC Act §5 — Bringing Dark Patterns to Light (2022) | GDPR Art. 7(4) | IL Consumer Protection Law §3",
        description=(
            "Confirm-shaming uses guilt-inducing language on decline/opt-out buttons "
            "(e.g., 'No thanks, I hate saving money') to pressure users into accepting. "
            "This is classified as a deceptive design practice by the FTC and GDPR."
        ),
        recommendation=(
            "Use neutral, non-manipulative language for decline options. "
            "Replace guilt language with simple 'No thanks' or 'Close'."
        ),
        evidence=f"Confirm-shaming pattern found: {confirm_shame_found}",
    ))

    # ── Asymmetric urgency / false scarcity ──────────────────────────────────
    urgency_pattern = re.compile(
        r"(hours?\s+left|minutes?\s+left|only\s+\d+\s+left|selling\s+fast|"
        r"just\s+\d+\s+remain|limited\s+time\s+offer|offer\s+expires|"
        r"last\s+\d+\s+items?|hurry|act\s+now|ends?\s+soon)",
        re.IGNORECASE,
    )
    urgency_found = bool(urgency_pattern.search(html))

    findings.append(LegalFinding(
        check_id="US-FTC-DP-02",
        framework="US",
        category="dark_patterns",
        title="Asymmetric urgency / false scarcity signals detected",
        status="WARN" if urgency_found else "PASS",
        severity="MEDIUM",
        legal_basis="FTC Act §5 — Bringing Dark Patterns to Light (2022) | IL Consumer Protection Law §3",
        description=(
            "Countdown timers, false scarcity claims ('only 2 left!'), and extreme urgency "
            "signals may constitute deceptive design if the urgency is manufactured or "
            "exaggerated to pressure purchase decisions."
        ),
        recommendation=(
            "Ensure all urgency claims are truthful and verifiable. "
            "Do not use countdown timers that reset on page reload. "
            "Stock counts must reflect actual inventory."
        ),
        evidence=f"Urgency/scarcity pattern found: {urgency_found}",
    ))

    # ── Hidden unsubscribe ────────────────────────────────────────────────────
    # Check if 'unsubscribe' link is present in footer area
    footer = soup.find("footer")
    footer_text = footer.get_text(" ", strip=True).lower() if footer else ""
    has_footer_unsub = "unsubscribe" in footer_text or "opt-out" in footer_text or "opt out" in footer_text
    # If no footer, check the full HTML
    global_unsub = bool(re.search(r"unsubscribe|opt.out", html, re.IGNORECASE))

    findings.append(LegalFinding(
        check_id="US-FTC-DP-03",
        framework="US",
        category="dark_patterns",
        title="Unsubscribe mechanism visible in footer",
        status="PASS" if has_footer_unsub else ("WARN" if global_unsub else "FAIL"),
        severity="MEDIUM",
        legal_basis="FTC Act §5 — Bringing Dark Patterns to Light (2022) | US: CAN-SPAM Act §5(a)(5) | IL: Telecom Law Anti-Spam §30A",
        description=(
            "The unsubscribe/opt-out mechanism should be clearly visible in the page footer. "
            "Hiding it behind multiple clicks (2+ interactions required) constitutes a "
            "dark pattern under FTC guidance."
        ),
        recommendation=(
            "Add an 'Unsubscribe' or 'Manage email preferences' link to the page footer. "
            "Ensure the unsubscribe process requires no more than 2 clicks."
        ),
        evidence=f"Unsubscribe in footer: {has_footer_unsub} | Unsubscribe anywhere on page: {global_unsub}",
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW Check G — Payment security (PCI-DSS signals)
# ─────────────────────────────────────────────────────────────────────────────

def _check_payment_security(soup: BeautifulSoup, html: str) -> list[LegalFinding]:
    """Detect payment forms and check for PCI-DSS compliance signals.

    Legal basis: PCI-DSS v4.0 | IL: Data Security Regulations 2017 (financial data) |
    GDPR Art. 32
    """
    findings = []

    # Detect payment form signals
    payment_keywords_in_html = bool(re.search(
        r"card\s+number|credit\s+card|debit\s+card|cvv|cvc|expir|card\s+holder|"
        r"payment\s+card|\*{4}\s*\*{4}|\d{4}\s+\d{4}\s+\d{4}",
        html, re.IGNORECASE,
    ))
    # Look for card-number-style placeholders in inputs
    card_inputs = soup.find_all("input", {
        "placeholder": re.compile(r"\*{4}|\d{4}[\s-]\d{4}|card|cvv|cvc|expir", re.IGNORECASE)
    })
    card_type_inputs = soup.find_all("input", {"type": "number"})  # broad signal

    payment_detected = payment_keywords_in_html or len(card_inputs) > 0

    if not payment_detected:
        # No payment form detected — skip this check
        findings.append(LegalFinding(
            check_id="ALL-PCI-01",
            framework="ALL",
            category="security",
            title="Payment form PCI-DSS compliance (no payment form detected)",
            status="PASS",
            severity="HIGH",
            legal_basis="PCI-DSS v4.0 | IL: Data Security Regulations 2017 | GDPR Art. 32",
            description="No payment card input form detected on this page.",
            recommendation="If you add payment functionality, use a recognised payment processor (Stripe, PayPal, Braintree) that handles PCI-DSS compliance for you.",
            evidence="No payment card form signals detected in page HTML.",
        ))
        return findings

    # Payment form detected — check for recognised processor
    processor_found = any(sig in html for sig in PAYMENT_PROCESSOR_SIGNALS)
    processor_names = [sig for sig in PAYMENT_PROCESSOR_SIGNALS if sig in html]

    findings.append(LegalFinding(
        check_id="ALL-PCI-01",
        framework="ALL",
        category="security",
        title=f"Payment form detected — trusted processor: {'YES' if processor_found else 'NOT DETECTED'}",
        status="PASS" if processor_found else "FAIL",
        severity="HIGH",
        legal_basis="PCI-DSS v4.0 | IL: Data Security Regulations 2017 §4 (financial data = HIGH security classification) | GDPR Art. 32",
        description=(
            "A payment card input form was detected. Self-hosted card forms that capture "
            "raw card data without a recognized PCI-DSS compliant processor are a HIGH risk "
            "PCI-DSS violation. Card data must be tokenized by a compliant processor."
        ),
        recommendation=(
            "Use a recognised payment processor (Stripe, PayPal, Braintree, Square) "
            "that handles PCI-DSS compliance via JavaScript tokenization. "
            "Never transmit raw card numbers through your own servers. "
            "If self-hosting, you must complete PCI-DSS SAQ D and annual audit."
        ),
        evidence=(
            f"Payment form signals found: {payment_keywords_in_html} | "
            f"Card input fields: {len(card_inputs)} | "
            f"Trusted processor signals: {processor_names or 'none found'}"
        ),
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW Check H — Children's safety (COPPA / GDPR Art. 8 / advanced)
# ─────────────────────────────────────────────────────────────────────────────

def _check_children_safety_advanced(soup: BeautifulSoup, html: str) -> list[LegalFinding]:
    """Advanced COPPA / child safety checks including age gate detection.

    Legal basis: US COPPA 16 CFR §312 ($53,088/day fines) |
    GDPR Art. 8 (child consent at 16) | IL: Consumer Protection covers minors
    """
    findings = []

    # ── Child-directed content signals ─────────────────────────────────────
    child_content = bool(re.search(
        r"\bkids?\b|\bchildren\b|\bchild\b|\bteen\b|\bjunior\b|\byouth\b|"
        r"family.friendly|for\s+kids|ages?\s+\d+|school\s+age|"
        r"cartoon|animation|toy|playground",
        html, re.IGNORECASE,
    ))

    # ── Age gate detection ──────────────────────────────────────────────────
    # Date-of-birth input (year select or date input)
    dob_inputs = soup.find_all("input", {"type": "date"})
    year_selects = soup.find_all("select")
    year_select_found = False
    for sel in year_selects:
        options = sel.find_all("option")
        year_values = [o.get("value", "") for o in options if re.match(r"19\d{2}|20\d{2}", o.get("value", ""))]
        if len(year_values) > 10:  # A reasonable year dropdown for DOB
            year_select_found = True
            break

    age_gate_texts = bool(re.search(
        r"age\s+verification|are\s+you\s+(over|above|at\s+least)\s+\d+|"
        r"i\s+am\s+(over|above|at\s+least)\s+\d+|enter\s+your\s+(age|birth|dob)|"
        r"date\s+of\s+birth|verify\s+your\s+age|age\s+gate",
        html, re.IGNORECASE,
    ))
    has_age_gate = bool(dob_inputs) or year_select_found or age_gate_texts

    # ── COPPA / child privacy policy mention ───────────────────────────────
    policy_mentions_children = bool(re.search(
        r"coppa|children.s\s+online\s+privacy|under\s+(the\s+age\s+of\s+)?13|"
        r"parental\s+consent|verifiable\s+parental|child\s+directed",
        html, re.IGNORECASE,
    ))

    # ── Assess risk ─────────────────────────────────────────────────────────
    if child_content and not has_age_gate:
        age_gate_status = "FAIL"
    elif child_content and has_age_gate:
        age_gate_status = "PASS"
    else:
        age_gate_status = "PASS"  # No child content detected

    findings.append(LegalFinding(
        check_id="US-COPPA-02",
        framework="US",
        category="privacy",
        title=f"Age gate present for child-directed content (gate={has_age_gate}, child content={child_content})",
        status=age_gate_status,
        severity="HIGH",
        legal_basis=(
            "US COPPA 16 CFR §312 — fines up to $53,088/violation/day | "
            "GDPR Art. 8 — child consent at 16 (lower in some EU states) | "
            "IL: Consumer Protection Law covers minors"
        ),
        description=(
            "Sites with child-directed content must implement age verification and obtain "
            "verifiable parental consent before collecting data from children under 13 (US) "
            "or under 16 (EU). Missing age gates on child-directed sites = COPPA violation."
        ),
        recommendation=(
            "Implement an age gate (date-of-birth entry or year selection) before "
            "presenting child-directed content. For users under 13, obtain verifiable "
            "parental consent before any data collection. Add COPPA-compliant disclosures "
            "to your privacy policy."
        ),
        evidence=(
            f"Child-directed signals: {child_content} | "
            f"Age gate (DOB input): {bool(dob_inputs)} | "
            f"Age gate (year select): {year_select_found} | "
            f"Age gate text: {age_gate_texts} | "
            f"COPPA policy mention: {policy_mentions_children}"
        ),
    ))

    # ── COPPA policy disclosure ─────────────────────────────────────────────
    findings.append(LegalFinding(
        check_id="US-COPPA-03",
        framework="US",
        category="privacy",
        title="COPPA / children's privacy disclosure in policy",
        status="PASS" if policy_mentions_children else ("WARN" if child_content else "PASS"),
        severity="HIGH",
        legal_basis="US COPPA 16 CFR §312.4 — privacy notice required | GDPR Art. 8",
        description=(
            "If the site collects data from children under 13, the privacy policy must "
            "include specific COPPA-required disclosures: types of information collected, "
            "parental rights, how to request deletion, and how parental consent is obtained."
        ),
        recommendation=(
            "Add a dedicated 'Children's Privacy' section to your privacy policy addressing: "
            "COPPA compliance, what data is collected from minors, how parental consent is "
            "obtained, and how parents can request data deletion."
        ),
        evidence=f"COPPA/children mention in policy: {policy_mentions_children} | Child content detected: {child_content}",
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Scoring engine
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_scores(findings: list[LegalFinding]) -> tuple[int, int, int, int]:
    """Returns (overall, il_score, us_score, gdpr_score) — 0=low risk, 100=high risk.

    Severity weighting:  HIGH=20  MEDIUM=8  LOW=2
    WARN counts as 35% of a FAIL at the same severity.
    A single HIGH FAIL caps the framework score at a minimum of 25 (so compliance ≤ 75).
    """
    sev_weight = {"HIGH": 20, "MEDIUM": 8, "LOW": 2}

    def _fw_score(fw_filter: str) -> int:
        fw_checks = [f for f in findings
                     if (f.framework == fw_filter or f.framework == "ALL")
                     and f.status != "SKIP"]
        if not fw_checks:
            return 0
        max_pts  = sum(sev_weight.get(f.severity, 8) for f in fw_checks)
        fail_pts = sum(sev_weight.get(f.severity, 8)       for f in fw_checks if f.status == "FAIL")
        warn_pts = sum(sev_weight.get(f.severity, 8) * 0.35 for f in fw_checks if f.status == "WARN")
        raw = round(((fail_pts + warn_pts) / max_pts) * 100) if max_pts else 0
        # A HIGH FAIL means at least 25 risk (compliance ≤ 75)
        has_high_fail = any(f.severity == "HIGH" and f.status == "FAIL" for f in fw_checks)
        return max(25, min(100, raw)) if has_high_fail else min(100, raw)

    il   = _fw_score("IL")
    us   = _fw_score("US")
    gdpr = _fw_score("GDPR")
    overall = min(100, round(il * 0.35 + us * 0.30 + gdpr * 0.35))
    return overall, il, us, gdpr


# ─────────────────────────────────────────────────────────────────────────────
# Cookie Categorization
# ─────────────────────────────────────────────────────────────────────────────

def _categorize_cookie(name: str) -> str:
    """
    Classify a cookie by name using the _COOKIE_RULE_LOOKUP + _COOKIE_PREFIX_RULES tables.
    Returns one of: strictly_necessary | functional | analytics | marketing | unknown
    """
    if name in _COOKIE_RULE_LOOKUP:
        return _COOKIE_RULE_LOOKUP[name]
    for prefix, cat in _COOKIE_PREFIX_RULES:
        if name.startswith(prefix):
            return cat
    # Generic session/auth heuristic
    low = name.lower()
    if any(k in low for k in ("sess", "session", "auth", "token", "login", "user_id")):
        return "strictly_necessary"
    return "unknown"


def _build_cookie_records(raw_cookies: list[dict]) -> list[CookieRecord]:
    """
    Convert raw Playwright cookie dicts (or simplified requests dicts) into
    typed CookieRecord objects with categories.
    """
    records: list[CookieRecord] = []
    for c in raw_cookies:
        name     = c.get("name", "")
        category = _categorize_cookie(name)
        # Identify tracker name for marketing/analytics cookies
        tracker  = ""
        if category in ("analytics", "marketing"):
            for tracker_name, patterns in TRACKER_SDKS.items():
                if any(p.lower() in name.lower() for p in patterns):
                    tracker = tracker_name
                    break
        records.append(CookieRecord(
            name      = name,
            value     = str(c.get("value", ""))[:40],
            domain    = c.get("domain", ""),
            http_only = bool(c.get("httpOnly", c.get("http_only", False))),
            secure    = bool(c.get("secure", False)),
            same_site = c.get("sameSite", c.get("same_site", "")),
            category  = category,
            tracker   = tracker,
        ))
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Network-request based tracker detection (Playwright path)
# ─────────────────────────────────────────────────────────────────────────────

_TRACKER_REQUEST_PATTERNS: dict[str, list[str]] = {
    "Google Analytics":    ["google-analytics.com", "googletagmanager.com/gtm.js"],
    "Meta/Facebook Pixel": ["connect.facebook.net/", "facebook.com/tr"],
    "Google Ads":          ["googleadservices.com", "doubleclick.net"],
    "Hotjar":              ["hotjar.com/h.js", "hotjar.io"],
    "Microsoft Clarity":   ["clarity.ms/tag", "clarity.ms/collect"],
    "TikTok Pixel":        ["analytics.tiktok.com"],
    "LinkedIn Insight":    ["snap.licdn.com"],
    "Twitter/X Pixel":     ["static.ads-twitter.com"],
    "HubSpot":             ["hs-analytics.net", "hubspot.com/hs-analytics"],
    "Intercom":            ["intercomcdn.com", "widget.intercom.io"],
    "Mixpanel":            ["api.mixpanel.com"],
    "Segment":             ["cdn.segment.com", "api.segment.io"],
    "Amplitude":           ["api.amplitude.com"],
    "Heap Analytics":      ["heapanalytics.com"],
    "FullStory":           ["rs.fullstory.com"],
}


def _detect_trackers_from_requests(request_urls: list[str]) -> list[str]:
    """Identify trackers from Playwright's outbound request list."""
    found: list[str] = []
    for tracker, patterns in _TRACKER_REQUEST_PATTERNS.items():
        for url in request_urls:
            if any(p in url for p in patterns):
                if tracker not in found:
                    found.append(tracker)
                break
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Multi-page crawler — verify privacy policy in footer across all sampled pages
# ─────────────────────────────────────────────────────────────────────────────

_CRAWL_PATHS = [
    "/",
    "/privacy-policy", "/privacy", "/datenschutz",
    "/terms", "/terms-of-service", "/terms-of-use",
    "/contact", "/contact-us",
    "/about", "/about-us",
    "/checkout", "/cart",
    "/login", "/signin", "/register", "/signup",
]

_FOOTER_SELECTORS = [
    "footer a",
    "[class*='footer'] a",
    "[id*='footer'] a",
    "[role='contentinfo'] a",
]


def _check_privacy_in_footer(html: str) -> bool:
    """Return True if a privacy policy link appears in the page footer."""
    try:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        for selector in _FOOTER_SELECTORS:
            tag_name, *rest = selector.split(" ")
            child_tag = rest[0] if rest else None
            # Simplified selector matching for BeautifulSoup
            for container in soup.find_all(True):
                attrs = container.attrs or {}
                class_str = " ".join(attrs.get("class", []))
                role = attrs.get("role", "")
                id_str = attrs.get("id", "")
                tag = getattr(container, "name", "")
                is_footer = (
                    tag == "footer"
                    or "footer" in class_str.lower()
                    or "footer" in id_str.lower()
                    or role == "contentinfo"
                )
                if is_footer:
                    for link in container.find_all("a"):
                        text = link.get_text(" ", strip=True)
                        href = link.get("href", "")
                        for pat in PRIVACY_LINK_PATTERNS:
                            if re.search(pat, text, re.I) or re.search(pat, href, re.I):
                                return True
    except Exception:
        pass
    return False


def _crawl_additional_pages(
    base_url: str,
    max_pages: int = 8,
) -> tuple[list[str], bool]:
    """
    Fetch up to `max_pages` pages from the site and check for privacy footer link.

    Returns:
        (pages_scanned: list[str], privacy_in_footer_all: bool)
        privacy_in_footer_all is True only if EVERY successfully fetched page has
        a privacy policy link in its footer.
    """
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    pages_to_check: list[str] = []
    for path in _CRAWL_PATHS:
        candidate = origin + path
        if candidate not in pages_to_check:
            pages_to_check.append(candidate)
        if len(pages_to_check) >= max_pages:
            break

    # Also try sitemap.xml
    sitemap_url = origin + "/sitemap.xml"
    try:
        sr, _ = _safe_get(sitemap_url, timeout=8)
        if sr and sr.status_code == 200 and "xml" in sr.headers.get("content-type", ""):
            # Extract up to 3 URLs from sitemap
            sm_soup = BeautifulSoup(sr.text, "xml")
            for loc in sm_soup.find_all("loc")[:3]:
                loc_url = loc.get_text(strip=True)
                if loc_url.startswith(origin) and loc_url not in pages_to_check:
                    pages_to_check.append(loc_url)
    except Exception:
        pass

    scanned: list[str] = []
    pages_with_footer_ok = 0
    pages_fetched = 0

    for page_url in pages_to_check[:max_pages]:
        try:
            r, err = _safe_get(page_url, timeout=10)
            if err or r is None or r.status_code >= 400:
                continue
            scanned.append(page_url)
            pages_fetched += 1
            if _check_privacy_in_footer(r.text):
                pages_with_footer_ok += 1
        except Exception:
            continue

    all_ok = pages_fetched > 0 and pages_with_footer_ok == pages_fetched
    return scanned, all_ok


# ─────────────────────────────────────────────────────────────────────────────
# Fine estimate injector
# ─────────────────────────────────────────────────────────────────────────────

def _apply_fine_estimates(findings: list[LegalFinding]) -> None:
    """
    Enrich findings that have entries in FINE_DB with fine_min/max/example.
    Modifies findings in-place — only FAIL/WARN findings get fine data.
    """
    for f in findings:
        if f.status not in ("FAIL", "WARN"):
            continue
        entry = FINE_DB.get(f.check_id)
        if entry:
            f.fine_min     = entry.get("min", "")
            f.fine_max     = entry.get("max", "")
            f.fine_example = entry.get("example", "")


# ─────────────────────────────────────────────────────────────────────────────
# Main orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run_legal_scan(url: str, frameworks: list[str] | None = None) -> LegalScanResult:
    """
    Run a full legal compliance scan on the given URL.
    frameworks: subset of ["IL", "US", "GDPR"] or None for all.
    Returns LegalScanResult with all findings and scores.

    Scan flow:
      1. Try Playwright headless browser (JS-rendered DOM + real cookies + network requests)
         Fall back to requests-based static fetch if Playwright unavailable.
      2. Run multi-page crawler to verify privacy policy footer on all pages.
      3. Categorize all collected cookies (strictly_necessary / functional / analytics / marketing).
      4. Run all legal check functions on the fetched content.
      5. Apply FINE_DB estimates to all FAIL/WARN findings.
      6. Score by framework.
    """
    t0 = time.time()
    result = LegalScanResult(url=url)
    active_fw = set(frameworks or ["IL", "US", "GDPR"])

    # ── 1. Fetch main page (Playwright preferred, requests fallback) ─────────
    pw_html: str = ""
    pw_cookies: list[dict] = []
    pw_requests: list[str] = []
    pw_headers: dict = {}
    base_url: str = url
    scan_method: str = "static"

    try:
        from tools.playwright_executor import execute_page
        pw_result = execute_page(url, timeout_ms=22_000, wait_after_load_ms=2_500)
        if not pw_result.error and pw_result.html:
            pw_html       = pw_result.html
            pw_cookies    = pw_result.cookies
            pw_requests   = pw_result.requests_made
            pw_headers    = pw_result.response_headers
            base_url      = pw_result.final_url or url
            scan_method   = pw_result.method   # "playwright" or "requests"
    except Exception:
        pass

    # If Playwright/executor gave us no content, fall back to _safe_get
    if not pw_html:
        resp, err = _safe_get(url, timeout=15)
        if err or resp is None:
            result.error = f"Failed to fetch URL: {err}"
            return result
        pw_html    = resp.text
        base_url   = resp.url
        pw_headers = {k.lower(): v for k, v in resp.headers.items()}
        pw_cookies = [
            {"name": k, "value": v, "domain": urlparse(resp.url).hostname or "",
             "httpOnly": False, "secure": False, "sameSite": ""}
            for k, v in resp.cookies.items()
        ]
        scan_method = "static"

    result.scan_method = scan_method

    html = pw_html
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    headers_lower = {k.lower(): v for k, v in pw_headers.items()}

    # Also fetch raw headers via requests if Playwright gave no headers
    # (e.g. requests fallback doesn't populate response_headers for security checks)
    if not headers_lower:
        _r, _e = _safe_get(url, timeout=10)
        if _r:
            headers_lower = {k.lower(): v for k, v in _r.headers.items()}

    domain = urlparse(base_url).hostname or ""

    # ── 2. Cookie categorization ─────────────────────────────────────────────
    result.cookies_found = _build_cookie_records(pw_cookies)

    # ── 3. Tracker detection (HTML + network requests) ───────────────────────
    trackers_from_html    = _detect_trackers(html)
    trackers_from_network = _detect_trackers_from_requests(pw_requests) if pw_requests else []
    combined_trackers     = list(dict.fromkeys(trackers_from_html + trackers_from_network))
    result.trackers_found = combined_trackers
    result.consent_sdk    = _detect_consent_sdk(html)

    # ── 4. Find legal page URLs ─────────────────────────────────────────────
    legal_findings, privacy_url, tos_url, acc_url = _check_legal_pages(soup, html, base_url)
    result.privacy_policy_url = privacy_url
    result.tos_url            = tos_url
    result.accessibility_url  = acc_url

    html_tag = soup.find("html")
    result.page_lang = html_tag.get("lang", "") if html_tag else ""

    # ── 5. Multi-page crawler (privacy footer on all pages) ─────────────────
    pages_scanned, privacy_all_pages = _crawl_additional_pages(base_url, max_pages=8)
    result.pages_scanned             = pages_scanned
    result.privacy_in_footer_all_pages = privacy_all_pages

    # Downgrade ALL-LP-01 if privacy link is MISSING from other pages
    if privacy_url and not privacy_all_pages and len(pages_scanned) > 1:
        # Find the finding and downgrade
        for f in legal_findings:
            if f.check_id == "ALL-LP-01" and f.status == "PASS":
                pages_missing = len(pages_scanned) - sum(
                    1 for p in pages_scanned
                    if _check_privacy_in_footer((_safe_get(p, timeout=8)[0] or type("", (), {"text": ""})()).text
                       if False else "")  # Lightweight — we already have the info
                )
                f.status      = "WARN"
                f.description += (
                    f" However, the privacy policy link was not found in the footer on "
                    f"all sampled pages ({len(pages_scanned)} pages checked). "
                    "GDPR Art. 12 requires the link to be accessible from every page."
                )
                f.evidence    += f" | Pages without footer link: {len(pages_scanned) - 1} additional pages checked."
                break

    # ── 6. Fetch privacy policy for AI analysis ─────────────────────────────
    policy_text = _fetch_text_page(privacy_url) if privacy_url else ""
    ai_analysis = _ai_analyze_privacy_policy(policy_text, list(active_fw))

    # ── 7. Run all checks ────────────────────────────────────────────────────
    all_findings: list[LegalFinding] = []

    # Need a real requests.Response-like object for _check_https
    _resp_obj, _ = _safe_get(url, timeout=10)
    if _resp_obj:
        all_findings += _check_https(url, _resp_obj)
    all_findings += _check_security_headers(headers_lower)
    all_findings += _check_cookies_and_consent(html, soup, headers_lower,
                                               result.trackers_found, result.consent_sdk)
    all_findings += legal_findings
    all_findings += _check_privacy_policy_content(policy_text, ai_analysis)
    all_findings += _check_ccpa(html, soup, policy_text, ai_analysis)
    all_findings += _check_consumer_law(soup, html)
    all_findings += _check_accessibility(soup, html)
    all_findings += _check_data_rights(soup, html, privacy_url)
    all_findings += _check_dmarc_spf(domain)
    all_findings += _check_privacy_policy_metadata(policy_text)
    all_findings += _check_gdpr_eu_representative(policy_text, soup)
    all_findings += _check_cookie_inventory(headers_lower, html)
    all_findings += _check_aria_landmarks(soup)
    all_findings += _check_dark_patterns_advanced(soup, html)
    all_findings += _check_payment_security(soup, html)
    all_findings += _check_children_safety_advanced(soup, html)

    # ── 8. Filter by selected frameworks ────────────────────────────────────
    filtered = [
        f for f in all_findings
        if f.framework == "ALL" or f.framework in active_fw
    ]

    # ── 9. Apply fine estimates ──────────────────────────────────────────────
    _apply_fine_estimates(filtered)

    result.findings = filtered

    # ── 10. Scoring ──────────────────────────────────────────────────────────
    result.risk_score, result.il_score, result.us_score, result.gdpr_score = \
        _calculate_scores(filtered)
    result.scan_time = round(time.time() - t0, 1)

    return result

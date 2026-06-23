"""
active_verifier.py — AI Cyber Shield v6

Active Vulnerability Verification Engine.

AUTHORISATION REQUIREMENT (MANDATORY)
──────────────────────────────────────
This module sends live HTTP probes to target endpoints. It MUST only be used:
  • On infrastructure you own or operate.
  • Under an authorised penetration testing engagement with written scope.
  • In authorised bug-bounty programmes within scope boundaries.
Using this module against systems without explicit written permission is
unlawful and violates Anthropic's usage policies.

Architecture
────────────
SafePayloadFactory  — constructs non-destructive, canary-token-based payloads.
                      Enforces an ethical gate that rejects any payload containing
                      destructive patterns before it ever reaches the network.

ActiveProber        — async HTTP probe dispatcher.  Uses httpx.AsyncClient with
                      a hard 5-second timeout and follow_redirects=False (giving
                      the ResponseOracle access to the raw redirect).

ResponseOracle      — analyses raw HTTP responses (status, headers, body) for
                      exploitation signatures.  Returns a (confirmed, confidence)
                      tuple per vulnerability type.

ActiveVerifier      — public facade.  Wires factory → prober → oracle into a
                      single async call: verify_vulnerability().

Supported vulnerability types
──────────────────────────────
  OPEN_REDIRECT          — 30x Location header matches canary domain
  REFLECTED_XSS          — canary string reflects unescaped in response DOM
  CORS_MISCONFIGURATION  — ACAO echoes attacker origin + credentials enabled
  PATH_TRAVERSAL         — /robots.txt content confirms directory escape
  HOST_HEADER_INJECTION  — injected Host echoed in Location or body
  SSTI                   — safe math expression (7×7=49) evaluated in response
  CRLF_INJECTION         — injected header appears in response headers

Ethical failsafes (non-negotiable)
───────────────────────────────────
  ✗ NO destructive payloads: rm -rf, DROP TABLE, system commands, shellcode
  ✗ NO blind SSRF: all targets checked against is_ssrf_blocked() before probe
  ✗ NO amplification: max 3 probes per vulnerability, 5-second timeout each
  ✗ NO confirmation on WAF block: 403/WAF → status=BLOCKED_BY_ACTIVE_DEFENSE
  ✓ All payloads use IANA-reserved example.com canary domain
  ✓ XSS canaries are non-executable HTML comment strings
  ✓ Path traversal targets public /robots.txt, never /etc/passwd or /etc/shadow
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, urljoin, quote

import httpx

from tools.http_utils import is_ssrf_blocked

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# IANA-reserved canary domain — safe by definition
_CANARY_DOMAIN     = "aics-probe.example.com"
_CANARY_PATH       = "/active-verify"
_CANARY_ORIGIN     = f"https://{_CANARY_DOMAIN}"

# Public file content we expect from a successful path traversal to /robots.txt
_ROBOTS_SIGNATURES = (
    "user-agent",
    "disallow",
    "allow",
    "sitemap",
    "crawl-delay",
)

# SSTI: safe arithmetic expression → look for integer result in response
_SSTI_EXPRESSION   = "7777"   # 7*11*101 — unlikely to appear randomly
_SSTI_PROBES       = [
    "{{7*1111}}",            # Jinja2 / Twig / Pebble
    "${7*1111}",             # Freemarker / Thymeleaf
    "#{7*1111}",             # Groovy / Spring Expression
    "<%= 7*1111 %>",         # ERB / Mako
    "*{7*1111}",             # Spring SpEL
]

# CRLF injection: safe header name that doesn't shadow any standard header
_CRLF_CANARY_HEADER = "X-AICS-Probe"
_CRLF_PAYLOADS       = [
    f"\r\n{_CRLF_CANARY_HEADER}: canary1",
    f"%0d%0a{_CRLF_CANARY_HEADER}: canary2",
    f"\r\n\t{_CRLF_CANARY_HEADER}: canary3",
]

# Path traversal depths and targets
_TRAVERSAL_DEPTHS  = (2, 3, 4, 5)
_TRAVERSAL_TARGET  = "robots.txt"
_WIN_SEP           = "..\\"
_TRAVERSAL_PATHS   = [
    *[("../" * d) + _TRAVERSAL_TARGET for d in _TRAVERSAL_DEPTHS],
    *[(_WIN_SEP * d) + _TRAVERSAL_TARGET for d in _TRAVERSAL_DEPTHS],
    *[("%2e%2e%2f" * d) + _TRAVERSAL_TARGET for d in _TRAVERSAL_DEPTHS],
]

# Active probe timeout — HARD CAP to prevent DoS conditions
_PROBE_TIMEOUT_SECONDS = 5.0
_MAX_PROBES_PER_VULN   = 3

# Maximum response body bytes read per probe
_MAX_RESPONSE_BYTES = 128 * 1024  # 128 KB

# ─────────────────────────────────────────────────────────────────────────────
# ETHICAL GATE — destructive pattern registry
# Any payload containing one of these strings is REJECTED before dispatch.
# ─────────────────────────────────────────────────────────────────────────────

_FORBIDDEN_PAYLOAD_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # Shell execution
        r"\brm\s+-rf\b", r"\bsudo\b", r"\bchmod\b", r"\bchown\b",
        r";\s*id\b", r";\s*whoami\b", r";\s*cat\s+/", r";\s*ls\b",
        r"\bwget\b", r"\bcurl\b", r"\bnc\b", r"\bnetcat\b",
        r"\bsh\b\s+-c", r"\bbash\b\s+-c", r"\bpython\b\s+-c",
        r"\bexec\b", r"\beval\b", r"\bsystem\b\s*\(",
        # Database destruction
        r"drop\s+table", r"drop\s+database", r"truncate\s+table",
        r"delete\s+from", r"insert\s+into", r"update\s+\w+\s+set",
        # Path escalation to sensitive files
        r"/etc/passwd", r"/etc/shadow", r"/etc/hosts",
        r"c:\\windows\\system32", r"win\.ini", r"boot\.ini",
        # Deserialization / polyglot
        r"serializ", r"unserializ", r"__import__", r"os\.system",
        r"subprocess\.(run|Popen|call)",
        # Network pivoting
        r"169\.254\.169\.254",    # AWS IMDS
        r"metadata\.google\.internal",
        r"100\.100\.100\.200",    # Alibaba IMDS
    )
)


def _assert_payload_safe(payload: str, context: str = "") -> None:
    """
    Ethical gate — raises EthicalViolationError if the payload contains any
    destructive pattern.  Called on EVERY payload before network dispatch.
    """
    for pattern in _FORBIDDEN_PAYLOAD_PATTERNS:
        if pattern.search(payload):
            raise EthicalViolationError(
                f"Payload rejected by ethical gate [{context}]: "
                f"matched forbidden pattern '{pattern.pattern}'. "
                f"Payload snippet: {payload[:80]!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# WAF block detection (inlined from stealth_http_client patterns)
# ─────────────────────────────────────────────────────────────────────────────

_WAF_ABORT_STATUSES = frozenset({403, 406, 429, 503})

_WAF_BODY_RE = re.compile(
    r"cloudflare|cf-ray|cf_chl_opt|Turnstile"
    r"|incapsula|visid_incap"
    r"|akamai|AccessDenied"
    r"|aws-?waf|Request\s+blocked"
    r"|datadome|dd_cookie"
    r"|BIG-IP|F5\s+Networks"
    r"|blocked|captcha|hcaptcha|recaptcha|robot check",
    re.IGNORECASE,
)

_WAF_HEADER_KEYS = frozenset({
    "cf-ray", "cf-cache-status", "x-iinfo", "x-amzn-waf",
    "x-akamai-transformed", "x-datadome",
})


def _detect_waf_block(
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> str | None:
    """
    Returns a WAF name string if the response looks like a WAF block,
    or None if the response appears clean.
    """
    if status_code not in _WAF_ABORT_STATUSES:
        return None

    lower_hdrs = {k.lower(): v for k, v in headers.items()}
    body_sample = body[:4096]

    # Header fingerprints
    hit_header = next(
        (k for k in _WAF_HEADER_KEYS if k in lower_hdrs), None
    )
    # Body fingerprints
    body_match = _WAF_BODY_RE.search(body_sample)

    if hit_header:
        return f"WAF-header:{hit_header}"
    if body_match:
        return f"WAF-body:{body_match.group(0)[:30]}"
    if status_code in _WAF_ABORT_STATUSES and (
        "block" in body_sample.lower()
        or "captcha" in body_sample.lower()
    ):
        return "WAF-generic"

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class VulnType(str, Enum):
    OPEN_REDIRECT         = "OPEN_REDIRECT"
    REFLECTED_XSS         = "REFLECTED_XSS"
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION"
    PATH_TRAVERSAL        = "PATH_TRAVERSAL"
    HOST_HEADER_INJECTION = "HOST_HEADER_INJECTION"
    SSTI                  = "SSTI"
    CRLF_INJECTION        = "CRLF_INJECTION"


class VerificationStatus(str, Enum):
    CONFIRMED                 = "CONFIRMED"
    NOT_CONFIRMED             = "NOT_CONFIRMED"
    BLOCKED_BY_ACTIVE_DEFENSE = "BLOCKED_BY_ACTIVE_DEFENSE"
    SSRF_BLOCKED              = "SSRF_BLOCKED"
    TIMEOUT                   = "TIMEOUT"
    ERROR                     = "ERROR"
    ETHICAL_VIOLATION         = "ETHICAL_VIOLATION"


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class WafBlockError(Exception):
    """Raised when a WAF block is detected during active probing."""
    def __init__(self, waf_signature: str, status_code: int) -> None:
        self.waf_signature = waf_signature
        self.status_code   = status_code
        super().__init__(
            f"WAF block detected ({waf_signature}) — HTTP {status_code}. "
            "Aborting verification session."
        )


class EthicalViolationError(Exception):
    """Raised when a payload fails the ethical safety gate."""


class SsrfBlockError(Exception):
    """Raised when the target endpoint resolves to a blocked (internal) address."""


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProbeRequest:
    """
    Exact representation of the HTTP request dispatched to the target.
    Captured before sending so the engineer can reproduce the probe manually.
    """
    method:       str
    url:          str
    headers:      dict[str, str] = field(default_factory=dict)
    params:       dict[str, str] = field(default_factory=dict)
    body:         str | None     = None
    allow_redirects: bool        = False

    def to_curl(self) -> str:
        """Generate a curl one-liner for manual reproduction."""
        parts = ["curl", "-v", "--max-time 5"]

        if not self.allow_redirects:
            parts.append("--no-location")
        else:
            parts.append("-L")

        for k, v in self.headers.items():
            # Never leak auth tokens in reproduction commands
            if k.lower() in ("authorization", "cookie"):
                v = "<REDACTED>"
            parts.append(f"-H '{k}: {v}'")

        if self.body:
            _assert_payload_safe(self.body, "curl-body")
            parts.append(f"-d '{self.body}'")
            parts.append(f"-X {self.method}")

        # Build URL with params
        target_url = self.url
        if self.params:
            qs = urlencode(self.params)
            target_url = f"{self.url}?{qs}" if "?" not in self.url else f"{self.url}&{qs}"

        _assert_payload_safe(target_url, "curl-url")
        parts.append(f"'{target_url}'")
        return " ".join(parts)


@dataclass
class ResponseSummary:
    """Compact view of the HTTP response stored in VerificationResult."""
    status_code:    int
    location:       str | None
    content_type:   str | None
    acao_header:    str | None   # Access-Control-Allow-Origin
    acac_header:    str | None   # Access-Control-Allow-Credentials
    body_snippet:   str          # first 500 chars, safe to log
    response_time:  float


@dataclass
class VerificationResult:
    """
    Structured output of a single vulnerability verification run.
    This is the Proof-of-Concept Oracle output.
    """
    vuln_type:         VulnType
    status:            VerificationStatus
    is_confirmed:      bool
    confidence_score:  float              # 0.0 → 1.0
    canary_token:      str
    endpoint:          str
    parameter:         str

    # The exact HTTP request dispatched — engineer can replay it
    raw_poc_request:   ProbeRequest | None = None

    # Summary of the response that triggered (or denied) confirmation
    response_summary:  ResponseSummary | None = None

    # Human-readable steps to manually verify
    reproduction_steps: list[str]  = field(default_factory=list)

    # WAF details if probe was blocked
    waf_signature:      str | None = None

    # Error message if status == ERROR
    error:              str        = ""

    # Probes sent (may be < max when confirmed on first attempt)
    probes_sent:        int        = 0

    # Probe duration (wall clock)
    duration_seconds:   float      = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Safe Payload Factory
# ─────────────────────────────────────────────────────────────────────────────

class SafePayloadFactory:
    """
    Constructs non-destructive verification payloads.

    Every generated payload passes through _assert_payload_safe() before
    being returned.  The factory never produces working exploit code.
    """

    @staticmethod
    def canary_token() -> str:
        """Generate a unique, clearly-labelled canary token."""
        uid = uuid.uuid4().hex[:12].upper()
        return f"AICS-CANARY-{uid}"

    # ── Open Redirect ─────────────────────────────────────────────────────────

    @staticmethod
    def open_redirect(
        base_url:  str,
        parameter: str,
        canary:    str,
    ) -> ProbeRequest:
        """
        Build a probe that injects the canary domain as the redirect destination.
        Safe: destination is IANA-reserved example.com (harmless).
        """
        canary_url = f"https://{_CANARY_DOMAIN}{_CANARY_PATH}?token={canary}"
        _assert_payload_safe(canary_url, "open_redirect")

        return ProbeRequest(
            method="GET",
            url=base_url,
            params={parameter: canary_url},
            headers={"X-Verification-Context": "AICS-Active-Probe"},
            allow_redirects=False,
        )

    # ── Reflected XSS ─────────────────────────────────────────────────────────

    @staticmethod
    def reflected_xss(
        base_url:  str,
        parameter: str,
        canary:    str,
    ) -> ProbeRequest:
        """
        Build a probe that injects an HTML comment containing the canary.
        Non-executable: HTML comment structure cannot trigger JS execution.
        """
        # HTML comment: visible in DOM source, cannot execute JS
        xss_canary = f"<!--{canary}-->"
        _assert_payload_safe(xss_canary, "reflected_xss")

        return ProbeRequest(
            method="GET",
            url=base_url,
            params={parameter: xss_canary},
            headers={"X-Verification-Context": "AICS-Active-Probe"},
            allow_redirects=True,
        )

    # ── CORS Misconfiguration ─────────────────────────────────────────────────

    @staticmethod
    def cors_probe(
        base_url: str,
        canary:   str,
    ) -> ProbeRequest:
        """
        Send a cross-origin request with a canary attacker Origin.
        Checks if ACAO echoes origin + ACAC: true (credential-bearing CORS).
        """
        attacker_origin = f"https://attacker-{canary.lower()}.example.com"
        _assert_payload_safe(attacker_origin, "cors_probe")

        return ProbeRequest(
            method="GET",
            url=base_url,
            headers={
                "Origin":  attacker_origin,
                "X-Verification-Context": "AICS-Active-Probe",
            },
            allow_redirects=True,
        )

    # ── Path Traversal / LFI ─────────────────────────────────────────────────

    @staticmethod
    def path_traversal(
        base_url:  str,
        parameter: str,
        depth:     int = 4,
    ) -> list[ProbeRequest]:
        """
        Build probes for multiple traversal depths targeting /robots.txt.
        Safe: robots.txt is a public file with no sensitive data.
        Never targets /etc/passwd, /etc/shadow, or any credentials file.
        """
        probes: list[ProbeRequest] = []
        for traversal in _TRAVERSAL_PATHS[:_MAX_PROBES_PER_VULN]:
            _assert_payload_safe(traversal, "path_traversal")
            probes.append(ProbeRequest(
                method="GET",
                url=base_url,
                params={parameter: traversal},
                headers={"X-Verification-Context": "AICS-Active-Probe"},
                allow_redirects=True,
            ))
        return probes

    # ── Host Header Injection ─────────────────────────────────────────────────

    @staticmethod
    def host_header_injection(
        base_url: str,
        canary:   str,
    ) -> ProbeRequest:
        """
        Inject a canary into the Host header to detect reflection in password
        reset emails, Location headers, or body content.
        """
        injected_host = f"{canary.lower()}.{_CANARY_DOMAIN}"
        _assert_payload_safe(injected_host, "host_header_injection")

        return ProbeRequest(
            method="GET",
            url=base_url,
            headers={
                "Host": injected_host,
                "X-Forwarded-Host": injected_host,
                "X-Verification-Context": "AICS-Active-Probe",
            },
            allow_redirects=False,
        )

    # ── SSTI — Server Side Template Injection ─────────────────────────────────

    @staticmethod
    def ssti(
        base_url:  str,
        parameter: str,
    ) -> list[ProbeRequest]:
        """
        Probe multiple template engine syntaxes with a safe arithmetic expression.
        Confirmation: the integer result (7777) appears in the response.
        Non-destructive: math expression has no side effects.
        """
        probes: list[ProbeRequest] = []
        for template_probe in _SSTI_PROBES[:_MAX_PROBES_PER_VULN]:
            _assert_payload_safe(template_probe, "ssti")
            probes.append(ProbeRequest(
                method="GET",
                url=base_url,
                params={parameter: template_probe},
                headers={"X-Verification-Context": "AICS-Active-Probe"},
                allow_redirects=True,
            ))
        return probes

    # ── CRLF Injection ────────────────────────────────────────────────────────

    @staticmethod
    def crlf_injection(
        base_url:  str,
        parameter: str,
    ) -> list[ProbeRequest]:
        """
        Probe for header injection by appending CRLF sequences.
        Safe canary header is clearly labelled as an AICS probe.
        """
        probes: list[ProbeRequest] = []
        for payload in _CRLF_PAYLOADS[:_MAX_PROBES_PER_VULN]:
            _assert_payload_safe(payload, "crlf_injection")
            probes.append(ProbeRequest(
                method="GET",
                url=base_url,
                params={parameter: payload},
                headers={"X-Verification-Context": "AICS-Active-Probe"},
                allow_redirects=False,
            ))
        return probes


# ─────────────────────────────────────────────────────────────────────────────
# Response Oracle — exploitation signature matching
# ─────────────────────────────────────────────────────────────────────────────

class ResponseOracle:
    """
    Analyses raw HTTP responses for exploitation confirmation signatures.
    Returns (is_confirmed: bool, confidence: float) per vulnerability type.
    """

    @staticmethod
    def open_redirect(
        status_code: int,
        headers:     dict[str, str],
        canary:      str,
    ) -> tuple[bool, float]:
        """
        Confirmed if:
          1. Status code is a 3xx redirect.
          2. Location header is present.
          3. Location header contains the exact canary domain.
        """
        if status_code not in range(300, 310):
            return False, 0.0

        location = headers.get("location", headers.get("Location", ""))
        if not location:
            return False, 0.1  # 3xx but no Location — partial signal

        canary_domain_hit = _CANARY_DOMAIN in location
        canary_token_hit  = canary in location

        if canary_domain_hit and canary_token_hit:
            return True, 1.0
        if canary_domain_hit:
            return True, 0.9
        if "example.com" in location:
            return True, 0.75  # weaker — domain match but token missing

        return False, 0.0

    @staticmethod
    def reflected_xss(
        body:   str,
        canary: str,
    ) -> tuple[bool, float]:
        """
        Confirmed if the canary string appears unescaped in the response body.
        Degrades confidence if the canary appears fully HTML-escaped (only
        applicable when the canary itself contains HTML special characters).
        """
        if canary in body:
            # Only check for HTML-encoding filter bypass when the canary
            # actually contains chars that could be encoded (<, >, ", ').
            # Plain alphanumeric canaries always confirm on direct match.
            escaped_canary = (
                canary.replace("<", "&lt;")
                      .replace(">", "&gt;")
                      .replace('"', "&quot;")
                      .replace("'", "&#x27;")
            )
            has_html_special = escaped_canary != canary
            if (
                has_html_special
                and escaped_canary in body
                and canary not in body.replace(escaped_canary, "")
            ):
                return False, 0.3  # canary reflected but HTML-escaped — filtered

            return True, 0.95

        # Partial match: the core token without any HTML comment delimiters
        core = canary.replace("<!--", "").replace("-->", "").strip()
        if core and core in body:
            return True, 0.6

        return False, 0.0

    @staticmethod
    def cors_misconfiguration(
        headers:      dict[str, str],
        sent_origin:  str,
    ) -> tuple[bool, float]:
        """
        Confirmed (credential-bearing CORS) if:
          1. ACAO header equals the exact attacker-controlled origin we sent.
          2. ACAC header is 'true'.

        Partial: ACAO echoes but no ACAC (less critical — not credential-bearing).
        """
        lower = {k.lower(): v for k, v in headers.items()}
        acao  = lower.get("access-control-allow-origin", "")
        acac  = lower.get("access-control-allow-credentials", "").lower()

        origin_echo = (acao == sent_origin) or (acao == "*")

        if acao == "*":
            # Wildcard — less severe (no credential theft), still a finding
            return True, 0.55

        if acao == sent_origin and acac == "true":
            # Full credential-bearing CORS — critical
            return True, 1.0

        if acao == sent_origin:
            # Origin echoed but no ACAC — moderate severity
            return True, 0.75

        return False, 0.0

    @staticmethod
    def path_traversal(
        body:        str,
        status_code: int,
    ) -> tuple[bool, float]:
        """
        Confirmed if the response body contains robots.txt content signatures.
        """
        if status_code not in (200, 206):
            return False, 0.0

        body_lower = body.lower()
        matched = sum(1 for sig in _ROBOTS_SIGNATURES if sig in body_lower)

        if matched >= 3:
            return True, 1.0
        if matched >= 2:
            return True, 0.8
        if matched >= 1:
            return True, 0.5

        return False, 0.0

    @staticmethod
    def host_header_injection(
        status_code: int,
        headers:     dict[str, str],
        body:        str,
        injected_host: str,
    ) -> tuple[bool, float]:
        """
        Confirmed if the injected Host value appears in:
          1. Location header (password-reset-style redirect) → highest confidence
          2. Response body (template renders Host dynamically)
        """
        lower = {k.lower(): v for k, v in headers.items()}
        location = lower.get("location", "")

        if injected_host in location:
            return True, 1.0

        if _CANARY_DOMAIN in location:
            return True, 0.9

        if injected_host in body:
            return True, 0.85

        if _CANARY_DOMAIN in body:
            return True, 0.75

        return False, 0.0

    @staticmethod
    def ssti(
        body:        str,
        status_code: int,
    ) -> tuple[bool, float]:
        """
        Confirmed if the arithmetic result (7777) appears in the response.
        """
        if status_code not in (200, 206):
            return False, 0.0

        if _SSTI_EXPRESSION in body:
            return True, 0.95

        return False, 0.0

    @staticmethod
    def crlf_injection(
        headers: dict[str, str],
    ) -> tuple[bool, float]:
        """
        Confirmed if the injected canary header appears in the response headers.
        """
        lower = {k.lower(): v for k, v in headers.items()}
        canary_key = _CRLF_CANARY_HEADER.lower()

        if canary_key in lower:
            return True, 1.0

        # Check if any value in existing headers contains the canary
        for v in lower.values():
            if "canary" in v.lower() and "aics" in v.lower():
                return True, 0.8

        return False, 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Active Prober — async HTTP dispatch with strict timeout & WAF abort
# ─────────────────────────────────────────────────────────────────────────────

class ActiveProber:
    """
    Async HTTP prober.  Dispatches ProbeRequest objects with:
      • 5-second hard timeout
      • SSRF guard on every target
      • WAF block detection → raises WafBlockError immediately
      • Max response body read capped at _MAX_RESPONSE_BYTES
    """

    def __init__(self, timeout: float = _PROBE_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    async def probe(self, request: ProbeRequest) -> tuple[int, dict[str, str], str, float]:
        """
        Dispatch a single ProbeRequest.

        Returns (status_code, headers_dict, body_text, elapsed_seconds).
        Raises:
            SsrfBlockError       — target is an internal/private address
            WafBlockError        — WAF block detected in response
            asyncio.TimeoutError — probe exceeded timeout
            httpx.HTTPError      — network-level errors
        """
        # ── SSRF guard ────────────────────────────────────────────────────────
        parsed   = urlparse(request.url)
        hostname = parsed.hostname or ""
        if is_ssrf_blocked(hostname):
            raise SsrfBlockError(
                f"SSRF protection: {hostname!r} resolves to a private/reserved address. "
                "Active probing of internal infrastructure is not permitted."
            )

        # ── Build full URL with params ────────────────────────────────────────
        target_url = request.url
        if request.params:
            qs = urlencode(request.params)
            sep = "&" if "?" in target_url else "?"
            target_url = f"{target_url}{sep}{qs}"

        # ── Dispatch ──────────────────────────────────────────────────────────
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=request.allow_redirects,
                timeout=httpx.Timeout(self._timeout),
                max_redirects=5,
            ) as client:
                resp = await client.request(
                    method=request.method,
                    url=target_url,
                    headers=request.headers,
                    content=request.body.encode() if request.body else None,
                )
        except asyncio.TimeoutError:
            raise
        except httpx.TimeoutException as exc:
            raise asyncio.TimeoutError(str(exc)) from exc

        elapsed = time.monotonic() - t0

        status  = resp.status_code
        headers = dict(resp.headers)
        body    = resp.text[:_MAX_RESPONSE_BYTES]

        # ── WAF abort ─────────────────────────────────────────────────────────
        waf_sig = _detect_waf_block(status, headers, body)
        if waf_sig:
            raise WafBlockError(waf_sig, status)

        return status, headers, body, elapsed

    def _make_response_summary(
        self,
        status:  int,
        headers: dict[str, str],
        body:    str,
        elapsed: float,
    ) -> ResponseSummary:
        lower = {k.lower(): v for k, v in headers.items()}
        return ResponseSummary(
            status_code   = status,
            location      = lower.get("location"),
            content_type  = lower.get("content-type"),
            acao_header   = lower.get("access-control-allow-origin"),
            acac_header   = lower.get("access-control-allow-credentials"),
            body_snippet  = body[:500],
            response_time = round(elapsed, 3),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Reproduction step builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_reproduction_steps(
    vuln_type:    VulnType,
    poc_request:  ProbeRequest,
    result:       tuple[bool, float],
) -> list[str]:
    """Build human-readable manual reproduction instructions."""
    confirmed, confidence = result
    status_label = "CONFIRMED" if confirmed else f"not confirmed (confidence={confidence:.0%})"

    steps = [
        f"Vulnerability type : {vuln_type.value}",
        f"Verification status: {status_label}",
        f"Endpoint           : {poc_request.url}",
        "",
        "Manual reproduction steps:",
    ]

    curl_cmd = poc_request.to_curl()
    steps += [
        f"1. Run the following curl command:",
        f"   {curl_cmd}",
        "",
    ]

    if vuln_type == VulnType.OPEN_REDIRECT:
        steps += [
            "2. Examine the HTTP response status code.",
            "   Expected: 30x Redirect",
            f"3. Inspect the Location header.",
            f"   Expected: contains '{_CANARY_DOMAIN}'",
            "4. If both conditions hold, the redirect is uncontrolled.",
        ]
    elif vuln_type == VulnType.REFLECTED_XSS:
        steps += [
            "2. Search the raw HTML response body for the canary string.",
            "   Expected: the canary appears verbatim (not HTML-escaped).",
            "3. Open browser DevTools → Sources → inspect the page source.",
            "4. Confirm the canary is not inside a JavaScript string literal.",
        ]
    elif vuln_type == VulnType.CORS_MISCONFIGURATION:
        steps += [
            "2. Inspect the response headers.",
            f"   Expected: Access-Control-Allow-Origin: (attacker origin)",
            "   Expected: Access-Control-Allow-Credentials: true",
            "3. Credential-bearing CORS confirmed if BOTH headers are present.",
            "4. To validate impact, send a credentialed fetch() from an",
            "   attacker-controlled page and inspect the response body.",
        ]
    elif vuln_type == VulnType.PATH_TRAVERSAL:
        steps += [
            "2. Examine the response body.",
            "   Expected: contains 'User-agent:' or 'Disallow:' (robots.txt content).",
            "3. If present, the server returned a file outside the web root.",
            "4. Increase traversal depth (../../../) to confirm escape depth.",
        ]
    elif vuln_type == VulnType.HOST_HEADER_INJECTION:
        steps += [
            "2. Check the Location header for the injected hostname.",
            "3. Check the response body for the injected hostname.",
            "4. Typical impact: password reset links point to attacker domain.",
        ]
    elif vuln_type == VulnType.SSTI:
        steps += [
            "2. Search the response body for the integer '7777'.",
            "   Expected: the server evaluated 7*1111 = 7777.",
            "3. Try template-specific payloads for confirmed engine type.",
            "   WARNING: escalation payloads (RCE) require separate authorisation.",
        ]
    elif vuln_type == VulnType.CRLF_INJECTION:
        steps += [
            "2. Inspect ALL response headers.",
            f"   Expected: '{_CRLF_CANARY_HEADER}' header present.",
            "3. If the injected header appears, CRLF injection is confirmed.",
            "4. Impact: session fixation, cache poisoning, response splitting.",
        ]

    return steps


# ─────────────────────────────────────────────────────────────────────────────
# ActiveVerifier — public facade
# ─────────────────────────────────────────────────────────────────────────────

class ActiveVerifier:
    """
    Async active vulnerability verifier.

    Usage::

        verifier = ActiveVerifier()
        result = await verifier.verify_vulnerability(
            vuln_type       = VulnType.OPEN_REDIRECT,
            endpoint        = "https://example.com/login",
            parameter       = "next",
            contextual_data = {},
        )
        print(result.is_confirmed, result.confidence_score)
        print(result.reproduction_steps)

    Parameters
    ----------
    timeout:
        Per-probe HTTP timeout in seconds (default: 5.0, hard max: 10.0).
    max_probes:
        Maximum probes per vulnerability (default: 3).
    ssrf_check:
        Whether to apply the SSRF guard before probing (default: True, never
        disable in production).
    """

    _MAX_ALLOWED_TIMEOUT = 10.0

    def __init__(
        self,
        timeout:    float = _PROBE_TIMEOUT_SECONDS,
        max_probes: int   = _MAX_PROBES_PER_VULN,
        ssrf_check: bool  = True,
    ) -> None:
        self._timeout    = min(timeout, self._MAX_ALLOWED_TIMEOUT)
        self._max_probes = max_probes
        self._ssrf_check = ssrf_check
        self._prober     = ActiveProber(timeout=self._timeout)
        self._factory    = SafePayloadFactory()
        self._oracle     = ResponseOracle()

    # ── Public API ─────────────────────────────────────────────────────────────

    async def verify_vulnerability(
        self,
        vuln_type:        VulnType,
        endpoint:         str,
        parameter:        str,
        contextual_data:  dict[str, Any] | None = None,
    ) -> VerificationResult:
        """
        Dispatch a safe, non-destructive verification probe for the given
        vulnerability type and return a structured VerificationResult.

        The SSRF guard fires before any network request.
        A WAF block immediately aborts and returns BLOCKED_BY_ACTIVE_DEFENSE.
        """
        ctx   = contextual_data or {}
        t_start = time.monotonic()

        _handler_map: dict[VulnType, Any] = {
            VulnType.OPEN_REDIRECT:         self._verify_open_redirect,
            VulnType.REFLECTED_XSS:         self._verify_reflected_xss,
            VulnType.CORS_MISCONFIGURATION:  self._verify_cors,
            VulnType.PATH_TRAVERSAL:         self._verify_path_traversal,
            VulnType.HOST_HEADER_INJECTION:  self._verify_host_header,
            VulnType.SSTI:                   self._verify_ssti,
            VulnType.CRLF_INJECTION:         self._verify_crlf,
        }

        handler = _handler_map.get(vuln_type)
        if handler is None:
            return VerificationResult(
                vuln_type=vuln_type, endpoint=endpoint, parameter=parameter,
                status=VerificationStatus.ERROR, is_confirmed=False,
                confidence_score=0.0, canary_token="",
                error=f"Unsupported vulnerability type: {vuln_type}",
            )

        try:
            result = await handler(endpoint, parameter, ctx)
        except EthicalViolationError as exc:
            result = VerificationResult(
                vuln_type=vuln_type, endpoint=endpoint, parameter=parameter,
                status=VerificationStatus.ETHICAL_VIOLATION,
                is_confirmed=False, confidence_score=0.0, canary_token="",
                error=str(exc),
            )
        except SsrfBlockError as exc:
            result = VerificationResult(
                vuln_type=vuln_type, endpoint=endpoint, parameter=parameter,
                status=VerificationStatus.SSRF_BLOCKED,
                is_confirmed=False, confidence_score=0.0, canary_token="",
                error=str(exc),
            )
        except Exception as exc:
            logger.exception("Unexpected error in verify_vulnerability: %s", exc)
            result = VerificationResult(
                vuln_type=vuln_type, endpoint=endpoint, parameter=parameter,
                status=VerificationStatus.ERROR,
                is_confirmed=False, confidence_score=0.0, canary_token="",
                error=str(exc),
            )

        result.duration_seconds = round(time.monotonic() - t_start, 3)
        return result

    # ── Individual verifiers ───────────────────────────────────────────────────

    async def _verify_open_redirect(
        self, endpoint: str, parameter: str, ctx: dict
    ) -> VerificationResult:
        canary  = SafePayloadFactory.canary_token()
        request = SafePayloadFactory.open_redirect(endpoint, parameter, canary)

        result = VerificationResult(
            vuln_type=VulnType.OPEN_REDIRECT, endpoint=endpoint,
            parameter=parameter, canary_token=canary,
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False, confidence_score=0.0,
            raw_poc_request=request,
        )

        try:
            status, headers, body, elapsed = await self._prober.probe(request)
        except WafBlockError as exc:
            result.status        = VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
            result.waf_signature = exc.waf_signature
            result.probes_sent   = 1
            return result
        except asyncio.TimeoutError:
            result.status      = VerificationStatus.TIMEOUT
            result.probes_sent = 1
            return result

        result.probes_sent      = 1
        result.response_summary = self._prober._make_response_summary(
            status, headers, body, elapsed
        )

        confirmed, confidence = ResponseOracle.open_redirect(status, headers, canary)
        result.is_confirmed     = confirmed
        result.confidence_score = confidence
        result.status           = (
            VerificationStatus.CONFIRMED if confirmed else VerificationStatus.NOT_CONFIRMED
        )
        result.reproduction_steps = _build_reproduction_steps(
            VulnType.OPEN_REDIRECT, request, (confirmed, confidence)
        )
        return result

    async def _verify_reflected_xss(
        self, endpoint: str, parameter: str, ctx: dict
    ) -> VerificationResult:
        canary  = SafePayloadFactory.canary_token()
        request = SafePayloadFactory.reflected_xss(endpoint, parameter, canary)

        result = VerificationResult(
            vuln_type=VulnType.REFLECTED_XSS, endpoint=endpoint,
            parameter=parameter, canary_token=canary,
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False, confidence_score=0.0,
            raw_poc_request=request,
        )

        try:
            status, headers, body, elapsed = await self._prober.probe(request)
        except WafBlockError as exc:
            result.status        = VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
            result.waf_signature = exc.waf_signature
            result.probes_sent   = 1
            return result
        except asyncio.TimeoutError:
            result.status      = VerificationStatus.TIMEOUT
            result.probes_sent = 1
            return result

        result.probes_sent      = 1
        result.response_summary = self._prober._make_response_summary(
            status, headers, body, elapsed
        )

        # The canary injected is <!--AICS-CANARY-XYZ-->
        # We look for the full canary token inside the HTML comment
        confirmed, confidence = ResponseOracle.reflected_xss(body, canary)
        result.is_confirmed     = confirmed
        result.confidence_score = confidence
        result.status           = (
            VerificationStatus.CONFIRMED if confirmed else VerificationStatus.NOT_CONFIRMED
        )
        result.reproduction_steps = _build_reproduction_steps(
            VulnType.REFLECTED_XSS, request, (confirmed, confidence)
        )
        return result

    async def _verify_cors(
        self, endpoint: str, parameter: str, ctx: dict
    ) -> VerificationResult:
        canary  = SafePayloadFactory.canary_token()
        request = SafePayloadFactory.cors_probe(endpoint, canary)

        # Extract the actual origin we injected
        sent_origin = request.headers.get("Origin", "")

        result = VerificationResult(
            vuln_type=VulnType.CORS_MISCONFIGURATION, endpoint=endpoint,
            parameter=parameter, canary_token=canary,
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False, confidence_score=0.0,
            raw_poc_request=request,
        )

        try:
            status, headers, body, elapsed = await self._prober.probe(request)
        except WafBlockError as exc:
            result.status        = VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
            result.waf_signature = exc.waf_signature
            result.probes_sent   = 1
            return result
        except asyncio.TimeoutError:
            result.status      = VerificationStatus.TIMEOUT
            result.probes_sent = 1
            return result

        result.probes_sent      = 1
        result.response_summary = self._prober._make_response_summary(
            status, headers, body, elapsed
        )

        confirmed, confidence = ResponseOracle.cors_misconfiguration(headers, sent_origin)
        result.is_confirmed     = confirmed
        result.confidence_score = confidence
        result.status           = (
            VerificationStatus.CONFIRMED if confirmed else VerificationStatus.NOT_CONFIRMED
        )
        result.reproduction_steps = _build_reproduction_steps(
            VulnType.CORS_MISCONFIGURATION, request, (confirmed, confidence)
        )
        return result

    async def _verify_path_traversal(
        self, endpoint: str, parameter: str, ctx: dict
    ) -> VerificationResult:
        probes = SafePayloadFactory.path_traversal(endpoint, parameter)
        canary = "path-traversal-probe"

        result = VerificationResult(
            vuln_type=VulnType.PATH_TRAVERSAL, endpoint=endpoint,
            parameter=parameter, canary_token=canary,
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False, confidence_score=0.0,
        )

        for i, request in enumerate(probes[:self._max_probes]):
            result.raw_poc_request = request
            result.probes_sent     = i + 1
            try:
                status, headers, body, elapsed = await self._prober.probe(request)
            except WafBlockError as exc:
                result.status        = VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
                result.waf_signature = exc.waf_signature
                return result
            except asyncio.TimeoutError:
                result.status = VerificationStatus.TIMEOUT
                continue

            result.response_summary = self._prober._make_response_summary(
                status, headers, body, elapsed
            )
            confirmed, confidence = ResponseOracle.path_traversal(body, status)
            if confirmed:
                result.is_confirmed     = True
                result.confidence_score = confidence
                result.status           = VerificationStatus.CONFIRMED
                result.reproduction_steps = _build_reproduction_steps(
                    VulnType.PATH_TRAVERSAL, request, (confirmed, confidence)
                )
                return result

        result.status = VerificationStatus.NOT_CONFIRMED
        if result.raw_poc_request:
            result.reproduction_steps = _build_reproduction_steps(
                VulnType.PATH_TRAVERSAL, result.raw_poc_request, (False, 0.0)
            )
        return result

    async def _verify_host_header(
        self, endpoint: str, parameter: str, ctx: dict
    ) -> VerificationResult:
        canary  = SafePayloadFactory.canary_token()
        request = SafePayloadFactory.host_header_injection(endpoint, canary)
        injected_host = request.headers.get("Host", "")

        result = VerificationResult(
            vuln_type=VulnType.HOST_HEADER_INJECTION, endpoint=endpoint,
            parameter=parameter, canary_token=canary,
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False, confidence_score=0.0,
            raw_poc_request=request,
        )

        try:
            status, headers, body, elapsed = await self._prober.probe(request)
        except WafBlockError as exc:
            result.status        = VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
            result.waf_signature = exc.waf_signature
            result.probes_sent   = 1
            return result
        except asyncio.TimeoutError:
            result.status      = VerificationStatus.TIMEOUT
            result.probes_sent = 1
            return result

        result.probes_sent      = 1
        result.response_summary = self._prober._make_response_summary(
            status, headers, body, elapsed
        )

        confirmed, confidence = ResponseOracle.host_header_injection(
            status, headers, body, injected_host
        )
        result.is_confirmed     = confirmed
        result.confidence_score = confidence
        result.status           = (
            VerificationStatus.CONFIRMED if confirmed else VerificationStatus.NOT_CONFIRMED
        )
        result.reproduction_steps = _build_reproduction_steps(
            VulnType.HOST_HEADER_INJECTION, request, (confirmed, confidence)
        )
        return result

    async def _verify_ssti(
        self, endpoint: str, parameter: str, ctx: dict
    ) -> VerificationResult:
        probes = SafePayloadFactory.ssti(endpoint, parameter)
        canary = f"ssti-{_SSTI_EXPRESSION}"

        result = VerificationResult(
            vuln_type=VulnType.SSTI, endpoint=endpoint,
            parameter=parameter, canary_token=canary,
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False, confidence_score=0.0,
        )

        for i, request in enumerate(probes[:self._max_probes]):
            result.raw_poc_request = request
            result.probes_sent     = i + 1
            try:
                status, headers, body, elapsed = await self._prober.probe(request)
            except WafBlockError as exc:
                result.status        = VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
                result.waf_signature = exc.waf_signature
                return result
            except asyncio.TimeoutError:
                result.status = VerificationStatus.TIMEOUT
                continue

            result.response_summary = self._prober._make_response_summary(
                status, headers, body, elapsed
            )
            confirmed, confidence = ResponseOracle.ssti(body, status)
            if confirmed:
                result.is_confirmed     = True
                result.confidence_score = confidence
                result.status           = VerificationStatus.CONFIRMED
                result.reproduction_steps = _build_reproduction_steps(
                    VulnType.SSTI, request, (confirmed, confidence)
                )
                return result

        result.status = VerificationStatus.NOT_CONFIRMED
        if result.raw_poc_request:
            result.reproduction_steps = _build_reproduction_steps(
                VulnType.SSTI, result.raw_poc_request, (False, 0.0)
            )
        return result

    async def _verify_crlf(
        self, endpoint: str, parameter: str, ctx: dict
    ) -> VerificationResult:
        probes = SafePayloadFactory.crlf_injection(endpoint, parameter)
        canary = "crlf-probe"

        result = VerificationResult(
            vuln_type=VulnType.CRLF_INJECTION, endpoint=endpoint,
            parameter=parameter, canary_token=canary,
            status=VerificationStatus.NOT_CONFIRMED,
            is_confirmed=False, confidence_score=0.0,
        )

        for i, request in enumerate(probes[:self._max_probes]):
            result.raw_poc_request = request
            result.probes_sent     = i + 1
            try:
                status, headers, body, elapsed = await self._prober.probe(request)
            except WafBlockError as exc:
                result.status        = VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE
                result.waf_signature = exc.waf_signature
                return result
            except asyncio.TimeoutError:
                result.status = VerificationStatus.TIMEOUT
                continue

            result.response_summary = self._prober._make_response_summary(
                status, headers, body, elapsed
            )
            confirmed, confidence = ResponseOracle.crlf_injection(headers)
            if confirmed:
                result.is_confirmed     = True
                result.confidence_score = confidence
                result.status           = VerificationStatus.CONFIRMED
                result.reproduction_steps = _build_reproduction_steps(
                    VulnType.CRLF_INJECTION, request, (confirmed, confidence)
                )
                return result

        result.status = VerificationStatus.NOT_CONFIRMED
        if result.raw_poc_request:
            result.reproduction_steps = _build_reproduction_steps(
                VulnType.CRLF_INJECTION, result.raw_poc_request, (False, 0.0)
            )
        return result

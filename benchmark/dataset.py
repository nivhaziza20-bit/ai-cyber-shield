"""
Benchmark ground truth dataset for AI Cyber Shield accuracy measurement.

Each BenchmarkCase defines:
  - A MockServerConfig  — exactly what the mock HTTP server serves
  - A list of GroundTruth — one per tool, with a check_fn that returns True
    when the tool correctly detected (positive case) or correctly did NOT detect
    (negative case) a security issue.

Scoring convention:
  category = "positive"  → site has a real issue; check_fn should return True (TP)
  category = "negative"  → site is clean;         check_fn should return False (TN)

  TP: positive case, check_fn → True   (correctly detected)
  FN: positive case, check_fn → False  (missed the issue)
  TN: negative case, check_fn → False  (correctly reported clean)
  FP: negative case, check_fn → True   (false alarm)

DNS cases are handled differently — they mock the DoH HTTP response rather than
spinning up a local server, so dns_mock_responses holds the fixture data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from benchmark.mock_target import MockServerConfig

# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GroundTruth:
    """Expected behaviour of one tool against one target."""
    tool: str                          # e.g. "security_headers"
    category: str                      # "positive" (has issue) | "negative" (clean)
    description: str                   # human-readable explanation
    check_fn: Callable[[dict], bool]   # returns True when issue IS detected


@dataclass
class BenchmarkCase:
    """A single benchmark scenario: one mock server config + multiple tool expectations."""
    name: str
    mock_config: MockServerConfig
    ground_truths: list[GroundTruth]
    tags: list[str] = field(default_factory=list)


@dataclass
class DnsBenchmarkCase:
    """DNS benchmark case — uses mocked DoH responses instead of a mock server."""
    name: str
    domain: str
    # Maps (domain, rtype) → list[str] of TXT/CAA records returned by DoH mock
    doh_records: dict[tuple[str, str], list[str]]
    ground_truths: list[GroundTruth]
    tags: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Reusable header sets
# ─────────────────────────────────────────────────────────────────────────────

_ALL_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy":          "default-src 'self'; script-src 'self'; object-src 'none'",
    "X-Frame-Options":                  "DENY",
    "X-Content-Type-Options":           "nosniff",
    "Strict-Transport-Security":        "max-age=31536000; includeSubDomains",
    "Referrer-Policy":                  "strict-origin-when-cross-origin",
    "Permissions-Policy":               "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Embedder-Policy":     "require-corp",
    "Cross-Origin-Opener-Policy":       "same-origin",
    "Cross-Origin-Resource-Policy":     "same-origin",
}

_STRONG_HSTS: str = "max-age=63072000; includeSubDomains; preload"
_MEDIUM_HSTS: str = "max-age=31536000; includeSubDomains"
_WEAK_HSTS:   str = "max-age=3600"

_ALL_SENSITIVE_PATHS_404: dict[str, tuple[int, str]] = {
    "/": (200, "<html><body>Clean Site</body></html>"),
    "/.env":                      (404, "Not Found"),
    "/.env.local":                (404, "Not Found"),
    "/.env.production":           (404, "Not Found"),
    "/.git/HEAD":                 (404, "Not Found"),
    "/.git/config":               (404, "Not Found"),
    "/phpinfo.php":               (404, "Not Found"),
    "/info.php":                  (404, "Not Found"),
    "/server-status":             (404, "Not Found"),
    "/server-info":               (404, "Not Found"),
    "/actuator":                  (404, "Not Found"),
    "/actuator/env":              (404, "Not Found"),
    "/actuator/health":           (404, "Not Found"),
    "/.htpasswd":                 (404, "Not Found"),
    "/web.config":                (404, "Not Found"),
    "/config.php.bak":            (404, "Not Found"),
    "/backup.sql":                (404, "Not Found"),
    "/database.sql":              (404, "Not Found"),
    "/backup.zip":                (404, "Not Found"),
    "/.DS_Store":                 (404, "Not Found"),
    "/crossdomain.xml":           (404, "Not Found"),
    "/elmah.axd":                 (404, "Not Found"),
    "/trace.axd":                 (404, "Not Found"),
    "/wp-config.php.bak":         (404, "Not Found"),
    "/config/database.yml":       (404, "Not Found"),
    "/storage/logs/laravel.log":  (404, "Not Found"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Security Headers cases  (tools/web_tools.py → check_security_headers)
# ─────────────────────────────────────────────────────────────────────────────

def _sh_has_issues(r: dict) -> bool:
    """Returns True if the security-headers tool detected meaningful missing headers."""
    return len(r.get("missing_headers", [])) >= 5


def _sh_has_info_disclosure(r: dict) -> bool:
    return bool(r.get("information_disclosure"))


def _sh_is_mostly_clean(r: dict) -> bool:
    """Returns True when tool incorrectly flags a well-configured site."""
    return len(r.get("missing_headers", [])) >= 5


SECURITY_HEADERS_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="SH_ALL_MISSING_P",
        mock_config=MockServerConfig(
            headers={},
            status=200,
            body="<html><body>No Security Headers</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="security_headers",
            category="positive",
            description="No security headers → tool must report >= 5 missing",
            check_fn=_sh_has_issues,
        )],
        tags=["security_headers", "critical"],
    ),
    BenchmarkCase(
        name="SH_INFO_DISCLOSURE_P",
        mock_config=MockServerConfig(
            headers={"Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1"},
            status=200,
            body="<html><body>Version Disclosure</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="security_headers",
            category="positive",
            description="Server header reveals version → information_disclosure must be populated",
            check_fn=_sh_has_info_disclosure,
        )],
        tags=["security_headers", "info_disclosure"],
    ),
    BenchmarkCase(
        name="SH_PARTIAL_MISSING_P",
        mock_config=MockServerConfig(
            headers={"X-Frame-Options": "DENY"},
            status=200,
            body="<html><body>Only XFO</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="security_headers",
            category="positive",
            description="Only X-Frame-Options set → still missing CSP, HSTS, etc.",
            check_fn=_sh_has_issues,
        )],
        tags=["security_headers"],
    ),
    BenchmarkCase(
        name="SH_ALL_PRESENT_N",
        mock_config=MockServerConfig(
            headers=_ALL_SECURITY_HEADERS,
            status=200,
            body="<html><body>Secure Site</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="security_headers",
            category="negative",
            description="All 9 security headers present → tool must NOT report 5+ missing",
            check_fn=_sh_is_mostly_clean,
        )],
        tags=["security_headers", "negative"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# CORS / CSP cases  (tools/cors_csp_checker.py → check_cors_csp)
# ─────────────────────────────────────────────────────────────────────────────

def _cors_has_issues(r: dict) -> bool:
    return len(r.get("cors_issues", [])) > 0


def _cors_csp_missing(r: dict) -> bool:
    return r.get("csp_quality", "none") == "none"


def _cors_critical_credentials(r: dict) -> bool:
    return r.get("risk_score", 0) >= 50


def _cors_is_clean(r: dict) -> bool:
    """True when tool incorrectly fires on a clean CORS/CSP config."""
    return _cors_has_issues(r) or _cors_csp_missing(r)


CORS_CSP_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="CORS_WILDCARD_P",
        mock_config=MockServerConfig(
            headers={"Access-Control-Allow-Origin": "*"},
            status=200,
            body="<html><body>Wildcard CORS</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cors_csp",
            category="positive",
            description="ACAO: * → cors_issues must be non-empty",
            check_fn=_cors_has_issues,
        )],
        tags=["cors_csp", "cors"],
    ),
    BenchmarkCase(
        name="CORS_WILDCARD_CREDS_P",
        mock_config=MockServerConfig(
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, PUT",
            },
            status=200,
            body="<html><body>Wildcard CORS + Credentials</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cors_csp",
            category="positive",
            description="ACAO: * + ACAC: true → critical CORS misconfiguration, risk >= 50",
            check_fn=_cors_critical_credentials,
        )],
        tags=["cors_csp", "cors", "critical"],
    ),
    BenchmarkCase(
        name="CORS_NO_CSP_P",
        mock_config=MockServerConfig(
            headers={},
            status=200,
            body="<html><script src='https://cdn.example.com/app.js'></script></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cors_csp",
            category="positive",
            description="No CSP header → csp_quality must equal 'none'",
            check_fn=_cors_csp_missing,
        )],
        tags=["cors_csp", "csp"],
    ),
    BenchmarkCase(
        name="CORS_UNSAFE_INLINE_P",
        mock_config=MockServerConfig(
            headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"},
            status=200,
            body="<html><body>Weak CSP</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cors_csp",
            category="positive",
            description="CSP with unsafe-inline + unsafe-eval → risk_score > 0, quality != strong",
            check_fn=lambda r: r.get("csp_quality", "none") != "strong" and r.get("risk_score", 0) > 0,
        )],
        tags=["cors_csp", "csp"],
    ),
    BenchmarkCase(
        name="CORS_CLEAN_N",
        mock_config=MockServerConfig(
            headers={
                "Access-Control-Allow-Origin": "https://api.mysite.com",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
                "Vary": "Origin",
            },
            status=200,
            body="<html><body>Clean CORS + CSP</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cors_csp",
            category="negative",
            description="Specific CORS origin + strong CSP → no cors_issues, csp_quality != none",
            check_fn=_cors_is_clean,
        )],
        tags=["cors_csp", "negative"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Cookie Security cases  (tools/cookie_security.py → scan_cookie_security)
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: mock server is HTTP, so the "Secure flag missing on HTTPS" check (+40)
# does NOT fire. Tests focus on issues that fire regardless of protocol:
#   SameSite=None without Secure (+35), HttpOnly missing (+30), etc.

def _cookie_high_risk(r: dict) -> bool:
    return r.get("risk_score", 0) >= 30


def _cookie_is_clean(r: dict) -> bool:
    """True when tool incorrectly reports high risk on a clean cookie."""
    return r.get("risk_score", 0) >= 30


COOKIE_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="COOKIE_SAMESITE_NONE_P",
        mock_config=MockServerConfig(
            headers={"Set-Cookie": "session=abc123; SameSite=None"},
            status=200,
            body="<html><body>SameSite=None without Secure</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cookie",
            category="positive",
            description="SameSite=None without Secure → risk +35 (HIGH), browsers reject it",
            check_fn=_cookie_high_risk,
        )],
        tags=["cookie", "samesite"],
    ),
    BenchmarkCase(
        name="COOKIE_AUTH_NO_HTTPONLY_P",
        mock_config=MockServerConfig(
            headers={"Set-Cookie": "session=abc123"},
            status=200,
            body="<html><body>Auth cookie no HttpOnly</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cookie",
            category="positive",
            description="Auth cookie (session) without HttpOnly → risk +30 (HIGH), XSS can steal it",
            check_fn=_cookie_high_risk,
        )],
        tags=["cookie", "httponly"],
    ),
    BenchmarkCase(
        name="COOKIE_SECURE_ATTRS_N",
        mock_config=MockServerConfig(
            headers={"Set-Cookie": "session=abc123; HttpOnly; SameSite=Lax; Path=/"},
            status=200,
            body="<html><body>Well-configured cookie</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cookie",
            category="negative",
            description="session cookie with HttpOnly + SameSite=Lax on HTTP → risk must be < 30",
            check_fn=_cookie_is_clean,
        )],
        tags=["cookie", "negative"],
    ),
    BenchmarkCase(
        name="COOKIE_NONE_N",
        mock_config=MockServerConfig(
            headers={},
            status=200,
            body="<html><body>No cookies set</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="cookie",
            category="negative",
            description="No Set-Cookie header → cookies_found == 0, risk == 0",
            check_fn=lambda r: r.get("cookies_found", 0) > 0 and r.get("risk_score", 0) >= 30,
        )],
        tags=["cookie", "negative"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Exposure Checker cases  (tools/exposure_checker.py → check_exposure)
# ─────────────────────────────────────────────────────────────────────────────

def _exposure_has_files(r: dict) -> bool:
    return len(r.get("exposed_files", [])) > 0


def _exposure_critical_risk(r: dict) -> bool:
    return r.get("risk_score", 0) >= 50


def _exposure_is_clean(r: dict) -> bool:
    """True when tool incorrectly reports exposed files on a clean server."""
    return len(r.get("exposed_files", [])) > 0


EXPOSURE_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="EXP_ENV_EXPOSED_P",
        mock_config=MockServerConfig(
            status=404,
            body="Not Found",
            paths={
                "/":     (200, "<html><body>Target Site</body></html>"),
                "/.env": (200, "SECRET_KEY=super_secret\nDB_PASSWORD=hunter2\nAPIKEY=abc123"),
            },
        ),
        ground_truths=[GroundTruth(
            tool="exposure",
            category="positive",
            description="/.env returns 200 → exposed_files must be non-empty, risk >= 50",
            check_fn=_exposure_critical_risk,
        )],
        tags=["exposure", "env", "critical"],
    ),
    BenchmarkCase(
        name="EXP_GIT_EXPOSED_P",
        mock_config=MockServerConfig(
            status=404,
            body="Not Found",
            paths={
                "/":          (200, "<html><body>Target Site</body></html>"),
                "/.git/HEAD": (200, "ref: refs/heads/main\n"),
            },
        ),
        ground_truths=[GroundTruth(
            tool="exposure",
            category="positive",
            description="/.git/HEAD returns 200 → Git repo exposed, risk >= 50",
            check_fn=_exposure_critical_risk,
        )],
        tags=["exposure", "git", "critical"],
    ),
    BenchmarkCase(
        name="EXP_PHPINFO_P",
        mock_config=MockServerConfig(
            status=404,
            body="Not Found",
            paths={
                "/":           (200, "<html><body>Target Site</body></html>"),
                "/phpinfo.php": (200, "<html><title>phpinfo()</title><body>PHP Version 8.1.0 Configure Command ./configure</body></html>"),
            },
        ),
        ground_truths=[GroundTruth(
            tool="exposure",
            category="positive",
            description="phpinfo.php exposed → full server config visible",
            check_fn=_exposure_has_files,
        )],
        tags=["exposure", "phpinfo"],
    ),
    BenchmarkCase(
        name="EXP_DUAL_CRITICAL_P",
        mock_config=MockServerConfig(
            status=404,
            body="Not Found",
            paths={
                "/":           (200, "<html><body>Target Site</body></html>"),
                "/.env":       (200, "DB_PASS=secret\n"),
                "/.git/HEAD":  (200, "ref: refs/heads/main\n"),
            },
        ),
        ground_truths=[GroundTruth(
            tool="exposure",
            category="positive",
            description="Both /.env and /.git/HEAD exposed → risk >= 100",
            check_fn=lambda r: r.get("risk_score", 0) >= 100,
        )],
        tags=["exposure", "critical"],
    ),
    BenchmarkCase(
        name="EXP_CLEAN_N",
        mock_config=MockServerConfig(
            status=404,
            body="Not Found",
            paths=_ALL_SENSITIVE_PATHS_404,
        ),
        ground_truths=[GroundTruth(
            tool="exposure",
            category="negative",
            description="All sensitive paths return 404 → exposed_files must be empty",
            check_fn=_exposure_is_clean,
        )],
        tags=["exposure", "negative"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# HSTS Preload cases  (tools/hsts_preload.py → check_hsts_preload)
# ─────────────────────────────────────────────────────────────────────────────

def _hsts_missing(r: dict) -> bool:
    return not r.get("hsts_present", True)


def _hsts_quality_weak_or_none(r: dict) -> bool:
    return r.get("hsts_quality", "none") in ("none", "weak")


def _hsts_is_adequate(r: dict) -> bool:
    """True when tool incorrectly flags an adequate HSTS config."""
    return not r.get("hsts_present", True)


HSTS_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="HSTS_MISSING_P",
        mock_config=MockServerConfig(
            headers={},
            status=200,
            body="<html><body>No HSTS</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="hsts",
            category="positive",
            description="No HSTS header → hsts_present must be False",
            check_fn=_hsts_missing,
        )],
        tags=["hsts"],
    ),
    BenchmarkCase(
        name="HSTS_WEAK_MAX_AGE_P",
        mock_config=MockServerConfig(
            headers={"Strict-Transport-Security": _WEAK_HSTS},
            status=200,
            body="<html><body>Weak HSTS</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="hsts",
            category="positive",
            description="max-age=3600 (1 hour) → hsts_quality must be 'weak'",
            check_fn=_hsts_quality_weak_or_none,
        )],
        tags=["hsts"],
    ),
    BenchmarkCase(
        name="HSTS_MEDIUM_N",
        mock_config=MockServerConfig(
            headers={"Strict-Transport-Security": _MEDIUM_HSTS},
            status=200,
            body="<html><body>Medium HSTS</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="hsts",
            category="negative",
            description="max-age=31536000; includeSubDomains → hsts_present must be True",
            check_fn=_hsts_is_adequate,
        )],
        tags=["hsts", "negative"],
    ),
    BenchmarkCase(
        name="HSTS_STRONG_N",
        mock_config=MockServerConfig(
            headers={"Strict-Transport-Security": _STRONG_HSTS},
            status=200,
            body="<html><body>Full HSTS preload</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="hsts",
            category="negative",
            description="max-age=63072000; includeSubDomains; preload → strong HSTS, hsts_present=True",
            check_fn=_hsts_is_adequate,
        )],
        tags=["hsts", "negative"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# WAF Detector cases  (tools/waf_detector.py → detect_waf)
# ─────────────────────────────────────────────────────────────────────────────
# "positive" = WAF correctly DETECTED (site is protected — tool should fire)
# "negative" = correctly NOT detected (no WAF headers, no probe blocking)

def _waf_detected(r: dict) -> bool:
    return r.get("waf_detected", False)


def _waf_cloudflare(r: dict) -> bool:
    return r.get("waf_detected", False) and "cloudflare" in (r.get("waf_name") or "").lower()


def _waf_probe_blocked(r: dict) -> bool:
    return r.get("probe_blocked", False)


WAF_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="WAF_CLOUDFLARE_P",
        mock_config=MockServerConfig(
            headers={
                "cf-ray": "87c3456789ab-IAD",
                "cf-cache-status": "MISS",
                "server": "cloudflare",
            },
            status=200,
            body="<html><body>Behind Cloudflare</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="waf",
            category="positive",
            description="cf-ray + cloudflare server header → Cloudflare WAF must be detected",
            check_fn=_waf_cloudflare,
        )],
        tags=["waf", "cloudflare"],
    ),
    BenchmarkCase(
        name="WAF_IMPERVA_P",
        mock_config=MockServerConfig(
            headers={
                "X-Iinfo": "8-12345678-0 0NNN RT(1700000000000 0) q(0 0 0 -1) r(0 0) B6(0)",
                "Set-Cookie": "incap_ses_1234_5678=abcdef; Path=/",
            },
            status=200,
            body="<html><body>Behind Imperva</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="waf",
            category="positive",
            description="x-iinfo header + incap_ses_ cookie → Imperva WAF must be detected",
            check_fn=_waf_detected,
        )],
        tags=["waf", "imperva"],
    ),
    BenchmarkCase(
        name="WAF_PROBE_BLOCKED_P",
        mock_config=MockServerConfig(
            headers={"server": "nginx"},
            status=200,
            body="<html><body>Normal Site</body></html>",
            probe_keyword="waf_probe",
            probe_status=403,
            probe_body="<html><body>Access Denied</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="waf",
            category="positive",
            description="Probe ?waf_probe=<xss> returns 403 → probe_blocked must be True",
            check_fn=_waf_probe_blocked,
        )],
        tags=["waf", "probe"],
    ),
    BenchmarkCase(
        name="WAF_NONE_N",
        mock_config=MockServerConfig(
            headers={"server": "nginx/1.24.0"},
            status=200,
            body="<html><body>No WAF</body></html>",
        ),
        ground_truths=[GroundTruth(
            tool="waf",
            category="negative",
            description="No WAF headers, probe returns 200 → waf_detected must be False",
            check_fn=_waf_detected,
        )],
        tags=["waf", "negative"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# DNS Security cases  (tools/dns_scanner.py → scan_dns_security)
# Uses DoH mock — these cases are executed differently by the runner.
# ─────────────────────────────────────────────────────────────────────────────

def _dns_spf_issue(r: dict) -> bool:
    return r.get("spf", {}).get("risk", 0) >= 30


def _dns_dmarc_issue(r: dict) -> bool:
    return r.get("dmarc", {}).get("risk", 0) >= 20


def _dns_any_issue(r: dict) -> bool:
    spf_risk   = r.get("spf",   {}).get("risk", 0)
    dmarc_risk = r.get("dmarc", {}).get("risk", 0)
    return (spf_risk + dmarc_risk) >= 30


def _dns_is_clean(r: dict) -> bool:
    """True when tool incorrectly flags a well-configured domain."""
    return r.get("risk_score", 0) >= 30


DNS_CASES: list[DnsBenchmarkCase] = [
    DnsBenchmarkCase(
        name="DNS_NO_SPF_P",
        domain="no-spf-example.test",
        doh_records={
            ("no-spf-example.test", "TXT"): [],     # no TXT records at all
            ("_dmarc.no-spf-example.test", "TXT"): [],
            ("no-spf-example.test", "CAA"): [],
        },
        ground_truths=[GroundTruth(
            tool="dns",
            category="positive",
            description="No SPF record → risk +30, anyone can spoof emails",
            check_fn=_dns_spf_issue,
        )],
        tags=["dns", "spf"],
    ),
    DnsBenchmarkCase(
        name="DNS_SPF_PLUS_ALL_P",
        domain="spf-plus-all.test",
        doh_records={
            ("spf-plus-all.test", "TXT"):           ["v=spf1 +all"],
            ("_dmarc.spf-plus-all.test", "TXT"):    [],
            ("spf-plus-all.test", "CAA"):            [],
        },
        ground_truths=[GroundTruth(
            tool="dns",
            category="positive",
            description="SPF with +all → CRITICAL, permits all senders, risk +40",
            check_fn=lambda r: r.get("spf", {}).get("risk", 0) >= 40,
        )],
        tags=["dns", "spf", "critical"],
    ),
    DnsBenchmarkCase(
        name="DNS_NO_DMARC_P",
        domain="no-dmarc.test",
        doh_records={
            ("no-dmarc.test", "TXT"):             ["v=spf1 include:_spf.example.com ~all"],
            ("_dmarc.no-dmarc.test", "TXT"):       [],   # No DMARC record
            ("no-dmarc.test", "CAA"):              [],
        },
        ground_truths=[GroundTruth(
            tool="dns",
            category="positive",
            description="SPF exists but no DMARC → risk +20, no enforcement policy",
            check_fn=_dns_dmarc_issue,
        )],
        tags=["dns", "dmarc"],
    ),
    DnsBenchmarkCase(
        name="DNS_FULL_PROTECTION_N",
        domain="secure-domain.test",
        doh_records={
            ("secure-domain.test", "TXT"):        ["v=spf1 include:_spf.google.com -all"],
            ("_dmarc.secure-domain.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@secure-domain.test; ruf=mailto:dmarc@secure-domain.test"],
            ("secure-domain.test", "CAA"):        ["0 issue \"letsencrypt.org\""],
        },
        ground_truths=[GroundTruth(
            tool="dns",
            category="negative",
            description="SPF -all + DMARC p=reject + CAA → low risk, tool must not fire high",
            check_fn=_dns_is_clean,
        )],
        tags=["dns", "negative"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Complete dataset
# ─────────────────────────────────────────────────────────────────────────────

ALL_HTTP_CASES: list[BenchmarkCase] = (
    SECURITY_HEADERS_CASES
    + CORS_CSP_CASES
    + COOKIE_CASES
    + EXPOSURE_CASES
    + HSTS_CASES
    + WAF_CASES
)

ALL_DNS_CASES: list[DnsBenchmarkCase] = DNS_CASES

TOTAL_CASES = len(ALL_HTTP_CASES) + len(ALL_DNS_CASES)

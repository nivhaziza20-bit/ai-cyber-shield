"""
active_verification_runner.py — AI Cyber Shield v6

Automatic active vulnerability verification.

Inspects completed URL scan tool_results for findings that can be confirmed
with a live probe, dispatches active_verifier.py non-destructive probes,
and returns structured VerificationResult objects.

All ethical failsafes from active_verifier.py are inherited:
  • No destructive payloads (rm -rf, DROP TABLE, etc.)
  • SSRF guard on every probe target
  • WAF block → BLOCKED_BY_ACTIVE_DEFENSE (never confirmed)
  • 5-second hard timeout per probe
  • Maximum _MAX_VERIFICATIONS_PER_SCAN probes per scan run

Public API
──────────
  run_active_verification(url, tool_results, timeout=5.0) -> list[VerificationResult]
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from dataclasses import dataclass, field
from typing import Any

from active_verifier import (
    ActiveVerifier,
    VerificationResult,
    VerificationStatus,
    VulnType,
)

logger = logging.getLogger(__name__)

_MAX_VERIFICATIONS_PER_SCAN = 5


# ─────────────────────────────────────────────────────────────────────────────
# Internal model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _VerifiableVuln:
    vuln_type:       VulnType
    endpoint:        str
    parameter:       str
    contextual_data: dict[str, Any] = field(default_factory=dict)
    source_tool:     str            = ""


# ─────────────────────────────────────────────────────────────────────────────
# Extractor — map tool findings to verifiable vuln types
# ─────────────────────────────────────────────────────────────────────────────

def _extract_verifiable_vulns(url: str, tool_results: dict) -> list[_VerifiableVuln]:
    """
    Inspect tool outputs and return a list of vulnerabilities suitable for
    active probing.  Each entry maps to exactly one VulnType.

    Finding priority order (most confident first):
      1. open_redirect.confirmed_redirects  → OPEN_REDIRECT
      2. cors_csp.cors_issues (wildcard)    → CORS_MISCONFIGURATION
      3. open_redirect.candidates           → OPEN_REDIRECT (fallback)
      4. deep_js_crawler API calls          → REFLECTED_XSS
      5. html.template_issues               → SSTI
      6. crawler.sensitive_paths (traversal)→ PATH_TRAVERSAL
      7. exposure.http_issues (CRLF)        → CRLF_INJECTION
      8. headers host injection hint        → HOST_HEADER_INJECTION
    """
    found: list[_VerifiableVuln] = []

    # ── 1. Open Redirect (confirmed) ─────────────────────────────────────────
    redir = tool_results.get("open_redirect", {})
    for r in redir.get("confirmed_redirects", [])[:2]:
        param    = r.get("param", "url")
        endpoint = r.get("url", url)
        if endpoint and param:
            found.append(_VerifiableVuln(
                vuln_type       = VulnType.OPEN_REDIRECT,
                endpoint        = endpoint.split("?")[0],
                parameter       = param,
                contextual_data = {"tool_finding": r},
                source_tool     = "open_redirect",
            ))

    # ── 2. CORS Misconfiguration ──────────────────────────────────────────────
    cors_data   = tool_results.get("cors_csp", {})
    cors_issues = cors_data.get("cors_issues", [])
    if any(
        any(kw in str(issue).lower() for kw in ("wildcard", "allow-origin", "cors", "acao"))
        for issue in cors_issues
    ):
        found.append(_VerifiableVuln(
            vuln_type       = VulnType.CORS_MISCONFIGURATION,
            endpoint        = url,
            parameter       = "",
            contextual_data = {"cors_issues": cors_issues[:3]},
            source_tool     = "cors_csp",
        ))

    # ── 3. Open Redirect (candidate params, not yet confirmed) ───────────────
    if not any(v.vuln_type == VulnType.OPEN_REDIRECT for v in found):
        for r in redir.get("candidates", [])[:1]:
            param    = r.get("param", "url")
            endpoint = r.get("url", url)
            if endpoint and param:
                found.append(_VerifiableVuln(
                    vuln_type       = VulnType.OPEN_REDIRECT,
                    endpoint        = endpoint.split("?")[0],
                    parameter       = param,
                    contextual_data = {"tool_finding": r},
                    source_tool     = "open_redirect_candidate",
                ))

    # ── 4. Reflected XSS (SPA API calls from deep JS crawler) ────────────────
    js_data = tool_results.get("deep_js_crawler", {})
    for call in js_data.get("api_calls", [])[:2]:
        ep = call.get("url", "")
        if ep and not ep.startswith(("chrome-extension", "data:", "blob:")):
            found.append(_VerifiableVuln(
                vuln_type       = VulnType.REFLECTED_XSS,
                endpoint        = ep.split("?")[0],
                parameter       = "q",
                contextual_data = {"xhr_endpoint": ep},
                source_tool     = "deep_js_crawler",
            ))
            break

    # ── 5. SSTI (template injection hints in HTML scan) ──────────────────────
    html_data = tool_results.get("html", {})
    for issue in html_data.get("template_issues", [])[:1]:
        if any(kw in str(issue).lower() for kw in ("ssti", "template", "expression")):
            found.append(_VerifiableVuln(
                vuln_type       = VulnType.SSTI,
                endpoint        = url,
                parameter       = "msg",
                contextual_data = {"issue": str(issue)},
                source_tool     = "html",
            ))

    # ── 6. Path Traversal (crawler found traversal-looking paths) ────────────
    crawler = tool_results.get("crawler", {})
    sensitive = crawler.get("sensitive_paths", [])
    if any(
        any(kw in str(p).lower() for kw in ("..", "traversal", "%2e"))
        for p in sensitive
    ):
        found.append(_VerifiableVuln(
            vuln_type       = VulnType.PATH_TRAVERSAL,
            endpoint        = url,
            parameter       = "file",
            contextual_data = {"sensitive_paths": [str(p) for p in sensitive[:3]]},
            source_tool     = "crawler",
        ))

    # ── 7. CRLF Injection (exposure checker or headers) ──────────────────────
    exposure = tool_results.get("exposure", {})
    for issue in exposure.get("http_issues", [])[:1]:
        if any(kw in str(issue).lower() for kw in ("crlf", "header inject", "response split")):
            found.append(_VerifiableVuln(
                vuln_type       = VulnType.CRLF_INJECTION,
                endpoint        = url,
                parameter       = "url",
                contextual_data = {"issue": str(issue)},
                source_tool     = "exposure",
            ))

    # ── 8. Host Header Injection (missing header + password reset hint) ───────
    headers_data = tool_results.get("headers", {})
    missing = headers_data.get("missing_headers", [])
    if any("host" in str(h).lower() for h in missing):
        found.append(_VerifiableVuln(
            vuln_type       = VulnType.HOST_HEADER_INJECTION,
            endpoint        = url,
            parameter       = "",
            contextual_data = {"missing_headers": [str(h) for h in missing[:3]]},
            source_tool     = "headers",
        ))

    return found[:_MAX_VERIFICATIONS_PER_SCAN]


# ─────────────────────────────────────────────────────────────────────────────
# Async runner
# ─────────────────────────────────────────────────────────────────────────────

async def _run_all_async(
    vulns:    list[_VerifiableVuln],
    verifier: ActiveVerifier,
) -> list[VerificationResult]:
    tasks = [
        verifier.verify_vulnerability(
            vuln_type       = v.vuln_type,
            endpoint        = v.endpoint,
            parameter       = v.parameter,
            contextual_data = v.contextual_data,
        )
        for v in vulns
    ]
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[VerificationResult] = []
    for item in raw:
        if isinstance(item, VerificationResult):
            results.append(item)
        else:
            logger.warning("active_verification_runner: probe error (skipped): %s", item)
    return results


def _run_async_safe(coro) -> list[VerificationResult]:
    """
    Execute a coroutine from a synchronous context.

    Handles both regular (no loop) and already-running loop cases
    (e.g. Streamlit 1.38+ async backend) by spawning a dedicated thread.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside a running event loop — spawn a thread with its own loop.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(asyncio.run, coro)
            return fut.result()

    return asyncio.run(coro)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_active_verification(
    url:          str,
    tool_results: dict,
    timeout:      float = 5.0,
) -> list[VerificationResult]:
    """
    Detect verifiable vulnerabilities in completed scan results and dispatch
    non-destructive active probes.

    Args:
        url:          Target URL (used as fallback endpoint for some probes).
        tool_results: The ``tool_results`` dict from run_url_security_audit().
        timeout:      Per-probe HTTP timeout in seconds (capped at 10s internally).

    Returns:
        List of VerificationResult objects (may be empty if nothing to verify).
        Never raises — errors per probe are logged and skipped.
    """
    vulns = _extract_verifiable_vulns(url, tool_results)
    if not vulns:
        logger.debug("active_verification_runner: no verifiable findings for %s", url)
        return []

    logger.info(
        "active_verification_runner: %d probe(s) for %s: %s",
        len(vulns), url, [v.vuln_type.value for v in vulns],
    )

    verifier = ActiveVerifier(timeout=timeout)
    try:
        results = _run_async_safe(_run_all_async(vulns, verifier))
    except Exception as exc:
        logger.error("active_verification_runner: run failed: %s", exc)
        return []

    confirmed = sum(1 for r in results if r.is_confirmed)
    blocked   = sum(1 for r in results
                    if r.status == VerificationStatus.BLOCKED_BY_ACTIVE_DEFENSE)
    logger.info(
        "active_verification_runner: %d confirmed, %d WAF-blocked, %d inconclusive",
        confirmed, blocked, len(results) - confirmed - blocked,
    )
    return results

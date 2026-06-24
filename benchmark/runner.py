"""
Benchmark runner — executes the real scanning tools against mock targets
and records the outcome of each ground-truth check.

Design principles:
  - Sets AICS_BENCHMARK_MODE=1 before any tool is called so the SSRF guard
    allows requests to 127.0.0.1.
  - Calls tool underlying functions directly via `tool_obj.func()` to bypass
    LangChain overhead and avoid serialisation issues.
  - Parses the JSON string returned by every tool into a plain dict.
  - Catches all exceptions so a single tool failure cannot abort the entire run.
  - DNS cases use unittest.mock to intercept Cloudflare DoH requests instead of
    a local HTTP server.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

from benchmark.dataset import (
    ALL_DNS_CASES,
    ALL_HTTP_CASES,
    BenchmarkCase,
    DnsBenchmarkCase,
    GroundTruth,
)
from benchmark.mock_target import mock_target


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    """Outcome of evaluating one GroundTruth against actual tool output."""
    case_name:    str
    tool:         str
    category:     str        # "positive" | "negative"
    description:  str
    outcome:      str        # "TP" | "FP" | "TN" | "FN" | "ERROR" | "SKIP"
    actual_output: dict      # parsed JSON from tool (empty on error)
    error_msg:    str | None
    duration_ms:  float


@dataclass
class BenchmarkRun:
    """Complete set of results from one benchmark execution."""
    timestamp:   str
    results:     list[CheckResult] = field(default_factory=list)
    total_cases: int = 0
    errors:      int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Tool function registry
# ─────────────────────────────────────────────────────────────────────────────

def _get_tool_funcs() -> dict[str, Any]:
    """
    Lazily imports tool modules and returns a dict of callable functions.
    Uses `.func` on LangChain @tool objects to call the underlying Python
    function directly, bypassing LangChain overhead.
    """
    from tools import (
        cors_csp_checker,
        cookie_security,
        exposure_checker,
        hsts_preload,
        waf_detector,
        web_tools,
        dns_scanner,
    )

    def _extract(obj: Any) -> Any:
        """Return the raw callable from a LangChain @tool-decorated object."""
        return getattr(obj, "func", obj)

    return {
        "security_headers": _extract(web_tools.check_security_headers),
        "cors_csp":         _extract(cors_csp_checker.check_cors_csp),
        "cookie":           _extract(cookie_security.scan_cookie_security),
        "exposure":         _extract(exposure_checker.check_exposure),
        "hsts":             _extract(hsts_preload.check_hsts_preload),
        "waf":              _extract(waf_detector.detect_waf),
        "dns":              _extract(dns_scanner.scan_dns_security),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scoring helper
# ─────────────────────────────────────────────────────────────────────────────

def _score(truth: GroundTruth, actual: dict) -> str:
    """
    Computes TP / FP / TN / FN from the ground truth + actual result dict.

    Semantics:
      check_fn(actual) == True  → tool detected an issue
      category == "positive"    → there IS a real issue (detector should fire)
      category == "negative"    → site is clean (detector should NOT fire)
    """
    try:
        detected = truth.check_fn(actual)
    except Exception:
        return "ERROR"

    if truth.category == "positive":
        return "TP" if detected else "FN"
    else:
        return "TN" if not detected else "FP"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP case runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_http_case(case: BenchmarkCase, tool_funcs: dict[str, Any]) -> list[CheckResult]:
    """Runs all GroundTruths for one HTTP-based BenchmarkCase."""
    results: list[CheckResult] = []

    with mock_target(case.mock_config) as url:
        for truth in case.ground_truths:
            func = tool_funcs.get(truth.tool)
            if func is None:
                results.append(CheckResult(
                    case_name=case.name, tool=truth.tool,
                    category=truth.category, description=truth.description,
                    outcome="SKIP", actual_output={},
                    error_msg=f"No tool registered for '{truth.tool}'",
                    duration_ms=0.0,
                ))
                continue

            t0 = time.perf_counter()
            try:
                raw = func(url)
                actual = json.loads(raw) if isinstance(raw, str) else (raw or {})
            except Exception as exc:
                results.append(CheckResult(
                    case_name=case.name, tool=truth.tool,
                    category=truth.category, description=truth.description,
                    outcome="ERROR", actual_output={},
                    error_msg=f"{type(exc).__name__}: {exc}",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                ))
                continue
            duration = (time.perf_counter() - t0) * 1000

            outcome = _score(truth, actual)
            results.append(CheckResult(
                case_name=case.name, tool=truth.tool,
                category=truth.category, description=truth.description,
                outcome=outcome, actual_output=actual,
                error_msg=None, duration_ms=duration,
            ))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# DNS case runner
# ─────────────────────────────────────────────────────────────────────────────

def _make_doh_mock(records: dict[tuple[str, str], list[str]]):
    """
    Returns a mock for ``requests.get`` that intercepts Cloudflare DoH calls.

    The DNS scanner calls:
        requests.get("https://cloudflare-dns.com/dns-query",
                      params={"name": domain, "type": rtype}, ...)

    We intercept this and return a fake JSON response built from ``records``.
    """
    def _fake_get(url: str, **kwargs) -> MagicMock:
        params  = kwargs.get("params", {})
        name    = params.get("name", "")
        rtype   = params.get("type", "TXT")
        key     = (name, rtype)
        data_list = records.get(key, [])

        # Build a minimal DoH response envelope
        rtype_num = {"TXT": 16, "CAA": 257}.get(rtype, 16)
        answers = [{"type": rtype_num, "data": d} for d in data_list]
        payload = {"Answer": answers}

        mock_resp = MagicMock()
        mock_resp.json.return_value = payload
        mock_resp.status_code = 200
        return mock_resp

    return _fake_get


def _run_dns_case(case: DnsBenchmarkCase, tool_funcs: dict[str, Any]) -> list[CheckResult]:
    """Runs all GroundTruths for one DNS BenchmarkCase using mocked DoH."""
    results: list[CheckResult] = []
    func = tool_funcs.get("dns")
    if func is None:
        for truth in case.ground_truths:
            results.append(CheckResult(
                case_name=case.name, tool="dns", category=truth.category,
                description=truth.description, outcome="SKIP", actual_output={},
                error_msg="No dns tool registered", duration_ms=0.0,
            ))
        return results

    doh_mock = _make_doh_mock(case.doh_records)

    for truth in case.ground_truths:
        t0 = time.perf_counter()
        try:
            # scan_dns_security takes a URL and extracts the hostname via urlparse.
            with patch("tools.dns_scanner.requests.get", side_effect=doh_mock):
                raw = func(f"http://{case.domain}")
            actual = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except Exception as exc:
            results.append(CheckResult(
                case_name=case.name, tool="dns", category=truth.category,
                description=truth.description, outcome="ERROR", actual_output={},
                error_msg=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.perf_counter() - t0) * 1000,
            ))
            continue

        duration = (time.perf_counter() - t0) * 1000
        outcome  = _score(truth, actual)
        results.append(CheckResult(
            case_name=case.name, tool="dns", category=truth.category,
            description=truth.description, outcome=outcome, actual_output=actual,
            error_msg=None, duration_ms=duration,
        ))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_benchmark(
    http_cases: list[BenchmarkCase] | None = None,
    dns_cases:  list[DnsBenchmarkCase] | None = None,
    verbose:    bool = False,
) -> BenchmarkRun:
    """
    Executes the full accuracy benchmark and returns a BenchmarkRun with all results.

    Sets AICS_BENCHMARK_MODE=1 for the duration of the run so the SSRF guard
    allows connections to localhost mock servers.

    Args:
        http_cases: HTTP-based cases (default: ALL_HTTP_CASES).
        dns_cases:  DNS cases with mocked DoH (default: ALL_DNS_CASES).
        verbose:    Print case names as they execute.

    Returns:
        BenchmarkRun with populated results list.
    """
    from datetime import datetime, timezone

    http_cases = http_cases if http_cases is not None else ALL_HTTP_CASES
    dns_cases  = dns_cases  if dns_cases  is not None else ALL_DNS_CASES

    # Enable SSRF bypass for mock servers
    prev_mode = os.environ.get("AICS_BENCHMARK_MODE", "")
    os.environ["AICS_BENCHMARK_MODE"] = "1"

    run = BenchmarkRun(
        timestamp=datetime.now(timezone.utc).isoformat(),
        total_cases=len(http_cases) + len(dns_cases),
    )

    try:
        tool_funcs = _get_tool_funcs()

        for case in http_cases:
            if verbose:
                print(f"  → {case.name}")
            results = _run_http_case(case, tool_funcs)
            run.results.extend(results)
            run.errors += sum(1 for r in results if r.outcome == "ERROR")

        for case in dns_cases:
            if verbose:
                print(f"  → {case.name} (dns)")
            results = _run_dns_case(case, tool_funcs)
            run.results.extend(results)
            run.errors += sum(1 for r in results if r.outcome == "ERROR")

    finally:
        # Restore previous env state
        if prev_mode:
            os.environ["AICS_BENCHMARK_MODE"] = prev_mode
        else:
            os.environ.pop("AICS_BENCHMARK_MODE", None)

    return run

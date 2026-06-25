"""
api/dependencies.py — AI Cyber Shield v6

FastAPI dependency providers.
Centralised here so tests can override via app.dependency_overrides.
"""

from __future__ import annotations

from typing import Callable


def _default_scanner(url: str, mode: str) -> dict:
    """
    Real scanner — lazy import so the API module can be imported
    even in environments where the full tool stack is not installed.
    """
    from url_scanner_pipeline import run_url_security_audit  # noqa: PLC0415
    result = run_url_security_audit(url)

    # If PT mode, also run active verification
    if mode == "pt":
        try:
            from active_verification_runner import run_active_verification  # noqa: PLC0415
            av_findings = run_active_verification(
                url, result.get("tool_results", {})
            )
            result["av_results"] = av_findings
        except Exception:
            pass  # PT mode unavailable — degrade gracefully

    return result


def get_scanner_fn() -> Callable[[str, str], dict]:
    """
    Dependency that provides the scanner callable.
    Override in tests:
        app.dependency_overrides[get_scanner_fn] = lambda: my_mock
    """
    return _default_scanner


def _default_webhook_sender(webhook_url: str, payload: dict) -> None:
    """Send completion webhook via httpx (fire-and-forget)."""
    try:
        import httpx  # noqa: PLC0415
        httpx.post(webhook_url, json=payload, timeout=10)
    except Exception:
        pass


def get_webhook_sender() -> Callable[[str, dict], None]:
    """Override in tests to capture webhook payloads without HTTP."""
    return _default_webhook_sender

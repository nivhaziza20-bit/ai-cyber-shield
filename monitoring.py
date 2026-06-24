"""Sentry error monitoring — initialize once at app startup."""
from __future__ import annotations
import logging

_log = logging.getLogger(__name__)
_initialized = False


def init_sentry() -> None:
    """Initialize Sentry if SENTRY_DSN is configured. Safe to call multiple times."""
    global _initialized
    if _initialized:
        return
    try:
        import streamlit as st
        dsn = st.secrets.get("SENTRY_DSN", "")
        if not dsn:
            return
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
        sentry_sdk.init(
            dsn=dsn,
            traces_sample_rate=0.1,       # 10% of transactions
            profiles_sample_rate=0.1,
            environment=st.secrets.get("ENVIRONMENT", "production"),
            integrations=[
                LoggingIntegration(level=logging.WARNING, event_level=logging.ERROR),
            ],
            before_send=_scrub_secrets,
        )
        _initialized = True
        _log.info("Sentry initialized")
    except Exception as exc:
        _log.debug("Sentry init skipped: %s", exc)


def _scrub_secrets(event: dict, hint: dict) -> dict:
    """Remove API keys from Sentry events before sending."""
    import re
    _KEY_RE = re.compile(
        r'(api[_-]?key|secret|token|password|groq|stripe|supabase)["\s:=]+[^\s"\'&,;]{8,}',
        re.IGNORECASE,
    )
    try:
        raw = str(event)
        if _KEY_RE.search(raw):
            # Scrub from exception values
            for exc_info in event.get("exception", {}).get("values", []):
                val = exc_info.get("value", "")
                exc_info["value"] = _KEY_RE.sub(r"\1=[REDACTED]", val)
    except Exception:
        pass
    return event


def capture_exception(exc: Exception, **context) -> None:
    """Manually capture an exception with extra context."""
    try:
        import sentry_sdk
        with sentry_sdk.push_scope() as scope:
            for k, v in context.items():
                scope.set_extra(k, v)
            sentry_sdk.capture_exception(exc)
    except Exception:
        pass


def set_user_context(user_id: str, email: str) -> None:
    """Tag Sentry events with the current user (no PII beyond email)."""
    try:
        import sentry_sdk
        sentry_sdk.set_user({"id": user_id, "email": email})
    except Exception:
        pass

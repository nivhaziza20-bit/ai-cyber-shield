"""
Playwright headless browser executor for legal compliance scanning.

Provides real JavaScript execution to detect:
  - Cookies set AFTER JavaScript loads (not visible in static HTML)
  - All third-party network requests (trackers loaded by GTM etc.)
  - Fully rendered DOM for consent banner + accessibility analysis
  - Security headers from actual HTTP response

Falls back to requests-based static scan if Playwright is unavailable.

Playwright version pinned to 1.49.0 — last version confirmed stable on
Streamlit Community Cloud (Debian bullseye base image, June 2025).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Result model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PlaywrightResult:
    url:              str
    final_url:        str              = ""
    html:             str              = ""       # Fully rendered DOM after JS
    cookies:          list[dict]       = field(default_factory=list)   # Playwright cookies
    requests_made:    list[str]        = field(default_factory=list)   # All outbound URLs
    response_headers: dict             = field(default_factory=dict)
    error:            str              = ""
    method:           str              = "playwright"  # "playwright" | "requests"
    load_time_ms:     float            = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Playwright availability (installed once per server boot via st.cache_resource)
# ─────────────────────────────────────────────────────────────────────────────

def _install_playwright_browser() -> bool:
    """
    Ensure Playwright Chromium binary is installed.
    Should be called via st.cache_resource so it runs only once per boot.
    Returns True if Playwright is available after the call.
    """
    # Step 1: quick check — try to import and probe executable
    try:
        from playwright.sync_api import sync_playwright
        # A minimal probe: just enter and immediately exit the context.
        # This exercises the same code path as a real scan launch.
        with sync_playwright() as _p:
            _exe = _p.chromium.executable_path
        return True
    except Exception as probe_err:
        _log.info("Playwright browser not found (%s) — installing…", probe_err)

    # Step 2: run playwright install
    try:
        rc = os.system("playwright install chromium --with-deps 2>&1")
        if rc == 0:
            # Verify it worked
            from playwright.sync_api import sync_playwright
            with sync_playwright() as _p:
                _exe = _p.chromium.executable_path
            _log.info("Playwright Chromium installed successfully.")
            return True
        _log.warning("playwright install chromium exited with code %d", rc)
    except Exception as install_err:
        _log.warning("playwright install failed: %s", install_err)

    return False


# Cached available flag — populated on first call from legal_scanner_ui
_playwright_available: Optional[bool] = None


def ensure_playwright_ready() -> bool:
    """
    Thread-safe singleton check — meant to be wrapped in st.cache_resource
    at the call site so it runs only once per Streamlit server boot.
    """
    global _playwright_available
    if _playwright_available is None:
        _playwright_available = _install_playwright_browser()
    return _playwright_available


# ─────────────────────────────────────────────────────────────────────────────
# SSRF guard integration
# ─────────────────────────────────────────────────────────────────────────────

def _is_ssrf_safe(url: str) -> bool:
    try:
        from tools.http_utils import is_ssrf_blocked
        host = urlparse(url).hostname or ""
        return not is_ssrf_blocked(host)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Core executor
# ─────────────────────────────────────────────────────────────────────────────

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


def execute_page(
    url: str,
    timeout_ms: int = 20_000,
    wait_after_load_ms: int = 2_500,
) -> PlaywrightResult:
    """
    Load `url` in a headless Chromium browser.

    Strategy:
      1. Navigate with wait_until='networkidle' (waits until no requests for 500 ms)
      2. Wait `wait_after_load_ms` for late-loading async scripts (GTM, pixels, etc.)
      3. Collect all cookies via context.cookies()
      4. Collect all outbound request URLs via page.on('request')
      5. Extract fully rendered DOM via page.content()

    Returns PlaywrightResult with method='playwright' on success,
    method='requests' on fallback, and error message if both fail.
    """
    result = PlaywrightResult(url=url)
    t0 = time.time()

    if not _is_ssrf_safe(url):
        result.error = "SSRF blocked"
        return result

    # ── Playwright path ──────────────────────────────────────────────────────
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

        outbound: list[str] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--single-process",
                ],
            )
            context = browser.new_context(
                user_agent=_USER_AGENT,
                ignore_https_errors=False,   # We want to detect SSL errors, not hide them
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9,he;q=0.8"},
            )
            page = context.new_page()

            # Capture every outbound request URL
            page.on("request", lambda req: outbound.append(req.url))

            try:
                response = page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=timeout_ms,
                )
            except PWTimeout:
                # networkidle timed out — fall through to domcontentloaded
                try:
                    response = page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=timeout_ms // 2,
                    )
                except Exception as e2:
                    result.error = f"Navigation failed: {e2}"
                    browser.close()
                    return result

            # Wait for late-loading async scripts (GTM, pixels)
            page.wait_for_timeout(wait_after_load_ms)

            # Collect state
            result.html             = page.content()
            result.cookies          = context.cookies()
            result.requests_made    = list(outbound)
            result.final_url        = page.url
            result.load_time_ms     = round((time.time() - t0) * 1000, 1)
            result.method           = "playwright"

            if response:
                result.response_headers = {
                    k.lower(): v for k, v in response.headers.items()
                }

            browser.close()

        return result

    except Exception as pw_err:
        _log.debug("Playwright execution failed (%s) — falling back to requests", pw_err)

    # ── requests fallback ────────────────────────────────────────────────────
    try:
        import requests as req_lib
        from bs4 import BeautifulSoup

        headers = {
            "User-Agent": _USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = req_lib.get(url, headers=headers, timeout=15, allow_redirects=True, verify=True)
        result.html             = resp.text
        result.final_url        = resp.url
        result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
        result.cookies          = [
            {"name": k, "value": v, "domain": urlparse(resp.url).hostname or "",
             "http_only": False, "secure": False, "same_site": ""}
            for k, v in resp.cookies.items()
        ]
        result.load_time_ms = round((time.time() - t0) * 1000, 1)
        result.method       = "requests"
        return result

    except Exception as req_err:
        result.error = str(req_err)
        result.method = "requests"
        return result

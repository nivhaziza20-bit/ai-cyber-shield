"""
Web Crawler v2 — Playwright async (headless Chromium)

Replaces the synchronous requests-based BFS with an async Playwright
crawler that executes JavaScript and renders SPAs (React / Vue / Next.js).

Architecture:
  crawl_website()   — @tool, synchronous LangChain entry-point
  _run_async()      — bridge: starts a fresh event loop per call (safe
                      from ThreadPoolExecutor workers or Streamlit threads)
  _async_crawl()    — async BFS using Playwright headless Chromium
  _request_guard()  — Playwright route-handler: SSRF + binary-resource blocking
  _compute_result() — pure function: risk score + recommendations from crawl data

Security guardrails (from tools/http_utils.py):
  • SSRF check on every request (including JS-initiated XHR/fetch) via the
    Playwright context-level route interceptor.
  • Response body capped at 5 MB per page (MAX_RESPONSE_BYTES).
  • Scheme restricted to http / https.
  • Private, loopback, link-local, and IPv4-mapped addresses are blocked.

Install note (first run):
  pip install playwright
  playwright install chromium
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

from langchain_core.tools import tool

from tools.http_utils import is_ssrf_blocked, MAX_RESPONSE_BYTES

# ── Optional Playwright import (graceful degradation) ─────────────────────────
try:
    from playwright.async_api import (
        async_playwright,
        Route,
        Request as PlaywrightRequest,
    )
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_CRAWLER_BUDGET_S = 25       # hard wall-clock budget for the whole crawl
_PAGE_TIMEOUT_MS  = 10_000   # per-page navigation timeout (10 s)
_SPA_SETTLE_MS    = 600      # extra wait after DOMContentLoaded for SPA hydration
_MAX_BODY_BYTES   = MAX_RESPONSE_BYTES   # 5 MB cap

# Extensions whose payloads we don't need for HTML analysis
_BINARY_EXT = re.compile(
    r"\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|otf|mp4|mp3|avi|"
    r"mov|pdf|zip|gz|tar|rar|7z|bz2|exe|dll|dmg|apk)$",
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# Pattern matchers (unchanged from v1)
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_PATHS = re.compile(
    r"/(admin|administrator|wp-admin|phpmyadmin|cpanel|manager|"
    r"backup|backups|db|database|dump|sql|"
    r"api|api/v\d|graphql|swagger|openapi|"
    r"\.git|\.env|\.htaccess|\.htpasswd|web\.config|"
    r"login|signin|auth|sso|oauth|"
    r"debug|test|dev|staging|internal|private|"
    r"config|conf|settings|setup|install)[/\?#]?",
    re.I,
)

_STACK_TRACE_PATTERNS = re.compile(
    r"(Traceback \(most recent call last\)|"
    r"at \w+\.\w+\([\w\.]+:\d+\)|"
    r"System\.NullReferenceException|"
    r"com\.mysql\.jdbc\.exceptions|"
    r"ORA-\d{5}|"
    r"<b>Fatal error</b>|"
    r"Warning: mysql_)",
    re.I,
)

_LOGIN_PATTERNS = re.compile(
    r"<input[^>]+type=[\"']password[\"']|"
    r"<form[^>]+action[^>]*(login|signin|auth)[^>]*>",
    re.I,
)


# ─────────────────────────────────────────────────────────────────────────────
# Pure helper functions (unit-testable, no I/O)
# ─────────────────────────────────────────────────────────────────────────────

def _same_origin(base: str, link: str) -> bool:
    base_p = urlparse(base)
    link_p = urlparse(link)
    return link_p.netloc == "" or link_p.netloc == base_p.netloc


def _normalise(base: str, href: str) -> str | None:
    """Resolve href to absolute URL on same scheme; strip fragments."""
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
        return None
    full   = urljoin(base, href)
    parsed = urlparse(full)
    if parsed.scheme not in ("http", "https"):
        return None
    return parsed._replace(fragment="").geturl()


def _extract_links(html: str, current_url: str) -> list[str]:
    hrefs = re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I)
    links = []
    for href in hrefs:
        url = _normalise(current_url, href)
        if url and _same_origin(current_url, url):
            links.append(url)
    return links


def _check_sensitive_path(url: str) -> str | None:
    path = urlparse(url).path
    m    = _SENSITIVE_PATHS.search(path)
    return path if m else None


def _compute_result(url: str, crawl_data: dict) -> dict:
    """
    Convert raw async crawl data into the final tool result dict.
    Pure function — no I/O.
    """
    pages_visited    = crawl_data.get("pages_visited",    [])
    sensitive_paths  = crawl_data.get("sensitive_paths",  [])
    broken_links     = crawl_data.get("broken_links",     [])
    login_pages      = crawl_data.get("login_pages",      [])
    stack_leaks      = crawl_data.get("stack_leaks",      [])
    robots_disallowed = crawl_data.get("robots_disallowed", [])

    risk_score = min(
        len(sensitive_paths) * 15
        + len(stack_leaks)   * 30
        + len(broken_links)  * 5,
        100,
    )

    recommendations: list[str] = []
    if sensitive_paths:
        recommendations.append(
            "Restrict access to sensitive paths with authentication or firewall rules: "
            + ", ".join(sensitive_paths[:3])
        )
    if stack_leaks:
        recommendations.append(
            "Disable debug/stack-trace output in production. "
            "Set DEBUG=False and configure a custom error page."
        )
    if broken_links:
        recommendations.append(
            f"{len(broken_links)} broken link(s) found — fix or remove dead URLs."
        )
    if robots_disallowed:
        recommendations.append(
            "robots.txt Disallow entries hint at hidden paths. "
            "Ensure these are protected by access controls, not just robots.txt."
        )

    return {
        "tool":              "web_crawler",
        "status":            "completed",
        "renderer":          "playwright-headless-chromium",
        "start_url":         url,
        "pages_visited":     pages_visited,
        "total_pages":       len(pages_visited),
        "sensitive_paths":   sensitive_paths,
        "broken_links":      broken_links,
        "login_pages":       login_pages,
        "stack_trace_leaks": stack_leaks,
        "robots_disallowed": robots_disallowed,
        "risk_score":        risk_score,
        "recommendations":   recommendations,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Playwright route handler (module-level — independently testable)
# ─────────────────────────────────────────────────────────────────────────────

async def _request_guard(route: "Route", request: "PlaywrightRequest") -> None:
    """
    Context-level Playwright route handler applied to EVERY request the
    browser makes (including JS-initiated XHR, fetch, script loads).

    Enforces two security rules in order:
      1. SSRF check  — aborts requests to private/loopback/link-local IPs.
      2. Binary skip — aborts images, fonts, videos to speed up crawl.
    """
    try:
        parsed = urlparse(request.url)
        if is_ssrf_blocked(parsed.hostname or ""):
            await route.abort("blockedbyclient")
            return
        if _BINARY_EXT.search(parsed.path or ""):
            await route.abort()
            return
    except Exception:
        pass  # if guard itself errors, let the request through
    await route.continue_()


# ─────────────────────────────────────────────────────────────────────────────
# Async crawler core
# ─────────────────────────────────────────────────────────────────────────────

async def _async_crawl(url: str, max_pages: int) -> dict:
    """
    BFS crawler using Playwright headless Chromium.

    Handles SPAs: waits for DOMContentLoaded then settles _SPA_SETTLE_MS
    before reading page.content() (the fully rendered DOM).

    Returns raw crawl data dict (not the final tool result).
    """
    parsed_base = urlparse(url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    visited:          set[str]   = set()
    queue:            list[str]  = [url]
    pages_visited:    list[dict] = []
    sensitive_paths:  list[str]  = []
    broken_links:     list[dict] = []
    login_pages:      list[str]  = []
    stack_leaks:      list[str]  = []
    robots_disallowed: list[str] = []

    loop     = asyncio.get_event_loop()
    deadline = loop.time() + _CRAWLER_BUDGET_S

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = await browser.new_context(
            user_agent="AICyberShield/2.0 (security-audit; authorized-use-only)",
            java_script_enabled=True,
            ignore_https_errors=True,   # SSL issues reported by ssl_analyzer.py
        )

        # Register SSRF + binary guard on the context (applies to all pages)
        await context.route("**/*", _request_guard)

        # ── robots.txt ────────────────────────────────────────────────────────
        try:
            rb_page = await context.new_page()
            rb_resp = await rb_page.goto(
                urljoin(base_origin, "/robots.txt"),
                timeout=5_000,
                wait_until="domcontentloaded",
            )
            if rb_resp and rb_resp.status == 200:
                ct = (rb_resp.headers.get("content-type", ""))
                if "text/plain" in ct or "text/x-robots" in ct:
                    rb_text = await rb_resp.text()
                    robots_disallowed = re.findall(r"Disallow:\s*(\S+)", rb_text, re.I)
            await rb_page.close()
        except Exception:
            pass

        # ── Main crawl (one reused page for efficiency) ────────────────────
        page = await context.new_page()

        while queue and len(visited) < max_pages:
            if loop.time() > deadline:
                break

            current = queue.pop(0)
            if current in visited:
                continue

            # Pre-flight: scheme and SSRF check before handing to browser
            c_parsed = urlparse(current)
            if c_parsed.scheme not in ("http", "https"):
                visited.add(current)
                continue
            if is_ssrf_blocked(c_parsed.hostname or ""):
                broken_links.append({"url": current, "status": "ssrf_blocked"})
                visited.add(current)
                continue
            if not _same_origin(url, current):
                visited.add(current)
                continue

            visited.add(current)

            try:
                response = await page.goto(
                    current,
                    wait_until="domcontentloaded",
                    timeout=_PAGE_TIMEOUT_MS,
                )

                # Brief pause — lets SPA frameworks inject routes / links
                await page.wait_for_timeout(_SPA_SETTLE_MS)

                if response is None:
                    broken_links.append({"url": current, "status": "no_response"})
                    continue

                status    = response.status
                final_url = page.url   # may differ after client-side redirect

                # ── Response size cap ─────────────────────────────────────
                try:
                    body_bytes = await response.body()
                    if len(body_bytes) > _MAX_BODY_BYTES:
                        pages_visited.append({
                            "url": current, "status": status,
                            "note": "truncated (>5 MB)",
                        })
                        continue
                except Exception:
                    pass

                if status >= 400:
                    broken_links.append({"url": current, "status": status})
                    pages_visited.append({"url": current, "status": status})
                    continue

                pages_visited.append({"url": current, "status": status})

                # ── Fully rendered DOM (post-JS execution) ────────────────
                html = await page.content()

                if _check_sensitive_path(current):
                    sensitive_paths.append(current)

                if _STACK_TRACE_PATTERNS.search(html):
                    stack_leaks.append(current)

                if _LOGIN_PATTERNS.search(html) and current not in login_pages:
                    login_pages.append(current)

                # Queue new links from rendered DOM
                for link in _extract_links(html, final_url):
                    if link not in visited and _same_origin(url, link):
                        if not is_ssrf_blocked(urlparse(link).hostname or ""):
                            queue.append(link)

            except asyncio.TimeoutError:
                broken_links.append({"url": current, "status": "timeout"})
            except Exception as exc:
                broken_links.append({
                    "url":    current,
                    "status": f"error:{type(exc).__name__}",
                })

        await page.close()
        await browser.close()

    return {
        "pages_visited":     pages_visited,
        "sensitive_paths":   sensitive_paths,
        "broken_links":      broken_links,
        "login_pages":       login_pages,
        "stack_leaks":       stack_leaks,
        "robots_disallowed": robots_disallowed,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Sync bridge (safe from ThreadPoolExecutor, Streamlit, Jupyter)
# ─────────────────────────────────────────────────────────────────────────────

def _run_async(url: str, max_pages: int) -> dict:
    """
    Run _async_crawl from any synchronous context.

    Strategy: try asyncio.run() first (creates & tears down its own loop).
    If a loop is already running in this thread (edge case: Streamlit main
    thread), fall back to a manually managed new loop.
    """
    try:
        return asyncio.run(_async_crawl(url, max_pages))
    except RuntimeError:
        # Fallback for threads that already carry a running loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_async_crawl(url, max_pages))
        finally:
            loop.close()
            asyncio.set_event_loop(None)


# ─────────────────────────────────────────────────────────────────────────────
# LangChain tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def crawl_website(url: str, max_pages: int = 20) -> str:
    """
    Crawls a website with a headless Chromium browser (Playwright), handles
    Client-Side Rendering (React / Vue / Next.js SPAs), and reports:
    sensitive paths, broken links, login forms, stack-trace leaks, and
    robots.txt Disallow entries.

    All requests (including JS-initiated XHR / fetch) are intercepted by
    an SSRF guard — private and loopback addresses are blocked.

    Args:
        url:       Starting URL (http / https only).
        max_pages: Hard page cap (default 20, max 50).

    Returns:
        JSON with total_pages, sensitive_paths, broken_links, login_pages,
        stack_trace_leaks, robots_disallowed, risk_score, recommendations.
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return json.dumps({
            "tool":   "web_crawler",
            "status": "error",
            "error":  (
                "Playwright not installed. "
                "Run: pip install playwright && playwright install chromium"
            ),
        })

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "web_crawler", "status": "invalid_url"})

    if is_ssrf_blocked(parsed.hostname or ""):
        return json.dumps({"tool": "web_crawler", "status": "ssrf_blocked"})

    max_pages = min(int(max_pages), 50)

    try:
        crawl_data = _run_async(url, max_pages)
    except Exception as exc:
        return json.dumps({
            "tool":   "web_crawler",
            "status": "error",
            "error":  str(exc),
        })

    return json.dumps(_compute_result(url, crawl_data), indent=2)

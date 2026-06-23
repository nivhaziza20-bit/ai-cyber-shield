"""
tools/deep_js_crawler.py — AI Cyber Shield v5

Deep JavaScript SPA Crawler using Playwright headless Chromium.

Capability 1: Stealth DOM execution — headless Chromium hides automation signals,
              waits for networkidle/hydration before extracting content.
Capability 2: XHR/Fetch spy — Playwright route intercept captures every API call,
              auth headers, GraphQL endpoints, and POST bodies.
Capability 3: Dynamic form/link/button discovery from the fully-rendered DOM.
Capability 4: Client-side secret scanner — async regex over all script content
              and response bodies for API keys, JWTs, source maps, etc.
Capability 5: SSRF prevention + crawl budget — aborts requests to private IPs,
              caps total time at 20s and pages visited at 30.

AUTHORISATION REQUIREMENT: Authorised targets only.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlparse

from langchain_core.tools import tool

from tools.http_utils import is_ssrf_blocked

logger = logging.getLogger(__name__)

# Playwright is optional — tests patch it; production requires: pip install playwright
try:
    from playwright.async_api import (
        Browser,
        BrowserContext,
        Page,
        Request,
        Response,
        Route,
        async_playwright,
    )
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

# ─────────────────────────────────────────────────────────────────────────────
# Capability 4 — secret pattern registry
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (kind_key, human_description, compiled_pattern)
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("AWS_ACCESS_KEY_ID",     "AWS Access Key ID",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS_SECRET_ACCESS_KEY", "AWS Secret Access Key",
     re.compile(r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})')),
    ("JWT_TOKEN",             "JSON Web Token",
     re.compile(r'eyJ[A-Za-z0-9\-_]{4,}\.eyJ[A-Za-z0-9\-_]{4,}\.[A-Za-z0-9\-_]{4,}')),
    ("FIREBASE_API_KEY",      "Firebase / Google API Key",
     re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("FIREBASE_DB_URL",       "Firebase Realtime Database URL",
     re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com', re.IGNORECASE)),
    ("STRIPE_SECRET_KEY",     "Stripe Secret Key",
     re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b')),
    ("STRIPE_PUB_KEY",        "Stripe Publishable Key",
     re.compile(r'\bpk_live_[0-9a-zA-Z]{24,}\b')),
    ("GITHUB_TOKEN",          "GitHub Personal Access Token",
     re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b')),
    ("SLACK_TOKEN",           "Slack API Token",
     re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}\b')),
    ("SENDGRID_KEY",          "SendGrid API Key",
     re.compile(r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b')),
    ("TWILIO_KEY",            "Twilio API Key",
     re.compile(r'\bSK[0-9a-fA-F]{32}\b')),
    ("PRIVATE_KEY_MATERIAL",  "Private Key Material",
     re.compile(r'-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE\sKEY-----')),
    ("SOURCEMAP_REF",         "JavaScript Source Map Reference",
     re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)')),
    ("HARDCODED_PASSWORD",    "Hardcoded Password Literal",
     re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^\'"]{8,})["\']')),
    ("BEARER_HARDCODED",      "Hardcoded Bearer Token in JS",
     re.compile(r'(?i)authorization\s*:\s*["\']?Bearer\s+([A-Za-z0-9\-_.~+/]+=*)')),
    ("MAPBOX_TOKEN",          "Mapbox Access Token",
     re.compile(r'\bpk\.eyJ[A-Za-z0-9\-_]{50,}\b')),
]

_MAX_BODY_SCAN_BYTES = 512 * 1024   # 512 KB per response — avoids memory explosion
_MAX_SCRIPT_BYTES    = 100 * 1024   # 100 KB per inline script

# ─────────────────────────────────────────────────────────────────────────────
# Browser launch constants
# ─────────────────────────────────────────────────────────────────────────────

_LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-setuid-sandbox",
    "--window-size=1920,1080",
    "--ignore-certificate-errors",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-hang-monitor",
    "--disable-popup-blocking",
    "--safebrowsing-disable-auto-update",
]

# Injected before page JS to mask automation fingerprints (Capability 1)
_STEALTH_INIT_SCRIPT = """\
() => {
    Object.defineProperty(navigator, 'webdriver', {get: () => false, configurable: true});
    Object.defineProperty(navigator, 'plugins',   {get: () => [1,2,3,4,5], configurable: true});
    Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en'], configurable: true});
    window.chrome = {app: {isInstalled: false}, runtime: {id: undefined}};
    const orig = window.navigator.permissions?.query;
    if (orig) {
        window.navigator.permissions.query = p =>
            p.name === 'notifications'
                ? Promise.resolve({state: Notification.permission})
                : orig(p);
    }
}"""

# JS snippets evaluated inside the page after hydration (Capability 3)
_JS_FORMS = """\
() => Array.from(document.querySelectorAll('form')).map(f => ({
    action: f.action || f.getAttribute('action') || null,
    method: (f.method || f.getAttribute('method') || 'get').toUpperCase(),
    inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(el => ({
        name:  el.name || el.id || '',
        type:  el.type || el.tagName.toLowerCase(),
        value: el.value || '',
    })).filter(el => el.name)
}))"""

_JS_LINKS = """\
() => Array.from(document.querySelectorAll('a[href]'))
    .map(a => ({href: a.href || '', text: (a.innerText||a.textContent||'').trim().substring(0,120)}))
    .filter(a => a.href.startsWith('http'))"""

_JS_SCRIPTS = """\
() => Array.from(document.querySelectorAll('script')).map(s => ({
    src:     s.src   || null,
    content: s.src   ? null : (s.textContent || '').substring(0, 102400)
}))"""

_JS_BUTTONS = """\
() => Array.from(document.querySelectorAll(
    'button,[role="button"],[data-href],[ng-click]'
)).slice(0,50).map(b => ({
    text: (b.innerText||b.textContent||'').trim().substring(0,80),
    href: b.getAttribute('data-href') || b.getAttribute('href') || null,
}))"""

# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CrawlConfig:
    max_total_seconds:  float = 20.0
    max_pages:          int   = 30
    page_load_timeout:  int   = 12_000   # ms, for page.goto()
    networkidle_timeout:int   =  5_000   # ms, extra wait for SPA hydration
    user_agent:         str   = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )


@dataclass
class NetworkRequest:
    url:             str
    method:          str
    headers:         dict[str, str]
    post_data:       str | None
    resource_type:   str    # "fetch", "xhr", "document", "script", etc.
    timestamp:       float
    query_params:    dict[str, list[str]]
    has_auth_header: bool
    auth_scheme:     str | None   # "Bearer", "Basic", "ApiKey", etc.


@dataclass
class NetworkResponse:
    url:          str
    status:       int
    headers:      dict[str, str]
    content_type: str | None


@dataclass
class FormField:
    name:          str
    field_type:    str    # "text", "password", "email", "hidden", etc.
    default_value: str


@dataclass
class DiscoveredForm:
    action:         str | None
    method:         str
    page_url:       str
    fields:         list[FormField]
    has_csrf_token: bool


@dataclass
class DiscoveredLink:
    href:           str
    text:           str
    is_same_origin: bool


@dataclass
class SecretLeak:
    kind:        str    # pattern key e.g. "AWS_ACCESS_KEY_ID"
    description: str    # human label
    sample:      str    # redacted first 8 chars + "..."
    source:      str    # "inline_script" | "external_script" | "response_body"
    source_url:  str


@dataclass
class SsrfAttempt:
    url:              str
    blocked_hostname: str
    resource_type:    str


@dataclass
class CrawlResult:
    url:              str
    status:           str     # "completed" | "timeout" | "ssrf_blocked" | "error:..."
    pages_visited:    list[str]
    network_requests: list[NetworkRequest]
    network_responses:list[NetworkResponse]
    discovered_forms: list[DiscoveredForm]
    discovered_links: list[DiscoveredLink]
    secret_leaks:     list[SecretLeak]
    ssrf_attempts:    list[SsrfAttempt]
    script_urls:      list[str]
    crawl_duration:   float
    risk_score:       int
    summary:          dict


# ─────────────────────────────────────────────────────────────────────────────
# Pure helper functions (testable without a browser)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_auth_info(headers: dict[str, str]) -> tuple[bool, str | None]:
    """Return (has_auth, scheme) from a request headers dict."""
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key == "authorization":
            parts = value.strip().split(" ", 1)
            return True, parts[0] if parts else None
        if lower_key in ("x-api-key", "x-auth-token", "x-access-token",
                         "api-key", "x-token"):
            return True, "ApiKey"
    return False, None


def _scan_text_for_secrets(
    text:       str,
    source:     str,
    source_url: str,
) -> list[SecretLeak]:
    """
    Run all secret patterns against `text`.
    Returns at most one SecretLeak per pattern per source_url (deduplication).
    The matched value is always redacted to the first 8 chars + "...".
    """
    leaks: list[SecretLeak] = []
    seen: set[tuple[str, str]] = set()

    for kind, description, pattern in _SECRET_PATTERNS:
        key = (kind, source_url)
        if key in seen:
            continue
        m = pattern.search(text)
        if not m:
            continue
        seen.add(key)
        full   = m.group(0)
        sample = full[:8] + "..." if len(full) > 8 else full
        leaks.append(SecretLeak(
            kind=kind,
            description=description,
            sample=sample,
            source=source,
            source_url=source_url,
        ))

    return leaks


def _parse_form(form_data: dict, page_url: str) -> DiscoveredForm:
    """Convert a raw JS form dict into a typed DiscoveredForm."""
    raw_inputs = form_data.get("inputs") or []
    fields = [
        FormField(
            name=inp.get("name", ""),
            field_type=inp.get("type", "text"),
            default_value=inp.get("value", ""),
        )
        for inp in raw_inputs
        if inp.get("name")
    ]

    has_csrf = any(
        re.search(r"csrf|authenticity|_token|nonce", f.name, re.IGNORECASE)
        for f in fields
    )

    action = (form_data.get("action") or "").strip() or page_url
    return DiscoveredForm(
        action=action,
        method=(form_data.get("method") or "GET").upper(),
        page_url=page_url,
        fields=fields,
        has_csrf_token=has_csrf,
    )


def _parse_link(link_data: dict, start_origin: str) -> DiscoveredLink | None:
    """Convert a raw JS link dict into a typed DiscoveredLink."""
    href = (link_data.get("href") or "").strip()
    if not href.startswith(("http://", "https://")):
        return None

    parsed         = urlparse(href)
    link_origin    = f"{parsed.scheme}://{parsed.netloc}"
    is_same_origin = link_origin == start_origin

    return DiscoveredLink(
        href=href,
        text=(link_data.get("text") or "")[:100],
        is_same_origin=is_same_origin,
    )


def _should_scan_response_body(content_type: str) -> bool:
    """Return True if the response body type may contain secrets."""
    ct = content_type.lower()
    return any(s in ct for s in (
        "javascript", "json", "text/html", "text/plain", "xml", "wasm",
    ))


def _calculate_risk_score(
    secret_leaks:     list[SecretLeak],
    ssrf_attempts:    list[SsrfAttempt],
    discovered_forms: list[DiscoveredForm],
) -> int:
    score = 0
    score += min(len(secret_leaks)  * 20, 60)   # secrets: HIGH
    score += min(len(ssrf_attempts) * 25, 50)   # SSRF probes: CRITICAL

    # POST forms with no CSRF protection — medium risk
    no_csrf = sum(
        1 for f in discovered_forms
        if not f.has_csrf_token and f.method == "POST"
    )
    score += min(no_csrf * 10, 20)

    return min(score, 100)


# ─────────────────────────────────────────────────────────────────────────────
# Core crawler class
# ─────────────────────────────────────────────────────────────────────────────

class DeepJsCrawler:
    """
    Headless Chromium SPA crawler with 5-layer security analysis.

    Usage::

        config  = CrawlConfig(max_total_seconds=20, max_pages=30)
        crawler = DeepJsCrawler(config)
        result  = await crawler.crawl("https://app.example.com")
        print(result.risk_score, result.secret_leaks)
    """

    def __init__(self, config: CrawlConfig | None = None):
        self._cfg = config or CrawlConfig()
        self._reset_state()

    # ── Mutable crawl state (reset per run) ────────────────────────────────────

    def _reset_state(self) -> None:
        self._network_requests:  list[NetworkRequest]  = []
        self._network_responses: list[NetworkResponse] = []
        self._discovered_forms:  list[DiscoveredForm]  = []
        self._discovered_links:  list[DiscoveredLink]  = []
        self._secret_leaks:      list[SecretLeak]      = []
        self._ssrf_attempts:     list[SsrfAttempt]     = []
        self._script_urls:       list[str]             = []
        self._visited:           set[str]              = set()

    # ── Public entry point ─────────────────────────────────────────────────────

    async def crawl(self, url: str) -> CrawlResult:
        """
        Run the full crawl pipeline against `url`.
        Always returns a CrawlResult — never raises (errors are captured in status).
        """
        self._reset_state()
        t0     = time.monotonic()
        status = "completed"

        try:
            await asyncio.wait_for(
                self._do_crawl(url),
                timeout=self._cfg.max_total_seconds,
            )
        except asyncio.TimeoutError:
            status = "timeout"
            logger.warning("Crawl of %s exceeded %ss budget.", url, self._cfg.max_total_seconds)
        except PermissionError as exc:
            status = f"ssrf_blocked: {exc}"
        except Exception as exc:
            status = f"error: {exc}"
            logger.exception("Unexpected crawl error for %s", url)

        elapsed    = time.monotonic() - t0
        risk_score = _calculate_risk_score(
            self._secret_leaks,
            self._ssrf_attempts,
            self._discovered_forms,
        )

        return CrawlResult(
            url              = url,
            status           = status,
            pages_visited    = list(self._visited),
            network_requests = self._network_requests,
            network_responses= self._network_responses,
            discovered_forms = self._discovered_forms,
            discovered_links = self._discovered_links,
            secret_leaks     = self._secret_leaks,
            ssrf_attempts    = self._ssrf_attempts,
            script_urls      = self._script_urls,
            crawl_duration   = round(elapsed, 2),
            risk_score       = risk_score,
            summary          = {
                "pages_visited":    len(self._visited),
                "requests_captured":len(self._network_requests),
                "forms_found":      len(self._discovered_forms),
                "links_found":      len(self._discovered_links),
                "secrets_detected": len(self._secret_leaks),
                "ssrf_blocked":     len(self._ssrf_attempts),
            },
        )

    # ── Browser lifecycle ──────────────────────────────────────────────────────

    async def _do_crawl(self, url: str) -> None:
        """Spin up Playwright, configure the page, and run the BFS crawl."""
        if not _HAS_PLAYWRIGHT:
            raise ImportError(
                "playwright is not installed. "
                "pip install playwright && playwright install chromium"
            )

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(
                headless=True,
                args=_LAUNCH_ARGS,
            )
            try:
                ctx: BrowserContext = await browser.new_context(
                    viewport            = {"width": 1920, "height": 1080},
                    user_agent          = self._cfg.user_agent,
                    ignore_https_errors = True,
                    java_script_enabled = True,
                    locale              = "en-US",
                    timezone_id         = "America/New_York",
                )
                page: Page = await ctx.new_page()

                # Capability 1 — stealth init script hides automation signals
                await page.add_init_script(body=_STEALTH_INIT_SCRIPT)

                # Capability 2 — route intercept for SSRF guard + request logging
                await page.route("**/*", self._handle_route)

                # Capability 2 — response listener for body scanning
                page.on("response", self._handle_response)

                await self._bfs_crawl(page, url)
            finally:
                await browser.close()

    # ── BFS crawl loop ─────────────────────────────────────────────────────────

    async def _bfs_crawl(self, page: Page, start_url: str) -> None:
        """
        BFS over same-origin pages using a single browser page.
        Single page preserves auth cookies / SPA session state.
        """
        start_parsed = urlparse(start_url)
        start_origin = f"{start_parsed.scheme}://{start_parsed.netloc}"

        queue: deque[str] = deque([start_url])

        while queue and len(self._visited) < self._cfg.max_pages:
            url = queue.popleft()
            if url in self._visited:
                continue
            self._visited.add(url)

            new_links = await self._crawl_single_page(page, url, start_origin)

            for link in new_links:
                if link.is_same_origin and link.href not in self._visited:
                    queue.append(link.href)

    # ── Per-page extraction ────────────────────────────────────────────────────

    async def _crawl_single_page(
        self, page: Page, url: str, start_origin: str
    ) -> list[DiscoveredLink]:
        """
        Navigate to url, wait for SPA hydration, extract all security-relevant
        content, and return newly discovered links.
        """
        try:
            await page.goto(
                url,
                wait_until="load",
                timeout=self._cfg.page_load_timeout,
            )
            # Extra wait for async JS (React/Angular hydration, Fetch calls)
            try:
                await page.wait_for_load_state(
                    "networkidle",
                    timeout=self._cfg.networkidle_timeout,
                )
            except Exception:
                pass   # Long-polling SPAs may never reach networkidle — that's OK

        except Exception as exc:
            logger.debug("Navigation failed for %s: %s", url, exc)
            return []

        # Capability 3 — extract forms, links, scripts in parallel
        forms_task   = asyncio.create_task(self._extract_forms(page, url))
        links_task   = asyncio.create_task(self._extract_links(page, url, start_origin))
        scripts_task = asyncio.create_task(self._extract_scripts(page, url))

        forms, links, _ = await asyncio.gather(
            forms_task, links_task, scripts_task,
            return_exceptions=True,
        )

        if isinstance(forms, list):
            self._discovered_forms.extend(forms)
        if isinstance(links, list):
            self._discovered_links.extend(links)

        return [l for l in (links if isinstance(links, list) else []) if isinstance(l, DiscoveredLink)]

    async def _extract_forms(self, page: Page, page_url: str) -> list[DiscoveredForm]:
        try:
            raw: list[dict] = await page.evaluate(_JS_FORMS) or []
        except Exception:
            return []
        return [_parse_form(f, page_url) for f in raw if isinstance(f, dict)]

    async def _extract_links(
        self, page: Page, page_url: str, start_origin: str
    ) -> list[DiscoveredLink]:
        try:
            raw: list[dict] = await page.evaluate(_JS_LINKS) or []
        except Exception:
            return []
        links = [_parse_link(l, start_origin) for l in raw if isinstance(l, dict)]
        return [l for l in links if l is not None]

    async def _extract_scripts(self, page: Page, page_url: str) -> None:
        """Capability 4 — scan inline scripts for secret leaks."""
        try:
            raw: list[dict] = await page.evaluate(_JS_SCRIPTS) or []
        except Exception:
            return

        for script in raw:
            if not isinstance(script, dict):
                continue
            src     = script.get("src")
            content = script.get("content")

            if src:
                self._script_urls.append(src)

            if content and len(content.strip()) > 0:
                source = "external_script" if src else "inline_script"
                url    = src or page_url
                leaks  = _scan_text_for_secrets(content, source, url)
                self._secret_leaks.extend(leaks)

    # ── Capability 2: Route intercept (SSRF guard + request logging) ───────────

    async def _handle_route(self, route: Route) -> None:
        """
        Fires for every request the page attempts.

        1. SSRF guard — abort any request to private/loopback addresses.
        2. Log request metadata for the network spy report.
        3. Pass-through all clean requests.
        """
        request  = route.request
        url      = request.url
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""

        # Capability 5 — SSRF prevention
        if is_ssrf_blocked(hostname):
            self._ssrf_attempts.append(SsrfAttempt(
                url              = url,
                blocked_hostname = hostname,
                resource_type    = request.resource_type,
            ))
            logger.warning("SSRF attempt aborted: %s (%s)", url, hostname)
            await route.abort("blockedbyclient")
            return

        # Capability 2 — log request metadata
        try:
            headers          = dict(request.headers)
            has_auth, scheme = _extract_auth_info(headers)
            query_params     = parse_qs(parsed.query)

            self._network_requests.append(NetworkRequest(
                url             = url,
                method          = request.method,
                headers         = headers,
                post_data       = request.post_data,
                resource_type   = request.resource_type,
                timestamp       = time.time(),
                query_params    = query_params,
                has_auth_header = has_auth,
                auth_scheme     = scheme,
            ))
        except Exception:
            pass  # Never let logging failure break the crawl

        await route.continue_()

    # ── Capability 2 + 4: Response listener (logging + body secret scan) ───────

    async def _handle_response(self, response: Response) -> None:
        """
        Fires after every response is received.

        Logs response metadata and scans JS/JSON bodies for secrets.
        """
        try:
            content_type = response.headers.get("content-type", "")
            self._network_responses.append(NetworkResponse(
                url          = response.url,
                status       = response.status,
                headers      = dict(response.headers),
                content_type = content_type or None,
            ))

            # Capability 4 — scan response body for secrets
            if _should_scan_response_body(content_type):
                try:
                    body = await response.text()
                    if body and len(body) <= _MAX_BODY_SCAN_BYTES:
                        leaks = _scan_text_for_secrets(body, "response_body", response.url)
                        self._secret_leaks.extend(leaks)
                except Exception:
                    pass  # Binary / already-consumed responses fail silently
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# @tool wrapper
# ─────────────────────────────────────────────────────────────────────────────

@tool
def crawl_spa(url: str) -> str:
    """
    Launch a headless Chromium browser to crawl a Single Page Application.
    Intercepts every API call, extracts forms, scans for client-side secrets,
    and enforces SSRF prevention on all background browser requests.

    Args:
        url: Target SPA URL (must have explicit authorisation to test).

    Returns:
        JSON with intercepted requests, discovered forms/links, secret leaks,
        blocked SSRF attempts, risk score 0-100, and a crawl summary.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "deep_js_crawler", "status": "invalid_url"})

    hostname = parsed.hostname or ""
    if is_ssrf_blocked(hostname):
        return json.dumps({"tool": "deep_js_crawler", "status": "ssrf_blocked"})

    try:
        result     = asyncio.run(DeepJsCrawler().crawl(url))
        result_dict= dataclasses.asdict(result)
        result_dict["tool"] = "deep_js_crawler"
        return json.dumps(result_dict, indent=2, default=str)
    except Exception as exc:
        return json.dumps({
            "tool":   "deep_js_crawler",
            "status": "error",
            "error":  str(exc),
        })

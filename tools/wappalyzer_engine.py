"""
tools/wappalyzer_engine.py — Wappalyzer-compatible tech fingerprinter

Uses the enthec/webappanalyzer community database (Apache 2.0 licensed fork of
Wappalyzer's last open-source release).  7 537 technologies as of 2026-06.

Detection surfaces (pure Python, no browser required):
  html        — regex patterns matched against full HTML source
  scriptSrc   — patterns matched against <script src="…"> attribute values
  scripts     — patterns matched against inline <script> content / full HTML
  headers     — patterns matched against specific HTTP response headers
  meta        — patterns matched against <meta name/property> content values
  url         — patterns matched against the page URL
  cookies     — patterns matched against cookie names / values

Skipped (require a browser / JS runtime):
  js          — JavaScript global variable access
  dom         — CSS selector evaluation

Security:
  • Database is loaded from a local bundled file — no outbound calls at runtime.
  • All callers must call safe_get() before obtaining html/headers (SSRF guard is
    the caller's responsibility, not this module's).
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

_log = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent / "wappalyzer_data.json"

# Max recursion depth for implies-chain resolution (A→B→C = depth 2)
_MAX_IMPLIES_DEPTH = 3


# ─────────────────────────────────────────────────────────────────────────────
# Public result type
# ─────────────────────────────────────────────────────────────────────────────

class TechMatch(NamedTuple):
    name:       str
    version:    str | None
    confidence: int          # 100 = directly detected; 75 = implied
    categories: list[int]    # Wappalyzer category IDs
    implies:    list[str]    # technology names this detection implies
    cpe:        str | None   # CPE 2.3 string if available


# ─────────────────────────────────────────────────────────────────────────────
# Pattern parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_pattern(raw: str) -> tuple[re.Pattern | None, str | None]:
    """
    Split a Wappalyzer pattern string into (compiled_regex, version_template).

    Wappalyzer encodes version metadata as suffix separated by "\\;":
      "jquery[.-](\\d+\\.\\d+)[/.-]\\;version:\\1"  →  regex + "\\1"
      "^WordPress(?: ([\\d.]+))?\\;version:\\1"       →  regex + "\\1"
      "/wp-content/"                                  →  regex + None
    """
    if not isinstance(raw, str):
        return None, None

    parts = raw.split("\\;")
    regex_part = parts[0]
    version_template: str | None = None

    for part in parts[1:]:
        if part.startswith("version:"):
            version_template = part[8:]   # e.g. "\\1", "\\1.\\2"
            break

    try:
        return re.compile(regex_part, re.I | re.S), version_template
    except re.error:
        return None, None


def _extract_version(match: re.Match, template: str | None) -> str | None:
    """
    Substitute regex capture groups into the version template.

    "\\1" → first capture group value.
    "\\1.\\2" → "major.minor" from groups 1 and 2.
    Returns None when template is absent or all referenced groups are empty.
    """
    if not template or not match:
        return None
    result = template
    try:
        for i, g in enumerate(match.groups(), 1):
            result = result.replace(f"\\{i}", g or "")
        # Any unreplaced \\N means the group was empty — drop the result
        if re.search(r"\\\d", result):
            return None
        cleaned = result.strip(". -_")
        return cleaned or None
    except Exception:
        return None


def _parse_implies(raw) -> list[str]:
    """
    Normalise the implies field to a flat list of technology names.
    Strips confidence/confidence suffixes:  "PHP\\;confidence:75" → "PHP"
    """
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    result: list[str] = []
    for item in raw:
        if isinstance(item, str):
            name = item.split("\\;")[0].strip()
            if name:
                result.append(name)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Compiled technology representation
# ─────────────────────────────────────────────────────────────────────────────

class _CompiledTech:
    """
    Holds pre-compiled regex patterns for one Wappalyzer technology entry.
    Built once at first use via _load_db() and cached for the process lifetime.
    """
    __slots__ = (
        "name", "cats", "cpe", "implies",
        "html_pats", "script_src_pats", "script_pats",
        "header_pats", "meta_pats", "url_pats", "cookie_pats",
    )

    def __init__(self, name: str, entry: dict):
        self.name = name
        self.cats: list[int]  = entry.get("cats", [])
        self.cpe:  str | None = entry.get("cpe")
        self.implies: list[str] = _parse_implies(entry.get("implies"))

        def _c(raw) -> list[tuple[re.Pattern, str | None]]:
            """
            Compile a string-or-list field into (pattern, version_template) pairs.
            Version-extracting patterns are sorted first — this ensures we try the
            more specific pattern (e.g. "jquery-3.6.0.min.js") before the broad one
            ("jquery"), so version is captured whenever possible.
            """
            if not raw:
                return []
            if isinstance(raw, str):
                raw = [raw]
            out = []
            for p in raw:
                pat, tmpl = _parse_pattern(p)
                if pat is not None:
                    out.append((pat, tmpl))
            # Sort: patterns with a version template come first
            out.sort(key=lambda x: x[1] is None)
            return out

        self.html_pats       = _c(entry.get("html"))
        self.script_src_pats = _c(entry.get("scriptSrc"))
        self.script_pats     = _c(entry.get("scripts"))
        self.url_pats        = _c(entry.get("url"))

        # headers: {"Header-Name": "pattern\\;version:\\1"}
        hdrs_raw = entry.get("headers", {})
        self.header_pats: list[tuple[str, re.Pattern, str | None]] = []
        if isinstance(hdrs_raw, dict):
            for hdr_name, pat_str in hdrs_raw.items():
                if isinstance(pat_str, str):
                    pat, tmpl = _parse_pattern(pat_str)
                    if pat is not None:
                        self.header_pats.append((hdr_name.lower(), pat, tmpl))

        # meta: {"generator": "pattern"}
        meta_raw = entry.get("meta", {})
        self.meta_pats: list[tuple[str, re.Pattern, str | None]] = []
        if isinstance(meta_raw, dict):
            for meta_name, pat_str in meta_raw.items():
                if isinstance(pat_str, str):
                    pat, tmpl = _parse_pattern(pat_str)
                    if pat is not None:
                        self.meta_pats.append((meta_name.lower(), pat, tmpl))

        # cookies: {"cookie_name": "value_pattern"}  (empty string = name-only match)
        cookie_raw = entry.get("cookies", {})
        self.cookie_pats: list[tuple[str, re.Pattern, str | None]] = []
        if isinstance(cookie_raw, dict):
            for cookie_name, pat_str in cookie_raw.items():
                if not isinstance(pat_str, str):
                    pat_str = ""
                pat, tmpl = _parse_pattern(pat_str if pat_str else ".*")
                if pat is not None:
                    self.cookie_pats.append((cookie_name.lower(), pat, tmpl))

    def has_passive_patterns(self) -> bool:
        """Return True if this tech can be detected without a JS runtime."""
        return bool(
            self.html_pats or self.script_src_pats or self.script_pats
            or self.header_pats or self.meta_pats
            or self.url_pats or self.cookie_pats
        )


# ─────────────────────────────────────────────────────────────────────────────
# Database loader (lazy, cached for process lifetime)
# ─────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_db() -> tuple[list[_CompiledTech], dict[str, _CompiledTech]]:
    """
    Load and compile the Wappalyzer technology database.
    Returns (db_list, name_index) where name_index maps lowercase name → tech.
    Called at most once per process (lru_cache).
    """
    if not _DATA_FILE.exists():
        _log.warning("wappalyzer_data.json not found — tech detection disabled")
        return [], {}

    try:
        raw: dict = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        _log.error("Failed to load wappalyzer_data.json: %s", exc)
        return [], {}

    db: list[_CompiledTech] = []
    name_index: dict[str, _CompiledTech] = {}

    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        try:
            ct = _CompiledTech(name, entry)
            if ct.has_passive_patterns():
                db.append(ct)
            # Always index by name (for implies resolution)
            name_index[name.lower()] = ct
            name_index[name] = ct
        except Exception:
            pass

    _log.debug("Wappalyzer DB loaded: %d detectable / %d total", len(db), len(raw))
    return db, name_index


# ─────────────────────────────────────────────────────────────────────────────
# HTML pre-processing helpers (called once per page, not once per tech)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_meta_tags(html: str) -> dict[str, str]:
    """
    Extract all <meta name/property="…" content="…"> tag values.
    Returns {lowered_name: content_value}.
    """
    meta_tags: dict[str, str] = {}
    # Match both attribute orders: name before content and content before name
    for m in re.finditer(
        r'<meta\s[^>]*?(?:name|property)=["\']([^"\']*)["\'][^>]*content=["\']([^"\']*)["\']'
        r'|<meta\s[^>]*?content=["\']([^"\']*)["\'][^>]*?(?:name|property)=["\']([^"\']*)["\']',
        html, re.I | re.S
    ):
        if m.group(1) is not None:
            meta_tags[m.group(1).lower()] = m.group(2) or ""
        elif m.group(4) is not None:
            meta_tags[m.group(4).lower()] = m.group(3) or ""
    return meta_tags


def _extract_script_srcs(html: str) -> str:
    """Return all <script src="…"> values joined by space (for pattern scanning)."""
    return " ".join(re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I))


# ─────────────────────────────────────────────────────────────────────────────
# Per-technology matcher
# ─────────────────────────────────────────────────────────────────────────────

def _try_match(
    tech:         _CompiledTech,
    html:         str,
    script_srcs:  str,
    norm_headers: dict[str, str],
    meta_tags:    dict[str, str],
    url:          str,
    cookies:      dict[str, str],
) -> tuple[bool, str | None]:
    """
    Try all passive detection surfaces for one technology.
    Returns (matched: bool, version: str | None).
    """
    # 1. HTML patterns (full HTML source, includes inline script content)
    for pat, tmpl in tech.html_pats:
        m = pat.search(html)
        if m:
            return True, _extract_version(m, tmpl)

    # 2. <script src="…"> URL patterns
    if script_srcs:
        for pat, tmpl in tech.script_src_pats:
            m = pat.search(script_srcs)
            if m:
                return True, _extract_version(m, tmpl)

    # 3. HTTP response header patterns
    for hdr_name, pat, tmpl in tech.header_pats:
        val = norm_headers.get(hdr_name, "")
        if val:
            m = pat.search(val)
            if m:
                return True, _extract_version(m, tmpl)

    # 4. <meta> tag content patterns
    for meta_name, pat, tmpl in tech.meta_pats:
        val = meta_tags.get(meta_name, "")
        if val:
            m = pat.search(val)
            if m:
                return True, _extract_version(m, tmpl)

    # 5. Page URL patterns
    if url:
        for pat, tmpl in tech.url_pats:
            if pat.search(url):
                return True, None

    # 6. Cookie name + optional value patterns
    for cookie_name, pat, tmpl in tech.cookie_pats:
        if cookie_name in cookies:
            val = cookies[cookie_name]
            if not val or pat.search(val):
                return True, None

    # 7. Inline <script> content patterns (matched against full HTML — same text)
    for pat, tmpl in tech.script_pats:
        m = pat.search(html)
        if m:
            return True, _extract_version(m, tmpl)

    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def detect_technologies(
    html:    str,
    headers: dict,
    url:     str = "",
    cookies: dict | None = None,
) -> list[TechMatch]:
    """
    Detect technologies used by a web page using the Wappalyzer database.

    Args:
        html:    Full HTML response body.
        headers: HTTP response headers dict.
        url:     Page URL (optional — used for url-pattern matching).
        cookies: Response cookies dict (optional).

    Returns:
        List of TechMatch objects sorted by name.
        Includes directly detected technologies AND those implied by detections
        (e.g., detecting WordPress automatically adds PHP, MySQL at confidence 75).

    Performance:
        ~7 500 technologies, ~3 patterns each, one page → typically < 400 ms.
        Database is compiled and cached after first call.
    """
    db, name_index = _load_db()
    if not db:
        return []

    # Pre-process inputs ONCE (not once per technology)
    script_srcs  = _extract_script_srcs(html)
    meta_tags    = _extract_meta_tags(html)
    norm_headers = {k.lower(): v for k, v in headers.items()}
    norm_cookies = {k.lower(): v for k, v in (cookies or {}).items()}

    matched: dict[str, TechMatch] = {}

    # ── Direct detection ──────────────────────────────────────────────────────
    for tech in db:
        if tech.name in matched:
            continue
        hit, version = _try_match(
            tech, html, script_srcs, norm_headers, meta_tags, url, norm_cookies
        )
        if hit:
            matched[tech.name] = TechMatch(
                name=tech.name,
                version=version,
                confidence=100,
                categories=list(tech.cats),
                implies=list(tech.implies),
                cpe=tech.cpe,
            )

    # ── Implies chain resolution (bounded depth) ──────────────────────────────
    queue: list[tuple[str, int]] = [
        (implied_name, 1)
        for tm in list(matched.values())
        for implied_name in tm.implies
    ]

    while queue:
        implied_name, depth = queue.pop(0)
        if implied_name in matched or depth > _MAX_IMPLIES_DEPTH:
            continue

        ct = name_index.get(implied_name) or name_index.get(implied_name.lower())
        if ct is None:
            continue

        matched[implied_name] = TechMatch(
            name=implied_name,
            version=None,
            confidence=75,
            categories=list(ct.cats),
            implies=list(ct.implies),
            cpe=ct.cpe,
        )
        for next_implied in ct.implies:
            queue.append((next_implied, depth + 1))

    return sorted(matched.values(), key=lambda t: t.name.lower())

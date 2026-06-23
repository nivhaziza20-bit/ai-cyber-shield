"""
differential_alert_manager.py — AI Cyber Shield v6

Differential Scan Manager: history tracking, structural diffing, and smart
multi-channel alerting.  Eliminates alert fatigue by dispatching only when
something materially changes between two scans of the same target URL.

Architecture
────────────
Stage 1 — Signature extraction
    Every critical finding is reduced to a deterministic SHA-256 fingerprint
    (normalised text of the finding + tool + category).  Category-level
    severity buckets ("healthy"/ "degraded" / "critical") also generate
    signatures so that a score collapse triggers a delta even when the raw
    finding text has not changed.

Stage 2 — Supabase state lookup
    The last successful scan for the target URL is fetched from the
    ``scan_history`` table.  On the very first scan the module stores the
    baseline and returns without alerting (prevents alert flood on day 0).

Stage 3 — Structural diff
    Each signature is classified:
      NEW_VULNERABILITY  — present now, absent in the previous scan
      RESOLVED_VULNERABILITY — present before, absent now
      UNCHANGED          — present in both scans

Stage 4 — Emergency-trigger logic
    An emergency alert fires when:
      • Any NEW_VULNERABILITY carries CRITICAL or HIGH severity, OR
      • The overall letter grade dropped by 2 or more steps (A→C, B→D …), OR
      • The overall numeric score fell by 15 or more points.

Stage 5 — Async multi-channel dispatch
    SlackDispatcher  — Block Kit payload, colour-coded by severity.
    WebhookDispatcher — compact JSON for SIEM / DevOps pipeline ingestion.
    Both run concurrently via asyncio.gather().

Supabase table (run once to set up):
────────────────────────────────────
    CREATE TABLE scan_history (
        id                UUID DEFAULT gen_random_uuid() PRIMARY KEY,
        url               TEXT NOT NULL,
        scan_id           TEXT NOT NULL UNIQUE,
        scan_timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        overall_score     INTEGER NOT NULL,
        overall_grade     TEXT NOT NULL,
        category_scores   JSONB NOT NULL DEFAULT '{}',
        critical_findings JSONB NOT NULL DEFAULT '[]',
        finding_signatures JSONB NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_scan_history_url ON scan_history (url, scan_timestamp DESC);

Required environment variables (add to .env):
─────────────────────────────────────────────
    SUPABASE_URL          = https://<project>.supabase.co
    SUPABASE_KEY          = <anon-or-service-role key>
    SLACK_WEBHOOK_URL     = https://hooks.slack.com/services/...  (optional)
    ALERT_WEBHOOK_URL     = https://your-siem.example.com/ingest  (optional)

SECURITY NOTES:
  • Webhook URLs are treated as sensitive credentials — never log them.
  • All finding text is truncated to 200 chars before being stored or sent.
  • This module sends outbound HTTPS requests; call is_ssrf_blocked() for any
    URL supplied by user input before dispatching.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Optional dependency: supabase-py
# ─────────────────────────────────────────────────────────────────────────────

try:
    from supabase import create_client, Client as SupabaseClient
    _HAS_SUPABASE = True
except ImportError:
    _HAS_SUPABASE = False
    SupabaseClient = None  # type: ignore[assignment,misc]
    logger.warning(
        "supabase-py not installed — history tracking disabled. "
        "Run: pip install supabase"
    )

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

class _AlertSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8-sig",
        case_sensitive=False,
        extra="ignore",
    )

    supabase_url: str = Field("", description="Supabase project URL")
    supabase_key: str = Field("", description="Supabase anon / service-role key")
    slack_webhook_url: str = Field("", description="Slack Incoming Webhook URL")
    alert_webhook_url: str = Field("", description="Generic SIEM / DevOps webhook URL")

    # Tunable thresholds
    grade_drop_threshold:    int = Field(2,  ge=1, le=4,
        description="Letter-grade drop that triggers an emergency alert (default: 2 = A→C)")
    score_drop_threshold:    int = Field(15, ge=5, le=50,
        description="Numeric score drop that triggers an emergency alert")
    webhook_timeout_seconds: int = Field(10, ge=3, le=30)
    max_findings_in_alert:   int = Field(10, ge=1, le=50,
        description="Cap the number of findings shown per channel")


def _get_alert_settings() -> _AlertSettings:
    try:
        return _AlertSettings()  # type: ignore[call-arg]
    except Exception:
        return _AlertSettings.model_construct(  # type: ignore[call-arg]
            supabase_url="", supabase_key="",
            slack_webhook_url="", alert_webhook_url="",
            grade_drop_threshold=2, score_drop_threshold=15,
            webhook_timeout_seconds=10, max_findings_in_alert=10,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_TABLE = "scan_history"

_GRADE_ORDER: dict[str, int] = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1, "?": 0}

_SCORE_BUCKETS = (
    (75, "healthy"),    # score ≥ 75
    (40, "degraded"),   # 40 ≤ score < 75
    (0,  "critical"),   # score < 40
)

_MAX_FINDING_TEXT = 200   # chars stored / sent per finding
_MAX_DETAIL_TEXT  = 120   # chars in a signature key


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

class DeltaClass(str, Enum):
    NEW_VULNERABILITY      = "NEW_VULNERABILITY"
    RESOLVED_VULNERABILITY = "RESOLVED_VULNERABILITY"
    UNCHANGED              = "UNCHANGED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass(frozen=True)
class FindingSignature:
    """Deterministic fingerprint for a single security finding."""
    fingerprint: str          # SHA-256 hex[:16] of (tool + category + normalised detail)
    tool:        str          # scanner tool name
    category:    str          # ssl / headers / cors_csp / …  or "score_bucket:<tool>"
    detail:      str          # human-readable truncated summary (safe text)
    severity:    Severity


@dataclass
class FindingDelta:
    """A single classified finding from the diff engine."""
    classification: DeltaClass
    signature:      FindingSignature

    @property
    def is_new(self) -> bool:
        return self.classification == DeltaClass.NEW_VULNERABILITY

    @property
    def is_resolved(self) -> bool:
        return self.classification == DeltaClass.RESOLVED_VULNERABILITY


@dataclass
class ScanDiff:
    """Complete structural difference between two consecutive scans."""
    url:            str
    scan_id:        str
    is_first_scan:  bool

    # Findings
    new_vulns:       list[FindingDelta] = field(default_factory=list)
    resolved_vulns:  list[FindingDelta] = field(default_factory=list)
    unchanged_vulns: list[FindingDelta] = field(default_factory=list)

    # Grade / score
    grade_before: str = "?"
    grade_after:  str = "?"
    score_before: int = 0
    score_after:  int = 0

    @property
    def grade_changed(self) -> bool:
        return self.grade_before != "?" and self.grade_before != self.grade_after

    @property
    def score_delta(self) -> int:
        """Positive = improvement, negative = regression."""
        return self.score_after - self.score_before

    @property
    def grade_drop_steps(self) -> int:
        """Number of letter-grade steps the score fell (0 if improved or equal)."""
        before = _GRADE_ORDER.get(self.grade_before, 0)
        after  = _GRADE_ORDER.get(self.grade_after,  0)
        return max(0, before - after)

    @property
    def has_critical_new(self) -> bool:
        return any(d.signature.severity == Severity.CRITICAL for d in self.new_vulns)

    @property
    def has_high_new(self) -> bool:
        return any(d.signature.severity == Severity.HIGH for d in self.new_vulns)

    def summary(self) -> str:
        parts: list[str] = []
        if self.grade_changed:
            parts.append(f"Grade changed {self.grade_before} → {self.grade_after}")
        if self.score_delta != 0:
            sign = "+" if self.score_delta > 0 else ""
            parts.append(f"Score {sign}{self.score_delta} pts "
                         f"({self.score_before} → {self.score_after})")
        parts.append(f"{len(self.new_vulns)} new")
        parts.append(f"{len(self.resolved_vulns)} resolved")
        parts.append(f"{len(self.unchanged_vulns)} unchanged")
        return " | ".join(parts)


@dataclass
class DispatchResult:
    channel:     str
    success:     bool
    status_code: int  = 0
    error:       str  = ""


@dataclass
class DiffReport:
    """Returned by run_differential_scan() to the caller."""
    url:              str
    scan_id:          str
    diff:             ScanDiff
    emergency_alert:  bool
    dispatch_results: list[DispatchResult] = field(default_factory=list)
    stored_in_db:     bool                 = False
    error:            str                  = ""


# ─────────────────────────────────────────────────────────────────────────────
# Finding signature extraction
# ─────────────────────────────────────────────────────────────────────────────

def _bucket(score: int) -> str:
    for threshold, label in _SCORE_BUCKETS:
        if score >= threshold:
            return label
    return "critical"


def _severity_from_finding(text: str) -> Severity:
    """Infer severity from the finding text produced by the pipeline."""
    t = text.lower()
    if any(kw in t for kw in ("critical", "confirmed takeover", "secret", "private key",
                               "rce", "shell", "no ssl", "no tls", "credential")):
        return Severity.CRITICAL
    if any(kw in t for kw in ("high", "no waf", "cors", "open redirect", "cve",
                               "exposed file", "graphql introspection", "ssrf")):
        return Severity.HIGH
    if any(kw in t for kw in ("medium", "missing header", "header", "csp", "hsts",
                               "dmarc", "weak", "sri missing")):
        return Severity.MEDIUM
    if any(kw in t for kw in ("low", "subdomain", "enumerat")):
        return Severity.LOW
    return Severity.INFO


def _severity_from_score_drop(before: int, after: int) -> Severity:
    if after < 20:
        return Severity.CRITICAL
    if after < 40:
        return Severity.HIGH
    if before - after >= 20:
        return Severity.HIGH
    return Severity.MEDIUM


def _fingerprint(tool: str, category: str, detail: str) -> str:
    """SHA-256 fingerprint, first 16 hex chars."""
    normalised = f"{tool}|{category}|{detail.lower().strip()}"
    return hashlib.sha256(normalised.encode()).hexdigest()[:16]


def extract_signatures(scan_result: dict) -> dict[str, FindingSignature]:
    """
    Build a fingerprint map from a pipeline result dict.

    Two sources of signatures:
      1. critical_findings — one FindingSignature per finding string
      2. category_scores   — one FindingSignature per tool whose score bucket
                             is "degraded" or "critical"

    Returns dict keyed by fingerprint hex string.
    """
    sigs: dict[str, FindingSignature] = {}

    # ── 1. Critical findings ─────────────────────────────────────────────────
    for raw_finding in scan_result.get("critical_findings", []):
        text    = str(raw_finding)[:_MAX_FINDING_TEXT]
        detail  = text[:_MAX_DETAIL_TEXT]
        tool    = _tool_from_finding(text)
        fp      = _fingerprint(tool, "critical_finding", detail)
        sigs[fp] = FindingSignature(
            fingerprint=fp,
            tool=tool,
            category="critical_finding",
            detail=detail,
            severity=_severity_from_finding(text),
        )

    # ── 2. Category score buckets ────────────────────────────────────────────
    for cat, score in scan_result.get("category_scores", {}).items():
        bucket = _bucket(int(score))
        if bucket == "healthy":
            continue  # healthy tools don't generate alert signatures
        detail = f"{cat} score={score} ({bucket})"
        fp     = _fingerprint(cat, f"score_bucket:{bucket}", detail)
        sigs[fp] = FindingSignature(
            fingerprint=fp,
            tool=cat,
            category=f"score_bucket:{bucket}",
            detail=detail,
            severity=Severity.CRITICAL if bucket == "critical" else Severity.MEDIUM,
        )

    return sigs


def _tool_from_finding(text: str) -> str:
    """Heuristic: infer which tool produced a critical finding from its text."""
    t = text.lower()
    mapping = (
        ("ssl",              ("ssl", "tls", "certificate", "https")),
        ("waf",              ("waf", "firewall", "protection")),
        ("cors_csp",         ("cors", "csp", "content security")),
        ("headers",          ("header", "x-frame", "referrer", "x-content")),
        ("html",             ("html", "page source", "csrf", "mixed content")),
        ("dns",              ("dns", "spf", "dmarc", "caa", "mx record")),
        ("crawler",          ("sensitive path", "admin", "debug", "stack trace")),
        ("exposure",         ("exposed", ".env", ".git", "sri", "source map", "dangerous method")),
        ("subdomain_takeover", ("takeover", "cname", "orphaned")),
        ("cert_transparency",  ("ct log", "subdomain", "crt.sh")),
        ("open_redirect",    ("redirect",)),
        ("api_spec",         ("api", "swagger", "openapi", "graphql")),
        ("port_scanner",     ("port", "redis", "mysql", "mongodb", "postgresql")),
        ("cookie_security",  ("cookie", "secure flag", "httponly", "samesite")),
        ("deep_js_crawler",  ("javascript", "js", "spa", "ssrf attempt", "secret leak")),
        ("tech",             ("cve", "component", "version", "dependency")),
        ("hsts_preload",     ("hsts", "preload", "downgrade")),
    )
    for tool, keywords in mapping:
        if any(kw in t for kw in keywords):
            return tool
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Supabase persistence layer
# ─────────────────────────────────────────────────────────────────────────────

class SupabaseStore:
    """Thin wrapper around the supabase-py client for scan history."""

    def __init__(self, url: str, key: str) -> None:
        if not _HAS_SUPABASE:
            raise RuntimeError(
                "supabase-py is not installed. Run: pip install supabase"
            )
        self._client: SupabaseClient = create_client(url, key)

    def get_last_scan(self, url: str) -> dict | None:
        """
        Return the most recent scan record for the given URL, or None if this
        is the first time the target has been scanned.
        """
        try:
            response = (
                self._client.table(_TABLE)
                .select(
                    "scan_id, scan_timestamp, overall_score, overall_grade, "
                    "category_scores, critical_findings, finding_signatures"
                )
                .eq("url", url)
                .order("scan_timestamp", desc=True)
                .limit(1)
                .execute()
            )
            if response.data:
                return response.data[0]
        except Exception as exc:
            logger.error("Supabase get_last_scan failed: %s", exc)
        return None

    def store_scan(
        self,
        scan_result: dict,
        signatures:  dict[str, FindingSignature],
    ) -> str:
        """
        Persist the current scan result.  Returns the generated scan_id.
        Raises on failure (caller decides whether to propagate).
        """
        scan_id = str(uuid.uuid4())
        serialised_sigs = {
            fp: {
                "tool": sig.tool,
                "category": sig.category,
                "detail": sig.detail,
                "severity": sig.severity.value,
            }
            for fp, sig in signatures.items()
        }
        record = {
            "url":               scan_result["url"],
            "scan_id":           scan_id,
            "scan_timestamp":    datetime.now(timezone.utc).isoformat(),
            "overall_score":     scan_result.get("overall_score", 0),
            "overall_grade":     scan_result.get("overall_grade", "?"),
            "category_scores":   scan_result.get("category_scores", {}),
            "critical_findings": scan_result.get("critical_findings", []),
            "finding_signatures": serialised_sigs,
        }
        self._client.table(_TABLE).insert(record).execute()
        logger.info("Stored scan %s for %s", scan_id, scan_result["url"])
        return scan_id


# ─────────────────────────────────────────────────────────────────────────────
# Diff engine
# ─────────────────────────────────────────────────────────────────────────────

def _deserialise_signatures(raw: dict) -> dict[str, FindingSignature]:
    """Reconstruct FindingSignature objects from the Supabase JSON payload."""
    result: dict[str, FindingSignature] = {}
    for fp, data in (raw or {}).items():
        try:
            result[fp] = FindingSignature(
                fingerprint=fp,
                tool=data.get("tool", "unknown"),
                category=data.get("category", ""),
                detail=data.get("detail", ""),
                severity=Severity(data.get("severity", "INFO")),
            )
        except (ValueError, KeyError):
            pass
    return result


def compute_diff(
    current_result:  dict,
    previous_record: dict | None,
    scan_id:         str,
) -> ScanDiff:
    """
    Perform a structural diff between the current scan and the previous record.

    Returns a ScanDiff with findings classified as NEW, RESOLVED, or UNCHANGED.
    When ``previous_record`` is None the scan is treated as the first scan
    (baseline establishment); the ScanDiff is marked ``is_first_scan=True``
    and no findings are classified as NEW.
    """
    url = current_result.get("url", "")

    current_sigs  = extract_signatures(current_result)
    previous_sigs = (
        _deserialise_signatures(previous_record.get("finding_signatures", {}))
        if previous_record
        else {}
    )

    is_first = previous_record is None

    new_vulns:       list[FindingDelta] = []
    resolved_vulns:  list[FindingDelta] = []
    unchanged_vulns: list[FindingDelta] = []

    if not is_first:
        current_fps  = set(current_sigs)
        previous_fps = set(previous_sigs)

        for fp in current_fps - previous_fps:
            new_vulns.append(
                FindingDelta(DeltaClass.NEW_VULNERABILITY, current_sigs[fp])
            )
        for fp in previous_fps - current_fps:
            resolved_vulns.append(
                FindingDelta(DeltaClass.RESOLVED_VULNERABILITY, previous_sigs[fp])
            )
        for fp in current_fps & previous_fps:
            unchanged_vulns.append(
                FindingDelta(DeltaClass.UNCHANGED, current_sigs[fp])
            )

    # Sort: higher severity first
    _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                  Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    new_vulns.sort(key=lambda d: _sev_order.get(d.signature.severity, 99))
    resolved_vulns.sort(key=lambda d: _sev_order.get(d.signature.severity, 99))

    grade_before = previous_record.get("overall_grade", "?") if previous_record else "?"
    score_before = int(previous_record.get("overall_score", 0)) if previous_record else 0

    return ScanDiff(
        url=url,
        scan_id=scan_id,
        is_first_scan=is_first,
        new_vulns=new_vulns,
        resolved_vulns=resolved_vulns,
        unchanged_vulns=unchanged_vulns,
        grade_before=grade_before,
        grade_after=current_result.get("overall_grade", "?"),
        score_before=score_before,
        score_after=current_result.get("overall_score", 0),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Alert trigger logic
# ─────────────────────────────────────────────────────────────────────────────

def should_trigger_emergency(diff: ScanDiff, settings: _AlertSettings) -> bool:
    """
    Return True if an emergency alert dispatch is warranted.

    Criteria (any one is sufficient):
      1. Any NEW finding is CRITICAL severity.
      2. Any NEW finding is HIGH severity.
      3. Overall letter grade dropped by ≥ grade_drop_threshold steps.
      4. Overall numeric score dropped by ≥ score_drop_threshold points.
    """
    if diff.is_first_scan:
        return False
    if not diff.new_vulns and not diff.grade_changed and diff.score_delta >= 0:
        return False
    if diff.has_critical_new or diff.has_high_new:
        return True
    if diff.grade_drop_steps >= settings.grade_drop_threshold:
        return True
    if diff.score_delta <= -settings.score_drop_threshold:
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Slack Block Kit dispatcher
# ─────────────────────────────────────────────────────────────────────────────

_GRADE_EMOJI: dict[str, str] = {
    "A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴", "?": "⚪",
}

def _grade_arrow(before: str, after: str) -> str:
    b = _GRADE_ORDER.get(before, 0)
    a = _GRADE_ORDER.get(after, 0)
    if a < b:
        return "⬇️"
    if a > b:
        return "⬆️"
    return "➡️"


def _slack_colour(diff: ScanDiff, is_emergency: bool) -> str:
    if is_emergency or diff.has_critical_new:
        return "#D32F2F"   # red
    if diff.new_vulns:
        return "#F57C00"   # orange
    if diff.resolved_vulns and not diff.new_vulns:
        return "#388E3C"   # green — net improvement
    return "#1976D2"       # blue — informational


def _build_slack_payload(
    diff:         ScanDiff,
    is_emergency: bool,
    max_findings: int,
) -> dict[str, Any]:
    colour = _slack_colour(diff, is_emergency)

    # ── Header text ──────────────────────────────────────────────────────────
    if is_emergency:
        header_text = "🚨 EMERGENCY: Critical Security Regression Detected"
    elif diff.new_vulns:
        header_text = "⚠️ Security Alert: New Vulnerabilities Detected"
    elif diff.resolved_vulns:
        header_text = "✅ Security Improvement: Vulnerabilities Resolved"
    else:
        header_text = "ℹ️ Security Scan: No Material Changes Detected"

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": header_text, "emoji": True},
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*🎯 Target:*\n<{diff.url}|{diff.url}>"},
                {"type": "mrkdwn", "text": f"*🕐 Scan ID:*\n`{diff.scan_id}`"},
            ],
        },
    ]

    # ── Grade & score change ─────────────────────────────────────────────────
    if not diff.is_first_scan:
        grade_txt = (
            f"{_GRADE_EMOJI.get(diff.grade_before, '⚪')} {diff.grade_before} "
            f"{_grade_arrow(diff.grade_before, diff.grade_after)} "
            f"{_GRADE_EMOJI.get(diff.grade_after, '⚪')} {diff.grade_after}"
        )
        sign  = "+" if diff.score_delta >= 0 else ""
        score_txt = (
            f"{diff.score_before}/100 → {diff.score_after}/100 "
            f"({sign}{diff.score_delta} pts)"
        )
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*📊 Grade Change:*\n{grade_txt}"},
                {"type": "mrkdwn", "text": f"*📈 Score Change:*\n{score_txt}"},
            ],
        })
        blocks.append({"type": "divider"})

    # ── New vulnerabilities ──────────────────────────────────────────────────
    if diff.new_vulns:
        sev_icon = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH:     "🟠 HIGH",
            Severity.MEDIUM:   "🟡 MEDIUM",
            Severity.LOW:      "🔵 LOW",
            Severity.INFO:     "⚪ INFO",
        }
        lines = [
            f"• [{sev_icon.get(d.signature.severity, '⚪')}] "
            f"*{d.signature.tool}* — {d.signature.detail[:80]}"
            for d in diff.new_vulns[:max_findings]
        ]
        if len(diff.new_vulns) > max_findings:
            lines.append(f"_… and {len(diff.new_vulns) - max_findings} more_")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🔴 New Vulnerabilities ({len(diff.new_vulns)}):*\n"
                        + "\n".join(lines),
            },
        })

    # ── Resolved vulnerabilities ─────────────────────────────────────────────
    if diff.resolved_vulns:
        lines = [
            f"• ✅ *{d.signature.tool}* — {d.signature.detail[:80]}"
            for d in diff.resolved_vulns[:max_findings]
        ]
        if len(diff.resolved_vulns) > max_findings:
            lines.append(f"_… and {len(diff.resolved_vulns) - max_findings} more_")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🟢 Resolved Vulnerabilities ({len(diff.resolved_vulns)}):*\n"
                        + "\n".join(lines),
            },
        })

    # ── Unchanged (summary only) ─────────────────────────────────────────────
    if diff.unchanged_vulns:
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"ℹ️ {len(diff.unchanged_vulns)} finding(s) unchanged since last scan.",
            }],
        })

    # ── First-scan notice ────────────────────────────────────────────────────
    if diff.is_first_scan:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"📋 *Baseline established* — {len(diff.unchanged_vulns or [])} "
                    f"finding(s) indexed. Future scans will diff against this baseline."
                ),
            },
        })

    # ── Footer ───────────────────────────────────────────────────────────────
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": (
                f"🛡️ *AI Cyber Shield* | Differential Scan Manager | "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            ),
        }],
    })

    return {
        "attachments": [{
            "color":  colour,
            "blocks": blocks,
        }]
    }


class SlackDispatcher:
    """
    Async Slack notifier using the Incoming Webhooks API (Block Kit payload).
    """

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        self._url     = webhook_url
        self._timeout = timeout

    async def dispatch(
        self,
        diff:         ScanDiff,
        is_emergency: bool,
        max_findings: int = 10,
    ) -> DispatchResult:
        if not self._url:
            return DispatchResult(channel="slack", success=False,
                                  error="SLACK_WEBHOOK_URL not configured")
        payload = _build_slack_payload(diff, is_emergency, max_findings)
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
            success = resp.status_code == 200
            error   = "" if success else f"HTTP {resp.status_code}: {resp.text[:100]}"
            return DispatchResult(
                channel="slack", success=success,
                status_code=resp.status_code, error=error,
            )
        except Exception as exc:
            logger.error("Slack dispatch failed: %s", exc)
            return DispatchResult(channel="slack", success=False, error=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Generic SIEM / Webhook dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def _build_webhook_payload(
    diff:         ScanDiff,
    is_emergency: bool,
) -> dict[str, Any]:
    """
    Compact, machine-readable JSON payload suitable for SIEM ingestion
    (Splunk HEC, Elastic Beats, Datadog Event API, custom webhook targets).
    """
    severity = (
        "CRITICAL" if (is_emergency or diff.has_critical_new)
        else "HIGH"    if diff.has_high_new
        else "MEDIUM"  if diff.new_vulns
        else "LOW"     if diff.resolved_vulns
        else "INFO"
    )

    def _sig_to_dict(d: FindingDelta) -> dict:
        return {
            "fingerprint": d.signature.fingerprint,
            "tool":        d.signature.tool,
            "category":    d.signature.category,
            "detail":      d.signature.detail,
            "severity":    d.signature.severity.value,
        }

    return {
        "event_type":       "SECURITY_SCAN_DIFF",
        "severity":         severity,
        "is_emergency":     is_emergency,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "url":              diff.url,
        "scan_id":          diff.scan_id,
        "is_first_scan":    diff.is_first_scan,
        "grade": {
            "before": diff.grade_before,
            "after":  diff.grade_after,
            "changed": diff.grade_changed,
            "drop_steps": diff.grade_drop_steps,
        },
        "score": {
            "before": diff.score_before,
            "after":  diff.score_after,
            "delta":  diff.score_delta,
        },
        "new_vulnerabilities":      [_sig_to_dict(d) for d in diff.new_vulns],
        "resolved_vulnerabilities":  [_sig_to_dict(d) for d in diff.resolved_vulns],
        "unchanged_count":           len(diff.unchanged_vulns),
        "summary":                   diff.summary(),
    }


class WebhookDispatcher:
    """
    Async generic JSON webhook dispatcher.
    Targets: Splunk HEC, Elastic Ingest, Datadog Events, custom SIEM endpoints.
    """

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        self._url     = webhook_url
        self._timeout = timeout

    async def dispatch(
        self,
        diff:         ScanDiff,
        is_emergency: bool,
    ) -> DispatchResult:
        if not self._url:
            return DispatchResult(channel="webhook", success=False,
                                  error="ALERT_WEBHOOK_URL not configured")
        payload = _build_webhook_payload(diff, is_emergency)
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._url,
                    json=payload,
                    headers={
                        "Content-Type":  "application/json",
                        "X-Scanner":     "AI-Cyber-Shield",
                        "X-Scan-Id":     diff.scan_id,
                        "X-Severity":    payload["severity"],
                    },
                )
            success = 200 <= resp.status_code < 300
            error   = "" if success else f"HTTP {resp.status_code}: {resp.text[:100]}"
            return DispatchResult(
                channel="webhook", success=success,
                status_code=resp.status_code, error=error,
            )
        except Exception as exc:
            logger.error("Webhook dispatch failed: %s", exc)
            return DispatchResult(channel="webhook", success=False, error=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Concurrent dispatch helper
# ─────────────────────────────────────────────────────────────────────────────

async def _dispatch_all(
    diff:         ScanDiff,
    is_emergency: bool,
    settings:     _AlertSettings,
) -> list[DispatchResult]:
    """
    Dispatch to all configured channels concurrently.
    Returns a list of DispatchResult (one per channel attempted).
    """
    tasks: list[asyncio.Task] = []

    if settings.slack_webhook_url:
        dispatcher = SlackDispatcher(
            settings.slack_webhook_url,
            timeout=settings.webhook_timeout_seconds,
        )
        tasks.append(asyncio.create_task(
            dispatcher.dispatch(diff, is_emergency,
                                max_findings=settings.max_findings_in_alert)
        ))

    if settings.alert_webhook_url:
        dispatcher = WebhookDispatcher(
            settings.alert_webhook_url,
            timeout=settings.webhook_timeout_seconds,
        )
        tasks.append(asyncio.create_task(
            dispatcher.dispatch(diff, is_emergency)
        ))

    if not tasks:
        logger.debug("No alert channels configured — skipping dispatch")
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)
    dispatch_results: list[DispatchResult] = []
    for result in results:
        if isinstance(result, DispatchResult):
            dispatch_results.append(result)
        else:
            # asyncio.gather returns exceptions as values when return_exceptions=True
            dispatch_results.append(
                DispatchResult(channel="unknown", success=False, error=str(result))
            )
    return dispatch_results


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def run_differential_scan_async(scan_result: dict) -> DiffReport:
    """
    Async entry point.  Accepts a pipeline result dict from run_url_security_audit()
    and returns a DiffReport with full diff, alert decision, and dispatch results.

    Behaviour on first scan:
        Stores baseline in Supabase, returns DiffReport with is_first_scan=True,
        emergency_alert=False, no dispatch.  This prevents alert flood on day 0.

    Behaviour on Supabase unavailability:
        If supabase-py is not installed or credentials are missing, the diff is
        still computed (all findings classified as NEW) and alerts still dispatch.
        stored_in_db will be False and DiffReport.error will describe the issue.
    """
    settings = _get_alert_settings()
    url = scan_result.get("url", "")
    scan_id = str(uuid.uuid4())

    current_sigs  = extract_signatures(scan_result)
    previous_record: dict | None = None
    stored_in_db = False
    db_error = ""

    # ── Supabase layer ────────────────────────────────────────────────────────
    store: SupabaseStore | None = None
    if _HAS_SUPABASE and settings.supabase_url and settings.supabase_key:
        try:
            store = SupabaseStore(settings.supabase_url, settings.supabase_key)
            previous_record = store.get_last_scan(url)
        except Exception as exc:
            db_error = f"Supabase read failed: {exc}"
            logger.error(db_error)
    elif not _HAS_SUPABASE:
        db_error = "supabase-py not installed"
    elif not settings.supabase_url:
        db_error = "SUPABASE_URL not configured"

    # ── Diff ─────────────────────────────────────────────────────────────────
    diff = compute_diff(scan_result, previous_record, scan_id)
    is_emergency = should_trigger_emergency(diff, settings)

    logger.info(
        "Diff for %s: first_scan=%s new=%d resolved=%d unchanged=%d emergency=%s",
        url, diff.is_first_scan,
        len(diff.new_vulns), len(diff.resolved_vulns), len(diff.unchanged_vulns),
        is_emergency,
    )

    # ── Dispatch ──────────────────────────────────────────────────────────────
    dispatch_results: list[DispatchResult] = []
    if not diff.is_first_scan and (is_emergency or diff.new_vulns or diff.resolved_vulns):
        dispatch_results = await _dispatch_all(diff, is_emergency, settings)
        for r in dispatch_results:
            status = "OK" if r.success else f"FAILED: {r.error}"
            logger.info("Channel %-10s → %s", r.channel, status)

    # ── Persist ───────────────────────────────────────────────────────────────
    if store is not None:
        try:
            scan_id = store.store_scan(scan_result, current_sigs)
            diff.scan_id = scan_id
            stored_in_db = True
        except Exception as exc:
            db_error = f"Supabase write failed: {exc}"
            logger.error(db_error)

    return DiffReport(
        url=url,
        scan_id=scan_id,
        diff=diff,
        emergency_alert=is_emergency,
        dispatch_results=dispatch_results,
        stored_in_db=stored_in_db,
        error=db_error,
    )


def run_differential_scan(scan_result: dict) -> DiffReport:
    """
    Synchronous wrapper around run_differential_scan_async().

    If an event loop is already running (e.g., inside a Jupyter notebook or
    Streamlit's async context), the caller should await run_differential_scan_async()
    directly.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Running inside an existing event loop (Jupyter, Streamlit, pytest-asyncio)
        # Create a concurrent future rather than blocking the loop.
        future = asyncio.ensure_future(run_differential_scan_async(scan_result))
        # This will block until the future completes, but only works in
        # environments where nest_asyncio is installed.
        return loop.run_until_complete(future)
    else:
        return asyncio.run(run_differential_scan_async(scan_result))

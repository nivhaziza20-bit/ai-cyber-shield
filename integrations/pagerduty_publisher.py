"""
integrations/pagerduty_publisher.py — AI Cyber Shield v6

Sends SecurityFinding objects to PagerDuty via Events API v2.

Key design decisions:
  • dedup_key = "aics-{finding_id[:16]}" → no duplicate alerts across re-scans
  • Auto-resolve: pass resolved_finding_ids to resolve_findings() after a re-scan
  • Severity mapping: CRITICAL→critical, HIGH→error, MEDIUM→warning, LOW/INFO→info
  • Grouped mode: one alert per OWASP category (not one per finding) to prevent alert fatigue
  • Rate limiting: exponential backoff on 429
  • Dry-run mode: logs what WOULD be sent without calling PagerDuty

Events API v2 docs: https://developer.pagerduty.com/docs/events-api-v2/

Environment variables:
  PAGERDUTY_INTEGRATION_KEY — 32-char Events API v2 Integration Key
  PAGERDUTY_DRY_RUN         — "1" to enable dry-run
  PAGERDUTY_GROUP_BY        — "owasp" | "cwe" | "none" (default: "none")
  PAGERDUTY_MIN_SEVERITY    — Minimum severity to alert: CRITICAL|HIGH|MEDIUM|LOW
                              (default: HIGH — don't page on every medium)

Defensive constraints:
  • No shell=True anywhere
  • Token never logged
  • Events endpoint is hardcoded (no SSRF surface)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)

_EVENTS_URL    = "https://events.pagerduty.com/v2/enqueue"
_DEDUP_PREFIX  = "aics-"
_MAX_RETRIES   = 4
_INITIAL_BACKOFF = 1.0

# AICS severity → PagerDuty severity
_SEV_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "info",
    "INFO":     "info",
}

# Severity ordering (lower index = higher priority)
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ─────────────────────────────────────────────────────────────────────────────
# Result tracking
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PagerDutyResult:
    triggered:  int = 0
    resolved:   int = 0
    skipped:    int = 0     # below min_severity threshold
    failed:     int = 0
    errors:     list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _dedup_key(finding_id: str) -> str:
    """Stable, unique dedup key — prevents duplicate PagerDuty incidents."""
    return f"{_DEDUP_PREFIX}{finding_id[:16]}"


def _group_key(finding, group_by: str) -> str:
    """Key used to group findings into a single PagerDuty alert."""
    if group_by == "owasp":
        return f"owasp-{finding.owasp.code}"
    if group_by == "cwe":
        return f"cwe-{finding.cwe.id}"
    return finding.finding_id  # one alert per finding (default)


def _severity_index(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev.upper())
    except ValueError:
        return len(_SEV_ORDER)


def _build_payload(
    integration_key: str,
    event_action:    str,          # "trigger" | "resolve"
    finding,
    target_url:      str,
    source:          str,
    dedup:           str,
    group_findings:  Optional[list] = None,  # for grouped mode
) -> dict:
    """
    Build a PagerDuty Events API v2 payload.
    https://developer.pagerduty.com/docs/events-api-v2/trigger-events/
    """
    group_findings = group_findings or [finding]
    top_finding    = min(group_findings, key=lambda f: _severity_index(f.severity))

    summary = (
        f"[{top_finding.severity}] {top_finding.title} — {target_url or top_finding.endpoint}"
    )
    if len(group_findings) > 1:
        summary = (
            f"[{top_finding.severity}] {len(group_findings)} findings "
            f"({top_finding.owasp.code}: {top_finding.owasp.name}) "
            f"— {target_url}"
        )

    payload_body: dict = {
        "summary":   summary[:1024],   # PD limit
        "severity":  _SEV_MAP.get(top_finding.severity, "error"),
        "source":    source or target_url,
        "component": "ai-cyber-shield",
        "group":     top_finding.owasp.code,        # groups alerts in PD
        "class":     top_finding.cwe.label,
        "custom_details": {
            "scan_url":       target_url,
            "finding_count":  len(group_findings),
            "top_cvss_score": top_finding.cvss.score,
            "top_cvss_vector": top_finding.cvss.vector.vector_string,
            "owasp_2025":    top_finding.owasp.label,
            "cwe":           top_finding.cwe.label,
            "business_impact": top_finding.business_impact,
            "attack_scenario": top_finding.attack_scenario,
            "endpoint":      top_finding.endpoint,
            "evidence":      (top_finding.evidence or "")[:500],
            "confirmed":     top_finding.confirmed,
            "remediation":   top_finding.remediation.summary,
            "compliance": {
                "pci_dss":   top_finding.compliance.pci_dss,
                "soc2":      top_finding.compliance.soc2_cc,
                "iso_27001": top_finding.compliance.iso_27001,
            },
            "all_findings": [
                {
                    "finding_id":  f.finding_id,
                    "title":       f.title,
                    "severity":    f.severity,
                    "cvss_score":  f.cvss.score,
                    "endpoint":    f.endpoint,
                    "confirmed":   f.confirmed,
                }
                for f in group_findings
            ],
        },
    }

    return {
        "routing_key":    integration_key,
        "event_action":   event_action,
        "dedup_key":      dedup,
        "payload":        payload_body,
        "client":         "AI Cyber Shield",
        "client_url":     target_url,
    }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helper
# ─────────────────────────────────────────────────────────────────────────────

def _post_event(payload: dict) -> dict:
    """POST to PagerDuty Events API v2 with retry on 429/5xx."""
    try:
        import requests  # noqa: PLC0415
    except ImportError:
        raise RuntimeError("requests library required: pip install requests")

    backoff = _INITIAL_BACKOFF

    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.post(
                _EVENTS_URL,
                json    = payload,
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent":   "AI-Cyber-Shield/6.0",
                },
                timeout = 15,
            )
        except Exception as exc:
            _log.warning("PagerDuty request error (attempt %d): %s", attempt + 1, exc)
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 202:
            body = resp.json()
            _log.debug("PagerDuty accepted: %s", body.get("message"))
            return body

        if resp.status_code == 429:
            wait = float(resp.headers.get("Retry-After", backoff))
            _log.warning("PagerDuty rate limit — waiting %.1fs", wait)
            time.sleep(wait)
            backoff *= 2
            continue

        if resp.status_code >= 500:
            _log.warning("PagerDuty 5xx (attempt %d): %s", attempt + 1, resp.text[:200])
            time.sleep(backoff)
            backoff *= 2
            continue

        # 4xx (except 429) — don't retry
        raise RuntimeError(
            f"PagerDuty Events API returned {resp.status_code}: {resp.text[:300]}"
        )

    raise RuntimeError(
        f"PagerDuty Events API failed after {_MAX_RETRIES} retries"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main publisher
# ─────────────────────────────────────────────────────────────────────────────

class PagerDutyPublisher:
    """
    Sends AI Cyber Shield findings to PagerDuty via Events API v2.

    One incident per finding (or per group when group_by is set).
    Re-scan with the same finding → dedup_key prevents a second incident.
    Re-scan where finding is gone → resolve_findings() closes the incident.
    """

    def __init__(
        self,
        integration_key: str,
        min_severity:    str  = "HIGH",
        group_by:        str  = "none",    # "none" | "owasp" | "cwe"
        dry_run:         bool = False,
        source:          str  = "ai-cyber-shield",
    ) -> None:
        """
        Args:
            integration_key: PagerDuty Events API v2 Integration Key (32 chars)
            min_severity:    Only alert on findings at this severity or above
            group_by:        Group findings into fewer alerts ("owasp" recommended
                             for large scans to prevent alert fatigue)
            dry_run:         Log what WOULD be sent without calling PagerDuty
            source:          Source label shown in PagerDuty UI
        """
        if not dry_run and len(integration_key) != 32:
            raise ValueError(
                f"PagerDuty integration key must be 32 characters, "
                f"got {len(integration_key)}"
            )
        self._key          = integration_key
        self._min_sev_idx  = _severity_index(min_severity.upper())
        self._group_by     = group_by.lower()
        self._dry_run      = dry_run
        self._source       = source

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "PagerDutyPublisher":
        key = os.environ.get("PAGERDUTY_INTEGRATION_KEY", "")
        if not key:
            raise ValueError("PAGERDUTY_INTEGRATION_KEY environment variable not set")
        return cls(
            integration_key = key,
            min_severity    = os.environ.get("PAGERDUTY_MIN_SEVERITY", "HIGH"),
            group_by        = os.environ.get("PAGERDUTY_GROUP_BY", "none"),
            dry_run         = os.environ.get("PAGERDUTY_DRY_RUN", "0") == "1",
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def trigger_findings(
        self,
        findings:   list,
        target_url: str = "",
    ) -> PagerDutyResult:
        """
        Send PagerDuty trigger events for new/active findings.

        Findings below min_severity are skipped silently.
        Grouped mode sends one alert per OWASP category / CWE.
        """
        result   = PagerDutyResult()
        eligible = [
            f for f in findings
            if _severity_index(f.severity) <= self._min_sev_idx
        ]
        eligible.sort(key=lambda f: _severity_index(f.severity))

        if not eligible:
            _log.info("No findings at or above min_severity threshold — nothing sent")
            result.skipped = len(findings)
            return result

        result.skipped = len(findings) - len(eligible)

        # Group findings if requested
        if self._group_by != "none":
            groups: dict[str, list] = {}
            for f in eligible:
                k = _group_key(f, self._group_by)
                groups.setdefault(k, []).append(f)
        else:
            groups = {f.finding_id: [f] for f in eligible}

        for group_id, group_findings in groups.items():
            # Use the highest-severity finding as the "representative"
            top = min(group_findings, key=lambda f: _severity_index(f.severity))
            dedup = (
                f"{_DEDUP_PREFIX}{group_id[:16]}"
                if self._group_by != "none"
                else _dedup_key(top.finding_id)
            )

            payload = _build_payload(
                integration_key = self._key,
                event_action    = "trigger",
                finding         = top,
                target_url      = target_url,
                source          = self._source,
                dedup           = dedup,
                group_findings  = group_findings,
            )

            try:
                if self._dry_run:
                    _log.info(
                        "[DRY-RUN] Would trigger PD alert: %s (dedup=%s)",
                        payload["payload"]["summary"][:80], dedup,
                    )
                else:
                    _post_event(payload)
                result.triggered += 1
            except Exception as exc:
                _log.error("PagerDuty trigger failed for %s: %s", dedup, exc)
                result.failed += 1
                result.errors.append(str(exc))

        return result

    def resolve_findings(
        self,
        resolved_finding_ids: list[str],
        target_url: str = "",
    ) -> PagerDutyResult:
        """
        Send PagerDuty resolve events for findings no longer present in a re-scan.
        Closes the corresponding PagerDuty incidents via dedup_key.
        """
        result = PagerDutyResult()

        for finding_id in resolved_finding_ids:
            dedup   = _dedup_key(finding_id)
            payload = {
                "routing_key":  self._key,
                "event_action": "resolve",
                "dedup_key":    dedup,
            }

            try:
                if self._dry_run:
                    _log.info("[DRY-RUN] Would resolve PD alert: %s", dedup)
                else:
                    _post_event(payload)
                result.resolved += 1
            except Exception as exc:
                _log.warning("PagerDuty resolve failed for %s: %s", dedup, exc)
                result.failed += 1
                result.errors.append(str(exc))

        return result

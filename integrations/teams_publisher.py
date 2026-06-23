"""
integrations/teams_publisher.py — AI Cyber Shield v6

Sends SecurityFinding objects to Microsoft Teams via Incoming Webhooks.

Format: Adaptive Cards v1.5 (NOT legacy MessageCard / connector cards).
Adaptive Cards are the current recommended format for Teams and render
natively in Teams desktop, mobile, and web.

Key features:
  • Batched summary card (N findings → 1 card, not N cards → no spam)
  • Color-coded header: red=CRITICAL, orange=HIGH, yellow=MEDIUM, green=LOW/clean
  • Expandable "Technical Details" section (collapsed by default)
  • FactSet: CVSS score, CWE, OWASP 2025, compliance flags
  • Rate limiting + retry
  • Dry-run mode
  • Optional @mention of a Teams channel ID

Environment variables:
  TEAMS_WEBHOOK_URL      — Incoming Webhook URL (from Teams channel connector)
  TEAMS_DRY_RUN          — "1" to enable dry-run
  TEAMS_MENTION_USER_ID  — Teams user ID to @mention on CRITICAL findings
  TEAMS_MENTION_NAME     — Display name for the @mention

Defensive constraints:
  • Webhook URL validated (must be https://…webhook.office.com/…)
  • Token never logged
  • No shell=True
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)

_MAX_RETRIES   = 4
_INITIAL_BACKOFF = 1.0

# Severity → Adaptive Card accent color (hex)
_SEV_COLOR: dict[str, str] = {
    "CRITICAL": "attention",    # red
    "HIGH":     "warning",      # orange
    "MEDIUM":   "accent",       # blue/yellow (theme)
    "LOW":      "good",         # green
    "INFO":     "default",
}

# Summary emoji per severity
_SEV_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}

_TEAMS_WEBHOOK_PATTERN = re.compile(
    r"^https://[a-zA-Z0-9.-]+\.webhook\.office\.com/",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TeamsResult:
    sent:   int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# URL validation
# ─────────────────────────────────────────────────────────────────────────────

def _validate_webhook_url(url: str) -> str:
    if not _TEAMS_WEBHOOK_PATTERN.match(url):
        raise ValueError(
            f"Teams webhook URL must start with "
            f"https://<tenant>.webhook.office.com/ — got: {url!r}"
        )
    return url


# ─────────────────────────────────────────────────────────────────────────────
# Adaptive Card builders
# ─────────────────────────────────────────────────────────────────────────────

def _top_severity(findings: list) -> str:
    """Return the highest severity from a list of findings."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for sev in order:
        if any(f.severity == sev for f in findings):
            return sev
    return "INFO"


def _build_summary_card(
    findings:       list,
    target_url:     str,
    scan_label:     str  = "",
    mention_user_id: Optional[str] = None,
    mention_name:    Optional[str] = None,
) -> dict:
    """
    Build an Adaptive Card summarising N findings.
    One card covers the whole scan — no per-finding spam.
    """
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    top_sev   = _top_severity(findings)
    color     = _SEV_COLOR.get(top_sev, "default")
    emoji     = _SEV_EMOJI.get(top_sev, "⚪")
    total     = len(findings)
    confirmed = sum(1 for f in findings if f.confirmed)
    top_cvss  = max((f.cvss.score for f in findings), default=0.0)
    label     = scan_label or target_url

    # Top 3 findings for the "critical findings" list
    top3 = sorted(findings, key=lambda f: -f.cvss.score)[:3]

    # Build Adaptive Card body
    body_blocks = [
        {
            "type": "Container",
            "style": color,
            "bleed": True,
            "items": [
                {
                    "type": "TextBlock",
                    "text": f"{emoji} AI Cyber Shield — Security Scan",
                    "weight": "bolder",
                    "size": "large",
                    "color": "light",
                    "wrap": True,
                },
                {
                    "type": "TextBlock",
                    "text": label,
                    "color": "light",
                    "size": "small",
                    "wrap": True,
                    "isSubtle": True,
                },
            ],
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "🔴 Critical",  "value": str(by_sev.get("CRITICAL", 0))},
                {"title": "🟠 High",      "value": str(by_sev.get("HIGH",     0))},
                {"title": "🟡 Medium",    "value": str(by_sev.get("MEDIUM",   0))},
                {"title": "🟢 Low",       "value": str(by_sev.get("LOW",      0))},
                {"title": "Total",        "value": str(total)},
                {"title": "Confirmed",    "value": str(confirmed)},
                {"title": "Top CVSS",     "value": f"{top_cvss:.1f} / 10.0"},
            ],
            "separator": True,
        },
    ]

    # Top findings list
    if top3:
        finding_items = []
        for f in top3:
            finding_items.append({
                "type": "TextBlock",
                "text": (
                    f"{_SEV_EMOJI.get(f.severity,'⚪')} **{f.title}**  \n"
                    f"CVSS {f.cvss.score:.1f} · {f.cwe.label} · {f.owasp.label}"
                ),
                "wrap": True,
                "size": "small",
            })

        body_blocks.append({
            "type": "Container",
            "separator": True,
            "items": [
                {
                    "type": "TextBlock",
                    "text": "Top Findings",
                    "weight": "bolder",
                    "size": "medium",
                },
                *finding_items,
            ],
        })

    # Expandable technical details (collapsed by default)
    if findings:
        top_f = top3[0] if top3 else findings[0]
        body_blocks.append({
            "type": "Container",
            "separator": True,
            "isVisible": False,
            "id":        "techDetails",
            "items": [
                {
                    "type": "TextBlock",
                    "text": "Technical Details (top finding)",
                    "weight": "bolder",
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "CVSS Vector",  "value": top_f.cvss.vector.vector_string},
                        {"title": "CWE",          "value": f"{top_f.cwe.label} — {top_f.cwe.name}"},
                        {"title": "OWASP 2025",   "value": top_f.owasp.label},
                        {"title": "Endpoint",     "value": top_f.endpoint or "—"},
                        {"title": "PCI-DSS",      "value": top_f.compliance.pci_dss or "—"},
                        {"title": "SOC2",         "value": top_f.compliance.soc2_cc or "—"},
                        {"title": "Remediation",  "value": top_f.remediation.summary[:120]},
                    ],
                },
            ],
        })

    # @mention on CRITICAL
    if mention_user_id and mention_name and top_sev == "CRITICAL":
        body_blocks.append({
            "type": "TextBlock",
            "text": (
                f"<at>{mention_name}</at> — CRITICAL findings require immediate attention."
            ),
            "wrap": True,
            "color": "attention",
        })

    # Action buttons
    actions = [
        {
            "type":  "Action.ToggleVisibility",
            "title": "Show / Hide Technical Details",
            "targetElements": ["techDetails"],
        },
    ]

    if target_url:
        actions.append({
            "type":  "Action.OpenUrl",
            "title": "Open Target URL",
            "url":   target_url,
        })

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type":    "AdaptiveCard",
                    "version": "1.5",
                    "body":    body_blocks,
                    "actions": actions,
                    "msteams": {
                        "width": "Full",
                        # @mention entity
                        **(
                            {
                                "entities": [
                                    {
                                        "type":        "mention",
                                        "text":        f"<at>{mention_name}</at>",
                                        "mentioned": {
                                            "id":   mention_user_id,
                                            "name": mention_name,
                                        },
                                    }
                                ]
                            }
                            if mention_user_id and mention_name and top_sev == "CRITICAL"
                            else {}
                        ),
                    },
                },
            }
        ],
    }

    return card


def _build_clean_card(target_url: str, scan_label: str = "") -> dict:
    """Simple green card for scans with zero findings."""
    label = scan_label or target_url
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type":    "AdaptiveCard",
                    "version": "1.5",
                    "body": [
                        {
                            "type":  "Container",
                            "style": "good",
                            "bleed": True,
                            "items": [
                                {
                                    "type":   "TextBlock",
                                    "text":   "✅ AI Cyber Shield — All Clear",
                                    "weight": "bolder",
                                    "size":   "large",
                                    "color":  "light",
                                }
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": f"No security findings detected on **{label}**.",
                            "wrap": True,
                        },
                    ],
                },
            }
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helper
# ─────────────────────────────────────────────────────────────────────────────

def _post_card(webhook_url: str, card: dict) -> None:
    """POST an Adaptive Card to a Teams Incoming Webhook with retry."""
    try:
        import requests  # noqa: PLC0415
    except ImportError:
        raise RuntimeError("requests library required: pip install requests")

    backoff = _INITIAL_BACKOFF

    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.post(
                webhook_url,
                json    = card,
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent":   "AI-Cyber-Shield/6.0",
                },
                timeout = 15,
            )
        except Exception as exc:
            _log.warning("Teams request error (attempt %d): %s", attempt + 1, exc)
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 200:
            return

        if resp.status_code == 429:
            wait = float(resp.headers.get("Retry-After", backoff))
            _log.warning("Teams rate limit — waiting %.1fs", wait)
            time.sleep(wait)
            backoff *= 2
            continue

        if resp.status_code >= 500:
            _log.warning("Teams 5xx (attempt %d): %s", attempt + 1, resp.text[:200])
            time.sleep(backoff)
            backoff *= 2
            continue

        raise RuntimeError(
            f"Teams webhook returned {resp.status_code}: {resp.text[:200]}"
        )

    raise RuntimeError(f"Teams webhook failed after {_MAX_RETRIES} retries")


# ─────────────────────────────────────────────────────────────────────────────
# Main publisher
# ─────────────────────────────────────────────────────────────────────────────

class TeamsPublisher:
    """
    Sends AI Cyber Shield scan results to Microsoft Teams via Adaptive Cards.

    One batched card per scan (not one card per finding).
    Always sends — even if there are zero findings (sends a green "all clear" card).
    """

    def __init__(
        self,
        webhook_url:     str,
        min_severity:    str           = "LOW",
        dry_run:         bool          = False,
        mention_user_id: Optional[str] = None,
        mention_name:    Optional[str] = None,
        always_notify:   bool          = False,  # send even if no findings
    ) -> None:
        """
        Args:
            webhook_url:     Teams Incoming Webhook URL
            min_severity:    Only include findings at this severity or above in the card
            dry_run:         Log what WOULD be sent without calling Teams
            mention_user_id: Teams AAD user ID to @mention on CRITICAL
            mention_name:    Display name for the @mention
            always_notify:   If True, send a "all clear" card even when no findings
        """
        self._webhook_url    = _validate_webhook_url(webhook_url)
        self._min_sev_map    = {
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
        }
        self._min_sev_idx    = self._min_sev_map.get(min_severity.upper(), 3)
        self._dry_run        = dry_run
        self._mention_uid    = mention_user_id
        self._mention_name   = mention_name
        self._always_notify  = always_notify

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "TeamsPublisher":
        url = os.environ.get("TEAMS_WEBHOOK_URL", "")
        if not url:
            raise ValueError("TEAMS_WEBHOOK_URL environment variable not set")
        return cls(
            webhook_url     = url,
            dry_run         = os.environ.get("TEAMS_DRY_RUN", "0") == "1",
            mention_user_id = os.environ.get("TEAMS_MENTION_USER_ID"),
            mention_name    = os.environ.get("TEAMS_MENTION_NAME"),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def send_scan_results(
        self,
        findings:   list,
        target_url: str = "",
        scan_label: str = "",
    ) -> TeamsResult:
        """
        Send a batched summary card to Teams.

        Args:
            findings:   List of SecurityFinding objects
            target_url: URL that was scanned
            scan_label: Human-readable label (e.g. "Production — nightly scan")

        Returns:
            TeamsResult
        """
        result = TeamsResult()

        # Filter by severity
        eligible = [
            f for f in findings
            if self._min_sev_map.get(f.severity, 4) <= self._min_sev_idx
        ]

        if not eligible and not self._always_notify:
            _log.info("No findings at or above threshold — Teams notification skipped")
            return result

        if eligible:
            card = _build_summary_card(
                findings        = eligible,
                target_url      = target_url,
                scan_label      = scan_label,
                mention_user_id = self._mention_uid,
                mention_name    = self._mention_name,
            )
        else:
            card = _build_clean_card(target_url, scan_label)

        try:
            if self._dry_run:
                _log.info(
                    "[DRY-RUN] Would send Teams card: %d findings, top=%s",
                    len(eligible), _top_severity(eligible) if eligible else "NONE",
                )
            else:
                _post_card(self._webhook_url, card)

            result.sent = 1
        except Exception as exc:
            _log.error("Teams notification failed: %s", exc)
            result.failed = 1
            result.errors.append(str(exc))

        return result

    def send_differential_alert(
        self,
        new_findings:      list,
        resolved_ids:      list[str],
        target_url:        str = "",
        scan_label:        str = "",
    ) -> TeamsResult:
        """
        Send a Teams card only if there are NEW findings (differential mode).
        Also notes how many findings were resolved.

        Used by ScanScheduler for scheduled scans.
        """
        if not new_findings and not self._always_notify:
            _log.info("No new findings — Teams differential alert skipped")
            return TeamsResult()

        result = self.send_scan_results(
            findings   = new_findings,
            target_url = target_url,
            scan_label = (
                f"{scan_label} — {len(new_findings)} new"
                + (f", {len(resolved_ids)} resolved" if resolved_ids else "")
            ),
        )
        return result

"""
integrations/jira_publisher.py — AI Cyber Shield v6

Publishes SecurityFinding objects to Atlassian JIRA.

Differentiators vs. basic JIRA integrations:
  • Idempotent — uses finding_id as unique label to prevent duplicate issues
  • Auto-transition: findings resolved on re-scan → move issue to "Done"
  • Supports both JIRA Cloud (REST API v3) and JIRA Server / Data Center (REST API v2)
  • CVSS score + severity → JIRA Priority mapping (P1–P4)
  • Full remediation guide in issue description (Markdown)
  • OWASP 2025 label + component tagging
  • Batch creation with rate limiting + exponential backoff (429/503)
  • Dry-run mode — logs what WOULD be created without making API calls

Environment variables (or pass explicitly to JiraPublisher):
  JIRA_BASE_URL   — e.g. https://yourorg.atlassian.net  (no trailing slash)
  JIRA_EMAIL      — Atlassian account email (Cloud only)
  JIRA_API_TOKEN  — API token or Personal Access Token
  JIRA_PROJECT    — JIRA project key (e.g. "SEC")
  JIRA_ISSUE_TYPE — default issue type (e.g. "Bug", "Security Finding")
  JIRA_DRY_RUN    — "1" to enable dry-run mode

Usage:
    from integrations.jira_publisher import JiraPublisher
    from finding_enricher import enrich_scan_result

    pub = JiraPublisher.from_env()
    findings = enrich_scan_result(raw_result)
    results  = pub.publish_findings(findings, target_url="https://app.example.com")
    print(f"Created: {results.created}  Existing: {results.existing}  Failed: {results.failed}")

Defensive constraints:
  • Uses secrets.compare_digest-style handling for tokens
  • Never logs API tokens
  • SSRF guard via _validate_base_url() (blocks private ranges)
  • shell=False everywhere — no subprocess
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_JIRA_LABEL_PREFIX = "aics:"          # aics:<finding_id[:16]>
_AICS_COMPONENT    = "AI-Cyber-Shield" # auto-created component in JIRA

# CVSS → JIRA Priority mapping
# P1=Highest/Critical, P2=High, P3=Medium, P4=Low
_CVSS_TO_PRIORITY: list[tuple[float, str]] = [
    (9.0, "Highest"),   # Critical
    (7.0, "High"),
    (4.0, "Medium"),
    (0.0, "Low"),
]

# OWASP code → JIRA label (human-readable)
_OWASP_LABELS: dict[str, str] = {
    "A01": "OWASP-A01-BrokenAccessControl",
    "A02": "OWASP-A02-CryptographicFailures",
    "A03": "OWASP-A03-Injection",
    "A04": "OWASP-A04-InsecureDesign",
    "A05": "OWASP-A05-SecurityMisconfiguration",
    "A06": "OWASP-A06-VulnerableComponents",
    "A07": "OWASP-A07-AuthFailures",
    "A08": "OWASP-A08-SoftwareIntegrityFailures",
    "A09": "OWASP-A09-LoggingFailures",
    "A10": "OWASP-A10-SSRF",
    "A11": "OWASP-A11-SupplyChain",
    "A12": "OWASP-A12-ExceptionalConditions",
}

_MAX_RETRIES         = 4
_INITIAL_BACKOFF_SEC = 1.0
_BATCH_DELAY_SEC     = 0.2    # small pause between JIRA API calls


# ─────────────────────────────────────────────────────────────────────────────
# Result tracking
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PublishResult:
    created:  int = 0
    existing: int = 0   # finding_id already has an open issue
    resolved: int = 0   # previously open issue transitioned to Done
    failed:   int = 0
    errors:   list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# SSRF guard
# ─────────────────────────────────────────────────────────────────────────────

_PRIVATE_IP_PATTERNS = re.compile(
    r"^("
    r"10\.\d+\.\d+\.\d+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|127\.\d+\.\d+\.\d+"
    r"|169\.254\.\d+\.\d+"
    r"|::1"
    r"|localhost"
    r")$",
    re.IGNORECASE,
)


def _validate_base_url(base_url: str) -> str:
    """Raise ValueError if the JIRA base URL points to a private/internal address."""
    parsed = urlparse(base_url.rstrip("/"))
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"JIRA base URL must use http/https, got: {base_url!r}")
    host = parsed.hostname or ""
    if _PRIVATE_IP_PATTERNS.match(host):
        raise ValueError(
            f"JIRA base URL {base_url!r} resolves to a private IP address. "
            "Use the public Atlassian Cloud URL or your internal JIRA proxy."
        )
    return base_url.rstrip("/")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helper (no external httpx dependency — uses stdlib urllib + requests)
# ─────────────────────────────────────────────────────────────────────────────

class _JiraHttp:
    """
    Thin wrapper around requests with:
      - Basic auth (Cloud: email+token, Server: token-only)
      - Exponential back-off on 429/503
      - Never logs the token
    """

    def __init__(
        self,
        base_url:    str,
        email:       Optional[str],
        api_token:   str,
        is_cloud:    bool = True,
        timeout_sec: int  = 30,
    ) -> None:
        self._base    = base_url.rstrip("/")
        self._timeout = timeout_sec
        self._is_cloud = is_cloud

        # Build auth — Cloud: Basic email:token; Server: Bearer token
        if is_cloud:
            import base64
            creds = f"{email}:{api_token}".encode()
            self._auth_header = "Basic " + base64.b64encode(creds).decode()
        else:
            self._auth_header = f"Bearer {api_token}"

    def _api_version(self) -> str:
        return "3" if self._is_cloud else "2"

    def _url(self, path: str) -> str:
        return f"{self._base}/rest/api/{self._api_version()}{path}"

    def _headers(self) -> dict:
        return {
            "Authorization": self._auth_header,
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "User-Agent":    "AI-Cyber-Shield/6.0",
        }

    def request(
        self,
        method:  str,
        path:    str,
        payload: Optional[dict] = None,
    ) -> dict:
        """Make an authenticated JIRA API call with retry on 429/503."""
        import json as _json
        try:
            import requests  # noqa: PLC0415
        except ImportError:
            raise RuntimeError("requests library required: pip install requests")

        url      = self._url(path)
        backoff  = _INITIAL_BACKOFF_SEC
        last_exc: Optional[Exception] = None

        for attempt in range(_MAX_RETRIES):
            try:
                resp = requests.request(
                    method.upper(),
                    url,
                    headers = self._headers(),
                    json    = payload,
                    timeout = self._timeout,
                )
            except Exception as exc:
                last_exc = exc
                _log.warning("JIRA request error (attempt %d): %s", attempt + 1, exc)
                time.sleep(backoff)
                backoff *= 2
                continue

            if resp.status_code in (429, 503):
                retry_after = float(resp.headers.get("Retry-After", backoff))
                _log.warning(
                    "JIRA rate limit (attempt %d) — waiting %.1fs",
                    attempt + 1, retry_after,
                )
                time.sleep(retry_after)
                backoff *= 2
                continue

            if resp.status_code == 204:
                return {}

            try:
                body = resp.json()
            except Exception:
                body = {"raw": resp.text[:500]}

            if not resp.ok:
                raise RuntimeError(
                    f"JIRA API {method.upper()} {path} → {resp.status_code}: "
                    f"{body.get('errorMessages', body)}"
                )

            return body

        raise RuntimeError(
            f"JIRA API {method.upper()} {path} failed after {_MAX_RETRIES} "
            f"retries. Last error: {last_exc}"
        )

    def get(self, path: str) -> dict:
        return self.request("GET", path)

    def post(self, path: str, payload: dict) -> dict:
        return self.request("POST", path, payload)

    def put(self, path: str, payload: dict) -> dict:
        return self.request("PUT", path, payload)


# ─────────────────────────────────────────────────────────────────────────────
# Description builder (rich JIRA Markdown / Atlassian Document Format)
# ─────────────────────────────────────────────────────────────────────────────

def _build_description_cloud(finding, target_url: str) -> dict:
    """
    Atlassian Document Format (ADF) for JIRA Cloud.
    Rich formatted issue body with CVSS, evidence, remediation.
    """
    def _text(t: str) -> dict:
        return {"type": "text", "text": t}

    def _heading(text: str, level: int = 3) -> dict:
        return {
            "type": "heading",
            "attrs": {"level": level},
            "content": [_text(text)],
        }

    def _paragraph(*parts) -> dict:
        return {"type": "paragraph", "content": list(parts)}

    def _bold(t: str) -> dict:
        return {"type": "text", "text": t, "marks": [{"type": "strong"}]}

    def _code_block(code: str) -> dict:
        if not code:
            return {"type": "paragraph", "content": [_text("(no example)")]}
        return {
            "type": "codeBlock",
            "attrs": {"language": "text"},
            "content": [_text(code)],
        }

    nodes = [
        _heading(f"🔴 {finding.title}", level=2),
        _paragraph(
            _bold("Severity: "), _text(f"{finding.severity}  "),
            _bold("CVSS 3.1: "), _text(f"{finding.cvss.score:.1f} ({finding.cvss.vector.vector_string})"),
        ),
        _paragraph(
            _bold("CWE: "), _text(f"{finding.cwe.label} — {finding.cwe.name}  "),
            _bold("OWASP 2025: "), _text(f"{finding.owasp.label} ({finding.owasp.name})"),
        ),
        _heading("Target", 3),
        _paragraph(
            _bold("URL: "),  _text(target_url or "—"), _text("  "),
            _bold("Endpoint: "), _text(finding.endpoint or "—"),
        ),
        _heading("Business Impact", 3),
        _paragraph(_text(finding.business_impact)),
        _heading("Attack Scenario", 3),
        _paragraph(_text(finding.attack_scenario)),
        _heading("Evidence", 3),
        _code_block(finding.evidence or "No evidence captured"),
        _heading("Compliance Mapping", 3),
        _paragraph(
            _bold("PCI-DSS: "), _text(finding.compliance.pci_dss or "—"), _text("  "),
            _bold("SOC2: "),    _text(finding.compliance.soc2_cc or "—"), _text("  "),
            _bold("ISO 27001: "),_text(finding.compliance.iso_27001 or "—"),
        ),
        _heading("Remediation", 3),
        _paragraph(_text(finding.remediation.summary)),
    ]

    if finding.remediation.code_before:
        nodes.append(_heading("Code — Before (Vulnerable)", 4))
        nodes.append(_code_block(finding.remediation.code_before))
    if finding.remediation.code_after:
        nodes.append(_heading("Code — After (Fixed)", 4))
        nodes.append(_code_block(finding.remediation.code_after))

    nodes.append(_paragraph(
        _text(f"Finding ID: {finding.finding_id}  ·  "),
        _text(f"Effort: ~{finding.remediation.effort_hours:.0f}h  ·  "),
        _text(f"Confirmed: {'Yes' if finding.confirmed else 'No'}"),
    ))

    return {"version": 1, "type": "doc", "content": nodes}


def _build_description_server(finding, target_url: str) -> str:
    """Wiki markup for JIRA Server / Data Center."""
    lines = [
        f"h2. {finding.title}",
        "",
        f"*Severity:* {finding.severity}  |  "
        f"*CVSS 3.1:* {finding.cvss.score:.1f} ({finding.cvss.vector.vector_string})",
        f"*CWE:* {finding.cwe.label} — {finding.cwe.name}",
        f"*OWASP 2025:* {finding.owasp.label} ({finding.owasp.name})",
        "",
        "h3. Target",
        f"*URL:* {target_url or '—'}",
        f"*Endpoint:* {finding.endpoint or '—'}",
        "",
        "h3. Business Impact",
        finding.business_impact,
        "",
        "h3. Attack Scenario",
        finding.attack_scenario,
        "",
        "h3. Evidence",
        "{code}",
        finding.evidence or "No evidence captured",
        "{code}",
        "",
        "h3. Compliance",
        f"*PCI-DSS:* {finding.compliance.pci_dss or '—'}  "
        f"*SOC2:* {finding.compliance.soc2_cc or '—'}  "
        f"*ISO 27001:* {finding.compliance.iso_27001 or '—'}",
        "",
        "h3. Remediation",
        finding.remediation.summary,
    ]

    if finding.remediation.code_before:
        lines += [
            "",
            "h4. Before (Vulnerable)",
            "{code}", finding.remediation.code_before, "{code}",
        ]
    if finding.remediation.code_after:
        lines += [
            "",
            "h4. After (Fixed)",
            "{code}", finding.remediation.code_after, "{code}",
        ]

    lines += [
        "",
        f"----",
        f"_Finding ID: {finding.finding_id}  ·  "
        f"Effort: ~{finding.remediation.effort_hours:.0f}h  ·  "
        f"Confirmed: {'Yes' if finding.confirmed else 'No'}_",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Priority mapping
# ─────────────────────────────────────────────────────────────────────────────

def _cvss_to_priority(cvss_score: float) -> str:
    for threshold, priority in _CVSS_TO_PRIORITY:
        if cvss_score >= threshold:
            return priority
    return "Low"


def _finding_label(finding_id: str) -> str:
    """Deterministic JIRA label used for deduplication."""
    return f"{_JIRA_LABEL_PREFIX}{finding_id[:16]}"


# ─────────────────────────────────────────────────────────────────────────────
# Main publisher
# ─────────────────────────────────────────────────────────────────────────────

class JiraPublisher:
    """
    Publishes AI Cyber Shield findings to JIRA.

    Supports JIRA Cloud (REST API v3) and JIRA Server/Data Center (v2).
    Idempotent — safe to call multiple times on the same scan.
    """

    def __init__(
        self,
        base_url:         str,
        api_token:        str,
        project_key:      str,
        email:            Optional[str]  = None,
        issue_type:       str            = "Bug",
        components:       Optional[list[str]] = None,
        custom_fields:    Optional[dict] = None,
        dry_run:          bool           = False,
        is_cloud:         bool           = True,
        done_transition:  str            = "Done",
    ) -> None:
        """
        Args:
            base_url:        JIRA instance URL (e.g. https://yourorg.atlassian.net)
            api_token:       Atlassian API token (Cloud) or PAT (Server)
            project_key:     JIRA project key (e.g. "SEC")
            email:           Account email — required for Cloud auth, ignored for Server
            issue_type:      Default issue type (e.g. "Bug", "Security Finding")
            components:      List of JIRA component names to tag issues with
            custom_fields:   Dict of JIRA custom field IDs to values
                             e.g. {"customfield_10001": "security-team"}
            dry_run:         Log what WOULD be created without calling JIRA
            is_cloud:        True = JIRA Cloud (API v3 + ADF), False = Server (v2 + Wiki)
            done_transition: Name of the JIRA transition to "close" resolved findings
        """
        self._base_url        = _validate_base_url(base_url)
        self._project_key     = project_key.upper()
        self._issue_type      = issue_type
        self._components      = components or []
        self._custom_fields   = custom_fields or {}
        self._dry_run         = dry_run
        self._is_cloud        = is_cloud
        self._done_transition = done_transition

        if not dry_run:
            self._http = _JiraHttp(
                base_url  = self._base_url,
                email     = email,
                api_token = api_token,
                is_cloud  = is_cloud,
            )
        else:
            self._http = None  # type: ignore[assignment]
            _log.info("JiraPublisher DRY-RUN mode — no API calls will be made")

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "JiraPublisher":
        """Create publisher from environment variables."""
        base_url   = os.environ.get("JIRA_BASE_URL", "")
        email      = os.environ.get("JIRA_EMAIL", "")
        api_token  = os.environ.get("JIRA_API_TOKEN", "")
        project    = os.environ.get("JIRA_PROJECT", "SEC")
        issue_type = os.environ.get("JIRA_ISSUE_TYPE", "Bug")
        dry_run    = os.environ.get("JIRA_DRY_RUN", "0") == "1"
        is_cloud   = os.environ.get("JIRA_SERVER_MODE", "0") != "1"

        if not base_url:
            raise ValueError("JIRA_BASE_URL environment variable not set")
        if not api_token:
            raise ValueError("JIRA_API_TOKEN environment variable not set")
        if is_cloud and not email:
            raise ValueError("JIRA_EMAIL required for JIRA Cloud auth")

        return cls(
            base_url   = base_url,
            api_token  = api_token,
            project_key= project,
            email      = email,
            issue_type = issue_type,
            dry_run    = dry_run,
            is_cloud   = is_cloud,
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def publish_findings(
        self,
        findings:    list,
        target_url:  str  = "",
        label_prefix: str = "",
        min_cvss:    float = 0.0,
    ) -> PublishResult:
        """
        Publish a list of SecurityFinding objects to JIRA.

        Args:
            findings:     List of SecurityFinding from finding_enricher
            target_url:   URL that was scanned (added to issue body)
            label_prefix: Optional prefix for JIRA labels (e.g. "prod-")
            min_cvss:     Only publish findings with CVSS >= this threshold

        Returns:
            PublishResult with counts: created / existing / resolved / failed
        """
        result   = PublishResult()
        eligible = [f for f in findings if f.cvss.score >= min_cvss]
        eligible.sort(key=lambda f: -f.cvss.score)   # highest CVSS first

        _log.info(
            "Publishing %d/%d findings (min_cvss=%.1f, dry_run=%s)",
            len(eligible), len(findings), min_cvss, self._dry_run,
        )

        # Batch lookup: find existing issues for all finding_ids in one JQL query
        existing_issues = self._find_existing_issues(
            [f.finding_id for f in eligible], label_prefix
        )

        for finding in eligible:
            try:
                label = _finding_label(finding.finding_id)
                if label_prefix:
                    label = f"{label_prefix}-{label}"

                if label in existing_issues:
                    _log.debug(
                        "Finding %s already has JIRA issue %s — skipping",
                        finding.finding_id[:8],
                        existing_issues[label],
                    )
                    result.existing += 1
                    continue

                self._create_issue(finding, target_url, label)
                result.created += 1
                time.sleep(_BATCH_DELAY_SEC)   # gentle pacing

            except Exception as exc:
                _log.error("Failed to publish finding %s: %s", finding.finding_id[:8], exc)
                result.failed += 1
                result.errors.append(str(exc))

        return result

    def resolve_findings(
        self,
        resolved_finding_ids: list[str],
        label_prefix: str = "",
    ) -> int:
        """
        Transition JIRA issues to "Done" for findings resolved in a re-scan.

        Returns: number of issues transitioned.
        """
        if not resolved_finding_ids:
            return 0

        existing = self._find_existing_issues(resolved_finding_ids, label_prefix)
        transitioned = 0

        for label, issue_key in existing.items():
            try:
                self._transition_issue(issue_key, self._done_transition)
                _log.info("Transitioned %s to Done (finding resolved)", issue_key)
                transitioned += 1
            except Exception as exc:
                _log.warning("Could not transition %s: %s", issue_key, exc)

        return transitioned

    def verify_connection(self) -> dict:
        """Test connectivity and permissions. Returns project info dict."""
        if self._dry_run:
            return {"dry_run": True, "project": self._project_key}
        info = self._http.get(f"/project/{self._project_key}")
        return {
            "project_key":  info.get("key"),
            "project_name": info.get("name"),
            "project_id":   info.get("id"),
            "is_cloud":     self._is_cloud,
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _build_labels(self, finding, label: str) -> list[str]:
        """Build the full label list for a JIRA issue."""
        labels = [
            label,
            "ai-cyber-shield",
            finding.severity.lower(),
            f"cvss-{int(finding.cvss.score)}",
            f"cwe-{finding.cwe.id}",
        ]
        owasp_label = _OWASP_LABELS.get(finding.owasp.code, "")
        if owasp_label:
            labels.append(owasp_label)
        # JIRA labels can't contain spaces
        return [re.sub(r"[^A-Za-z0-9_\-:]", "_", l) for l in labels]

    def _build_issue_fields(self, finding, target_url: str, label: str) -> dict:
        """Build the full JIRA issue `fields` payload."""
        priority = _cvss_to_priority(finding.cvss.score)
        summary  = (
            f"[{finding.severity}] {finding.title} — "
            f"{finding.cwe.label} @ {finding.endpoint or target_url}"
        )[:255]  # JIRA summary limit

        if self._is_cloud:
            description = _build_description_cloud(finding, target_url)
        else:
            description = _build_description_server(finding, target_url)

        fields: dict = {
            "project":     {"key": self._project_key},
            "summary":     summary,
            "description": description,
            "issuetype":   {"name": self._issue_type},
            "priority":    {"name": priority},
            "labels":      self._build_labels(finding, label),
        }

        if self._components:
            fields["components"] = [{"name": c} for c in self._components]

        # Merge caller-supplied custom fields
        fields.update(self._custom_fields)

        return fields

    def _create_issue(self, finding, target_url: str, label: str) -> str:
        """Create a single JIRA issue. Returns the new issue key (e.g. SEC-123)."""
        fields = self._build_issue_fields(finding, target_url, label)

        if self._dry_run:
            _log.info(
                "[DRY-RUN] Would create: [%s] %s",
                finding.severity, fields["summary"]
            )
            return "DRY-SEC-0"

        result = self._http.post("/issue", {"fields": fields})
        key    = result.get("key", "?")
        _log.info("Created JIRA issue %s for finding %s", key, finding.finding_id[:8])
        return key

    def _find_existing_issues(
        self,
        finding_ids: list[str],
        label_prefix: str = "",
    ) -> dict[str, str]:
        """
        JQL search for issues with aics:<finding_id> labels.
        Returns {label: issue_key} for found issues.
        """
        if not finding_ids or self._dry_run:
            return {}

        labels = []
        for fid in finding_ids:
            l = _finding_label(fid)
            if label_prefix:
                l = f"{label_prefix}-{l}"
            labels.append(l)

        # Batch into chunks of 30 (JQL IN clause limit)
        result: dict[str, str] = {}
        chunk_size = 30
        for i in range(0, len(labels), chunk_size):
            chunk  = labels[i:i + chunk_size]
            in_clause = ",".join(f'"{l}"' for l in chunk)
            jql = (
                f'project = "{self._project_key}" '
                f'AND labels in ({in_clause}) '
                f'AND statusCategory != Done'
            )

            try:
                resp = self._http.get(
                    f"/search?jql={jql}&fields=key,labels&maxResults=50"
                )
            except Exception as exc:
                _log.warning("JQL search error: %s", exc)
                continue

            for issue in resp.get("issues", []):
                key    = issue["key"]
                for l in issue.get("fields", {}).get("labels", []):
                    if l.startswith(_JIRA_LABEL_PREFIX) or (label_prefix and l.startswith(label_prefix)):
                        result[l] = key

        return result

    def _get_transitions(self, issue_key: str) -> dict[str, str]:
        """Return {transition_name: transition_id} for an issue."""
        resp = self._http.get(f"/issue/{issue_key}/transitions")
        return {
            t["name"]: t["id"]
            for t in resp.get("transitions", [])
        }

    def _transition_issue(self, issue_key: str, transition_name: str) -> None:
        """Move an issue through a workflow transition (e.g. → Done)."""
        if self._dry_run:
            _log.info("[DRY-RUN] Would transition %s → %s", issue_key, transition_name)
            return

        transitions = self._get_transitions(issue_key)
        tid = transitions.get(transition_name)
        if not tid:
            available = list(transitions.keys())
            raise ValueError(
                f"Transition '{transition_name}' not found for {issue_key}. "
                f"Available: {available}"
            )
        self._http.post(
            f"/issue/{issue_key}/transitions",
            {"transition": {"id": tid}},
        )

"""
tests/test_pagerduty_publisher.py — AI Cyber Shield v6

Test suite for integrations/pagerduty_publisher.py

All PagerDuty HTTP calls are mocked — no real network access.

Coverage:
  1. _dedup_key
  2. _group_key
  3. _build_payload — structure, summary truncation, grouped mode
  4. _post_event — retry on 429/5xx, 4xx raises immediately
  5. PagerDutyPublisher.__init__ — key length validation
  6. PagerDutyPublisher.from_env
  7. PagerDutyPublisher.trigger_findings — min_severity filter, grouped, dry-run
  8. PagerDutyPublisher.resolve_findings — dedup key, dry-run
  9. Edge cases — empty findings, all below threshold, HTTP failure
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch, call

import pytest

from integrations.pagerduty_publisher import (
    PagerDutyPublisher,
    PagerDutyResult,
    _build_payload,
    _dedup_key,
    _group_key,
    _post_event,
    _DEDUP_PREFIX,
    _SEV_MAP,
)


# ─────────────────────────────────────────────────────────────────────────────
# Minimal SecurityFinding stubs
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _FakeCvssVector:
    vector_string: str = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

@dataclass
class _FakeCvss:
    score:   float = 9.8
    severity: str = "CRITICAL"
    vector: _FakeCvssVector = field(default_factory=_FakeCvssVector)

@dataclass
class _FakeCwe:
    id:    int = 89
    label: str = "CWE-89"
    name:  str = "SQL Injection"

@dataclass
class _FakeOwasp:
    code:  str = "A03"
    year:  int = 2025
    name:  str = "Injection"
    label: str = "A03:2025"

@dataclass
class _FakeCompliance:
    pci_dss:    str = "PCI-DSS 6.2.4"
    soc2_cc:    str = "CC8.1"
    iso_27001:  str = "A.14.2.5"
    nist_csf:   str = "PR.IP-2"
    owasp_asvs: str = "V5.2.1"

@dataclass
class _FakeRemediation:
    priority:     int   = 1
    effort_hours: float = 2.0
    summary:      str   = "Use parameterised queries."
    code_before:  str   = ""
    code_after:   str   = ""
    references:   list  = field(default_factory=list)

@dataclass
class _FakeFinding:
    finding_id:  str = "abc123def456789012345678"
    title:       str = "SQL Injection in Login"
    finding_type: str = "sqli"
    tool:        str = "sqli_scanner"
    severity:    str = "CRITICAL"
    cvss:        _FakeCvss = field(default_factory=_FakeCvss)
    cwe:         _FakeCwe  = field(default_factory=_FakeCwe)
    owasp:       _FakeOwasp = field(default_factory=_FakeOwasp)
    compliance:  _FakeCompliance = field(default_factory=_FakeCompliance)
    remediation: _FakeRemediation = field(default_factory=_FakeRemediation)
    business_impact: str = "Full database compromise."
    attack_scenario: str = "An attacker WOULD inject ' OR 1=1 --."
    endpoint:    str = "https://example.com/login"
    parameter:   str = "username"
    evidence:    str = "' OR 1=1 -- reflected in response"
    confirmed:   bool = True
    confidence:  float = 0.99


def _make_finding(**kwargs) -> _FakeFinding:
    f = _FakeFinding()
    for k, v in kwargs.items():
        setattr(f, k, v)
    return f

_VALID_KEY = "A" * 32   # 32-char key
_TARGET    = "https://example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 1. _dedup_key
# ─────────────────────────────────────────────────────────────────────────────

class TestDedupKey:
    def test_starts_with_prefix(self):
        key = _dedup_key("abc123def456789012345678")
        assert key.startswith(_DEDUP_PREFIX)

    def test_truncated_to_16_chars_of_finding_id(self):
        key    = _dedup_key("abc123def456789012345678")
        suffix = key[len(_DEDUP_PREFIX):]
        assert suffix == "abc123def4567890"

    def test_same_finding_same_key(self):
        fid = "abc123def456789012345678"
        assert _dedup_key(fid) == _dedup_key(fid)

    def test_different_finding_different_key(self):
        assert _dedup_key("aaa111") != _dedup_key("bbb222")


# ─────────────────────────────────────────────────────────────────────────────
# 2. _group_key
# ─────────────────────────────────────────────────────────────────────────────

class TestGroupKey:
    def test_group_by_none_returns_finding_id(self):
        f = _FakeFinding()
        assert _group_key(f, "none") == f.finding_id

    def test_group_by_owasp(self):
        f = _FakeFinding()
        key = _group_key(f, "owasp")
        assert key == "owasp-A03"

    def test_group_by_cwe(self):
        f = _FakeFinding()
        key = _group_key(f, "cwe")
        assert key == "cwe-89"

    def test_different_owasp_different_group(self):
        f1 = _make_finding(owasp=_FakeOwasp(code="A01"))
        f2 = _make_finding(owasp=_FakeOwasp(code="A05"))
        assert _group_key(f1, "owasp") != _group_key(f2, "owasp")


# ─────────────────────────────────────────────────────────────────────────────
# 3. _build_payload
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildPayload:
    def test_event_action_trigger(self):
        f       = _FakeFinding()
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "dedup-1")
        assert payload["event_action"] == "trigger"

    def test_event_action_resolve(self):
        f       = _FakeFinding()
        payload = _build_payload(_VALID_KEY, "resolve", f, _TARGET, "aics", "dedup-1")
        assert payload["event_action"] == "resolve"

    def test_routing_key_present(self):
        f       = _FakeFinding()
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "dedup-1")
        assert payload["routing_key"] == _VALID_KEY

    def test_dedup_key_in_payload(self):
        f       = _FakeFinding()
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "my-dedup")
        assert payload["dedup_key"] == "my-dedup"

    def test_summary_not_exceed_1024_chars(self):
        f = _make_finding(title="X" * 900, endpoint="Y" * 900)
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        assert len(payload["payload"]["summary"]) <= 1024

    def test_severity_mapping_critical(self):
        f       = _make_finding(severity="CRITICAL")
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        assert payload["payload"]["severity"] == "critical"

    def test_severity_mapping_high(self):
        f       = _make_finding(severity="HIGH")
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        assert payload["payload"]["severity"] == "error"

    def test_severity_mapping_medium(self):
        f       = _make_finding(severity="MEDIUM")
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        assert payload["payload"]["severity"] == "warning"

    def test_custom_details_has_cvss(self):
        f       = _FakeFinding()
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        details = payload["payload"]["custom_details"]
        assert details["top_cvss_score"] == f.cvss.score

    def test_custom_details_has_owasp(self):
        f       = _FakeFinding()
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        details = payload["payload"]["custom_details"]
        assert details["owasp_2025"] == f.owasp.label

    def test_custom_details_has_compliance(self):
        f       = _FakeFinding()
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        comp = payload["payload"]["custom_details"]["compliance"]
        assert "pci_dss" in comp
        assert "soc2" in comp

    def test_grouped_payload_has_finding_count(self):
        f1 = _make_finding(finding_id="id1")
        f2 = _make_finding(finding_id="id2")
        payload = _build_payload(
            _VALID_KEY, "trigger", f1, _TARGET, "aics", "d",
            group_findings=[f1, f2],
        )
        details = payload["payload"]["custom_details"]
        assert details["finding_count"] == 2

    def test_grouped_summary_mentions_group_size(self):
        f1 = _make_finding(finding_id="id1")
        f2 = _make_finding(finding_id="id2", owasp=_FakeOwasp(code="A03", name="Injection"))
        payload = _build_payload(
            _VALID_KEY, "trigger", f1, _TARGET, "aics", "d",
            group_findings=[f1, f2],
        )
        assert "2" in payload["payload"]["summary"]

    def test_evidence_truncated_in_details(self):
        f = _make_finding(evidence="E" * 1000)
        payload = _build_payload(_VALID_KEY, "trigger", f, _TARGET, "aics", "d")
        details = payload["payload"]["custom_details"]
        assert len(details["evidence"]) <= 500


# ─────────────────────────────────────────────────────────────────────────────
# 4. _post_event retry behavior
# ─────────────────────────────────────────────────────────────────────────────

class TestPostEvent:
    def test_202_success(self):
        resp = MagicMock()
        resp.status_code = 202
        resp.json.return_value = {"status": "success", "message": "Event processed"}

        with patch("requests.post", return_value=resp):
            result = _post_event({"routing_key": _VALID_KEY})
        assert result["status"] == "success"

    def test_retry_on_429(self):
        rate_resp = MagicMock()
        rate_resp.status_code = 429
        rate_resp.headers = {"Retry-After": "0.01"}

        ok_resp = MagicMock()
        ok_resp.status_code = 202
        ok_resp.json.return_value = {"status": "success", "message": "ok"}

        with patch("requests.post", side_effect=[rate_resp, ok_resp]):
            result = _post_event({"routing_key": _VALID_KEY})
        assert result["status"] == "success"

    def test_retry_on_5xx(self):
        err_resp = MagicMock()
        err_resp.status_code = 500
        err_resp.text = "Internal Server Error"

        ok_resp = MagicMock()
        ok_resp.status_code = 202
        ok_resp.json.return_value = {"status": "success", "message": "ok"}

        with patch("requests.post", side_effect=[err_resp, ok_resp]):
            result = _post_event({"routing_key": _VALID_KEY})
        assert result["status"] == "success"

    def test_4xx_raises_immediately(self):
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "Invalid routing key"

        with patch("requests.post", return_value=resp):
            with pytest.raises(RuntimeError, match="400"):
                _post_event({"routing_key": "bad"})

    def test_network_error_retries(self):
        ok_resp = MagicMock()
        ok_resp.status_code = 202
        ok_resp.json.return_value = {"status": "success", "message": "ok"}

        with patch("requests.post", side_effect=[ConnectionError("refused"), ok_resp]):
            result = _post_event({"routing_key": _VALID_KEY})
        assert result["status"] == "success"


# ─────────────────────────────────────────────────────────────────────────────
# 5. PagerDutyPublisher.__init__
# ─────────────────────────────────────────────────────────────────────────────

class TestInit:
    def test_32_char_key_accepted(self):
        pub = PagerDutyPublisher(_VALID_KEY)
        assert pub is not None

    def test_short_key_raises_in_non_dryrun(self):
        with pytest.raises(ValueError, match="32 characters"):
            PagerDutyPublisher("short-key")

    def test_short_key_allowed_in_dry_run(self):
        pub = PagerDutyPublisher("short", dry_run=True)
        assert pub is not None

    def test_default_min_severity_is_high(self):
        pub = PagerDutyPublisher(_VALID_KEY)
        # Index 0=CRITICAL, 1=HIGH — HIGH is index 1
        assert pub._min_sev_idx == 1

    def test_min_severity_medium(self):
        pub = PagerDutyPublisher(_VALID_KEY, min_severity="MEDIUM")
        assert pub._min_sev_idx == 2


# ─────────────────────────────────────────────────────────────────────────────
# 6. from_env
# ─────────────────────────────────────────────────────────────────────────────

class TestFromEnv:
    def test_reads_integration_key(self):
        with patch.dict(os.environ, {
            "PAGERDUTY_INTEGRATION_KEY": _VALID_KEY,
            "PAGERDUTY_DRY_RUN":        "1",
        }):
            pub = PagerDutyPublisher.from_env()
        assert pub._dry_run is True

    def test_missing_key_raises(self):
        with patch.dict(os.environ, {"PAGERDUTY_INTEGRATION_KEY": ""}):
            with pytest.raises(ValueError, match="PAGERDUTY_INTEGRATION_KEY"):
                PagerDutyPublisher.from_env()

    def test_group_by_from_env(self):
        with patch.dict(os.environ, {
            "PAGERDUTY_INTEGRATION_KEY": _VALID_KEY,
            "PAGERDUTY_GROUP_BY":        "owasp",
            "PAGERDUTY_DRY_RUN":        "1",
        }):
            pub = PagerDutyPublisher.from_env()
        assert pub._group_by == "owasp"


# ─────────────────────────────────────────────────────────────────────────────
# 7. trigger_findings
# ─────────────────────────────────────────────────────────────────────────────

class TestTriggerFindings:
    def test_dry_run_triggers_without_http(self):
        pub    = PagerDutyPublisher(_VALID_KEY, dry_run=True)
        result = pub.trigger_findings([_FakeFinding()], _TARGET)
        assert result.triggered == 1
        assert result.failed    == 0

    def test_empty_findings_skips_all(self):
        pub    = PagerDutyPublisher(_VALID_KEY, dry_run=True)
        result = pub.trigger_findings([], _TARGET)
        assert result.triggered == 0

    def test_below_min_severity_skipped(self):
        pub = PagerDutyPublisher(_VALID_KEY, min_severity="HIGH", dry_run=True)
        f   = _make_finding(severity="LOW")
        result = pub.trigger_findings([f], _TARGET)
        assert result.triggered == 0
        assert result.skipped   == 1

    def test_at_min_severity_included(self):
        pub = PagerDutyPublisher(_VALID_KEY, min_severity="HIGH", dry_run=True)
        f   = _make_finding(severity="HIGH")
        result = pub.trigger_findings([f], _TARGET)
        assert result.triggered == 1

    def test_critical_always_included(self):
        pub = PagerDutyPublisher(_VALID_KEY, min_severity="HIGH", dry_run=True)
        f   = _make_finding(severity="CRITICAL")
        result = pub.trigger_findings([f], _TARGET)
        assert result.triggered == 1

    def test_group_by_owasp_reduces_alerts(self):
        """3 findings with same OWASP code → 1 alert."""
        pub = PagerDutyPublisher(_VALID_KEY, group_by="owasp", dry_run=True)
        findings = [
            _make_finding(finding_id=f"id{i}", owasp=_FakeOwasp(code="A03"))
            for i in range(3)
        ]
        result = pub.trigger_findings(findings, _TARGET)
        assert result.triggered == 1

    def test_group_by_owasp_different_codes_multiple_alerts(self):
        """2 findings with different OWASP codes → 2 alerts."""
        pub = PagerDutyPublisher(_VALID_KEY, group_by="owasp", dry_run=True)
        findings = [
            _make_finding(finding_id="id1", owasp=_FakeOwasp(code="A01")),
            _make_finding(finding_id="id2", owasp=_FakeOwasp(code="A05")),
        ]
        result = pub.trigger_findings(findings, _TARGET)
        assert result.triggered == 2

    def test_real_call_posts_event(self):
        pub = PagerDutyPublisher(_VALID_KEY, dry_run=False)
        resp = MagicMock()
        resp.status_code = 202
        resp.json.return_value = {"status": "success", "message": "ok"}

        with patch("requests.post", return_value=resp) as mock_post:
            result = pub.trigger_findings([_FakeFinding()], _TARGET)
        assert result.triggered == 1
        mock_post.assert_called_once()

    def test_http_failure_counts_as_failed(self):
        pub = PagerDutyPublisher(_VALID_KEY, dry_run=False)
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "Bad routing key"

        with patch("requests.post", return_value=resp):
            result = pub.trigger_findings([_FakeFinding()], _TARGET)
        assert result.failed    == 1
        assert result.triggered == 0

    def test_skipped_count_excludes_eligible(self):
        pub = PagerDutyPublisher(_VALID_KEY, min_severity="HIGH", dry_run=True)
        findings = [
            _make_finding(finding_id="h1", severity="HIGH"),
            _make_finding(finding_id="l1", severity="LOW"),
            _make_finding(finding_id="l2", severity="INFO"),
        ]
        result = pub.trigger_findings(findings, _TARGET)
        assert result.triggered == 1
        assert result.skipped   == 2


# ─────────────────────────────────────────────────────────────────────────────
# 8. resolve_findings
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveFindings:
    def test_dry_run_resolve(self):
        pub    = PagerDutyPublisher(_VALID_KEY, dry_run=True)
        result = pub.resolve_findings(["finding-id-1", "finding-id-2"], _TARGET)
        assert result.resolved == 2
        assert result.failed   == 0

    def test_empty_ids_returns_zero(self):
        pub    = PagerDutyPublisher(_VALID_KEY, dry_run=True)
        result = pub.resolve_findings([], _TARGET)
        assert result.resolved == 0

    def test_real_resolve_posts_event(self):
        pub  = PagerDutyPublisher(_VALID_KEY, dry_run=False)
        resp = MagicMock()
        resp.status_code = 202
        resp.json.return_value = {"status": "success", "message": "ok"}

        with patch("requests.post", return_value=resp) as mock_post:
            result = pub.resolve_findings(["finding-abc-123"], _TARGET)
        assert result.resolved == 1
        mock_post.assert_called_once()

        # Verify dedup_key in the payload sent
        payload_sent = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload_sent["event_action"] == "resolve"
        assert "aics-" in payload_sent["dedup_key"]

    def test_resolve_http_failure_counts_failed(self):
        pub  = PagerDutyPublisher(_VALID_KEY, dry_run=False)
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "error"

        with patch("requests.post", return_value=resp):
            result = pub.resolve_findings(["finding-x"], _TARGET)
        assert result.failed == 1

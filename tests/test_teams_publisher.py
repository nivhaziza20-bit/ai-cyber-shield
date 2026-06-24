"""
tests/test_teams_publisher.py — AI Cyber Shield v6

Test suite for integrations/teams_publisher.py

All Teams HTTP calls are mocked — no real network access.

Coverage:
  1. _validate_webhook_url
  2. _top_severity
  3. _build_summary_card — structure, color, facts, expandable section, mention
  4. _build_clean_card
  5. _post_card — retry on 429/5xx, 4xx raises
  6. TeamsPublisher.from_env
  7. TeamsPublisher.send_scan_results — findings, empty, dry-run, min_severity
  8. TeamsPublisher.send_differential_alert
  9. Edge cases — always_notify, mention on CRITICAL, HTTP failure
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

import pytest

from integrations.teams_publisher import (
    TeamsPublisher,
    TeamsResult,
    _build_clean_card,
    _build_summary_card,
    _post_card,
    _top_severity,
    _validate_webhook_url,
)


# ─────────────────────────────────────────────────────────────────────────────
# Stubs
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _FakeCvssVector:
    vector_string: str = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

@dataclass
class _FakeCvss:
    score:   float = 8.5
    severity: str  = "HIGH"
    vector: _FakeCvssVector = field(default_factory=_FakeCvssVector)

@dataclass
class _FakeCwe:
    id:    int = 79
    label: str = "CWE-79"
    name:  str = "XSS"

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
    priority:     int   = 2
    effort_hours: float = 3.0
    summary:      str   = "Escape all user input."
    code_before:  str   = ""
    code_after:   str   = ""
    references:   list  = field(default_factory=list)

@dataclass
class _FakeFinding:
    finding_id:  str = "abc123def456789012345678"
    title:       str = "Reflected XSS"
    finding_type: str = "xss_reflected"
    tool:        str = "xss_scanner"
    severity:    str = "HIGH"
    cvss:        _FakeCvss = field(default_factory=_FakeCvss)
    cwe:         _FakeCwe  = field(default_factory=_FakeCwe)
    owasp:       _FakeOwasp = field(default_factory=_FakeOwasp)
    compliance:  _FakeCompliance = field(default_factory=_FakeCompliance)
    remediation: _FakeRemediation = field(default_factory=_FakeRemediation)
    business_impact: str  = "Session theft."
    attack_scenario: str  = "An attacker WOULD inject a script."
    endpoint:    str  = "https://example.com/search"
    parameter:   str  = "q"
    evidence:    str  = "<script>alert(1)</script>"
    confirmed:   bool = True
    confidence:  float = 0.9


def _make_finding(**kwargs) -> _FakeFinding:
    f = _FakeFinding()
    for k, v in kwargs.items():
        setattr(f, k, v)
    return f


_WEBHOOK = "https://contoso.webhook.office.com/webhookb2/test"
_TARGET  = "https://example.com"


# ─────────────────────────────────────────────────────────────────────────────
# 1. _validate_webhook_url
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateWebhookUrl:
    @pytest.mark.parametrize("url", [
        "https://contoso.webhook.office.com/webhookb2/abc123",
        "https://outlook.webhook.office.com/webhookb2/xyz",
        "https://eu.webhook.office.com/webhookb2/eu-hook",
    ])
    def test_valid_teams_urls_accepted(self, url):
        result = _validate_webhook_url(url)
        assert result == url

    @pytest.mark.parametrize("url", [
        "https://example.com/webhook",
        "http://contoso.webhook.office.com/webhookb2/test",
        "https://attacker.com/office.com/fake",
        "not-a-url",
    ])
    def test_non_teams_urls_rejected(self, url):
        with pytest.raises(ValueError, match="webhook.office.com"):
            _validate_webhook_url(url)


# ─────────────────────────────────────────────────────────────────────────────
# 2. _top_severity
# ─────────────────────────────────────────────────────────────────────────────

class TestTopSeverity:
    def test_critical_wins_over_high(self):
        findings = [
            _make_finding(severity="HIGH"),
            _make_finding(severity="CRITICAL"),
        ]
        assert _top_severity(findings) == "CRITICAL"

    def test_single_medium(self):
        assert _top_severity([_make_finding(severity="MEDIUM")]) == "MEDIUM"

    def test_empty_returns_info(self):
        assert _top_severity([]) == "INFO"

    def test_all_low_returns_low(self):
        findings = [_make_finding(severity="LOW")] * 3
        assert _top_severity(findings) == "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# 3. _build_summary_card
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildSummaryCard:
    def test_returns_dict(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        assert isinstance(card, dict)

    def test_type_is_message(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        assert card["type"] == "message"

    def test_has_attachments(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        assert "attachments" in card
        assert len(card["attachments"]) == 1

    def test_adaptive_card_content_type(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        ct = card["attachments"][0]["contentType"]
        assert "adaptive-card" in ct

    def test_adaptive_card_version(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        content = card["attachments"][0]["content"]
        assert content["version"] == "1.5"

    def test_card_has_body(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        content = card["attachments"][0]["content"]
        assert "body" in content
        assert len(content["body"]) > 0

    def test_card_has_actions(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        content = card["attachments"][0]["content"]
        assert "actions" in content

    def test_toggle_details_action_present(self):
        card    = _build_summary_card([_FakeFinding()], _TARGET)
        actions = card["attachments"][0]["content"]["actions"]
        toggle_actions = [a for a in actions if a["type"] == "Action.ToggleVisibility"]
        assert len(toggle_actions) == 1

    def test_open_url_action_present_when_target(self):
        card    = _build_summary_card([_FakeFinding()], "https://target.com")
        actions = card["attachments"][0]["content"]["actions"]
        url_actions = [a for a in actions if a["type"] == "Action.OpenUrl"]
        assert len(url_actions) == 1
        assert url_actions[0]["url"] == "https://target.com"

    def test_critical_color_style(self):
        f    = _make_finding(severity="CRITICAL")
        card = _build_summary_card([f], _TARGET)
        body = card["attachments"][0]["content"]["body"]
        # First block is the header container
        assert body[0]["style"] == "attention"

    def test_high_color_style(self):
        f    = _make_finding(severity="HIGH")
        card = _build_summary_card([f], _TARGET)
        body = card["attachments"][0]["content"]["body"]
        assert body[0]["style"] == "warning"

    def test_factset_has_severity_counts(self):
        findings = [
            _make_finding(finding_id="c1", severity="CRITICAL"),
            _make_finding(finding_id="h1", severity="HIGH"),
            _make_finding(finding_id="h2", severity="HIGH"),
        ]
        card = _build_summary_card(findings, _TARGET)
        body = card["attachments"][0]["content"]["body"]
        # Find the FactSet block
        factsets = [b for b in body if b["type"] == "FactSet"]
        assert len(factsets) >= 1
        facts = {f["title"]: f["value"] for f in factsets[0]["facts"]}
        assert facts.get("🔴 Critical") == "1"
        assert facts.get("🟠 High")     == "2"

    def test_mention_in_critical_card(self):
        f    = _make_finding(severity="CRITICAL")
        card = _build_summary_card(
            [f], _TARGET,
            mention_user_id="user-aad-id",
            mention_name="Alice Security",
        )
        content = card["attachments"][0]["content"]
        entities = content.get("msteams", {}).get("entities", [])
        assert any(e.get("type") == "mention" for e in entities)

    def test_no_mention_for_non_critical(self):
        f    = _make_finding(severity="HIGH")
        card = _build_summary_card(
            [f], _TARGET,
            mention_user_id="user-aad-id",
            mention_name="Alice Security",
        )
        entities = card["attachments"][0]["content"].get("msteams", {}).get("entities", [])
        assert len(entities) == 0

    def test_expandable_section_present(self):
        card = _build_summary_card([_FakeFinding()], _TARGET)
        body = card["attachments"][0]["content"]["body"]
        # The expandable section has isVisible=False
        hidden = [b for b in body if b.get("isVisible") is False]
        assert len(hidden) == 1

    def test_top3_findings_in_card(self):
        findings = [
            _make_finding(finding_id=f"id{i}", cvss=_FakeCvss(score=float(9 - i)))
            for i in range(5)
        ]
        card = _build_summary_card(findings, _TARGET)
        body_str = str(card)
        # At least some of the top 3 findings should be mentioned
        assert "id0" in body_str or "id1" in body_str


# ─────────────────────────────────────────────────────────────────────────────
# 4. _build_clean_card
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildCleanCard:
    def test_clean_card_is_dict(self):
        card = _build_clean_card(_TARGET)
        assert isinstance(card, dict)

    def test_clean_card_type_message(self):
        card = _build_clean_card(_TARGET)
        assert card["type"] == "message"

    def test_clean_card_has_good_style(self):
        card = _build_clean_card(_TARGET)
        body = card["attachments"][0]["content"]["body"]
        assert body[0]["style"] == "good"

    def test_clean_card_contains_all_clear_text(self):
        card = _build_clean_card(_TARGET)
        card_str = str(card)
        assert "All Clear" in card_str or "clear" in card_str.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 5. _post_card retry
# ─────────────────────────────────────────────────────────────────────────────

class TestPostCard:
    def test_200_success(self):
        resp = MagicMock()
        resp.status_code = 200

        with patch("requests.post", return_value=resp):
            _post_card(_WEBHOOK, {"type": "message"})  # Should not raise

    def test_retry_on_429(self):
        rate_resp = MagicMock()
        rate_resp.status_code = 429
        rate_resp.headers = {"Retry-After": "0.01"}

        ok_resp = MagicMock()
        ok_resp.status_code = 200

        with patch("requests.post", side_effect=[rate_resp, ok_resp]):
            _post_card(_WEBHOOK, {"type": "message"})  # Should not raise

    def test_4xx_raises(self):
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "Bad request"

        with patch("requests.post", return_value=resp):
            with pytest.raises(RuntimeError, match="400"):
                _post_card(_WEBHOOK, {"type": "message"})


# ─────────────────────────────────────────────────────────────────────────────
# 6. TeamsPublisher.from_env
# ─────────────────────────────────────────────────────────────────────────────

class TestFromEnv:
    def test_reads_webhook_url(self):
        with patch.dict(os.environ, {
            "TEAMS_WEBHOOK_URL": _WEBHOOK,
            "TEAMS_DRY_RUN":    "1",
        }):
            pub = TeamsPublisher.from_env()
        assert pub._dry_run is True

    def test_missing_url_raises(self):
        with patch.dict(os.environ, {"TEAMS_WEBHOOK_URL": ""}):
            with pytest.raises(ValueError, match="TEAMS_WEBHOOK_URL"):
                TeamsPublisher.from_env()


# ─────────────────────────────────────────────────────────────────────────────
# 7. TeamsPublisher.send_scan_results
# ─────────────────────────────────────────────────────────────────────────────

class TestSendScanResults:
    def test_dry_run_sends_without_http(self):
        pub    = TeamsPublisher(_WEBHOOK, dry_run=True)
        result = pub.send_scan_results([_FakeFinding()], _TARGET)
        assert result.sent   == 1
        assert result.failed == 0

    def test_no_findings_no_notification_by_default(self):
        pub    = TeamsPublisher(_WEBHOOK, dry_run=True)
        result = pub.send_scan_results([], _TARGET)
        assert result.sent == 0

    def test_always_notify_sends_clean_card_on_empty(self):
        pub    = TeamsPublisher(_WEBHOOK, dry_run=True, always_notify=True)
        result = pub.send_scan_results([], _TARGET)
        assert result.sent == 1

    def test_min_severity_medium_filters_low(self):
        pub    = TeamsPublisher(_WEBHOOK, min_severity="MEDIUM", dry_run=True)
        f      = _make_finding(severity="LOW")
        result = pub.send_scan_results([f], _TARGET)
        assert result.sent == 0   # filtered below threshold

    def test_min_severity_medium_includes_high(self):
        pub    = TeamsPublisher(_WEBHOOK, min_severity="MEDIUM", dry_run=True)
        f      = _make_finding(severity="HIGH")
        result = pub.send_scan_results([f], _TARGET)
        assert result.sent == 1

    def test_real_call_posts_to_webhook(self):
        pub  = TeamsPublisher(_WEBHOOK, dry_run=False)
        resp = MagicMock()
        resp.status_code = 200

        with patch("requests.post", return_value=resp) as mock_post:
            pub.send_scan_results([_FakeFinding()], _TARGET)
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0] if mock_post.call_args[0] else mock_post.call_args.args[0]
        assert call_url == _WEBHOOK

    def test_http_failure_counted_as_failed(self):
        pub  = TeamsPublisher(_WEBHOOK, dry_run=False)
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "Internal Server Error"

        with patch("requests.post", return_value=resp):
            result = pub.send_scan_results([_FakeFinding()], _TARGET)
        assert result.failed == 1
        assert result.sent   == 0

    def test_scan_label_used_when_provided(self):
        pub  = TeamsPublisher(_WEBHOOK, dry_run=True)
        # Should not raise
        result = pub.send_scan_results(
            [_FakeFinding()], _TARGET, scan_label="Production — nightly"
        )
        assert result.sent == 1


# ─────────────────────────────────────────────────────────────────────────────
# 8. TeamsPublisher.send_differential_alert
# ─────────────────────────────────────────────────────────────────────────────

class TestSendDifferentialAlert:
    def test_no_new_findings_no_alert(self):
        pub    = TeamsPublisher(_WEBHOOK, dry_run=True)
        result = pub.send_differential_alert([], [], _TARGET)
        assert result.sent == 0

    def test_new_findings_triggers_alert(self):
        pub    = TeamsPublisher(_WEBHOOK, dry_run=True)
        result = pub.send_differential_alert([_FakeFinding()], [], _TARGET)
        assert result.sent == 1

    def test_resolved_count_in_label(self):
        pub = TeamsPublisher(_WEBHOOK, dry_run=True)
        # Should include resolved count in label — no exception
        result = pub.send_differential_alert(
            [_FakeFinding()],
            ["resolved-id-1", "resolved-id-2"],
            _TARGET,
        )
        assert result.sent == 1


# ─────────────────────────────────────────────────────────────────────────────
# 9. Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_multiple_findings_one_card(self):
        pub = TeamsPublisher(_WEBHOOK, dry_run=True)
        findings = [_make_finding(finding_id=f"id{i}") for i in range(10)]
        result   = pub.send_scan_results(findings, _TARGET)
        assert result.sent == 1   # Always one card regardless of finding count

    def test_all_severities_in_factset(self):
        findings = [
            _make_finding(finding_id="c1", severity="CRITICAL"),
            _make_finding(finding_id="h1", severity="HIGH"),
            _make_finding(finding_id="m1", severity="MEDIUM"),
            _make_finding(finding_id="l1", severity="LOW"),
        ]
        card  = _build_summary_card(findings, _TARGET)
        body  = card["attachments"][0]["content"]["body"]
        facts = []
        for block in body:
            if block["type"] == "FactSet":
                facts.extend(block["facts"])
        titles = [f["title"] for f in facts]
        assert any("Critical" in t for t in titles)
        assert any("High" in t for t in titles)

    def test_clean_card_target_url_in_body(self):
        card     = _build_clean_card("https://my-site.com")
        card_str = str(card)
        assert "my-site.com" in card_str

    def test_network_error_counted_as_failed(self):
        pub = TeamsPublisher(_WEBHOOK, dry_run=False)
        with patch("requests.post", side_effect=ConnectionError("refused")):
            result = pub.send_scan_results([_FakeFinding()], _TARGET)
        assert result.failed == 1

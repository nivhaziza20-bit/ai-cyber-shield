"""
tests/test_jira_publisher.py — AI Cyber Shield v6

Test suite for integrations/jira_publisher.py

All JIRA HTTP calls are mocked — no real network access.

Coverage:
  1. _validate_base_url  — SSRF guard
  2. _cvss_to_priority   — CVSS → JIRA priority mapping
  3. _finding_label      — deterministic deduplication label
  4. _JiraHttp           — rate-limit retry, auth headers
  5. _build_description_cloud / _build_description_server
  6. JiraPublisher.from_env
  7. JiraPublisher.publish_findings — create, skip duplicate, dry-run
  8. JiraPublisher.resolve_findings — transition to Done
  9. JiraPublisher.verify_connection
  10. Edge cases — failed HTTP, empty findings, min_cvss filter, batch chunking
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, patch, call

import pytest

from integrations.jira_publisher import (
    JiraPublisher,
    PublishResult,
    _JiraHttp,
    _build_description_cloud,
    _build_description_server,
    _cvss_to_priority,
    _finding_label,
    _validate_base_url,
    _JIRA_LABEL_PREFIX,
)


# ─────────────────────────────────────────────────────────────────────────────
# Minimal SecurityFinding stubs (no dependency on real finding_enricher)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _FakeCvssVector:
    vector_string: str = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

@dataclass
class _FakeCvss:
    score:  float       = 9.8
    severity: str       = "CRITICAL"
    vector: _FakeCvssVector = field(default_factory=_FakeCvssVector)

@dataclass
class _FakeCwe:
    id:    int  = 79
    label: str  = "CWE-79"
    name:  str  = "Improper Neutralization of Input"
    url:   str  = "https://cwe.mitre.org/data/definitions/79.html"

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
    effort_hours: float = 4.0
    summary:      str   = "Escape all user-supplied data before rendering in HTML."
    code_before:  str   = '<div>{{user_input}}</div>'
    code_after:   str   = '<div>{{user_input | escape}}</div>'
    references:   list  = field(default_factory=list)

@dataclass
class _FakeFinding:
    finding_id:  str            = "abc123def456789012345678"
    title:       str            = "Reflected XSS in Search Parameter"
    finding_type: str           = "xss_reflected"
    tool:        str            = "xss_scanner"
    severity:    str            = "HIGH"
    cvss:        _FakeCvss      = field(default_factory=_FakeCvss)
    cwe:         _FakeCwe       = field(default_factory=_FakeCwe)
    owasp:       _FakeOwasp     = field(default_factory=_FakeOwasp)
    compliance:  _FakeCompliance= field(default_factory=_FakeCompliance)
    remediation: _FakeRemediation = field(default_factory=_FakeRemediation)
    business_impact: str        = "Attackers can steal session tokens."
    attack_scenario: str        = "An attacker WOULD inject a script payload into the search field."
    endpoint:    str            = "https://example.com/search?q="
    parameter:   str            = "q"
    evidence:    str            = "<script>alert(1)</script>"
    confirmed:   bool           = True
    confidence:  float          = 0.95


def _make_finding(**kwargs) -> _FakeFinding:
    f = _FakeFinding()
    for k, v in kwargs.items():
        setattr(f, k, v)
    return f


_TARGET = "https://example.com"
_BASE   = "https://yourorg.atlassian.net"
_TOKEN  = "test-api-token"
_EMAIL  = "test@example.com"
_PROJ   = "SEC"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_publisher(dry_run=False, **kwargs) -> JiraPublisher:
    return JiraPublisher(
        base_url    = _BASE,
        api_token   = _TOKEN,
        project_key = _PROJ,
        email       = _EMAIL,
        dry_run     = dry_run,
        is_cloud    = True,
        **kwargs,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. _validate_base_url — SSRF guard
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateBaseUrl:
    @pytest.mark.parametrize("url", [
        "https://yourorg.atlassian.net",
        "https://jira.external-corp.com",
        "http://jira.external-corp.com",
    ])
    def test_valid_urls_accepted(self, url):
        result = _validate_base_url(url)
        assert result == url.rstrip("/")

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8080",
        "http://localhost/jira",
        "http://192.168.1.50/jira",
        "http://10.0.0.1/jira",
        "http://172.16.0.1/jira",
        "http://169.254.169.254",   # AWS metadata
    ])
    def test_private_ip_rejected(self, url):
        with pytest.raises(ValueError, match="private IP"):
            _validate_base_url(url)

    def test_non_http_scheme_rejected(self):
        with pytest.raises(ValueError, match="http"):
            _validate_base_url("ftp://yourorg.atlassian.net")

    def test_trailing_slash_stripped(self):
        result = _validate_base_url("https://yourorg.atlassian.net/")
        assert not result.endswith("/")


# ─────────────────────────────────────────────────────────────────────────────
# 2. _cvss_to_priority
# ─────────────────────────────────────────────────────────────────────────────

class TestCvssToPriority:
    @pytest.mark.parametrize("score,expected", [
        (9.8, "Highest"),
        (9.0, "Highest"),
        (8.9, "High"),
        (7.0, "High"),
        (6.9, "Medium"),
        (4.0, "Medium"),
        (3.9, "Low"),
        (0.0, "Low"),
        (1.5, "Low"),
    ])
    def test_mapping(self, score, expected):
        assert _cvss_to_priority(score) == expected


# ─────────────────────────────────────────────────────────────────────────────
# 3. _finding_label
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingLabel:
    def test_label_starts_with_prefix(self):
        label = _finding_label("abc123def456789012345678")
        assert label.startswith(_JIRA_LABEL_PREFIX)

    def test_label_truncated_to_16_chars(self):
        label = _finding_label("abc123def456789012345678")
        suffix = label[len(_JIRA_LABEL_PREFIX):]
        assert len(suffix) == 16

    def test_same_finding_same_label(self):
        fid   = "abc123def456789012345678"
        assert _finding_label(fid) == _finding_label(fid)

    def test_different_findings_different_labels(self):
        assert _finding_label("aaa111") != _finding_label("bbb222")


# ─────────────────────────────────────────────────────────────────────────────
# 4. _JiraHttp
# ─────────────────────────────────────────────────────────────────────────────

class TestJiraHttp:
    def _make_http(self, is_cloud=True):
        return _JiraHttp(
            base_url  = _BASE,
            email     = _EMAIL,
            api_token = _TOKEN,
            is_cloud  = is_cloud,
        )

    def test_cloud_auth_header_is_basic(self):
        http = self._make_http(is_cloud=True)
        assert http._auth_header.startswith("Basic ")

    def test_server_auth_header_is_bearer(self):
        http = self._make_http(is_cloud=False)
        assert http._auth_header.startswith("Bearer ")

    def test_api_version_cloud(self):
        http = self._make_http(is_cloud=True)
        assert http._api_version() == "3"

    def test_api_version_server(self):
        http = self._make_http(is_cloud=False)
        assert http._api_version() == "2"

    def test_url_construction(self):
        http = self._make_http()
        assert http._url("/issue") == f"{_BASE}/rest/api/3/issue"

    def test_token_not_in_log(self, caplog):
        import logging
        http = self._make_http()
        with caplog.at_level(logging.DEBUG):
            # Just building the object should not log the token
            pass
        assert _TOKEN not in caplog.text

    def test_retry_on_429(self):
        """Verify exponential backoff is triggered on rate limit."""
        http = self._make_http()

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429
        rate_limit_resp.headers = {"Retry-After": "0.01"}
        rate_limit_resp.ok = False

        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.ok = True
        ok_resp.json.return_value = {"id": "1", "key": "SEC-1"}

        with patch("requests.request", side_effect=[rate_limit_resp, ok_resp]):
            result = http.request("GET", "/issue/SEC-1")
        assert result["key"] == "SEC-1"

    def test_204_returns_empty_dict(self):
        http = self._make_http()

        resp = MagicMock()
        resp.status_code = 204
        resp.ok = True

        with patch("requests.request", return_value=resp):
            result = http.request("DELETE", "/issue/SEC-1")
        assert result == {}

    def test_non_ok_raises_runtime_error(self):
        http = self._make_http()

        resp = MagicMock()
        resp.status_code = 400
        resp.ok = False
        resp.json.return_value = {"errorMessages": ["Invalid field"]}

        with patch("requests.request", return_value=resp):
            with pytest.raises(RuntimeError, match="400"):
                http.request("POST", "/issue", {"fields": {}})


# ─────────────────────────────────────────────────────────────────────────────
# 5. Description builders
# ─────────────────────────────────────────────────────────────────────────────

class TestDescriptionBuilders:
    def test_cloud_description_is_adf_dict(self):
        f = _FakeFinding()
        desc = _build_description_cloud(f, _TARGET)
        assert isinstance(desc, dict)
        assert desc["version"] == 1
        assert desc["type"] == "doc"
        assert isinstance(desc["content"], list)

    def test_cloud_description_has_heading(self):
        f = _FakeFinding()
        desc = _build_description_cloud(f, _TARGET)
        headings = [
            n for n in desc["content"]
            if n["type"] == "heading"
        ]
        assert len(headings) >= 2

    def test_cloud_description_contains_title(self):
        f = _FakeFinding(title="Test XSS Finding")
        desc = _build_description_cloud(f, _TARGET)
        # Title should appear in first heading
        first_heading_text = desc["content"][0]["content"][0]["text"]
        assert "Test XSS Finding" in first_heading_text

    def test_server_description_is_string(self):
        f = _FakeFinding()
        desc = _build_description_server(f, _TARGET)
        assert isinstance(desc, str)

    def test_server_description_has_wiki_markup(self):
        f = _FakeFinding()
        desc = _build_description_server(f, _TARGET)
        assert "h2." in desc
        assert "h3." in desc

    def test_server_description_contains_cvss(self):
        f = _FakeFinding()
        desc = _build_description_server(f, _TARGET)
        assert "CVSS 3.1" in desc
        assert str(f.cvss.score) in desc

    def test_server_description_contains_remediation(self):
        f = _FakeFinding()
        desc = _build_description_server(f, _TARGET)
        assert f.remediation.summary in desc

    def test_cloud_description_code_blocks(self):
        f = _FakeFinding()
        desc = _build_description_cloud(f, _TARGET)
        code_blocks = [
            n for n in desc["content"]
            if n.get("type") == "codeBlock"
        ]
        assert len(code_blocks) >= 1

    def test_server_description_contains_code(self):
        f = _FakeFinding(remediation=_FakeRemediation(
            code_before="BAD CODE",
            code_after="GOOD CODE",
        ))
        desc = _build_description_server(f, _TARGET)
        assert "BAD CODE" in desc
        assert "GOOD CODE" in desc

    def test_description_contains_finding_id(self):
        f = _FakeFinding(finding_id="my-unique-finding-id-12345")
        desc_cloud  = _build_description_cloud(f, _TARGET)
        desc_server = _build_description_server(f, _TARGET)
        # Finding ID should appear somewhere in both
        assert "my-unique-finding-id-12345" in str(desc_cloud)
        assert "my-unique-finding-id-12345" in desc_server

    def test_compliance_fields_in_cloud_description(self):
        f = _FakeFinding()
        desc = _build_description_cloud(f, _TARGET)
        flat = str(desc)
        assert "PCI-DSS" in flat
        assert "SOC2" in flat or "soc2" in flat.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 6. JiraPublisher.from_env
# ─────────────────────────────────────────────────────────────────────────────

class TestFromEnv:
    def test_from_env_reads_env_vars(self):
        env = {
            "JIRA_BASE_URL":   _BASE,
            "JIRA_EMAIL":      _EMAIL,
            "JIRA_API_TOKEN":  _TOKEN,
            "JIRA_PROJECT":    _PROJ,
            "JIRA_DRY_RUN":    "1",
        }
        with patch.dict(os.environ, env, clear=False):
            pub = JiraPublisher.from_env()
        assert pub._project_key == _PROJ
        assert pub._dry_run is True

    def test_from_env_missing_base_url_raises(self):
        with patch.dict(os.environ, {
            "JIRA_BASE_URL":  "",
            "JIRA_API_TOKEN": _TOKEN,
            "JIRA_EMAIL":     _EMAIL,
        }, clear=False):
            with pytest.raises(ValueError, match="JIRA_BASE_URL"):
                JiraPublisher.from_env()

    def test_from_env_missing_token_raises(self):
        with patch.dict(os.environ, {
            "JIRA_BASE_URL":  _BASE,
            "JIRA_API_TOKEN": "",
            "JIRA_EMAIL":     _EMAIL,
        }, clear=False):
            with pytest.raises(ValueError, match="JIRA_API_TOKEN"):
                JiraPublisher.from_env()

    def test_from_env_cloud_missing_email_raises(self):
        with patch.dict(os.environ, {
            "JIRA_BASE_URL":   _BASE,
            "JIRA_API_TOKEN":  _TOKEN,
            "JIRA_EMAIL":      "",
            "JIRA_SERVER_MODE": "0",  # Cloud mode
        }, clear=False):
            with pytest.raises(ValueError, match="JIRA_EMAIL"):
                JiraPublisher.from_env()


# ─────────────────────────────────────────────────────────────────────────────
# 7. JiraPublisher.publish_findings
# ─────────────────────────────────────────────────────────────────────────────

class TestPublishFindings:
    def test_dry_run_creates_nothing(self):
        pub = _make_publisher(dry_run=True)
        findings = [_FakeFinding()]
        result   = pub.publish_findings(findings, _TARGET)
        assert result.created == 1
        assert result.failed  == 0

    def test_dry_run_returns_created_count(self):
        pub = _make_publisher(dry_run=True)
        findings = [_FakeFinding(), _FakeFinding(finding_id="id2")]
        result   = pub.publish_findings(findings, _TARGET)
        assert result.created == 2

    def test_empty_findings_returns_zero(self):
        pub = _make_publisher(dry_run=True)
        result = pub.publish_findings([], _TARGET)
        assert result.created == 0
        assert result.failed  == 0

    def test_min_cvss_filters_findings(self):
        pub = _make_publisher(dry_run=True)
        findings = [
            _make_finding(finding_id="low",  cvss=_FakeCvss(score=2.0)),
            _make_finding(finding_id="high", cvss=_FakeCvss(score=8.5)),
        ]
        result = pub.publish_findings(findings, _TARGET, min_cvss=7.0)
        assert result.created == 1  # only the high one

    def test_duplicate_finding_counted_as_existing(self):
        pub = _make_publisher(dry_run=False)
        finding = _FakeFinding(finding_id="dup-finding-id-12345678")
        label   = _finding_label(finding.finding_id)

        # Mock HTTP so _find_existing_issues returns this label as existing
        pub._http = MagicMock()
        pub._http.get.return_value = {
            "issues": [{"key": "SEC-42", "fields": {"labels": [label]}}]
        }

        result = pub.publish_findings([finding], _TARGET)
        assert result.existing == 1
        assert result.created  == 0

    def test_new_finding_creates_issue(self):
        pub = _make_publisher(dry_run=False)
        finding = _FakeFinding()
        pub._http = MagicMock()
        # _find_existing_issues returns nothing (no duplicates)
        pub._http.get.return_value = {"issues": []}
        # _create_issue call
        pub._http.post.return_value = {"id": "10001", "key": "SEC-1"}

        result = pub.publish_findings([finding], _TARGET)
        assert result.created == 1
        assert result.failed  == 0
        pub._http.post.assert_called_once()

    def test_created_issue_has_correct_project(self):
        pub = _make_publisher(dry_run=False)
        finding = _FakeFinding()
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.return_value = {"key": "SEC-1"}

        pub.publish_findings([finding], _TARGET)

        call_payload = pub._http.post.call_args[0][1]
        assert call_payload["fields"]["project"]["key"] == _PROJ

    def test_created_issue_has_priority_based_on_cvss(self):
        pub = _make_publisher(dry_run=False)
        finding = _make_finding(cvss=_FakeCvss(score=9.8))
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.return_value = {"key": "SEC-1"}

        pub.publish_findings([finding], _TARGET)

        fields = pub._http.post.call_args[0][1]["fields"]
        assert fields["priority"]["name"] == "Highest"

    def test_labels_contain_finding_id_label(self):
        pub = _make_publisher(dry_run=False)
        finding = _FakeFinding()
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.return_value = {"key": "SEC-1"}

        pub.publish_findings([finding], _TARGET)

        fields  = pub._http.post.call_args[0][1]["fields"]
        labels  = fields["labels"]
        expected_label = _finding_label(finding.finding_id)
        assert expected_label in labels

    def test_labels_contain_owasp_code(self):
        pub = _make_publisher(dry_run=False)
        finding = _FakeFinding()
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.return_value = {"key": "SEC-1"}

        pub.publish_findings([finding], _TARGET)

        fields = pub._http.post.call_args[0][1]["fields"]
        labels = fields["labels"]
        assert any("A03" in l for l in labels)

    def test_components_added_to_issue(self):
        pub = _make_publisher(dry_run=False, components=["security", "backend"])
        finding = _FakeFinding()
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.return_value = {"key": "SEC-1"}

        pub.publish_findings([finding], _TARGET)

        fields = pub._http.post.call_args[0][1]["fields"]
        assert {"name": "security"} in fields["components"]

    def test_http_failure_counts_as_failed(self):
        pub = _make_publisher(dry_run=False)
        finding = _FakeFinding()
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.side_effect = RuntimeError("JIRA down")

        result = pub.publish_findings([finding], _TARGET)
        assert result.failed == 1
        assert result.created == 0
        assert len(result.errors) == 1

    def test_multiple_findings_with_one_failure(self):
        pub = _make_publisher(dry_run=False)
        f1 = _make_finding(finding_id="good-finding-1")
        f2 = _make_finding(finding_id="bad-finding-2")
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.side_effect = [
            {"key": "SEC-1"},        # f1 succeeds
            RuntimeError("error"),   # f2 fails
        ]

        result = pub.publish_findings([f1, f2], _TARGET)
        assert result.created == 1
        assert result.failed  == 1

    def test_publish_result_has_no_errors_on_success(self):
        pub = _make_publisher(dry_run=True)
        result = pub.publish_findings([_FakeFinding()], _TARGET)
        assert result.errors == []


# ─────────────────────────────────────────────────────────────────────────────
# 8. JiraPublisher.resolve_findings
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveFindings:
    def test_empty_ids_returns_zero(self):
        pub = _make_publisher(dry_run=True)
        result = pub.resolve_findings([])
        assert result == 0

    def test_dry_run_resolve_returns_count(self):
        pub = _make_publisher(dry_run=True)
        pub._find_existing_issues = MagicMock(return_value={
            "aics:abc123": "SEC-10",
            "aics:def456": "SEC-11",
        })
        result = pub.resolve_findings(["abc123", "def456"])
        assert result == 2

    def test_resolve_calls_transition(self):
        pub = _make_publisher(dry_run=False)
        pub._http = MagicMock()

        # _find_existing_issues JQL search
        pub._http.get.side_effect = [
            # JQL search result
            {"issues": [{"key": "SEC-10", "fields": {"labels": ["aics:abc123def456"]}}]},
            # get_transitions for SEC-10
            {"transitions": [{"id": "31", "name": "Done"}]},
        ]
        pub._http.post.return_value = {}  # transition POST

        resolved = pub.resolve_findings(["abc123def456789012345678"])
        assert resolved == 1
        pub._http.post.assert_called_once()

    def test_unknown_transition_name_logs_warning(self):
        pub = _make_publisher(dry_run=False)
        pub._http = MagicMock()
        pub._http.get.side_effect = [
            {"issues": [{"key": "SEC-10", "fields": {"labels": ["aics:abc123def456"]}}]},
            {"transitions": [{"id": "21", "name": "In Progress"}]},  # no "Done"
        ]

        resolved = pub.resolve_findings(["abc123def456789012345678"])
        # Should not raise, just log a warning
        assert resolved == 0


# ─────────────────────────────────────────────────────────────────────────────
# 9. JiraPublisher.verify_connection
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifyConnection:
    def test_dry_run_returns_dry_run_flag(self):
        pub = _make_publisher(dry_run=True)
        result = pub.verify_connection()
        assert result["dry_run"] is True

    def test_real_connection_calls_project_endpoint(self):
        pub = _make_publisher(dry_run=False)
        pub._http = MagicMock()
        pub._http.get.return_value = {
            "key": _PROJ, "name": "Security", "id": "10000"
        }
        result = pub.verify_connection()
        assert result["project_key"] == _PROJ
        pub._http.get.assert_called_once_with(f"/project/{_PROJ}")

    def test_verify_connection_includes_is_cloud(self):
        pub = _make_publisher(dry_run=False)
        pub._http = MagicMock()
        pub._http.get.return_value = {"key": _PROJ, "name": "Security", "id": "10"}
        result = pub.verify_connection()
        assert "is_cloud" in result


# ─────────────────────────────────────────────────────────────────────────────
# 10. Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_label_with_prefix(self):
        pub = _make_publisher(dry_run=True)
        finding = _FakeFinding()
        result  = pub.publish_findings([finding], _TARGET, label_prefix="prod")
        assert result.created == 1

    def test_build_labels_no_spaces(self):
        pub     = _make_publisher(dry_run=True)
        finding = _FakeFinding()
        labels  = pub._build_labels(finding, _finding_label(finding.finding_id))
        for label in labels:
            assert " " not in label, f"Label has space: {label!r}"

    def test_custom_fields_merged_into_issue(self):
        pub = _make_publisher(
            dry_run=False,
            custom_fields={"customfield_10001": "security-team"},
        )
        finding = _FakeFinding()
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.return_value = {"key": "SEC-1"}

        pub.publish_findings([finding], _TARGET)

        fields = pub._http.post.call_args[0][1]["fields"]
        assert fields.get("customfield_10001") == "security-team"

    def test_summary_truncated_at_255_chars(self):
        pub     = _make_publisher(dry_run=False)
        finding = _make_finding(
            title    = "X" * 200,
            endpoint = "Y" * 200,
        )
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}
        pub._http.post.return_value = {"key": "SEC-1"}

        pub.publish_findings([finding], _TARGET)

        fields  = pub._http.post.call_args[0][1]["fields"]
        assert len(fields["summary"]) <= 255

    def test_server_mode_uses_wiki_markup(self):
        pub = JiraPublisher(
            base_url    = _BASE,
            api_token   = _TOKEN,
            project_key = _PROJ,
            dry_run     = True,
            is_cloud    = False,  # Server mode
        )
        finding  = _FakeFinding()
        fields   = pub._build_issue_fields(finding, _TARGET, "test-label")
        assert isinstance(fields["description"], str)   # wiki markup, not ADF dict
        assert "h2." in fields["description"]

    def test_cloud_mode_uses_adf(self):
        pub    = _make_publisher(dry_run=True, is_cloud=True)
        finding = _FakeFinding()
        fields  = pub._build_issue_fields(finding, _TARGET, "test-label")
        assert isinstance(fields["description"], dict)  # ADF
        assert fields["description"]["type"] == "doc"

    def test_jql_batch_chunking(self):
        """When > 30 finding IDs, _find_existing_issues should batch them."""
        pub = _make_publisher(dry_run=False)
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}

        finding_ids = [f"finding-{i:04d}" for i in range(35)]
        pub._find_existing_issues(finding_ids)

        # Should have made 2 GET calls (30 + 5)
        assert pub._http.get.call_count == 2

    def test_findings_sorted_by_cvss_descending(self):
        """Highest CVSS findings should be created first."""
        creation_order = []

        pub = _make_publisher(dry_run=False)
        pub._http = MagicMock()
        pub._http.get.return_value = {"issues": []}

        original_post = pub._http.post

        def track_post(path, payload):
            if path == "/issue":
                priority = payload["fields"]["priority"]["name"]
                creation_order.append(priority)
            return {"key": f"SEC-{len(creation_order)}"}

        pub._http.post.side_effect = track_post

        findings = [
            _make_finding(finding_id="low-1",  cvss=_FakeCvss(score=3.0)),
            _make_finding(finding_id="crit-1", cvss=_FakeCvss(score=9.8)),
            _make_finding(finding_id="high-1", cvss=_FakeCvss(score=7.5)),
        ]
        pub.publish_findings(findings, _TARGET)

        # Highest CVSS (9.8 → Highest priority) should be first
        assert creation_order[0] == "Highest"

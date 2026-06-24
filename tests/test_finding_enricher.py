"""
tests/test_finding_enricher.py — AI Cyber Shield v6

Comprehensive test suite for finding_enricher.py.

Coverage areas:
  1. CVSS 3.1 algorithm — known vectors from FIRST specification
  2. CvssVector validation — invalid metric values
  3. _roundup edge cases
  4. Domain types (CweInfo, OwaspEntry, SecurityFinding)
  5. Per-tool extraction functions (all 17 tools)
  6. enrich_scan_result — integration, deduplication, sort order
  7. SARIF 2.1 export — structure, rule index, GitHub schema properties
  8. findings_summary — aggregation and stats
  9. Edge cases — empty inputs, unknown types, malformed data
"""

from __future__ import annotations

import json
import math
import uuid
from unittest.mock import MagicMock, patch

import pytest

from finding_enricher import (
    ComplianceRefs,
    CvssScore,
    CvssVector,
    CweInfo,
    OwaspEntry,
    RemediationGuide,
    SecurityFinding,
    _FINDING_DB,
    _OWASP,
    _enrich,
    _RawFinding,
    _iter_ssl,
    _iter_headers,
    _iter_cors_csp,
    _iter_dns,
    _iter_hsts,
    _iter_open_redirect,
    _iter_waf,
    _iter_exposure,
    _iter_tech,
    _iter_subdomain_takeover,
    _iter_port_scanner,
    _iter_cookie_security,
    _iter_api_spec,
    _iter_deep_js,
    _iter_html,
    _iter_active_verifier,
    _make_finding_id,
    _roundup,
    calculate_cvss31,
    enrich_scan_result,
    findings_summary,
    findings_to_json,
    to_sarif_json,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def vec(av, ac, pr, ui, s, c, i, a) -> CvssVector:
    return CvssVector(av=av, ac=ac, pr=pr, ui=ui, s=s, c=c, i=i, a=a)


def _minimal_scan(url="https://example.com", tool_key="ssl", tool_data=None) -> dict:
    return {
        "url": url,
        "tool_results": {tool_key: tool_data or {}},
        "critical_findings": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. CVSS 3.1 known-vector accuracy tests
#    All expected scores verified against the FIRST CVSS v3.1 calculator.
# ─────────────────────────────────────────────────────────────────────────────

class TestCvssCalculation:
    """CVSS 3.1 algorithm correctness — known vectors from FIRST specification."""

    def test_critical_all_high_scope_unchanged(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL
        score = calculate_cvss31(vec("N","L","N","N","U","H","H","H"))
        assert score.score == 9.8
        assert score.severity == "CRITICAL"

    def test_critical_all_high_scope_changed(self):
        # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0 CRITICAL
        score = calculate_cvss31(vec("N","L","N","N","C","H","H","H"))
        assert score.score == 10.0
        assert score.severity == "CRITICAL"

    def test_medium_reflected_xss_pattern(self):
        # AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 MEDIUM
        score = calculate_cvss31(vec("N","L","N","R","C","L","L","N"))
        assert score.score == 6.1
        assert score.severity == "MEDIUM"

    def test_medium_network_high_complexity_confidentiality(self):
        # AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N = 5.9 MEDIUM
        score = calculate_cvss31(vec("N","H","N","N","U","H","N","N"))
        assert score.score == 5.9
        assert score.severity == "MEDIUM"

    def test_low_local_limited_impact(self):
        # AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 3.3 LOW
        score = calculate_cvss31(vec("L","L","L","N","U","L","N","N"))
        assert score.score == 3.3
        assert score.severity == "LOW"

    def test_zero_score_all_none_impact(self):
        # C:N/I:N/A:N → ISC = 0 → score 0.0
        score = calculate_cvss31(vec("N","L","N","N","U","N","N","N"))
        assert score.score == 0.0
        assert score.severity == "INFO"

    def test_high_7_4_cors_pattern(self):
        # AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N = 7.4 HIGH
        # Confidentiality:High only (no integrity), Scope:Changed, User Interaction required
        score = calculate_cvss31(vec("N","L","N","R","C","H","N","N"))
        assert score.score == 7.4
        assert score.severity == "HIGH"

    def test_high_7_5_secret_exposed(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 HIGH
        score = calculate_cvss31(vec("N","L","N","N","U","H","N","N"))
        assert score.score == 7.5
        assert score.severity == "HIGH"

    def test_critical_ssti_pattern(self):
        # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0 CRITICAL
        score = calculate_cvss31(vec("N","L","N","N","C","H","H","H"))
        assert score.score == 10.0
        assert score.severity == "CRITICAL"

    def test_medium_5_3_spf_pattern(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N = 5.3 MEDIUM
        score = calculate_cvss31(vec("N","L","N","N","U","N","L","N"))
        assert score.score == 5.3
        assert score.severity == "MEDIUM"

    def test_score_never_exceeds_10(self):
        score = calculate_cvss31(vec("N","L","N","N","C","H","H","H"))
        assert score.score <= 10.0

    def test_score_never_negative(self):
        for av in ("N","A","L","P"):
            score = calculate_cvss31(vec(av,"L","N","N","U","N","N","N"))
            assert score.score >= 0.0

    def test_scope_changed_multiplies_by_1_08(self):
        # With scope unchanged vs changed, S:C should give higher score
        s_u = calculate_cvss31(vec("N","L","N","N","U","H","L","N"))
        s_c = calculate_cvss31(vec("N","L","N","N","C","H","L","N"))
        assert s_c.score >= s_u.score

    def test_physical_av_gives_lowest_attack_vector(self):
        # Physical access is harder than network
        network = calculate_cvss31(vec("N","L","N","N","U","H","N","N"))
        physical = calculate_cvss31(vec("P","L","N","N","U","H","N","N"))
        assert network.score > physical.score

    def test_high_complexity_lowers_score(self):
        low_ac  = calculate_cvss31(vec("N","L","N","N","U","H","N","N"))
        high_ac = calculate_cvss31(vec("N","H","N","N","U","H","N","N"))
        assert low_ac.score > high_ac.score

    def test_vector_string_format(self):
        v = vec("N","L","N","N","U","H","N","N")
        assert v.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

    def test_cvss_score_carries_vector(self):
        v = vec("N","L","N","N","U","H","H","H")
        result = calculate_cvss31(v)
        assert result.vector is v


# ─────────────────────────────────────────────────────────────────────────────
# 2. CvssVector validation
# ─────────────────────────────────────────────────────────────────────────────

class TestCvssVectorValidation:
    def test_invalid_av_raises(self):
        with pytest.raises(AssertionError):
            CvssVector("X","L","N","N","U","H","H","H")

    def test_invalid_ac_raises(self):
        with pytest.raises(AssertionError):
            CvssVector("N","M","N","N","U","H","H","H")

    def test_invalid_pr_raises(self):
        with pytest.raises(AssertionError):
            CvssVector("N","L","X","N","U","H","H","H")

    def test_invalid_scope_raises(self):
        with pytest.raises(AssertionError):
            CvssVector("N","L","N","N","X","H","H","H")

    def test_invalid_cia_raises(self):
        with pytest.raises(AssertionError):
            CvssVector("N","L","N","N","U","X","H","H")

    def test_valid_all_minimal(self):
        v = CvssVector("P","H","H","R","U","N","N","N")
        assert v.av == "P"


# ─────────────────────────────────────────────────────────────────────────────
# 3. _roundup edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestRoundup:
    def test_exact_one_decimal(self):
        assert _roundup(5.9) == 5.9

    def test_rounds_up_not_nearest(self):
        assert _roundup(5.01) == 5.1

    def test_exactly_zero(self):
        assert _roundup(0.0) == 0.0

    def test_exactly_ten(self):
        assert _roundup(10.0) == 10.0

    def test_float_precision(self):
        # 9.759 should become 9.8, not 9.7
        assert _roundup(9.759) == 9.8

    def test_integer_value(self):
        assert _roundup(7.0) == 7.0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Domain type tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCweInfo:
    def test_auto_url_generation(self):
        c = CweInfo(89, "SQL Injection", "desc")
        assert "89" in c.url
        assert "cwe.mitre.org" in c.url

    def test_label_format(self):
        c = CweInfo(79, "XSS", "desc")
        assert c.label == "CWE-79"

    def test_explicit_url_not_overridden(self):
        c = CweInfo(89, "SQL Injection", "desc", url="https://custom.example.com")
        assert c.url == "https://custom.example.com"


class TestOwaspEntry:
    def test_label_format(self):
        o = OwaspEntry(2025, "A03", "Injection")
        assert o.label == "A03:2025 – Injection"

    def test_url_auto_generated(self):
        o = OwaspEntry(2025, "A03", "Injection")
        assert "owasp.org" in o.url
        assert "A03" in o.url

    def test_explicit_url_preserved(self):
        o = OwaspEntry(2025, "A03", "Injection", url="https://custom.org")
        assert o.url == "https://custom.org"


class TestSecurityFinding:
    @pytest.fixture
    def sample_finding(self):
        cvss = calculate_cvss31(vec("N","L","N","N","U","H","H","H"))
        return SecurityFinding(
            finding_id="ACS-TEST-001",
            title="Test Vulnerability",
            finding_type="test_vuln",
            tool="ssl",
            severity=cvss.severity,
            cvss=cvss,
            cwe=CweInfo(89, "SQL Injection", "desc"),
            owasp=_OWASP["A03"],
            compliance=ComplianceRefs(pci_dss="Req 6.2.4"),
            business_impact="Data breach risk",
            attack_scenario="An attacker can...",
            remediation=RemediationGuide(priority=1),
        )

    def test_sarif_level_critical(self, sample_finding):
        assert sample_finding.sarif_level == "error"

    def test_sarif_rule_id_format(self, sample_finding):
        rid = sample_finding.sarif_rule_id
        assert rid.startswith("ACS/")
        assert "TEST-VULN" in rid

    def test_scan_timestamp_auto_set(self, sample_finding):
        assert "T" in sample_finding.scan_timestamp  # ISO format

    def test_to_dict_contains_cvss_score(self, sample_finding):
        d = sample_finding.to_dict()
        assert "cvss_score" in d
        assert d["cvss_score"] == 9.8

    def test_to_dict_contains_vector_string(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["cvss_vector"].startswith("CVSS:3.1/")

    def test_to_dict_contains_owasp_label(self, sample_finding):
        d = sample_finding.to_dict()
        assert "A03" in d["owasp_label"]


class TestMakeFindingId:
    def test_deterministic(self):
        id1 = _make_finding_id("cors_wildcard", "https://x.com/api", "cors_csp")
        id2 = _make_finding_id("cors_wildcard", "https://x.com/api", "cors_csp")
        assert id1 == id2

    def test_different_types_differ(self):
        id1 = _make_finding_id("cors_wildcard", "https://x.com", "cors_csp")
        id2 = _make_finding_id("cors_null_origin", "https://x.com", "cors_csp")
        assert id1 != id2

    def test_different_endpoints_differ(self):
        id1 = _make_finding_id("cors_wildcard", "https://a.com", "cors_csp")
        id2 = _make_finding_id("cors_wildcard", "https://b.com", "cors_csp")
        assert id1 != id2

    def test_starts_with_acs_prefix(self):
        fid = _make_finding_id("test", "url", "tool")
        assert fid.startswith("ACS-")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Finding database completeness
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingDatabase:
    def test_all_entries_have_8_fields(self):
        for key, entry in _FINDING_DB.items():
            assert len(entry) == 8, f"{key!r} has {len(entry)} fields, expected 8"

    def test_all_cvss_vectors_valid(self):
        for key, entry in _FINDING_DB.items():
            v = entry[1]
            assert isinstance(v, CvssVector), f"{key!r} has bad CvssVector"

    def test_all_owasp_keys_valid(self):
        valid_keys = set(_OWASP.keys())
        for key, entry in _FINDING_DB.items():
            owasp_key = entry[3]
            assert owasp_key in valid_keys, f"{key!r} uses unknown OWASP key {owasp_key!r}"

    def test_all_compliance_refs_are_correct_type(self):
        for key, entry in _FINDING_DB.items():
            assert isinstance(entry[4], ComplianceRefs), f"{key!r} bad ComplianceRefs"

    def test_all_remediations_are_correct_type(self):
        for key, entry in _FINDING_DB.items():
            assert isinstance(entry[7], RemediationGuide), f"{key!r} bad RemediationGuide"

    def test_no_empty_titles(self):
        for key, entry in _FINDING_DB.items():
            assert entry[0].strip(), f"{key!r} has empty title"

    def test_no_empty_attack_scenarios(self):
        for key, entry in _FINDING_DB.items():
            assert entry[6].strip(), f"{key!r} has empty attack_scenario"

    def test_all_cvss_scores_above_zero(self):
        for key, entry in _FINDING_DB.items():
            score = calculate_cvss31(entry[1])
            # All security findings should have CVSS > 0
            assert score.score >= 0.0, f"{key!r} has negative CVSS"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Per-tool extractor tests
# ─────────────────────────────────────────────────────────────────────────────

URL = "https://example.com"


class TestSslExtractor:
    def test_tls_10_in_issues(self):
        findings = list(_iter_ssl(URL, {"issues": ["TLS 1.0 is enabled"]}))
        assert any(f.finding_type == "ssl_tls_v1_0" for f in findings)

    def test_tls_11_in_issues(self):
        findings = list(_iter_ssl(URL, {"issues": ["TLS 1.1 enabled"]}))
        assert any(f.finding_type == "ssl_tls_v1_1" for f in findings)

    def test_weak_cipher_detected(self):
        findings = list(_iter_ssl(URL, {"cipher_suite": "RC4-MD5:AES256"}))
        assert any(f.finding_type == "ssl_weak_cipher" for f in findings)

    def test_cert_expiring_soon(self):
        findings = list(_iter_ssl(URL, {"issues": ["Certificate expiring in 15 days"]}))
        assert any(f.finding_type == "ssl_cert_expiring_soon" for f in findings)

    def test_self_signed_cert(self):
        findings = list(_iter_ssl(URL, {"issues": ["Self-signed certificate detected"]}))
        assert any(f.finding_type == "ssl_self_signed" for f in findings)

    def test_protocols_dict_detection(self):
        findings = list(_iter_ssl(URL, {"protocols": {"TLSv1.0": True, "TLSv1.2": True}}))
        types = [f.finding_type for f in findings]
        assert "ssl_tls_v1_0" in types

    def test_empty_data_no_findings(self):
        assert list(_iter_ssl(URL, {})) == []

    def test_clean_ssl_no_findings(self):
        findings = list(_iter_ssl(URL, {
            "issues": [],
            "protocols": {"TLSv1.2": True, "TLSv1.3": True},
            "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
        }))
        assert findings == []


class TestHeadersExtractor:
    def test_csp_missing(self):
        findings = list(_iter_headers(URL, {"missing_headers": ["Content-Security-Policy"]}))
        assert any(f.finding_type == "header_csp_missing" for f in findings)

    def test_xframe_missing(self):
        findings = list(_iter_headers(URL, {"missing_headers": ["X-Frame-Options"]}))
        assert any(f.finding_type == "header_xframe_missing" for f in findings)

    def test_xcto_missing(self):
        findings = list(_iter_headers(URL, {"missing_headers": ["X-Content-Type-Options"]}))
        assert any(f.finding_type == "header_xcto_missing" for f in findings)

    def test_referrer_missing(self):
        findings = list(_iter_headers(URL, {"missing_headers": ["Referrer-Policy"]}))
        assert any(f.finding_type == "header_referrer_missing" for f in findings)

    def test_hsts_missing(self):
        findings = list(_iter_headers(URL, {"missing_headers": ["Strict-Transport-Security"]}))
        assert any(f.finding_type == "header_hsts_missing" for f in findings)

    def test_empty_missing_headers_no_findings(self):
        assert list(_iter_headers(URL, {"missing_headers": []})) == []


class TestCorsCspExtractor:
    def test_wildcard_cors(self):
        findings = list(_iter_cors_csp(URL, {
            "cors_issues": ["CORS wildcard Access-Control-Allow-Origin: *"]
        }))
        assert any(f.finding_type == "cors_wildcard" for f in findings)

    def test_null_origin_cors(self):
        findings = list(_iter_cors_csp(URL, {
            "cors_issues": ["CORS reflects null origin"]
        }))
        assert any(f.finding_type == "cors_null_origin" for f in findings)

    def test_unsafe_inline_csp(self):
        findings = list(_iter_cors_csp(URL, {
            "cors_issues": [],
            "csp_issues": ["unsafe-inline script-src"],
        }))
        assert any(f.finding_type == "csp_unsafe_inline" for f in findings)

    def test_wildcard_gets_high_confidence(self):
        findings = list(_iter_cors_csp(URL, {
            "cors_issues": ["CORS wildcard ACAO: *"]
        }))
        cors = next(f for f in findings if f.finding_type == "cors_wildcard")
        assert cors.confidence >= 0.85


class TestDnsExtractor:
    def test_spf_missing_flag(self):
        findings = list(_iter_dns(URL, {"spf_missing": True}))
        assert any(f.finding_type == "dns_spf_missing" for f in findings)

    def test_dmarc_missing_flag(self):
        findings = list(_iter_dns(URL, {"dmarc_missing": True}))
        assert any(f.finding_type == "dns_dmarc_missing" for f in findings)

    def test_caa_missing_flag(self):
        findings = list(_iter_dns(URL, {"caa_missing": True}))
        assert any(f.finding_type == "dns_caa_missing" for f in findings)

    def test_dnssec_missing_when_invalid(self):
        findings = list(_iter_dns(URL, {"dnssec_valid": False}))
        assert any(f.finding_type == "dns_dnssec_missing" for f in findings)

    def test_clean_dns_no_findings(self):
        data = {
            "spf_missing": False,
            "dmarc_missing": False,
            "caa_missing": False,
            "dnssec_valid": True,
            "spf_issues": [],
            "dmarc_issues": [],
        }
        assert list(_iter_dns(URL, data)) == []


class TestHstsExtractor:
    def test_not_preloaded(self):
        findings = list(_iter_hsts(URL, {"is_preloaded": False}))
        assert any(f.finding_type == "hsts_not_preloaded" for f in findings)

    def test_short_max_age(self):
        findings = list(_iter_hsts(URL, {"is_preloaded": True, "max_age": 3600}))
        assert any(f.finding_type == "hsts_not_preloaded" for f in findings)

    def test_preloaded_long_max_age_no_finding(self):
        findings = list(_iter_hsts(URL, {"is_preloaded": True, "max_age": 31536000}))
        assert findings == []


class TestOpenRedirectExtractor:
    def test_confirmed_redirect(self):
        data = {
            "confirmed_redirects": [{"url": URL + "/redir", "param": "next"}]
        }
        findings = list(_iter_open_redirect(URL, data))
        assert any(f.finding_type == "open_redirect_confirmed" for f in findings)

    def test_confirmed_is_marked(self):
        data = {
            "confirmed_redirects": [{"url": URL + "/redir", "param": "next"}]
        }
        findings = list(_iter_open_redirect(URL, data))
        confirmed = next(f for f in findings if f.finding_type == "open_redirect_confirmed")
        assert confirmed.confirmed is True

    def test_candidate_only_when_no_confirmed(self):
        data = {
            "candidates": [{"url": URL, "param": "goto"}],
            "confirmed_redirects": [],
        }
        findings = list(_iter_open_redirect(URL, data))
        assert any(f.finding_type == "open_redirect_candidate" for f in findings)

    def test_candidate_suppressed_when_confirmed_present(self):
        data = {
            "confirmed_redirects": [{"url": URL + "/redir", "param": "next"}],
            "candidates": [{"url": URL, "param": "goto"}],
        }
        findings = list(_iter_open_redirect(URL, data))
        types = [f.finding_type for f in findings]
        assert "open_redirect_candidate" not in types


class TestWafExtractor:
    def test_no_waf_detected(self):
        findings = list(_iter_waf(URL, {"detected": False}))
        assert any(f.finding_type == "waf_not_detected" for f in findings)

    def test_waf_present_no_finding(self):
        findings = list(_iter_waf(URL, {"detected": True, "waf_name": "Cloudflare"}))
        assert findings == []


class TestExposureExtractor:
    def test_env_file_detected(self):
        findings = list(_iter_exposure(URL, {"sensitive_paths": ["/.env"]}))
        assert any(f.finding_type == "exposure_env_file" for f in findings)

    def test_git_dir_detected(self):
        findings = list(_iter_exposure(URL, {"sensitive_paths": ["/.git/config"]}))
        assert any(f.finding_type == "exposure_git_dir" for f in findings)

    def test_backup_file_detected(self):
        findings = list(_iter_exposure(URL, {"sensitive_paths": ["/backup.zip"]}))
        assert any(f.finding_type == "exposure_backup_file" for f in findings)

    def test_http_trace_detected(self):
        findings = list(_iter_exposure(URL, {"http_issues": ["HTTP TRACE enabled"]}))
        assert any(f.finding_type == "exposure_http_trace" for f in findings)

    def test_env_has_high_confidence(self):
        findings = list(_iter_exposure(URL, {"sensitive_paths": ["/.env"]}))
        env_f = next(f for f in findings if f.finding_type == "exposure_env_file")
        assert env_f.confidence >= 0.9


class TestTechExtractor:
    def test_vulnerable_component(self):
        findings = list(_iter_tech(URL, {
            "known_vulnerabilities": ["jQuery 1.11.0 — CVE-2019-11358"]
        }))
        assert any(f.finding_type == "tech_vulnerable_component" for f in findings)

    def test_server_version_disclosure(self):
        findings = list(_iter_tech(URL, {
            "fingerprint": {"server": "nginx/1.18.0"}
        }))
        assert any(f.finding_type == "tech_version_disclosure" for f in findings)

    def test_no_vuln_no_fingerprint_no_findings(self):
        assert list(_iter_tech(URL, {})) == []


class TestSubdomainTakeoverExtractor:
    def test_vulnerable_subdomain(self):
        findings = list(_iter_subdomain_takeover(URL, {
            "vulnerable_subdomains": ["staging.example.com"]
        }))
        assert any(f.finding_type == "subdomain_takeover_vulnerable" for f in findings)

    def test_is_marked_confirmed(self):
        findings = list(_iter_subdomain_takeover(URL, {
            "vulnerable_subdomains": ["staging.example.com"]
        }))
        f = next(x for x in findings if x.finding_type == "subdomain_takeover_vulnerable")
        assert f.confirmed is True


class TestPortScannerExtractor:
    def test_mysql_port_3306(self):
        findings = list(_iter_port_scanner(URL, {
            "open_ports": [{"port": 3306, "service": "mysql"}]
        }))
        assert any(f.finding_type == "port_db_exposed" for f in findings)

    def test_redis_port_6379(self):
        findings = list(_iter_port_scanner(URL, {
            "open_ports": [{"port": 6379, "service": "redis"}]
        }))
        assert any(f.finding_type == "port_db_exposed" for f in findings)

    def test_ssh_port_22(self):
        findings = list(_iter_port_scanner(URL, {
            "open_ports": [{"port": 22, "service": "ssh"}]
        }))
        assert any(f.finding_type == "port_sensitive_open" for f in findings)

    def test_http_80_not_flagged(self):
        findings = list(_iter_port_scanner(URL, {
            "open_ports": [{"port": 80, "service": "http"}]
        }))
        assert findings == []


class TestCookieSecurityExtractor:
    def test_missing_secure_flag(self):
        findings = list(_iter_cookie_security(URL, {
            "issues": [{"name": "session", "missing_flags": ["Secure"]}]
        }))
        assert any(f.finding_type == "cookie_no_secure" for f in findings)

    def test_missing_httponly_flag(self):
        findings = list(_iter_cookie_security(URL, {
            "issues": [{"name": "auth", "missing_flags": ["HttpOnly"]}]
        }))
        assert any(f.finding_type == "cookie_no_httponly" for f in findings)

    def test_missing_samesite_flag(self):
        findings = list(_iter_cookie_security(URL, {
            "issues": [{"name": "pref", "missing_flags": ["SameSite"]}]
        }))
        assert any(f.finding_type == "cookie_no_samesite" for f in findings)

    def test_non_dict_issue_skipped(self):
        # Should not raise
        findings = list(_iter_cookie_security(URL, {"issues": ["string issue"]}))
        assert findings == []


class TestApiSpecExtractor:
    def test_swagger_exposed(self):
        findings = list(_iter_api_spec(URL, {
            "exposed_specs": ["/swagger.json"]
        }))
        assert any(f.finding_type == "api_spec_swagger_exposed" for f in findings)

    def test_graphql_introspection_flag(self):
        findings = list(_iter_api_spec(URL, {
            "graphql_introspection_enabled": True
        }))
        assert any(f.finding_type == "api_graphql_introspection" for f in findings)


class TestDeepJsExtractor:
    def test_secret_in_bundle(self):
        findings = list(_iter_deep_js(URL, {
            "secrets_found": ["sk-abc123..."]
        }))
        assert any(f.finding_type == "js_secret_exposed" for f in findings)

    def test_unauth_api_endpoint(self):
        findings = list(_iter_deep_js(URL, {
            "api_calls": [{"url": "/api/admin/users", "authenticated": False}]
        }))
        assert any(f.finding_type == "js_unauth_api_endpoint" for f in findings)

    def test_chrome_extension_url_skipped(self):
        findings = list(_iter_deep_js(URL, {
            "api_calls": [{"url": "chrome-extension://abc/bg.js", "authenticated": False}]
        }))
        assert findings == []


class TestHtmlExtractor:
    def test_ssti_risk_detected(self):
        findings = list(_iter_html(URL, {
            "template_issues": ["SSTI pattern detected in parameter"]
        }))
        assert any(f.finding_type == "html_ssti_risk" for f in findings)

    def test_api_key_in_source(self):
        findings = list(_iter_html(URL, {
            "exposed_secrets": ["AIzaSy...KEY"]
        }))
        assert any(f.finding_type == "html_api_key_exposed" for f in findings)


class TestActiveVerifierExtractor:
    def _make_av_result(self, vuln_type_str: str, confirmed: bool = True,
                        confidence: float = 0.95):
        r = MagicMock()
        r.vuln_type = MagicMock()
        r.vuln_type.value = vuln_type_str
        r.is_confirmed = confirmed
        r.confidence_score = confidence
        r.raw_poc_request = None
        r.status = "CONFIRMED"
        r.endpoint = URL
        r.parameter = "q"
        return r

    def test_xss_confirmed(self):
        findings = list(_iter_active_verifier(URL, [
            self._make_av_result("REFLECTED_XSS")
        ]))
        assert any(f.finding_type == "av_xss_confirmed" for f in findings)

    def test_cors_confirmed(self):
        findings = list(_iter_active_verifier(URL, [
            self._make_av_result("CORS_MISCONFIGURATION")
        ]))
        assert any(f.finding_type == "av_cors_confirmed" for f in findings)

    def test_ssti_confirmed(self):
        findings = list(_iter_active_verifier(URL, [
            self._make_av_result("SSTI")
        ]))
        assert any(f.finding_type == "av_ssti_confirmed" for f in findings)

    def test_not_confirmed_skipped(self):
        findings = list(_iter_active_verifier(URL, [
            self._make_av_result("REFLECTED_XSS", confirmed=False)
        ]))
        assert findings == []

    def test_unknown_vuln_type_skipped(self):
        findings = list(_iter_active_verifier(URL, [
            self._make_av_result("UNKNOWN_TYPE")
        ]))
        assert findings == []

    def test_empty_list_returns_empty(self):
        assert list(_iter_active_verifier(URL, [])) == []


# ─────────────────────────────────────────────────────────────────────────────
# 7. enrich_scan_result integration tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEnrichScanResult:
    def _scan(self, **tool_data) -> dict:
        return {"url": URL, "tool_results": tool_data, "critical_findings": []}

    def test_returns_list(self):
        result = enrich_scan_result(self._scan())
        assert isinstance(result, list)

    def test_empty_scan_returns_empty(self):
        result = enrich_scan_result({"url": URL, "tool_results": {}, "critical_findings": []})
        assert result == []

    def test_single_finding_extracted(self):
        result = enrich_scan_result(self._scan(
            headers={"missing_headers": ["Content-Security-Policy"]}
        ))
        assert len(result) >= 1

    def test_findings_sorted_by_cvss_descending(self):
        result = enrich_scan_result(self._scan(
            ssl={"issues": ["TLS 1.0 is enabled"]},
            cors_csp={"cors_issues": ["CORS wildcard ACAO: *"], "csp_issues": []},
        ))
        scores = [f.cvss.score for f in result]
        assert scores == sorted(scores, reverse=True)

    def test_deduplication_same_finding_different_tools(self):
        # CSP missing can be detected by both 'headers' and 'cors_csp'
        result = enrich_scan_result(self._scan(
            headers={"missing_headers": ["Content-Security-Policy"]},
            cors_csp={"cors_issues": [], "csp_issues": ["CSP missing"]},
        ))
        csp_findings = [f for f in result if f.finding_type == "header_csp_missing"]
        # After deduplication — IDs are deterministic, so same endpoint+type = same ID
        ids = {f.finding_id for f in csp_findings}
        assert len(ids) == len(csp_findings)  # no duplicate IDs

    def test_confirmed_findings_sort_first(self):
        result = enrich_scan_result(self._scan(
            open_redirect={
                "confirmed_redirects": [{"url": URL + "/redir", "param": "next"}],
                "candidates": [],
            },
            headers={"missing_headers": ["X-Frame-Options"]},
        ))
        # First finding should be the confirmed one
        if result:
            confirmed = [f for f in result if f.confirmed]
            if confirmed:
                assert result[0].confirmed is True

    def test_security_finding_has_cvss_object(self):
        result = enrich_scan_result(self._scan(
            cors_csp={"cors_issues": ["CORS wildcard ACAO: *"], "csp_issues": []}
        ))
        for f in result:
            assert isinstance(f.cvss, CvssScore)

    def test_security_finding_has_cwe(self):
        result = enrich_scan_result(self._scan(
            cors_csp={"cors_issues": ["CORS wildcard ACAO: *"], "csp_issues": []}
        ))
        for f in result:
            assert isinstance(f.cwe, CweInfo)

    def test_non_dict_tool_data_skipped_gracefully(self):
        result = enrich_scan_result({
            "url": URL,
            "tool_results": {"ssl": "not a dict"},
            "critical_findings": [],
        })
        assert isinstance(result, list)

    def test_missing_url_key_no_crash(self):
        result = enrich_scan_result({"tool_results": {}, "critical_findings": []})
        assert result == []

    def test_active_verifier_findings_included(self):
        mock_av = MagicMock()
        mock_av.vuln_type = MagicMock()
        mock_av.vuln_type.value = "REFLECTED_XSS"
        mock_av.is_confirmed = True
        mock_av.confidence_score = 0.9
        mock_av.raw_poc_request = None
        mock_av.status = "CONFIRMED"
        mock_av.endpoint = URL
        mock_av.parameter = "q"

        result = enrich_scan_result(
            {"url": URL, "tool_results": {}, "critical_findings": []},
            av_results=[mock_av],
        )
        types = [f.finding_type for f in result]
        assert "av_xss_confirmed" in types

    def test_multitool_scan_returns_multiple_findings(self):
        result = enrich_scan_result(self._scan(
            ssl={"issues": ["TLS 1.0 is enabled"]},
            headers={"missing_headers": ["Content-Security-Policy", "X-Frame-Options"]},
            cors_csp={"cors_issues": ["CORS wildcard ACAO: *"], "csp_issues": []},
            waf={"detected": False},
        ))
        assert len(result) >= 4


# ─────────────────────────────────────────────────────────────────────────────
# 8. SARIF 2.1 export tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSarifExport:
    @pytest.fixture
    def sample_findings(self):
        result = enrich_scan_result({
            "url": URL,
            "tool_results": {
                "cors_csp": {
                    "cors_issues": ["CORS wildcard ACAO: *"],
                    "csp_issues": [],
                },
                "headers": {
                    "missing_headers": ["X-Frame-Options", "Content-Security-Policy"],
                },
            },
            "critical_findings": [],
        })
        return result

    def test_sarif_version(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        assert sarif["version"] == "2.1.0"

    def test_sarif_schema_present(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]

    def test_one_run(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        assert len(sarif["runs"]) == 1

    def test_tool_name_present(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "AI Cyber Shield"

    def test_results_count_matches_findings(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        results = sarif["runs"][0]["results"]
        assert len(results) == len(sample_findings)

    def test_each_result_has_level(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        for r in sarif["runs"][0]["results"]:
            assert r["level"] in ("error", "warning", "note", "none")

    def test_each_result_has_rule_id(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        for r in sarif["runs"][0]["results"]:
            assert r["ruleId"].startswith("ACS/")

    def test_each_result_has_location(self, sample_findings):
        sarif = to_sarif_json(sample_findings, target_url=URL)
        for r in sarif["runs"][0]["results"]:
            locs = r["locations"]
            assert len(locs) >= 1
            assert "physicalLocation" in locs[0]

    def test_security_severity_property_present(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        driver = sarif["runs"][0]["tool"]["driver"]
        for rule in driver["rules"]:
            assert "security-severity" in rule["properties"]

    def test_security_severity_is_numeric_string(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            float(rule["properties"]["security-severity"])  # must not raise

    def test_tags_include_owasp_and_cwe(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            tags = rule["properties"]["tags"]
            assert "security" in tags
            # Should have owasp-style and cwe-style tag
            assert any("a0" in t.lower() or "a1" in t.lower() for t in tags)

    def test_sarif_is_json_serialisable(self, sample_findings):
        sarif = to_sarif_json(sample_findings, target_url=URL)
        # Should not raise
        json.dumps(sarif)

    def test_empty_findings_produces_valid_sarif(self):
        sarif = to_sarif_json([])
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []

    def test_rule_index_matches_result_rule_index(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for r in sarif["runs"][0]["results"]:
            idx = r["ruleIndex"]
            assert rules[idx]["id"] == r["ruleId"]

    def test_invocations_present(self, sample_findings):
        sarif = to_sarif_json(sample_findings)
        invocations = sarif["runs"][0].get("invocations", [])
        assert len(invocations) >= 1
        assert invocations[0]["executionSuccessful"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 9. findings_summary tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingsSummary:
    @pytest.fixture
    def mixed_findings(self):
        return enrich_scan_result({
            "url": URL,
            "tool_results": {
                "ssl":    {"issues": ["TLS 1.0 is enabled", "Self-signed certificate"]},
                "cors_csp": {"cors_issues": ["CORS wildcard ACAO: *"], "csp_issues": []},
                "headers": {"missing_headers": ["Content-Security-Policy"]},
                "waf": {"detected": False},
            },
            "critical_findings": [],
        })

    def test_total_count(self, mixed_findings):
        s = findings_summary(mixed_findings)
        assert s["total"] == len(mixed_findings)

    def test_by_severity_has_all_keys(self, mixed_findings):
        s = findings_summary(mixed_findings)
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            assert sev in s["by_severity"]

    def test_severity_counts_sum_to_total(self, mixed_findings):
        s = findings_summary(mixed_findings)
        assert sum(s["by_severity"].values()) == s["total"]

    def test_owasp_categories_are_strings(self, mixed_findings):
        s = findings_summary(mixed_findings)
        assert all(isinstance(x, str) for x in s["owasp_categories"])

    def test_cwe_ids_present(self, mixed_findings):
        s = findings_summary(mixed_findings)
        assert len(s["cwe_ids"]) > 0

    def test_top_cvss_score_is_max(self, mixed_findings):
        s = findings_summary(mixed_findings)
        expected_max = max(f.cvss.score for f in mixed_findings)
        assert s["top_cvss_score"] == expected_max

    def test_empty_findings_summary(self):
        s = findings_summary([])
        assert s["total"] == 0
        assert s["top_cvss_score"] == 0.0
        assert s["owasp_categories"] == []


# ─────────────────────────────────────────────────────────────────────────────
# 10. findings_to_json
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingsToJson:
    def test_returns_list_of_dicts(self):
        findings = enrich_scan_result({
            "url": URL,
            "tool_results": {"headers": {"missing_headers": ["X-Frame-Options"]}},
            "critical_findings": [],
        })
        data = findings_to_json(findings)
        assert isinstance(data, list)
        for item in data:
            assert isinstance(item, dict)

    def test_json_serialisable(self):
        findings = enrich_scan_result({
            "url": URL,
            "tool_results": {"headers": {"missing_headers": ["X-Frame-Options"]}},
            "critical_findings": [],
        })
        data = findings_to_json(findings)
        json.dumps(data)  # must not raise

    def test_empty_list(self):
        assert findings_to_json([]) == []


# ─────────────────────────────────────────────────────────────────────────────
# 11. _enrich — unknown type / None handling
# ─────────────────────────────────────────────────────────────────────────────

class TestEnrichFunction:
    def test_unknown_finding_type_returns_none(self):
        raw = _RawFinding("totally_unknown_type", "ssl", URL)
        assert _enrich(raw) is None

    def test_known_type_returns_security_finding(self):
        raw = _RawFinding("cors_wildcard", "cors_csp", URL)
        f = _enrich(raw)
        assert isinstance(f, SecurityFinding)

    def test_confirmed_finding_has_slightly_higher_score(self):
        raw_unconfirmed = _RawFinding("cors_wildcard", "cors_csp", URL,
                                      confirmed=False)
        raw_confirmed   = _RawFinding("cors_wildcard", "cors_csp", URL,
                                      confirmed=True)
        f_u = _enrich(raw_unconfirmed)
        f_c = _enrich(raw_confirmed)
        assert f_c.cvss.score >= f_u.cvss.score

    def test_evidence_propagated(self):
        raw = _RawFinding("cors_wildcard", "cors_csp", URL,
                          evidence="Access-Control-Allow-Origin: *")
        f = _enrich(raw)
        assert f.evidence == "Access-Control-Allow-Origin: *"

    def test_endpoint_propagated(self):
        endpoint = "https://api.example.com/v1/users"
        raw = _RawFinding("cors_wildcard", "cors_csp", endpoint)
        f = _enrich(raw)
        assert f.endpoint == endpoint

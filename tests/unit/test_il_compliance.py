"""
tests/unit/test_il_compliance.py — Brief 12: Israeli Compliance Bundle

8 tests verifying the YAML mapping and il_mapper logic.
"""

import pytest
from finding_enricher import (
    SecurityFinding, CvssScore, CvssVector, CweInfo,
    OwaspEntry, ComplianceRefs, RemediationGuide,
)
from core.compliance.il_mapper import (
    load_il_regulations,
    map_findings_to_il_compliance,
    ComplianceIndicator,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_finding(
    finding_id:   str,
    tool:         str,
    finding_type: str,
    title:        str = "",
    severity:     str = "MEDIUM",
    cvss_score:   float = 5.0,
) -> SecurityFinding:
    vector = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="N")
    return SecurityFinding(
        finding_id      = finding_id,
        title           = title or finding_type.replace("_", " ").title(),
        finding_type    = finding_type,
        tool            = tool,
        severity        = severity,
        cvss            = CvssScore(vector=vector, score=cvss_score, severity=severity),
        cwe             = CweInfo(200, "Exposure", "desc"),
        owasp           = OwaspEntry(year=2021, code="A05", name="Security Misconfiguration"),
        compliance      = ComplianceRefs(),
        business_impact = "Risk",
        attack_scenario = "Attacker does X.",
        remediation     = RemediationGuide(priority=1, effort_hours=2, summary="Fix it"),
    )


# ─── 1. test_yaml_loads ───────────────────────────────────────────────────────

class TestYamlLoads:
    def test_yaml_loads_without_errors(self):
        """il_regulations.yaml must load without exception and return a non-empty list."""
        # Clear lru_cache to ensure fresh load in each test run
        load_il_regulations.cache_clear()
        mappings = load_il_regulations()
        assert isinstance(mappings, list), "Expected a list of mappings"
        assert len(mappings) > 0, "Expected at least 1 mapping entry"

    def test_all_entries_have_required_fields(self):
        """Every mapping entry must have finding_category, finding_types, and regulation."""
        load_il_regulations.cache_clear()
        mappings = load_il_regulations()
        for entry in mappings:
            assert "finding_category" in entry, f"Missing finding_category: {entry}"
            assert "finding_types" in entry, f"Missing finding_types: {entry}"
            assert "regulation" in entry, f"Missing regulation: {entry}"
            reg = entry["regulation"]
            assert "name" in reg, f"Regulation missing name: {reg}"
            assert "confidence" in reg, f"Regulation missing confidence: {reg}"
            assert reg["confidence"] in ("direct_indicator", "related_context"), (
                f"Invalid confidence value: {reg['confidence']}"
            )


# ─── 2. test_exposed_env_maps_to_data_security ───────────────────────────────

class TestExposedEnvMapping:
    def test_exposed_env_maps_to_data_security_regulation(self):
        """exposed_env finding → Privacy Protection Regulations (Data Security) 5777-2017."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-env", tool="exposure", finding_type="exposed_env",
                                title="Exposed .env File", severity="HIGH", cvss_score=7.5)
        report = map_findings_to_il_compliance([finding], language="en")
        assert report.total_count == 1
        ind = report.indicators[0]
        assert "Data Security" in ind.regulation_name or "5777" in ind.regulation_name
        assert ind.confidence == "direct_indicator"

    def test_exposed_git_also_maps(self):
        """exposed_git should also map to Data Security Regulations."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-git", tool="exposure", finding_type="exposed_git",
                                title="Exposed .git Directory")
        report = map_findings_to_il_compliance([finding], language="en")
        assert report.total_count >= 1


# ─── 3. test_weak_ssl_maps_to_encryption ─────────────────────────────────────

class TestWeakSslMapping:
    def test_weak_tls_maps_to_encryption_requirement(self):
        """weak_tls finding → Privacy Protection Regulations, Encryption section."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-tls", tool="ssl", finding_type="weak_tls",
                                title="Weak TLS Protocol", severity="HIGH", cvss_score=7.4)
        report = map_findings_to_il_compliance([finding], language="en")
        assert report.total_count == 1
        ind = report.indicators[0]
        assert "ncryption" in ind.regulation_section or "4" in ind.regulation_section
        assert ind.confidence == "direct_indicator"

    def test_expired_cert_maps(self):
        """expired_cert should map to the same encryption requirement."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-cert", tool="ssl", finding_type="expired_cert")
        report = map_findings_to_il_compliance([finding], language="en")
        assert report.total_count >= 1


# ─── 4. test_unmapped_finding_returns_empty ───────────────────────────────────

class TestUnmappedFinding:
    def test_unmapped_finding_returns_empty_list(self):
        """A finding_type not in any YAML entry should not crash and return no indicators."""
        load_il_regulations.cache_clear()
        finding = _make_finding(
            "f-unknown", tool="waf", finding_type="totally_unknown_type_xyz",
            title="Unknown", severity="LOW", cvss_score=1.0
        )
        report = map_findings_to_il_compliance([finding], language="en")
        assert report.total_count == 0
        assert report.indicators == []
        assert report.unmapped_count == 1

    def test_empty_findings_list(self):
        """Empty findings list → empty report, no crash."""
        load_il_regulations.cache_clear()
        report = map_findings_to_il_compliance([], language="he")
        assert report.total_count == 0
        assert report.indicators == []


# ─── 5. test_disclaimer_always_present ───────────────────────────────────────

class TestDisclaimerAlwaysPresent:
    def test_every_indicator_has_non_empty_disclaimer(self):
        """Every ComplianceIndicator must carry a non-empty disclaimer string."""
        load_il_regulations.cache_clear()
        findings = [
            _make_finding("f-env",  tool="exposure",  finding_type="exposed_env"),
            _make_finding("f-tls",  tool="ssl",       finding_type="weak_tls"),
            _make_finding("f-spf",  tool="dns",       finding_type="spf_missing"),
            _make_finding("f-cors", tool="cors_csp",  finding_type="cors_wildcard"),
        ]
        report = map_findings_to_il_compliance(findings, language="he")
        assert len(report.indicators) >= 1, "Expected at least 1 mapped indicator"
        for ind in report.indicators:
            assert ind.disclaimer, f"Indicator {ind.finding_id} has empty disclaimer"
            assert len(ind.disclaimer) > 30, "Disclaimer is suspiciously short"

    def test_report_level_disclaimer_present(self):
        """The ILComplianceReport itself must carry a disclaimer."""
        load_il_regulations.cache_clear()
        report = map_findings_to_il_compliance([], language="en")
        assert report.disclaimer
        assert "legal advice" in report.disclaimer.lower() or "ייעוץ" in report.disclaimer


# ─── 6. test_hebrew_descriptions ─────────────────────────────────────────────

class TestHebrewDescriptions:
    def test_language_he_returns_hebrew_description(self):
        """language='he' → description field must contain Hebrew characters."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-env", tool="exposure", finding_type="exposed_env")
        report = map_findings_to_il_compliance([finding], language="he")
        assert report.total_count == 1
        description = report.indicators[0].description
        # Hebrew Unicode block: ֐–׿
        has_hebrew = any("֐" <= ch <= "׿" for ch in description)
        assert has_hebrew, f"Expected Hebrew characters in description, got: {description!r}"

    def test_report_language_field_is_he(self):
        """Report's language field should reflect the requested language."""
        load_il_regulations.cache_clear()
        report = map_findings_to_il_compliance([], language="he")
        assert report.language == "he"


# ─── 7. test_english_descriptions ────────────────────────────────────────────

class TestEnglishDescriptions:
    def test_language_en_returns_english_description(self):
        """language='en' → description field should be predominantly ASCII/English."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-env", tool="exposure", finding_type="exposed_env")
        report = map_findings_to_il_compliance([finding], language="en")
        assert report.total_count == 1
        description = report.indicators[0].description
        has_hebrew = any("֐" <= ch <= "׿" for ch in description)
        assert not has_hebrew, f"Expected English description, got Hebrew: {description!r}"

    def test_disclaimer_language_matches(self):
        """English mode disclaimer should also be in English."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-tls", tool="ssl", finding_type="weak_tls")
        report = map_findings_to_il_compliance([finding], language="en")
        ind = report.indicators[0]
        # English disclaimer should not be predominantly Hebrew
        has_hebrew = any("֐" <= ch <= "׿" for ch in ind.disclaimer)
        assert not has_hebrew, "English-mode disclaimer should be in English"


# ─── 8. test_confidence_levels ───────────────────────────────────────────────

class TestConfidenceLevels:
    def test_direct_indicator_confidence(self):
        """exposed_env and weak_tls should both be 'direct_indicator'."""
        load_il_regulations.cache_clear()
        f_env = _make_finding("f-env", tool="exposure", finding_type="exposed_env")
        f_tls = _make_finding("f-tls", tool="ssl",      finding_type="weak_tls")
        report = map_findings_to_il_compliance([f_env, f_tls], language="en")
        assert report.direct_count == 2
        for ind in report.indicators:
            assert ind.confidence == "direct_indicator"

    def test_related_context_confidence(self):
        """DNS (spf_missing) should be 'related_context'."""
        load_il_regulations.cache_clear()
        finding = _make_finding("f-spf", tool="dns", finding_type="spf_missing")
        report = map_findings_to_il_compliance([finding], language="en")
        assert report.total_count == 1
        assert report.indicators[0].confidence == "related_context"
        assert report.related_count == 1
        assert report.direct_count == 0

    def test_confidence_values_are_valid(self):
        """All detected indicators must have one of the two valid confidence values."""
        load_il_regulations.cache_clear()
        findings = [
            _make_finding("f-env",  tool="exposure",        finding_type="exposed_env"),
            _make_finding("f-spf",  tool="dns",             finding_type="spf_missing"),
            _make_finding("f-cors", tool="cors_csp",        finding_type="cors_wildcard"),
            _make_finding("f-port", tool="port_scanner",    finding_type="exposed_database_port"),
        ]
        report = map_findings_to_il_compliance(findings, language="en")
        valid = {"direct_indicator", "related_context"}
        for ind in report.indicators:
            assert ind.confidence in valid, (
                f"Invalid confidence '{ind.confidence}' for finding '{ind.finding_title}'"
            )

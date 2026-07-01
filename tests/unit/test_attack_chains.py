"""Tests for core/attack_chain_engine.py — Brief 10."""
import pytest
from finding_enricher import (
    SecurityFinding, CvssScore, CvssVector, CweInfo, OwaspEntry,
    ComplianceRefs, RemediationGuide,
)
from core.attack_chain_engine import detect_chains, AttackChain


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_finding(
    finding_id:   str,
    tool:         str,
    finding_type: str,
    severity:     str  = "MEDIUM",
    cvss_score:   float = 5.0,
) -> SecurityFinding:
    vector = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="N")
    return SecurityFinding(
        finding_id   = finding_id,
        title        = finding_type.replace("_", " ").title(),
        finding_type = finding_type,
        tool         = tool,
        severity     = severity,
        cvss         = CvssScore(vector=vector, score=cvss_score, severity=severity),
        cwe          = CweInfo(79, "XSS", "desc"),
        owasp        = OwaspEntry(year=2021, code="A03", name="Injection"),
        compliance   = ComplianceRefs(),
        business_impact = "Risk",
        attack_scenario = "Attacker does X.",
        remediation  = RemediationGuide(priority=1, effort_hours=1, summary="Fix it"),
    )


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def cors_finding():
    return _make_finding("f-cors", "cors_csp", "cors_wildcard", "MEDIUM", 5.3)

@pytest.fixture
def samesite_finding():
    return _make_finding("f-cookie", "cookie_security", "missing_samesite", "MEDIUM", 4.8)

@pytest.fixture
def csp_frame_finding():
    return _make_finding("f-csp", "cors_csp", "missing_csp_frame_ancestors", "LOW", 3.1)

@pytest.fixture
def hsts_finding():
    return _make_finding("f-hsts", "hsts_preload", "missing_hsts", "MEDIUM", 4.5)

@pytest.fixture
def redirect_finding():
    return _make_finding("f-redirect", "open_redirect", "confirmed_redirect", "HIGH", 6.1)

@pytest.fixture
def subdomain_finding():
    return _make_finding("f-sub", "subdomain_takeover", "dangling_cname", "HIGH", 6.5)

@pytest.fixture
def cookie_scope_finding():
    return _make_finding("f-cookie2", "cookie_security", "broad_cookie_domain", "MEDIUM", 4.2)

@pytest.fixture
def spf_finding():
    return _make_finding("f-spf", "dns", "spf_missing", "HIGH", 7.0)

@pytest.fixture
def dmarc_finding():
    return _make_finding("f-dmarc", "dns", "dmarc_none", "MEDIUM", 5.0)


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestCorsSessionChain:
    """test_detects_cors_session_chain: CORS + missing SameSite → chain detected"""

    def test_chain_detected(self, cors_finding, samesite_finding):
        chains = detect_chains([cors_finding, samesite_finding])
        chain_ids = [c.id for c in chains]
        assert "session_hijack_cors" in chain_ids

    def test_no_chain_when_samesite_missing(self, cors_finding):
        """Only CORS, no SameSite → no session hijack chain"""
        chains = detect_chains([cors_finding])
        chain_ids = [c.id for c in chains]
        assert "session_hijack_cors" not in chain_ids

    def test_no_chain_when_cors_missing(self, samesite_finding):
        """Only SameSite missing, no CORS → no chain"""
        chains = detect_chains([samesite_finding])
        chain_ids = [c.id for c in chains]
        assert "session_hijack_cors" not in chain_ids


class TestAmplifiers:
    """test_amplifier_included_when_present / test_amplifier_optional"""

    def test_amplifier_included_when_present(self, cors_finding, samesite_finding, csp_frame_finding):
        chains = detect_chains([cors_finding, samesite_finding, csp_frame_finding])
        chain = next(c for c in chains if c.id == "session_hijack_cors")
        amp_ids = [n.finding_id for n in chain.amplifiers]
        assert "f-csp" in amp_ids

    def test_amplifier_optional_chain_still_detected(self, cors_finding, samesite_finding):
        """Chain is detected even without amplifier (amplifiers are optional)"""
        chains = detect_chains([cors_finding, samesite_finding])
        chain = next((c for c in chains if c.id == "session_hijack_cors"), None)
        assert chain is not None
        assert chain.amplifiers == []


class TestMultipleChains:
    """test_multiple_chains_detected: findings match 2+ patterns"""

    def test_two_chains_detected(self, cors_finding, samesite_finding, redirect_finding, hsts_finding):
        chains = detect_chains([cors_finding, samesite_finding, redirect_finding, hsts_finding])
        chain_ids = [c.id for c in chains]
        assert "session_hijack_cors" in chain_ids
        assert "credential_harvest_redirect" in chain_ids

    def test_subdomain_cookie_chain(self, subdomain_finding, cookie_scope_finding):
        chains = detect_chains([subdomain_finding, cookie_scope_finding])
        chain_ids = [c.id for c in chains]
        assert "subdomain_takeover_cookie" in chain_ids

    def test_dns_email_chain(self, spf_finding, dmarc_finding):
        chains = detect_chains([spf_finding, dmarc_finding])
        chain_ids = [c.id for c in chains]
        assert "dns_email_spoofing" in chain_ids


class TestChainSeverity:
    """test_chain_severity_higher_than_individuals"""

    def test_session_chain_severity_is_critical(self, cors_finding, samesite_finding):
        """Session hijack chain is CRITICAL even though both inputs are MEDIUM"""
        chains = detect_chains([cors_finding, samesite_finding])
        chain = next(c for c in chains if c.id == "session_hijack_cors")
        # Both inputs are MEDIUM (5.x CVSS) but chain is CRITICAL (8.1)
        assert chain.severity == "CRITICAL"
        max_individual = max(cors_finding.cvss.score, samesite_finding.cvss.score)
        assert chain.cvss > max_individual


class TestCleanScan:
    """test_no_chains_clean_scan: no vulnerable findings → empty chains list"""

    def test_empty_findings_no_chains(self):
        chains = detect_chains([])
        assert chains == []

    def test_unrelated_findings_no_chains(self):
        # Findings that don't match any chain prerequisites
        f = _make_finding("f-misc", "waf", "no_waf_detected", "LOW", 2.0)
        chains = detect_chains([f])
        # waf alone doesn't form a chain
        assert not any(c.id == "session_hijack_cors" for c in chains)


class TestChainRemediation:
    """test_chain_remediation_present: each chain has remediation text"""

    def test_all_detected_chains_have_remediation(self, cors_finding, samesite_finding, spf_finding, dmarc_finding):
        chains = detect_chains([cors_finding, samesite_finding, spf_finding, dmarc_finding])
        for chain in chains:
            assert chain.remediation, f"Chain {chain.id} has no remediation"
            assert len(chain.remediation) > 20


class TestChainSorting:
    """Chains should be sorted by CVSS descending"""

    def test_critical_chains_before_high(self, cors_finding, samesite_finding, redirect_finding, hsts_finding):
        chains = detect_chains([cors_finding, samesite_finding, redirect_finding, hsts_finding])
        if len(chains) >= 2:
            for i in range(len(chains) - 1):
                # Severity rank of earlier chain should be ≤ later chain
                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                assert (
                    sev_order.get(chains[i].severity, 5)
                    <= sev_order.get(chains[i + 1].severity, 5)
                )


class TestChainDict:
    """Chain.to_dict() produces serializable output"""

    def test_to_dict_is_json_serializable(self, cors_finding, samesite_finding):
        import json
        chains = detect_chains([cors_finding, samesite_finding])
        chain  = next(c for c in chains if c.id == "session_hijack_cors")
        d = chain.to_dict()
        json.dumps(d)  # must not raise

    def test_to_dict_has_required_fields(self, cors_finding, samesite_finding):
        chains = detect_chains([cors_finding, samesite_finding])
        d = chains[0].to_dict()
        for key in ("id", "name", "severity", "cvss", "impact", "remediation", "prerequisites"):
            assert key in d

"""
tests/test_cve_intelligence.py

Full test suite for Stage C — Real-time CVE Intelligence.

Coverage:
  1. CVERecord dataclass and severity helpers
  2. NVD API v2 fetcher (mocked HTTP)
  3. GitHub Advisory fetcher (mocked HTTP)
  4. OSV.dev fetcher (mocked HTTP)
  5. EPSS enrichment (mocked HTTP)
  6. Disk cache (write / read / expire / prune)
  7. Deduplication across sources
  8. enrich_technology() end-to-end
  9. enrich_findings() — enriches tech_fingerprinter output
  10. tech_fingerprinter integration — uses live feed, falls back gracefully
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _mock_resp(body: dict | list | str, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    if isinstance(body, (dict, list)):
        text = json.dumps(body)
        resp.json.return_value = body
    else:
        text = body
    resp.text = text
    return resp


def _nvd_response(cve_id: str = "CVE-2019-11358", score: float = 6.1) -> dict:
    """Minimal NVD API v2 response envelope."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N/AC:L"}}
                        ]
                    },
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/" + cve_id}],
                    "published": "2024-01-15T00:00:00.000",
                    "lastModified": "2024-03-01T00:00:00.000",
                }
            }
        ]
    }


def _github_response(cve_id: str = "CVE-2019-11358", package: str = "jquery") -> list:
    return [
        {
            "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
            "cve_id": cve_id,
            "summary": f"Test advisory for {package}",
            "description": "Prototype pollution via $.extend()",
            "severity": "MODERATE",
            "cvss": {"score": 6.1, "vector_string": "CVSS:3.1/AV:N/AC:L"},
            "cwes": [{"cwe_id": "CWE-1321"}],
            "references": [{"url": "https://github.com/advisories/GHSA-test"}],
            "published_at": "2024-01-15T00:00:00Z",
            "updated_at": "2024-03-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": package},
                    "vulnerable_version_range": "< 3.5.0",
                    "first_patched_version": "3.5.0",
                }
            ],
        }
    ]


def _osv_response(cve_id: str = "CVE-2019-11358") -> dict:
    return {
        "vulns": [
            {
                "id": "GHSA-xxxx-xxxx-xxxx",
                "aliases": [cve_id],
                "summary": "Prototype pollution",
                "details": "Prototype pollution via $.extend().",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
                "database_specific": {"severity": "HIGH"},
                "references": [{"url": "https://osv.dev/vulnerability/GHSA-test"}],
                "published": "2024-01-15T00:00:00Z",
                "modified": "2024-03-01T00:00:00Z",
                "affected": [
                    {
                        "package": {"name": "jquery", "ecosystem": "npm"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.5.0"}]}],
                    }
                ],
            }
        ]
    }


def _epss_response(cve_ids: list[str], score: float = 0.3) -> dict:
    return {
        "data": [
            {"cve": cve_id, "epss": str(score), "percentile": "0.8"}
            for cve_id in cve_ids
        ]
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. CVERecord + severity helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestCVERecord:
    def test_to_dict_contains_required_fields(self):
        from tools.cve_feed import CVERecord
        rec = CVERecord(cve_id="CVE-2019-11358", cvss_score=6.1, severity="MEDIUM")
        d = rec.to_dict()
        for field in ("cve", "severity", "cvss_score", "epss_score", "sources"):
            assert field in d, f"Missing field: {field}"

    def test_to_dict_rounds_epss(self):
        from tools.cve_feed import CVERecord
        rec = CVERecord(cve_id="CVE-2024-0001", epss_score=0.123456789)
        assert rec.to_dict()["epss_score"] == 0.1235

    def test_severity_from_cvss_critical(self):
        from tools.cve_feed import _severity_from_cvss
        assert _severity_from_cvss(9.0) == "CRITICAL"
        assert _severity_from_cvss(10.0) == "CRITICAL"

    def test_severity_from_cvss_high(self):
        from tools.cve_feed import _severity_from_cvss
        assert _severity_from_cvss(7.0) == "HIGH"
        assert _severity_from_cvss(8.9) == "HIGH"

    def test_severity_from_cvss_medium(self):
        from tools.cve_feed import _severity_from_cvss
        assert _severity_from_cvss(4.0) == "MEDIUM"
        assert _severity_from_cvss(6.9) == "MEDIUM"

    def test_severity_from_cvss_low(self):
        from tools.cve_feed import _severity_from_cvss
        assert _severity_from_cvss(0.1) == "LOW"
        assert _severity_from_cvss(3.9) == "LOW"

    def test_severity_from_cvss_unknown(self):
        from tools.cve_feed import _severity_from_cvss
        assert _severity_from_cvss(0.0) == "UNKNOWN"

    def test_amplify_severity_high_to_critical_when_high_epss(self):
        from tools.cve_feed import CVERecord, _amplify_severity
        rec = CVERecord(cve_id="CVE-2024-0001", severity="HIGH", epss_score=0.75)
        assert _amplify_severity(rec) == "CRITICAL"

    def test_amplify_severity_medium_to_high_when_epss_above_half(self):
        from tools.cve_feed import CVERecord, _amplify_severity
        rec = CVERecord(cve_id="CVE-2024-0001", severity="MEDIUM", epss_score=0.6)
        assert _amplify_severity(rec) == "HIGH"

    def test_amplify_severity_unchanged_when_low_epss(self):
        from tools.cve_feed import CVERecord, _amplify_severity
        rec = CVERecord(cve_id="CVE-2024-0001", severity="HIGH", epss_score=0.1)
        assert _amplify_severity(rec) == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# 2. NVD fetcher
# ─────────────────────────────────────────────────────────────────────────────

class TestNVDFetcher:
    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        """Redirect cache to a temp directory so tests don't pollute .cve_cache/."""
        import tools.cve_feed as cf
        monkeypatch.setattr(cf, "_CACHE_DIR", tmp_path / "cve_cache")
        monkeypatch.setattr(cf, "_NVD_DELAY_S", 0)  # no sleep in tests

    def test_parses_nvd_response_correctly(self):
        from tools.cve_feed import _fetch_nvd

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp(_nvd_response())):
            records = _fetch_nvd("jQuery", "3.1.0")

        assert len(records) == 1
        assert records[0].cve_id == "CVE-2019-11358"
        assert records[0].cvss_score == 6.1
        assert records[0].severity == "MEDIUM"
        assert "nvd" in records[0].sources

    def test_parses_cwe_ids(self):
        from tools.cve_feed import _fetch_nvd

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp(_nvd_response())):
            records = _fetch_nvd("jQuery", "3.1.0")

        assert "CWE-79" in records[0].cwe_ids

    def test_returns_empty_on_network_error(self):
        from tools.cve_feed import _fetch_nvd

        with patch("tools.cve_feed.safe_get", side_effect=ConnectionError("down")):
            records = _fetch_nvd("jQuery", "3.1.0")

        assert records == []

    def test_returns_empty_on_empty_vulnerabilities(self):
        from tools.cve_feed import _fetch_nvd

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp({"vulnerabilities": []})):
            records = _fetch_nvd("jQuery", "3.1.0")

        assert records == []

    def test_critical_cvss_score_mapped_correctly(self):
        from tools.cve_feed import _fetch_nvd

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp(_nvd_response(score=9.8))):
            records = _fetch_nvd("Log4j", "2.14.0")

        assert records[0].severity == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# 3. GitHub Advisory fetcher
# ─────────────────────────────────────────────────────────────────────────────

class TestGitHubAdvisoryFetcher:
    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        import tools.cve_feed as cf
        monkeypatch.setattr(cf, "_CACHE_DIR", tmp_path / "cve_cache")

    def test_parses_github_response(self):
        from tools.cve_feed import _fetch_github_advisory

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp(_github_response())):
            records = _fetch_github_advisory("npm", "jquery", "3.1.0")

        assert len(records) == 1
        assert records[0].cve_id == "CVE-2019-11358"
        assert "github" in records[0].sources

    def test_maps_moderate_severity_to_medium(self):
        from tools.cve_feed import _fetch_github_advisory

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp(_github_response())):
            records = _fetch_github_advisory("npm", "jquery", "3.1.0")

        assert records[0].severity == "MEDIUM"

    def test_filters_by_version_range(self):
        """Version 3.6.0 is ABOVE the fixed 3.5.0 — should be excluded."""
        from tools.cve_feed import _fetch_github_advisory

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp(_github_response())):
            records = _fetch_github_advisory("npm", "jquery", "3.6.0")

        assert records == []

    def test_returns_empty_on_network_error(self):
        from tools.cve_feed import _fetch_github_advisory

        with patch("tools.cve_feed.safe_get", side_effect=ConnectionError()):
            records = _fetch_github_advisory("npm", "jquery", "3.1.0")

        assert records == []

    def test_returns_empty_on_non_list_response(self):
        from tools.cve_feed import _fetch_github_advisory

        with patch("tools.cve_feed.safe_get", return_value=_mock_resp({"error": "rate limited"})):
            records = _fetch_github_advisory("npm", "jquery", "3.1.0")

        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 4. OSV fetcher
# ─────────────────────────────────────────────────────────────────────────────

class TestOSVFetcher:
    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        import tools.cve_feed as cf
        monkeypatch.setattr(cf, "_CACHE_DIR", tmp_path / "cve_cache")

    def test_parses_osv_response(self):
        from tools.cve_feed import _fetch_osv

        with patch("tools.cve_feed._req.post", return_value=_mock_resp(_osv_response())):
            records = _fetch_osv("npm", "jquery", "3.1.0")

        assert len(records) == 1
        assert records[0].cve_id == "CVE-2019-11358"
        assert "osv" in records[0].sources

    def test_uses_cve_alias_over_osv_id(self):
        from tools.cve_feed import _fetch_osv

        with patch("tools.cve_feed._req.post", return_value=_mock_resp(_osv_response("CVE-2024-0001"))):
            records = _fetch_osv("npm", "jquery", "3.1.0")

        assert records[0].cve_id == "CVE-2024-0001"

    def test_extracts_fixed_version(self):
        from tools.cve_feed import _fetch_osv

        with patch("tools.cve_feed._req.post", return_value=_mock_resp(_osv_response())):
            records = _fetch_osv("npm", "jquery", "3.1.0")

        assert records[0].fixed_version == "3.5.0"

    def test_returns_empty_on_network_error(self):
        from tools.cve_feed import _fetch_osv

        with patch("tools.cve_feed._req.post", side_effect=ConnectionError()):
            records = _fetch_osv("npm", "jquery", "3.1.0")

        assert records == []

    def test_returns_empty_when_no_vulns(self):
        from tools.cve_feed import _fetch_osv

        with patch("tools.cve_feed._req.post", return_value=_mock_resp({"vulns": []})):
            records = _fetch_osv("npm", "jquery", "99.0.0")

        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 5. EPSS enrichment
# ─────────────────────────────────────────────────────────────────────────────

class TestEPSSEnrichment:
    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        import tools.cve_feed as cf
        monkeypatch.setattr(cf, "_CACHE_DIR", tmp_path / "cve_cache")

    def test_injects_epss_score(self):
        from tools.cve_feed import CVERecord, _enrich_with_epss

        records = [CVERecord(cve_id="CVE-2019-11358", severity="HIGH")]

        with patch("tools.cve_feed.safe_get",
                   return_value=_mock_resp(_epss_response(["CVE-2019-11358"], 0.3))):
            enriched = _enrich_with_epss(records)

        assert enriched[0].epss_score == pytest.approx(0.3)

    def test_amplifies_high_to_critical_when_epss_above_threshold(self):
        from tools.cve_feed import CVERecord, _enrich_with_epss

        records = [CVERecord(cve_id="CVE-2021-44228", severity="HIGH")]

        with patch("tools.cve_feed.safe_get",
                   return_value=_mock_resp(_epss_response(["CVE-2021-44228"], 0.97))):
            enriched = _enrich_with_epss(records)

        assert enriched[0].severity == "CRITICAL"
        assert enriched[0].exploit_available is True

    def test_exploit_available_set_when_epss_above_half(self):
        from tools.cve_feed import CVERecord, _enrich_with_epss

        records = [CVERecord(cve_id="CVE-2024-0001", severity="MEDIUM")]

        with patch("tools.cve_feed.safe_get",
                   return_value=_mock_resp(_epss_response(["CVE-2024-0001"], 0.55))):
            enriched = _enrich_with_epss(records)

        assert enriched[0].exploit_available is True

    def test_skips_non_cve_ids(self):
        from tools.cve_feed import CVERecord, _enrich_with_epss

        records = [CVERecord(cve_id="GHSA-xxxx-xxxx-xxxx", severity="HIGH")]
        # No EPSS call should be made since ID doesn't start with "CVE-"
        with patch("tools.cve_feed.safe_get") as mock_get:
            _enrich_with_epss(records)
        mock_get.assert_not_called()

    def test_returns_unchanged_on_epss_error(self):
        from tools.cve_feed import CVERecord, _enrich_with_epss

        records = [CVERecord(cve_id="CVE-2019-11358", severity="HIGH")]

        with patch("tools.cve_feed.safe_get", side_effect=ConnectionError()):
            enriched = _enrich_with_epss(records)

        assert enriched[0].epss_score == 0.0
        assert enriched[0].severity == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Disk cache
# ─────────────────────────────────────────────────────────────────────────────

class TestCVECache:
    @pytest.fixture(autouse=True)
    def _temp_cache(self, tmp_path, monkeypatch):
        import tools.cve_feed as cf
        monkeypatch.setattr(cf, "_CACHE_DIR", tmp_path / "cve_cache")

    def test_write_and_read_cache(self):
        from tools.cve_feed import _cache_key, _write_cache, _read_cache

        key = _cache_key("test", "jquery:3.1.0")
        payload = [{"cve": "CVE-2019-11358", "test": True}]
        _write_cache(key, payload)
        result = _read_cache(key)
        assert result == payload

    def test_expired_cache_returns_none(self):
        from tools.cve_feed import _cache_key, _cache_path, _read_cache
        import tools.cve_feed as cf

        key = _cache_key("test", "expired:test")
        # Write a cache file with past expiry
        import tools.cve_feed as module
        path = cf._cache_path(key)
        cf._CACHE_DIR.mkdir(exist_ok=True)
        path.write_text(json.dumps({
            "expires_at": "2020-01-01T00:00:00+00:00",
            "payload": [{"cve": "CVE-OLD"}],
        }))

        result = _read_cache(key)
        assert result is None

    def test_missing_cache_returns_none(self):
        from tools.cve_feed import _cache_key, _read_cache

        key = _cache_key("test", "nonexistent:key:99")
        assert _read_cache(key) is None

    def test_cache_key_is_deterministic(self):
        from tools.cve_feed import _cache_key

        k1 = _cache_key("nvd", "jquery:3.1.0")
        k2 = _cache_key("nvd", "jquery:3.1.0")
        assert k1 == k2

    def test_different_queries_produce_different_keys(self):
        from tools.cve_feed import _cache_key

        k1 = _cache_key("nvd", "jquery:3.1.0")
        k2 = _cache_key("nvd", "bootstrap:4.3.0")
        assert k1 != k2


# ─────────────────────────────────────────────────────────────────────────────
# 7. Deduplication
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplication:
    def test_same_cve_from_two_sources_merged(self):
        from tools.cve_feed import CVERecord, _deduplicate

        r1 = CVERecord(cve_id="CVE-2019-11358", cvss_score=6.1, sources=["nvd"])
        r2 = CVERecord(cve_id="CVE-2019-11358", cvss_score=6.3, sources=["github"])
        result = _deduplicate([r1, r2])

        assert len(result) == 1
        assert "nvd" in result[0].sources
        assert "github" in result[0].sources

    def test_higher_cvss_score_kept_on_merge(self):
        from tools.cve_feed import CVERecord, _deduplicate

        r1 = CVERecord(cve_id="CVE-2024-0001", cvss_score=5.0, sources=["nvd"])
        r2 = CVERecord(cve_id="CVE-2024-0001", cvss_score=8.0, sources=["github"])
        result = _deduplicate([r1, r2])

        assert result[0].cvss_score == 8.0

    def test_different_cves_not_merged(self):
        from tools.cve_feed import CVERecord, _deduplicate

        r1 = CVERecord(cve_id="CVE-2019-11358", sources=["nvd"])
        r2 = CVERecord(cve_id="CVE-2021-44228", sources=["nvd"])
        result = _deduplicate([r1, r2])

        assert len(result) == 2

    def test_description_merged_from_second_when_first_empty(self):
        from tools.cve_feed import CVERecord, _deduplicate

        r1 = CVERecord(cve_id="CVE-2024-0001", description="", sources=["nvd"])
        r2 = CVERecord(cve_id="CVE-2024-0001", description="Real description", sources=["osv"])
        result = _deduplicate([r1, r2])

        assert result[0].description == "Real description"


# ─────────────────────────────────────────────────────────────────────────────
# 8. enrich_technology() end-to-end
# ─────────────────────────────────────────────────────────────────────────────

class TestEnrichTechnology:
    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        import tools.cve_feed as cf
        monkeypatch.setattr(cf, "_CACHE_DIR", tmp_path / "cve_cache")
        monkeypatch.setattr(cf, "_NVD_DELAY_S", 0)

    def test_known_tech_returns_cves(self):
        """jquery is in _TECH_MAP — all three sources queried."""
        from tools.cve_feed import enrich_technology

        with patch("tools.cve_feed._fetch_osv",      return_value=[]):
            with patch("tools.cve_feed._fetch_github_advisory",
                       return_value=[__import__("tools.cve_feed", fromlist=["CVERecord"]).CVERecord(
                           cve_id="CVE-2019-11358", cvss_score=6.1, severity="MEDIUM", sources=["github"]
                       )]):
                with patch("tools.cve_feed._fetch_nvd", return_value=[]):
                    with patch("tools.cve_feed._enrich_with_epss", side_effect=lambda x: x):
                        records = enrich_technology("jquery", "3.1.0")

        assert len(records) >= 1
        assert records[0].cve_id == "CVE-2019-11358"

    def test_unknown_tech_falls_back_to_nvd_only(self):
        """Technology not in _TECH_MAP should do NVD keyword search."""
        from tools.cve_feed import enrich_technology, CVERecord

        fake_record = CVERecord(cve_id="CVE-2024-9999", cvss_score=7.5, severity="HIGH", sources=["nvd"])

        with patch("tools.cve_feed._fetch_nvd", return_value=[fake_record]) as mock_nvd:
            with patch("tools.cve_feed._enrich_with_epss", side_effect=lambda x: x):
                records = enrich_technology("some-obscure-tech", "1.0.0")

        mock_nvd.assert_called_once()
        assert len(records) == 1

    def test_sorted_critical_first(self):
        from tools.cve_feed import enrich_technology, CVERecord

        critical = CVERecord(cve_id="CVE-2024-0001", severity="CRITICAL", sources=["nvd"])
        medium   = CVERecord(cve_id="CVE-2024-0002", severity="MEDIUM",   sources=["nvd"])

        with patch("tools.cve_feed._fetch_osv", return_value=[]):
            with patch("tools.cve_feed._fetch_github_advisory", return_value=[]):
                with patch("tools.cve_feed._fetch_nvd", return_value=[medium, critical]):
                    with patch("tools.cve_feed._enrich_with_epss", side_effect=lambda x: x):
                        records = enrich_technology("jquery", "3.1.0")

        assert records[0].severity == "CRITICAL"

    def test_returns_empty_when_all_sources_fail(self):
        from tools.cve_feed import enrich_technology

        with patch("tools.cve_feed._fetch_osv", return_value=[]):
            with patch("tools.cve_feed._fetch_github_advisory", return_value=[]):
                with patch("tools.cve_feed._fetch_nvd", return_value=[]):
                    records = enrich_technology("jquery", "3.1.0")

        assert records == []


# ─────────────────────────────────────────────────────────────────────────────
# 9. enrich_findings()
# ─────────────────────────────────────────────────────────────────────────────

class TestEnrichFindings:
    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        import tools.cve_feed as cf
        monkeypatch.setattr(cf, "_CACHE_DIR", tmp_path / "cve_cache")

    def test_adds_epss_to_existing_findings(self):
        from tools.cve_feed import enrich_findings

        findings = [{"cve": "CVE-2019-11358", "detected": "3.1.0", "severity": "HIGH"}]

        with patch("tools.cve_feed.safe_get",
                   return_value=_mock_resp(_epss_response(["CVE-2019-11358"], 0.4))):
            enriched = enrich_findings(findings)

        assert enriched[0]["epss_score"] == pytest.approx(0.4)

    def test_does_not_mutate_original(self):
        from tools.cve_feed import enrich_findings

        findings = [{"cve": "CVE-2019-11358", "severity": "HIGH"}]
        original_severity = findings[0]["severity"]

        with patch("tools.cve_feed.safe_get",
                   return_value=_mock_resp(_epss_response(["CVE-2019-11358"], 0.1))):
            enrich_findings(findings)

        assert findings[0]["severity"] == original_severity

    def test_skips_non_cve_findings(self):
        from tools.cve_feed import enrich_findings

        findings = [{"cve": "WP-OUTDATED", "detected": "5.8"}]

        with patch("tools.cve_feed.safe_get") as mock_get:
            result = enrich_findings(findings)

        # No EPSS API call should be made
        mock_get.assert_not_called()
        assert result[0]["cve"] == "WP-OUTDATED"

    def test_empty_findings_returns_empty(self):
        from tools.cve_feed import enrich_findings
        assert enrich_findings([]) == []

    def test_amplifies_high_to_critical_with_high_epss(self):
        from tools.cve_feed import enrich_findings

        findings = [{"cve": "CVE-2021-44228", "severity": "HIGH"}]

        with patch("tools.cve_feed.safe_get",
                   return_value=_mock_resp(_epss_response(["CVE-2021-44228"], 0.97))):
            enriched = enrich_findings(findings)

        assert enriched[0]["severity"] == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# 10. tech_fingerprinter integration
# ─────────────────────────────────────────────────────────────────────────────

class TestTechFingerprintCVEIntegration:
    def test_uses_live_feed_when_available(self):
        """When cve_feed returns records, tech fingerprinter includes them."""
        mock_html = b"<script src='jquery-3.1.0.min.js'></script>"
        mock_resp = MagicMock()
        mock_resp.text = mock_html.decode()
        mock_resp.headers = {}
        mock_resp.url = "https://example.com"

        live_finding = {
            "cve":             "CVE-2019-11358",
            "affected":        "jquery (detected: 3.1.0)",
            "detected":        "3.1.0",
            "description":     "Prototype pollution",
            "severity":        "MEDIUM",
            "cvss_score":      6.1,
            "epss_score":      0.0,
            "exploit_available": False,
            "fixed_version":   "3.5.0",
            "sources":         ["github"],
        }

        with patch("tools.tech_fingerprinter.safe_get", return_value=mock_resp):
            with patch("tools.tech_fingerprinter._check_cves_live", return_value=[live_finding]):
                from tools.tech_fingerprinter import fingerprint_technologies
                result_json = fingerprint_technologies.func("https://example.com")

        result = json.loads(result_json)
        assert result["status"] == "completed"
        cve_ids = [f["cve"] for f in result.get("cve_findings", [])]
        assert "CVE-2019-11358" in cve_ids

    def test_falls_back_to_static_table_when_feed_raises(self):
        """When enrich_technology raises, fallback table still provides CVEs."""
        from tools.tech_fingerprinter import _check_cves_live

        # Patch enrich_technology to raise
        with patch("tools.tech_fingerprinter.enrich_technology" if False else
                   "tools.cve_feed.enrich_technology", side_effect=ConnectionError("feed down")):
            result = _check_cves_live("jQuery", "3.1.0")

        # Fallback table should catch jQuery 3.1.0 < 3.5.0
        assert any(f["cve"] == "CVE-2019-11358" for f in result)

    def test_fallback_does_not_flag_patched_version(self):
        """jQuery 3.6.0 is safe — fallback should return no findings."""
        from tools.tech_fingerprinter import _check_fallback_cves

        result = _check_fallback_cves("jQuery", "3.6.0")
        assert result == []

    def test_fallback_flags_old_version(self):
        """jQuery 1.11.0 < 1.12.0 safe boundary → CVE-2015-9251 must appear."""
        from tools.tech_fingerprinter import _check_fallback_cves

        result = _check_fallback_cves("jQuery", "1.11.0")
        cve_ids = [f["cve"] for f in result]
        assert "CVE-2015-9251" in cve_ids

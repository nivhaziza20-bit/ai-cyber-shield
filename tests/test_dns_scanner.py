"""
Tests for DNS Security Scanner.
All DNS-over-HTTPS calls are mocked — no real network.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.dns_scanner import (
    scan_dns_security,
    _analyse_spf,
    _analyse_dmarc,
    _analyse_caa,
)


# ─────────────────────────────────────────────────────────────────────────────
# Unit — SPF analyser
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyseSpf:

    def _run(self, txt_records: list[str]) -> tuple:
        with patch("tools.dns_scanner._doh_query", return_value=txt_records):
            return _analyse_spf("example.com")

    def test_missing_spf_high_risk(self):
        risk, record, issues, _ = self._run([])
        assert risk >= 30
        assert record is None
        assert any("no spf" in i.lower() for i in issues)

    def test_spf_plus_all_critical(self):
        risk, _, issues, _ = self._run(["v=spf1 include:_spf.google.com +all"])
        assert risk >= 40
        assert any("+all" in i for i in issues)

    def test_spf_question_all_warning(self):
        risk, _, issues, _ = self._run(["v=spf1 include:_spf.google.com ?all"])
        assert risk >= 20
        assert any("?all" in i for i in issues)

    def test_spf_tilde_all_low_risk(self):
        risk, _, _, _ = self._run(["v=spf1 include:_spf.google.com ~all"])
        assert risk <= 10

    def test_spf_minus_all_zero_risk(self):
        risk, record, _, _ = self._run(["v=spf1 include:_spf.google.com -all"])
        assert risk == 0
        assert record is not None


# ─────────────────────────────────────────────────────────────────────────────
# Unit — DMARC analyser
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyseDmarc:

    def _run(self, txt_records: list[str]) -> tuple:
        with patch("tools.dns_scanner._doh_query", return_value=txt_records):
            return _analyse_dmarc("example.com")

    def test_missing_dmarc_risk(self):
        risk, record, issues, _ = self._run([])
        assert risk >= 20
        assert record is None
        assert any("dmarc" in i.lower() for i in issues)

    def test_dmarc_none_policy_penalised(self):
        risk, _, issues, _ = self._run(
            ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
        )
        assert risk >= 10
        assert any("p=none" in i or "none" in i.lower() for i in issues)

    def test_dmarc_quarantine_low_risk(self):
        risk, _, _, _ = self._run(
            ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]
        )
        assert risk <= 5

    def test_dmarc_reject_zero_risk(self):
        risk, _, issues, _ = self._run(
            ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        )
        assert risk == 0

    def test_missing_reporting_address_flagged(self):
        _, _, issues, recs = self._run(["v=DMARC1; p=reject"])
        assert any("rua" in r or "report" in r.lower() for r in recs)


# ─────────────────────────────────────────────────────────────────────────────
# Unit — CAA analyser
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyseCaa:

    def test_missing_caa_small_risk(self):
        with patch("tools.dns_scanner._doh_query", return_value=[]):
            risk, records, issues, _ = _analyse_caa("example.com")
        assert risk >= 5
        assert records == []
        assert issues

    def test_caa_present_zero_risk(self):
        with patch("tools.dns_scanner._doh_query",
                   return_value=['0 issue "letsencrypt.org"']):
            risk, records, issues, _ = _analyse_caa("example.com")
        assert risk == 0
        assert issues == []


# ─────────────────────────────────────────────────────────────────────────────
# Integration — full tool with mocked DoH
# ─────────────────────────────────────────────────────────────────────────────

class TestScanDnsSecurity:

    def _run(self, spf_records, dmarc_records, caa_records) -> dict:
        def mock_doh(name: str, rtype: str) -> list[str]:
            if rtype == "TXT" and "_dmarc" in name:
                return dmarc_records
            elif rtype == "TXT":
                return spf_records
            elif rtype == "CAA":
                return caa_records
            return []

        with patch("tools.dns_scanner._doh_query", side_effect=mock_doh):
            return json.loads(scan_dns_security.invoke({"url": "https://example.com"}))

    def test_invalid_url_rejected(self):
        result = json.loads(scan_dns_security.invoke({"url": "not-a-url"}))
        assert result["status"] == "invalid_url"

    def test_returns_required_keys(self):
        result = self._run(
            ["v=spf1 -all"],
            ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
            ['0 issue "letsencrypt.org"']
        )
        for key in ("spf", "dmarc", "caa", "risk_score", "recommendations"):
            assert key in result

    def test_no_records_high_risk(self):
        result = self._run([], [], [])
        assert result["risk_score"] >= 50

    def test_secure_domain_low_risk(self):
        result = self._run(
            ["v=spf1 include:_spf.google.com -all"],
            ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            ['0 issue "letsencrypt.org"'],
        )
        assert result["risk_score"] <= 10

    def test_www_prefix_stripped(self):
        def mock_doh(name, rtype):
            assert not name.startswith("www.")
            return []
        with patch("tools.dns_scanner._doh_query", side_effect=mock_doh):
            scan_dns_security.invoke({"url": "https://www.example.com"})

    def test_spf_record_included_in_output(self):
        result = self._run(
            ["v=spf1 include:_spf.google.com -all"], [], []
        )
        assert result["spf"]["record"] is not None
        assert "v=spf1" in result["spf"]["record"]

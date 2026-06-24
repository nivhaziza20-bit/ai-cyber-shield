"""Tests for Certificate Transparency scanner. crt.sh calls mocked."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from tools.cert_transparency import (
    scan_certificate_transparency,
    _extract_subdomains,
    _query_crtsh,
)

_SAMPLE_RECORDS = [
    {"name_value": "example.com\nwww.example.com\nstaging.example.com"},
    {"name_value": "*.example.com\nadmin.example.com"},
    {"name_value": "api.example.com\ndev.example.com\ntest.example.com"},
    {"name_value": "git.example.com"},
]


# ─────────────────────────────────────────────────────────────────────────────
# Unit — subdomain extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractSubdomains:

    def test_basic_subdomains_extracted(self):
        records = [{"name_value": "sub1.example.com\nsub2.example.com"}]
        subs = _extract_subdomains(records, "example.com")
        assert "sub1.example.com" in subs
        assert "sub2.example.com" in subs

    def test_wildcard_stripped(self):
        records = [{"name_value": "*.example.com"}]
        subs = _extract_subdomains(records, "example.com")
        assert "example.com" in subs or len(subs) == 0  # wildcard stripped, only root

    def test_root_domain_not_included(self):
        records = [{"name_value": "example.com\nsub.example.com"}]
        subs = _extract_subdomains(records, "example.com")
        assert "example.com" not in subs
        assert "sub.example.com" in subs

    def test_non_matching_domains_excluded(self):
        records = [{"name_value": "other.com\nsub.example.com"}]
        subs = _extract_subdomains(records, "example.com")
        assert "other.com" not in subs

    def test_www_excluded(self):
        records = [{"name_value": "www.example.com\napp.example.com"}]
        subs = _extract_subdomains(records, "example.com")
        assert "www.example.com" not in subs
        assert "app.example.com" in subs


# ─────────────────────────────────────────────────────────────────────────────
# Integration — mocked crt.sh API
# ─────────────────────────────────────────────────────────────────────────────

class TestScanCertTransparency:

    def _run(self, records=None, url="https://example.com"):
        records = _SAMPLE_RECORDS if records is None else records
        with patch("tools.cert_transparency._query_crtsh", return_value=records):
            return json.loads(scan_certificate_transparency.invoke({"url": url}))

    def test_invalid_url_rejected(self):
        result = json.loads(scan_certificate_transparency.invoke({"url": "ftp://x.com"}))
        assert result["status"] == "invalid_url"

    def test_completed_with_records(self):
        result = self._run()
        assert result["status"] == "completed"
        assert result["subdomain_count"] > 0

    def test_no_records_returns_no_data(self):
        result = self._run(records=[])
        assert result["status"] == "no_data"

    def test_interesting_subdomains_flagged(self):
        result = self._run()
        interesting = result["interesting_subdomains"]
        # admin, staging, dev, test, git, api should all be flagged
        names = " ".join(interesting)
        assert any(kw in names for kw in ("admin", "staging", "dev", "api", "git"))

    def test_risk_increases_with_sensitive_subs(self):
        result = self._run()
        assert result["risk_score"] > 0

    def test_clean_site_low_risk(self):
        few_records = [{"name_value": "mail.example.com"}]
        result = self._run(records=few_records)
        assert result["risk_score"] < 20

    def test_www_stripped_from_domain(self):
        result = self._run(url="https://www.example.com")
        assert result["domain"] == "example.com"

    def test_subdomain_count_correct(self):
        result = self._run()
        assert result["subdomain_count"] == len(result["all_subdomains"])

    def test_recommendation_present(self):
        result = self._run()
        assert len(result["recommendations"]) >= 1

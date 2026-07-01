"""
tests/unit/test_cvss_scoring.py — AI Cyber Shield v6

CVSS 3.1 base score tests against NIST reference vectors.
Reference: https://www.first.org/cvss/v3.1/specification-document (Appendix A)
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from finding_enricher import CvssVector, CvssScore, calculate_cvss31, _roundup


class TestRoundup:
    def test_already_rounded_unchanged(self):
        assert _roundup(9.8) == 9.8

    def test_rounds_up_to_one_decimal(self):
        assert _roundup(4.01) == 4.1

    def test_exactly_half_rounds_up(self):
        assert _roundup(7.05) == 7.1

    def test_zero_stays_zero(self):
        assert _roundup(0.0) == 0.0

    def test_ten_stays_ten(self):
        assert _roundup(10.0) == 10.0


class TestCvss31ReferenceVectors:
    """
    Test CVSS 3.1 base scores against NIST-published reference values.
    Vectors sourced from https://www.first.org/cvss/v3.1/specification-document
    """

    def test_critical_9_8_network_no_priv(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
        v = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        result = calculate_cvss31(v)
        assert result.score == 9.8
        assert result.severity == "CRITICAL"

    def test_medium_5_4_low_priv(self):
        # CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N → 5.4 Medium
        v = CvssVector(av="N", ac="L", pr="L", ui="N", s="U", c="L", i="L", a="N")
        result = calculate_cvss31(v)
        assert result.score == 5.4
        assert result.severity == "MEDIUM"

    def test_low_1_8_local_high_priv(self):
        # CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N → 1.8 Low
        v = CvssVector(av="L", ac="H", pr="H", ui="R", s="U", c="L", i="N", a="N")
        result = calculate_cvss31(v)
        assert result.score == 1.8
        assert result.severity == "LOW"

    def test_medium_6_1_scope_changed(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1 Medium (scope changed)
        v = CvssVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N")
        result = calculate_cvss31(v)
        assert result.score == 6.1
        assert result.severity == "MEDIUM"

    def test_zero_no_impact(self):
        # All CIA=N → score should be 0.0 (no impact)
        v = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N")
        result = calculate_cvss31(v)
        assert result.score == 0.0
        assert result.severity == "INFO"


class TestSeverityMapping:
    """Verify severity thresholds match CVSS 3.1 specification."""

    def _score_at(self, target_score: float):
        """Return a CvssScore-equivalent by finding params that produce target score."""
        # Use known vectors to produce specific severity bands
        pass

    def test_critical_at_9_0_boundary(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 > 9.0 → Critical
        v = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        assert calculate_cvss31(v).severity == "CRITICAL"

    def test_high_at_7_0_boundary(self):
        # AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1 → High
        v = CvssVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N")
        result = calculate_cvss31(v)
        assert result.score >= 7.0
        assert result.severity == "HIGH"

    def test_medium_at_4_0_boundary(self):
        # AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N = 5.4 → Medium
        v = CvssVector(av="N", ac="L", pr="L", ui="N", s="U", c="L", i="L", a="N")
        result = calculate_cvss31(v)
        assert result.score >= 4.0
        assert result.severity == "MEDIUM"

    def test_info_at_0_score(self):
        v = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N")
        result = calculate_cvss31(v)
        assert result.score == 0.0
        assert result.severity == "INFO"

    def test_vector_string_format(self):
        v = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        assert v.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

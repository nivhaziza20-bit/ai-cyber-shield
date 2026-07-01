"""
tests/unit/test_trend_analyzer.py — Brief 8: Trend Dashboard

8 tests verifying compute_trend_summary, detect_degradation, compute_mttr.
"""

import pytest
from datetime import datetime, timezone, timedelta

from core.trend_analyzer import (
    compute_trend_summary,
    detect_degradation,
    compute_mttr,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ts(days_ago: int) -> str:
    """Return an ISO timestamp N days ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat()


def _scan(
    score: int,
    grade: str,
    days_ago: int = 0,
    findings: list | None = None,
    category_scores: dict | None = None,
    scan_id: str = "scan-x",
) -> dict:
    return {
        "scan_id":         scan_id,
        "overall_score":   score,
        "overall_grade":   grade,
        "scanned_at":      _ts(days_ago),
        "findings":        findings or [],
        "category_scores": category_scores or {},
    }


def _f(fid: str) -> dict:
    return {"finding_id": fid, "severity": "HIGH"}


# ─── 1. test_improving_trend_detected ────────────────────────────────────────

class TestImprovingTrend:
    """test_improving_trend_detected — scores going up → 'improving'"""

    def test_improving_direction(self):
        scans = [
            _scan(60, "C", days_ago=30, scan_id="s1"),
            _scan(70, "C", days_ago=20, scan_id="s2"),
            _scan(80, "B", days_ago=10, scan_id="s3"),
            _scan(90, "A", days_ago=0,  scan_id="s4"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.trend_direction == "improving"
        assert summary.score_delta == 30
        assert summary.scan_count   == 4

    def test_small_improvement_is_stable(self):
        """Score +3 is within stable threshold."""
        scans = [
            _scan(75, "B", days_ago=7, scan_id="s1"),
            _scan(78, "B", days_ago=0, scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.trend_direction == "stable"


# ─── 2. test_degrading_trend_detected ────────────────────────────────────────

class TestDegradingTrend:
    """test_degrading_trend_detected — scores going down → 'degrading'"""

    def test_degrading_direction(self):
        scans = [
            _scan(85, "B", days_ago=30, scan_id="s1"),
            _scan(75, "C", days_ago=20, scan_id="s2"),
            _scan(60, "C", days_ago=10, scan_id="s3"),
            _scan(45, "D", days_ago=0,  scan_id="s4"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.trend_direction == "degrading"
        assert summary.score_delta == -40

    def test_grade_drop_captured(self):
        scans = [
            _scan(85, "B", days_ago=10, scan_id="s1"),
            _scan(45, "D", days_ago=0,  scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.grade_change == "B → D"


# ─── 3. test_stable_trend ─────────────────────────────────────────────────────

class TestStableTrend:
    """test_stable_trend — scores ±2 → 'stable'"""

    def test_stable_direction(self):
        scans = [
            _scan(72, "C", days_ago=14, scan_id="s1"),
            _scan(73, "C", days_ago=7,  scan_id="s2"),
            _scan(71, "C", days_ago=0,  scan_id="s3"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.trend_direction == "stable"
        assert abs(summary.score_delta) <= 5

    def test_stable_no_grade_change(self):
        scans = [
            _scan(80, "B", days_ago=7, scan_id="s1"),
            _scan(82, "B", days_ago=0, scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.grade_change is None  # same grade → no change string


# ─── 4. test_grade_change_computed ───────────────────────────────────────────

class TestGradeChange:
    """test_grade_change_computed — C→B correctly identified"""

    def test_c_to_b_grade_change(self):
        scans = [
            _scan(62, "C", days_ago=30, scan_id="s1"),
            _scan(78, "B", days_ago=0,  scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.grade_change == "C → B"
        assert summary.first_grade  == "C"
        assert summary.last_grade   == "B"

    def test_same_grade_no_change_string(self):
        scans = [
            _scan(80, "B", days_ago=7, scan_id="s1"),
            _scan(85, "B", days_ago=0, scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.grade_change is None

    def test_empty_scans_returns_unknown(self):
        summary = compute_trend_summary([])
        assert summary.trend_direction == "unknown"
        assert summary.scan_count      == 0


# ─── 5. test_mttr_calculation ─────────────────────────────────────────────────

class TestMttrCalculation:
    """test_mttr_calculation — known resolve times → correct average"""

    def test_single_resolved_finding(self):
        """f1 resolved after 10 days → MTTR = 10.0"""
        scans = [
            _scan(70, "C", days_ago=10, findings=[_f("f1"), _f("f2")], scan_id="s1"),
            _scan(85, "B", days_ago=0,  findings=[_f("f2")],            scan_id="s2"),
        ]
        mttr = compute_mttr(scans)
        assert mttr is not None
        assert abs(mttr - 10.0) < 0.5

    def test_multiple_resolved_findings(self):
        """f1, f2 both resolved after 7 days → MTTR = 7.0"""
        scans = [
            _scan(65, "C", days_ago=7, findings=[_f("f1"), _f("f2"), _f("f3")], scan_id="s1"),
            _scan(80, "B", days_ago=0, findings=[_f("f3")],                     scan_id="s2"),
        ]
        mttr = compute_mttr(scans)
        assert mttr is not None
        assert abs(mttr - 7.0) < 0.5

    def test_consecutive_scan_resolution(self):
        """Resolved in scan 2, more resolved in scan 3."""
        scans = [
            _scan(60, "C", days_ago=14, findings=[_f("f1"), _f("f2"), _f("f3")], scan_id="s1"),
            _scan(70, "C", days_ago=7,  findings=[_f("f2"), _f("f3")],           scan_id="s2"),
            _scan(85, "B", days_ago=0,  findings=[],                              scan_id="s3"),
        ]
        mttr = compute_mttr(scans)
        # f1 resolved between s1→s2 (7 days), f2+f3 resolved between s2→s3 (7 days)
        # all resolved in 7 days → avg = 7.0
        assert mttr is not None
        assert abs(mttr - 7.0) < 0.5


# ─── 6. test_mttr_null_when_no_resolves ──────────────────────────────────────

class TestMttrNull:
    """test_mttr_null_when_no_resolves — no findings resolved → null"""

    def test_no_resolved_findings(self):
        scans = [
            _scan(70, "C", days_ago=7, findings=[_f("f1"), _f("f2")], scan_id="s1"),
            _scan(72, "C", days_ago=0, findings=[_f("f1"), _f("f2"), _f("f3")], scan_id="s2"),
        ]
        mttr = compute_mttr(scans)
        assert mttr is None

    def test_single_scan(self):
        """Single scan → no pairs → MTTR = None"""
        scans = [_scan(80, "B", days_ago=0, findings=[_f("f1")], scan_id="s1")]
        mttr = compute_mttr(scans)
        assert mttr is None

    def test_empty_scans(self):
        mttr = compute_mttr([])
        assert mttr is None


# ─── 7. test_category_degradation_alert ──────────────────────────────────────

class TestCategoryDegradation:
    """test_category_degradation_alert — 20-point drop detected"""

    def test_detects_20_point_drop(self):
        scans = [
            _scan(80, "B", days_ago=30, category_scores={"ssl": 90, "dns": 85, "headers": 70}, scan_id="s1"),
            _scan(65, "C", days_ago=0,  category_scores={"ssl": 90, "dns": 55, "headers": 70}, scan_id="s2"),
        ]
        degraded = detect_degradation(scans, threshold=15)
        cats = [d["category"] for d in degraded]
        assert "dns" in cats

    def test_does_not_flag_below_threshold(self):
        scans = [
            _scan(80, "B", days_ago=7, category_scores={"ssl": 90, "dns": 80}, scan_id="s1"),
            _scan(78, "B", days_ago=0, category_scores={"ssl": 88, "dns": 72}, scan_id="s2"),
        ]
        # 8-point drop < threshold 15 → not flagged
        degraded = detect_degradation(scans, threshold=15)
        cats = [d["category"] for d in degraded]
        assert "dns" not in cats

    def test_detects_multiple_degraded_cats(self):
        scans = [
            _scan(85, "B", days_ago=30, category_scores={"ssl": 95, "cors": 80, "dns": 90}, scan_id="s1"),
            _scan(50, "D", days_ago=0,  category_scores={"ssl": 70, "cors": 50, "dns": 65}, scan_id="s2"),
        ]
        degraded = detect_degradation(scans, threshold=10)
        assert len(degraded) >= 2

    def test_single_scan_returns_empty(self):
        scans = [_scan(80, "B", days_ago=0, category_scores={"ssl": 90}, scan_id="s1")]
        degraded = detect_degradation(scans)
        assert degraded == []


# ─── 8. test_most_improved_category ──────────────────────────────────────────

class TestMostImprovedCategory:
    """test_most_improved_category — identifies correct category"""

    def test_identifies_most_improved(self):
        scans = [
            _scan(70, "C", days_ago=30, category_scores={
                "ssl": 50, "headers": 60, "dns": 75
            }, scan_id="s1"),
            _scan(85, "B", days_ago=0, category_scores={
                "ssl": 85, "headers": 65, "dns": 77   # ssl improved by 35, most
            }, scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.most_improved_category == "ssl"

    def test_no_improved_category_when_all_degraded(self):
        scans = [
            _scan(90, "A", days_ago=7, category_scores={"ssl": 95, "dns": 90}, scan_id="s1"),
            _scan(60, "C", days_ago=0, category_scores={"ssl": 70, "dns": 65}, scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.most_improved_category is None

    def test_identifies_most_degraded(self):
        scans = [
            _scan(85, "B", days_ago=7, category_scores={
                "ssl": 95, "cors": 80, "dns": 90
            }, scan_id="s1"),
            _scan(65, "C", days_ago=0, category_scores={
                "ssl": 93, "cors": 40, "dns": 85   # cors dropped by 40
            }, scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        assert summary.most_degraded_category == "cors"

    def test_categories_needing_attention_includes_low_scores(self):
        scans = [
            _scan(70, "C", days_ago=7, category_scores={"ssl": 95, "cors": 45}, scan_id="s1"),
            _scan(72, "C", days_ago=0, category_scores={"ssl": 95, "cors": 48}, scan_id="s2"),
        ]
        summary = compute_trend_summary(scans)
        attention_cats = [a["category"] for a in summary.categories_needing_attention]
        assert "cors" in attention_cats  # score < 60 → needs attention
        assert "ssl" not in attention_cats

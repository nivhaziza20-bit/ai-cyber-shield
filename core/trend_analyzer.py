"""
core/trend_analyzer.py — AI Cyber Shield v6

Analyzes scan history to compute security posture trends.
All computation from stored scan records — no new scanning triggered.

Public API:
    summary = compute_trend_summary(scans: list[dict]) -> TrendSummary
    degraded = detect_degradation(scans: list[dict], threshold: int = 15) -> list[dict]
    mttr = compute_mttr(scans: list[dict]) -> float | None
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class CategoryTrend:
    category:      str
    first_score:   Optional[float]
    last_score:    Optional[float]
    delta:         float     # positive = improved
    trend:         str       # "improving" | "stable" | "degrading" | "unknown"


@dataclass
class TrendSummary:
    scan_count:               int
    score_delta:              int           # last - first
    first_score:              Optional[int]
    last_score:               Optional[int]
    first_grade:              Optional[str]
    last_grade:               Optional[str]
    grade_change:             Optional[str]  # e.g. "C → B"
    trend_direction:          str           # "improving" | "stable" | "degrading" | "unknown"
    findings_resolved:        int
    findings_new:             int
    mean_time_to_remediate_days: Optional[float]
    most_improved_category:  Optional[str]
    most_degraded_category:  Optional[str]
    categories:              list[CategoryTrend] = field(default_factory=list)
    categories_needing_attention: list[dict] = field(default_factory=list)


_STABLE_THRESHOLD = 5   # ±5 points = stable


def _parse_ts(ts) -> Optional[datetime]:
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# ─── compute_mttr ─────────────────────────────────────────────────────────────

def compute_mttr(scans: list[dict]) -> Optional[float]:
    """
    Compute Mean Time To Remediate (in days) across the scan history.

    For each consecutive scan pair, if a finding_id in scan[N] is absent
    in scan[N+1], it was resolved. MTTR = (timestamp[N+1] - timestamp[N]).days
    Average across all such resolved findings.
    Returns None if no findings were resolved.
    """
    if len(scans) < 2:
        return None

    # Sort scans by timestamp
    sorted_scans = sorted(
        scans,
        key=lambda s: _parse_ts(s.get("scanned_at") or s.get("timestamp")) or datetime.min,
    )

    total_days = 0.0
    resolved_count = 0

    for i in range(len(sorted_scans) - 1):
        prev = sorted_scans[i]
        curr = sorted_scans[i + 1]

        t_prev = _parse_ts(prev.get("scanned_at") or prev.get("timestamp"))
        t_curr = _parse_ts(curr.get("scanned_at") or curr.get("timestamp"))
        if t_prev is None or t_curr is None:
            continue

        duration_days = max((t_curr - t_prev).total_seconds() / 86400, 0)

        prev_ids = {
            f.get("finding_id") or f.get("id")
            for f in prev.get("findings", [])
            if isinstance(f, dict)
        }
        curr_ids = {
            f.get("finding_id") or f.get("id")
            for f in curr.get("findings", [])
            if isinstance(f, dict)
        }

        resolved = prev_ids - curr_ids
        for _ in resolved:
            total_days += duration_days
            resolved_count += 1

    if resolved_count == 0:
        return None
    return round(total_days / resolved_count, 1)


# ─── detect_degradation ───────────────────────────────────────────────────────

def detect_degradation(scans: list[dict], threshold: int = 15) -> list[dict]:
    """
    Return categories that dropped by more than `threshold` points
    between the first and last scan in the list.

    Returns list of dicts: {category, current_score, delta, trend}
    """
    if len(scans) < 2:
        return []

    sorted_scans = sorted(
        scans,
        key=lambda s: _parse_ts(s.get("scanned_at") or s.get("timestamp")) or datetime.min,
    )

    first_cats = sorted_scans[0].get("category_scores") or {}
    last_cats  = sorted_scans[-1].get("category_scores") or {}

    degraded = []
    for cat, last_score in last_cats.items():
        if not isinstance(last_score, (int, float)):
            continue
        first_score = first_cats.get(cat)
        if not isinstance(first_score, (int, float)):
            continue
        delta = last_score - first_score
        if delta < -threshold:
            degraded.append({
                "category":      cat,
                "current_score": last_score,
                "first_score":   first_score,
                "trend":         "degrading",
                "delta":         delta,
            })

    return degraded


# ─── compute_trend_summary ────────────────────────────────────────────────────

def compute_trend_summary(scans: list[dict]) -> TrendSummary:
    """
    Full trend analysis for a URL's scan history.

    Args:
        scans: list of scan result dicts, each with:
               overall_score, overall_grade, scanned_at (or timestamp),
               findings (list with finding_id/id), category_scores (dict)

    Returns:
        TrendSummary with all computed fields.
    """
    if not scans:
        return TrendSummary(
            scan_count=0, score_delta=0,
            first_score=None, last_score=None,
            first_grade=None, last_grade=None,
            grade_change=None,
            trend_direction="unknown",
            findings_resolved=0, findings_new=0,
            mean_time_to_remediate_days=None,
            most_improved_category=None,
            most_degraded_category=None,
        )

    sorted_scans = sorted(
        scans,
        key=lambda s: _parse_ts(s.get("scanned_at") or s.get("timestamp")) or datetime.min,
    )

    first = sorted_scans[0]
    last  = sorted_scans[-1]

    first_score = first.get("overall_score")
    last_score  = last.get("overall_score")
    first_grade = first.get("overall_grade")
    last_grade  = last.get("overall_grade")

    score_delta = 0
    if isinstance(first_score, (int, float)) and isinstance(last_score, (int, float)):
        score_delta = int(last_score - first_score)

    # Trend direction
    if score_delta > _STABLE_THRESHOLD:
        trend_direction = "improving"
    elif score_delta < -_STABLE_THRESHOLD:
        trend_direction = "degrading"
    else:
        trend_direction = "stable" if len(scans) >= 2 else "unknown"

    # Grade change string
    grade_change = None
    if first_grade and last_grade and first_grade != last_grade:
        grade_change = f"{first_grade} → {last_grade}"

    # Findings delta (first vs last)
    first_ids = {
        f.get("finding_id") or f.get("id")
        for f in first.get("findings", [])
        if isinstance(f, dict)
    }
    last_ids = {
        f.get("finding_id") or f.get("id")
        for f in last.get("findings", [])
        if isinstance(f, dict)
    }
    findings_resolved = len(first_ids - last_ids)
    findings_new      = len(last_ids - first_ids)

    # MTTR
    mttr = compute_mttr(sorted_scans)

    # Category trends
    first_cats = first.get("category_scores") or {}
    last_cats  = last.get("category_scores")  or {}
    all_cats   = set(first_cats.keys()) | set(last_cats.keys())

    cat_trends: list[CategoryTrend] = []
    for cat in sorted(all_cats):
        fs = first_cats.get(cat)
        ls = last_cats.get(cat)
        if isinstance(fs, (int, float)) and isinstance(ls, (int, float)):
            delta = ls - fs
            if delta > _STABLE_THRESHOLD:
                direction = "improving"
            elif delta < -_STABLE_THRESHOLD:
                direction = "degrading"
            else:
                direction = "stable"
        else:
            delta = 0.0
            direction = "unknown"
        cat_trends.append(CategoryTrend(
            category    = cat,
            first_score = fs if isinstance(fs, (int, float)) else None,
            last_score  = ls if isinstance(ls, (int, float)) else None,
            delta       = delta,
            trend       = direction,
        ))

    # Most improved / most degraded
    scored_cats = [c for c in cat_trends if c.first_score is not None and c.last_score is not None]
    most_improved  = max(scored_cats, key=lambda c: c.delta, default=None)
    most_degraded  = min(scored_cats, key=lambda c: c.delta, default=None)

    most_improved_cat = most_improved.category if most_improved and most_improved.delta > 0 else None
    most_degraded_cat = most_degraded.category if most_degraded and most_degraded.delta < 0 else None

    # Categories needing attention (degrading or score < 60)
    attention = []
    for ct in cat_trends:
        if ct.trend == "degrading" or (ct.last_score is not None and ct.last_score < 60):
            attention.append({
                "category":      ct.category,
                "current_score": ct.last_score,
                "trend":         ct.trend,
                "delta":         ct.delta,
            })

    return TrendSummary(
        scan_count                   = len(scans),
        score_delta                  = score_delta,
        first_score                  = int(first_score) if isinstance(first_score, (int, float)) else None,
        last_score                   = int(last_score)  if isinstance(last_score,  (int, float)) else None,
        first_grade                  = first_grade,
        last_grade                   = last_grade,
        grade_change                 = grade_change,
        trend_direction              = trend_direction,
        findings_resolved            = findings_resolved,
        findings_new                 = findings_new,
        mean_time_to_remediate_days  = mttr,
        most_improved_category       = most_improved_cat,
        most_degraded_category       = most_degraded_cat,
        categories                   = cat_trends,
        categories_needing_attention = attention,
    )

"""
api/routers/trends.py — AI Cyber Shield v6

GET /api/v1/trends — scan history trend analysis for a URL.

Returns aggregated trend data computed from scan history.
No new scanning is triggered.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from api.auth import verify_api_key
from api.scan_store import ScanStore, get_store
from core.trend_analyzer import (
    compute_trend_summary,
    detect_degradation,
    TrendSummary,
)

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/trends", tags=["trends"])

# Valid period strings → timedelta
_PERIOD_MAP: dict[str, timedelta] = {
    "7d":   timedelta(days=7),
    "30d":  timedelta(days=30),
    "90d":  timedelta(days=90),
    "365d": timedelta(days=365),
    "1y":   timedelta(days=365),
}


# ─── Response models ──────────────────────────────────────────────────────────

class FindingsBySeverity(BaseModel):
    critical: int = 0
    high:     int = 0
    medium:   int = 0
    low:      int = 0
    info:     int = 0


class TrendDataPoint(BaseModel):
    scan_id:              str
    date:                 str
    score:                Optional[int]
    grade:                Optional[str]
    findings_by_severity: FindingsBySeverity
    category_scores:      dict[str, float]


class CategoryAttention(BaseModel):
    category:      str
    current_score: Optional[float]
    trend:         str
    delta:         float


class TrendSummaryResponse(BaseModel):
    score_delta:                  int
    grade_change:                 Optional[str]
    trend_direction:              str
    findings_resolved:            int
    findings_new:                 int
    mean_time_to_remediate_days:  Optional[float]
    most_improved_category:       Optional[str]
    most_degraded_category:       Optional[str]
    categories_needing_attention: list[CategoryAttention]


class TrendsResponse(BaseModel):
    url:         str
    period:      str
    scan_count:  int
    data_points: list[TrendDataPoint]
    summary:     TrendSummaryResponse


def _severity_counts(findings: list) -> FindingsBySeverity:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        if isinstance(f, dict):
            sev = (f.get("severity") or "INFO").upper()
            if sev in counts:
                counts[sev] += 1
        else:
            sev = getattr(f, "severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
    return FindingsBySeverity(
        critical = counts["CRITICAL"],
        high     = counts["HIGH"],
        medium   = counts["MEDIUM"],
        low      = counts["LOW"],
        info     = counts["INFO"],
    )


# ─── Endpoint ─────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=TrendsResponse,
    summary="Scan history trend analysis",
)
async def get_trends(
    url:      str  = Query(..., description="Target URL to analyze trends for"),
    period:   str  = Query("30d", description="Time period: 7d | 30d | 90d | 365d"),
    store:    ScanStore = Depends(get_store),
    _api_key: str       = Depends(verify_api_key),
) -> TrendsResponse:
    """
    Analyze security posture evolution over time for a given URL.

    Returns score trend, grade changes, MTTR, and per-category trends.
    Requires at least 1 completed scan for the URL.
    Available on all tiers.
    """
    if period not in _PERIOD_MAP:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Invalid period '{period}'. Use: {', '.join(_PERIOD_MAP)}",
                "code":  "INVALID_PERIOD",
            },
        )

    period_delta = _PERIOD_MAP[period]
    cutoff = datetime.now(timezone.utc) - period_delta

    # Filter completed scans for the URL within the requested period
    all_states = store.list(url_filter=url, status_filter="completed", page=1, per_page=500)

    def _in_period(state) -> bool:
        ts = state.completed_at or state.created_at
        if not ts:
            return True
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt >= cutoff
        except (ValueError, TypeError):
            return True

    matching = [s for s in all_states if _in_period(s)]

    if not matching:
        # Try without url filter if maybe the url format differs
        all_states_no_filter = store.list(status_filter="completed", page=1, per_page=500)
        matching = [s for s in all_states_no_filter if _in_period(s) and url in (s.url or "")]

    if not matching:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": f"No completed scans found for '{url}' in the last {period}",
                "code":  "NO_SCANS_FOUND",
            },
        )

    # Build scan dicts for trend_analyzer
    scan_dicts: list[dict] = []
    for state in matching:
        findings_raw = []
        for f in state.findings:
            if hasattr(f, "to_dict"):
                findings_raw.append(f.to_dict())
            elif isinstance(f, dict):
                findings_raw.append(f)

        scan_dicts.append({
            "scan_id":         state.scan_id,
            "scanned_at":      state.completed_at or state.created_at,
            "overall_score":   state.overall_score,
            "overall_grade":   state.overall_grade,
            "findings":        findings_raw,
            "category_scores": state.raw_result.get("category_scores", {}),
        })

    # Compute summary
    summary = compute_trend_summary(scan_dicts)

    # Build data points
    data_points = []
    for sd in sorted(scan_dicts, key=lambda s: s.get("scanned_at") or ""):
        ts = sd.get("scanned_at") or ""
        if isinstance(ts, datetime):
            ts = ts.isoformat()
        cat_scores = sd.get("category_scores") or {}
        data_points.append(TrendDataPoint(
            scan_id              = sd["scan_id"],
            date                 = str(ts),
            score                = sd.get("overall_score"),
            grade                = sd.get("overall_grade"),
            findings_by_severity = _severity_counts(sd.get("findings") or []),
            category_scores      = {k: float(v) for k, v in cat_scores.items() if isinstance(v, (int, float))},
        ))

    return TrendsResponse(
        url         = url,
        period      = period,
        scan_count  = len(matching),
        data_points = data_points,
        summary     = TrendSummaryResponse(
            score_delta                  = summary.score_delta,
            grade_change                 = summary.grade_change,
            trend_direction              = summary.trend_direction,
            findings_resolved            = summary.findings_resolved,
            findings_new                 = summary.findings_new,
            mean_time_to_remediate_days  = summary.mean_time_to_remediate_days,
            most_improved_category       = summary.most_improved_category,
            most_degraded_category       = summary.most_degraded_category,
            categories_needing_attention = [
                CategoryAttention(**a)
                for a in summary.categories_needing_attention
            ],
        ),
    )

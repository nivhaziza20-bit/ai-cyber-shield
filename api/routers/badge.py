"""
api/routers/badge.py — AI Cyber Shield v6

Public endpoint returning a dynamic SVG security-score badge.
No authentication required — badges must be publicly accessible
so they can be embedded in READMEs and web pages.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from api.scan_store import ScanStore, get_store

router = APIRouter(tags=["badge"])

_GRADE_COLORS = {
    "A": "#22c55e",
    "B": "#3b82f6",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}
_GRAY = "#6b7280"


def _badge_svg(label: str, color: str) -> str:
    """
    Render a shields.io-style badge with left panel 'security' and
    right panel showing the label in the given color.
    """
    left_w  = 74
    right_w = max(len(label) * 7 + 20, 70)
    total_w = left_w + right_w

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="{total_w}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <rect width="{left_w}" height="20" fill="#555"/>
    <rect x="{left_w}" width="{right_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{left_w // 2}" y="15" fill="#010101" fill-opacity=".3">security</text>
    <text x="{left_w // 2}" y="14">security</text>
    <text x="{left_w + right_w // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{left_w + right_w // 2}" y="14">{label}</text>
  </g>
</svg>"""


def _not_scanned_badge() -> str:
    return _badge_svg("not scanned", _GRAY)


def _score_badge(grade: str, score: int) -> str:
    color = _GRADE_COLORS.get(grade.upper(), _GRAY)
    label = f"{grade} ({score}/100)"
    return _badge_svg(label, color)


@router.get(
    "/badge/{domain}",
    summary="Dynamic security score badge (public, no auth)",
    response_class=Response,
    responses={200: {"content": {"image/svg+xml": {}}}},
)
def get_badge(
    domain: str,
    store: ScanStore = Depends(get_store),
) -> Response:
    """
    Return a shields.io-style SVG badge with the most recent
    security grade and score for the given domain.

    Embed in Markdown:
        ![Security](https://api.example.com/badge/yoursite.com)
    """
    # Find the most recent completed scan for this domain
    page = 1
    found_grade = None
    found_score = None

    while True:
        items, total = store.list(
            url_filter=domain,
            status_filter="complete",
            page=page,
            per_page=50,
        )
        if not items:
            break
        # list() returns newest-first; first match is the most recent
        for scan in items:
            if (
                domain.lower() in scan.url.lower()
                and scan.overall_grade
                and scan.overall_score is not None
            ):
                found_grade = scan.overall_grade
                found_score = scan.overall_score
                break
        if found_grade is not None:
            break
        if page * 50 >= total:
            break
        page += 1

    if found_grade is None:
        svg = _not_scanned_badge()
    else:
        svg = _score_badge(found_grade, found_score)

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            # Cache for 1 hour — badge data is stale-safe
            "Cache-Control": "max-age=3600, public",
            "Content-Type": "image/svg+xml; charset=utf-8",
        },
    )

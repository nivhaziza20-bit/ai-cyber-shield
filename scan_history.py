"""Scan history persistence and comparison — Supabase-backed."""
from __future__ import annotations
import logging
import json
from typing import Optional
import streamlit as st

_log = logging.getLogger(__name__)


def _client():
    from auth.streamlit_auth import _client as auth_client
    return auth_client()


# ── Save / load ───────────────────────────────────────────────────────────────

def save_scan(
    user_id: str,
    target_url: str,
    overall_grade: str,
    overall_score: int,
    category_scores: dict,
    critical_count: int,
    high_count: int,
    scan_mode: str,
    scan_duration_s: float,
    report_md: str,
) -> Optional[str]:
    """Persist a completed scan to Supabase scan_history. Returns the new record ID or None."""
    c = _client()
    if c is None:
        return None
    try:
        resp = c.table("scan_history").insert({
            "user_id":        user_id,
            "target_url":     target_url,
            "overall_grade":  overall_grade,
            "overall_score":  overall_score,
            "category_scores": category_scores,
            "findings_count": critical_count + high_count,
            "critical_count": critical_count,
            "high_count":     high_count,
            "scan_mode":      scan_mode,
            "scan_duration_s": round(scan_duration_s, 2),
            "report_md":      report_md[:50_000],  # safety limit
        }).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        _log.debug("save_scan: %s", exc)
        return None


def load_history(user_id: str, limit: int = 20) -> list[dict]:
    """Return the user's last `limit` scans, newest first."""
    c = _client()
    if c is None:
        return []
    try:
        resp = (c.table("scan_history")
                .select("id,target_url,overall_grade,overall_score,critical_count,high_count,scan_mode,scan_duration_s,created_at")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .limit(limit)
                .execute())
        return resp.data or []
    except Exception as exc:
        _log.debug("load_history: %s", exc)
        return []


def load_scan_detail(scan_id: str) -> Optional[dict]:
    """Load a full scan record (including report_md) by ID."""
    c = _client()
    if c is None:
        return None
    try:
        resp = c.table("scan_history").select("*").eq("id", scan_id).maybe_single().execute()
        return resp.data
    except Exception as exc:
        _log.debug("load_scan_detail: %s", exc)
        return None


# ── Comparison ────────────────────────────────────────────────────────────────

def compare_scans(scan_a: dict, scan_b: dict) -> dict:
    """
    Generate a diff between two scan records.
    Returns delta: score_delta, grade_delta, per-category deltas, improved/regressed lists.
    """
    score_a = scan_a.get("overall_score", 0)
    score_b = scan_b.get("overall_score", 0)
    score_delta = score_b - score_a

    cats_a: dict = scan_a.get("category_scores") or {}
    cats_b: dict = scan_b.get("category_scores") or {}

    if isinstance(cats_a, str):
        try: cats_a = json.loads(cats_a)
        except Exception: cats_a = {}
    if isinstance(cats_b, str):
        try: cats_b = json.loads(cats_b)
        except Exception: cats_b = {}

    all_cats = set(cats_a) | set(cats_b)
    cat_deltas: list[dict] = []
    improved:  list[str] = []
    regressed: list[str] = []

    for cat in sorted(all_cats):
        before = cats_a.get(cat, 0)
        after  = cats_b.get(cat, 0)
        delta  = after - before
        cat_deltas.append({"category": cat, "before": before, "after": after, "delta": delta})
        if delta > 5:
            improved.append(cat)
        elif delta < -5:
            regressed.append(cat)

    return {
        "target_url":    scan_b.get("target_url", ""),
        "scan_a_date":   (scan_a.get("created_at") or "")[:10],
        "scan_b_date":   (scan_b.get("created_at") or "")[:10],
        "score_a":       score_a,
        "score_b":       score_b,
        "score_delta":   score_delta,
        "grade_a":       scan_a.get("overall_grade", "?"),
        "grade_b":       scan_b.get("overall_grade", "?"),
        "critical_delta": scan_b.get("critical_count", 0) - scan_a.get("critical_count", 0),
        "high_delta":    scan_b.get("high_count", 0) - scan_a.get("high_count", 0),
        "category_deltas": cat_deltas,
        "improved":      improved,
        "regressed":     regressed,
    }


# ── Streamlit UI ──────────────────────────────────────────────────────────────

def show_scan_history_panel(user_id: str) -> None:
    """Render the scan history + comparison UI."""
    st.markdown("## 📊 Scan History")

    rows = load_history(user_id, limit=20)
    if not rows:
        st.info("No scans saved yet. Run your first scan to start tracking history.")
        return

    import pandas as pd
    df_rows = []
    for r in rows:
        ts  = (r.get("created_at") or "")[:16].replace("T", " ")
        url = r.get("target_url", "")[:50]
        df_rows.append({
            "Date (UTC)": ts,
            "URL":         url,
            "Grade":       r.get("overall_grade", "?"),
            "Score":       r.get("overall_score", 0),
            "Critical":    r.get("critical_count", 0),
            "High":        r.get("high_count", 0),
            "Mode":        r.get("scan_mode", ""),
            "id":          r.get("id", ""),
        })
    df = pd.DataFrame(df_rows)

    def _color_grade(val: str) -> str:
        return {
            "A+": "color:#10b981;font-weight:700",
            "A":  "color:#10b981;font-weight:700",
            "B":  "color:#3b82f6",
            "C":  "color:#f59e0b",
            "D":  "color:#f97316",
            "F":  "color:#ef4444;font-weight:700",
        }.get(val, "")

    styled = df.drop(columns=["id"]).style.map(_color_grade, subset=["Grade"])
    st.dataframe(styled, use_container_width=True, hide_index=True)

    # ── Comparison tool ───────────────────────────────────────────────────────
    st.markdown("### 🔄 Compare Two Scans")
    if len(rows) < 2:
        st.caption("Need at least 2 scans to compare.")
        return

    scan_labels = {
        f"{(r.get('created_at') or '')[:16]} — {r.get('target_url','')[:40]} ({r.get('overall_grade','?')})": r
        for r in rows
    }
    labels = list(scan_labels.keys())

    col1, col2 = st.columns(2)
    with col1:
        label_a = st.selectbox("Scan A (before)", labels, index=min(1, len(labels)-1), key="cmp_a")
    with col2:
        label_b = st.selectbox("Scan B (after)",  labels, index=0, key="cmp_b")

    if st.button("Compare →", type="primary", key="cmp_btn"):
        if label_a == label_b:
            st.warning("Select two different scans to compare.")
            return

        scan_a_row = scan_labels[label_a]
        scan_b_row = scan_labels[label_b]

        detail_a = load_scan_detail(scan_a_row["id"])
        detail_b = load_scan_detail(scan_b_row["id"])

        if not detail_a or not detail_b:
            st.error("Could not load scan details.")
            return

        diff = compare_scans(detail_a, detail_b)
        _render_comparison(diff)


def _render_comparison(diff: dict) -> None:
    """Render the diff result."""
    import pandas as pd

    score_delta = diff["score_delta"]
    delta_sign  = "+" if score_delta >= 0 else ""
    delta_color = "#10b981" if score_delta >= 0 else "#ef4444"

    st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1f2d3d;border-radius:12px;padding:24px;margin-top:16px;">
  <div style="text-align:center;margin-bottom:16px;">
    <span style="font-size:0.75rem;color:#475569;text-transform:uppercase;letter-spacing:0.1em;">Score Change</span><br>
    <span style="font-size:2.5rem;font-weight:900;color:{delta_color};">{delta_sign}{score_delta}</span>
    <span style="color:#475569;font-size:1rem;"> points</span>
  </div>
  <div style="display:flex;justify-content:space-around;text-align:center;">
    <div>
      <div style="font-size:0.7rem;color:#475569;">Before ({diff['scan_a_date']})</div>
      <div style="font-size:1.8rem;font-weight:700;color:#c9d1d9;">{diff['grade_a']}</div>
      <div style="color:#475569;">{diff['score_a']}/100</div>
    </div>
    <div style="color:#475569;font-size:2rem;padding-top:16px;">→</div>
    <div>
      <div style="font-size:0.7rem;color:#475569;">After ({diff['scan_b_date']})</div>
      <div style="font-size:1.8rem;font-weight:700;color:#c9d1d9;">{diff['grade_b']}</div>
      <div style="color:#475569;">{diff['score_b']}/100</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

    if diff["improved"]:
        st.success(f"Improved categories: {', '.join(diff['improved'])}")
    if diff["regressed"]:
        st.warning(f"Regressed categories: {', '.join(diff['regressed'])}")

    # Category delta table
    cat_df = pd.DataFrame(diff["category_deltas"])
    if not cat_df.empty:
        def _delta_color(val):
            if isinstance(val, (int, float)):
                if val > 5:  return "color:#10b981"
                if val < -5: return "color:#ef4444"
            return ""
        st.dataframe(
            cat_df.style.map(_delta_color, subset=["delta"]),
            use_container_width=True,
            hide_index=True,
        )

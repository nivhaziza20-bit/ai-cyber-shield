"""API Documentation page — Swagger-style reference for AI Cyber Shield API."""
from __future__ import annotations
import streamlit as st

_ENDPOINTS = [
    {
        "method": "POST",
        "path":   "/api/v1/scan",
        "summary": "Run a security scan",
        "description": "Submits a target URL for scanning. Returns a job ID. Use GET /api/v1/scan/{job_id} to poll results.",
        "body": {
            "target_url":  "string — HTTPS URL to scan",
            "mode":        "'standard' | 'passive' — default: standard",
            "notify_email": "bool — send email on completion (paid only)",
        },
        "response": {
            "job_id":   "UUID of the queued scan",
            "status":   "'queued' | 'running' | 'complete' | 'error'",
            "eta_s":    "Estimated seconds to completion",
        },
        "auth":   "Bearer JWT",
        "tier":   "All tiers",
        "color":  "#3b82f6",
    },
    {
        "method": "GET",
        "path":   "/api/v1/scan/{job_id}",
        "summary": "Poll scan results",
        "description": "Returns the current status and, when complete, the full security report.",
        "body": None,
        "response": {
            "status":         "'complete'",
            "overall_grade":  "A+ … F",
            "overall_score":  "0–100",
            "category_scores": "dict[category → score]",
            "findings":       "list of finding objects",
            "recommendations": "list of prioritized action items",
            "report_md":      "Full Markdown report",
        },
        "auth":   "Bearer JWT",
        "tier":   "All tiers",
        "color":  "#22d3ee",
    },
    {
        "method": "GET",
        "path":   "/api/v1/scans",
        "summary": "List scan history",
        "description": "Returns the authenticated user's recent scan results.",
        "body": None,
        "response": {
            "scans": "list — id, target_url, grade, score, created_at",
            "total": "int — total scans",
        },
        "auth":   "Bearer JWT",
        "tier":   "All tiers",
        "color":  "#22d3ee",
    },
    {
        "method": "GET",
        "path":   "/api/v1/quota",
        "summary": "Check daily quota",
        "description": "Returns how many scans the user has used and how many remain today.",
        "body": None,
        "response": {
            "used":      "int",
            "limit":     "int (-1 = unlimited)",
            "remaining": "int",
            "resets_at": "ISO 8601 timestamp",
        },
        "auth":   "Bearer JWT",
        "tier":   "All tiers",
        "color":  "#22d3ee",
    },
    {
        "method": "POST",
        "path":   "/api/v1/schedules",
        "summary": "Create a scheduled scan",
        "description": "Schedule a recurring scan. Paid tiers only.",
        "body": {
            "target_url":       "string",
            "cron_expression":  "string — '0 6 * * *'",
            "label":            "string — optional label",
        },
        "response": {
            "schedule_id": "UUID",
            "next_run_at": "ISO 8601 timestamp",
        },
        "auth":   "Bearer JWT",
        "tier":   "Starter+",
        "color":  "#3b82f6",
    },
    {
        "method": "DELETE",
        "path":   "/api/v1/schedules/{schedule_id}",
        "summary": "Delete a scheduled scan",
        "description": "Cancels a recurring scan schedule.",
        "body": None,
        "response": {"deleted": "bool"},
        "auth":   "Bearer JWT",
        "tier":   "Starter+",
        "color":  "#ef4444",
    },
    {
        "method": "GET",
        "path":   "/api/v1/health",
        "summary": "Health check",
        "description": "Returns service status — no auth required.",
        "body": None,
        "response": {
            "status": "'ok'",
            "version": "string",
            "db": "'ok' | 'degraded'",
        },
        "auth":   "None",
        "tier":   "All tiers",
        "color":  "#22d3ee",
    },
]

_METHOD_COLORS = {
    "GET":    "#22d3ee",
    "POST":   "#3b82f6",
    "DELETE": "#ef4444",
    "PUT":    "#f59e0b",
    "PATCH":  "#8b5cf6",
}

_CURL_EXAMPLES = {
    "/api/v1/scan": '''curl -X POST https://api.ai-cyber-shield.com/api/v1/scan \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"target_url": "https://example.com", "mode": "standard"}'
''',
    "/api/v1/quota": '''curl https://api.ai-cyber-shield.com/api/v1/quota \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
''',
    "/api/v1/health": '''curl https://api.ai-cyber-shield.com/api/v1/health
''',
}


def show_api_docs() -> None:
    """Render the full API documentation page."""
    st.markdown("# 📡 API Documentation")
    st.caption("REST API for AI Cyber Shield — integrate security scanning into your CI/CD pipeline.")

    st.info(
        "🚧 **API is in beta** — endpoints are stable but require manual JWT token extraction from "
        "your browser session. A dedicated API key system (Starter+) is coming in Q3 2026."
    )

    # Auth section
    with st.expander("🔐 Authentication", expanded=True):
        st.markdown("""
All protected endpoints require a **Bearer JWT** in the Authorization header.

**Get your token:**
1. Log in to AI Cyber Shield
2. Open browser DevTools → Application → Local Storage → find `access_token`
3. Use it as: `Authorization: Bearer <token>`

Tokens expire after **1 hour**. Refresh by logging in again.

**Base URL:** `https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app/api/v1`
*(Dedicated API subdomain coming in Q3 2026)*
        """)

    # Rate limits
    with st.expander("⚡ Rate Limits"):
        st.markdown("""
| Tier | Scans/day | API req/min |
|------|-----------|-------------|
| Free | 5 | 10 |
| Starter ($29) | 50 | 60 |
| Professional ($99) | 200 | 300 |
| Enterprise ($299) | Unlimited | Unlimited |

Exceeded limits return **HTTP 429** with `Retry-After` header.
        """)

    st.divider()
    st.markdown("## Endpoints")

    for ep in _ENDPOINTS:
        method = ep["method"]
        m_color = _METHOD_COLORS.get(method, "#475569")
        tier_badge = (
            f"<span style='background:#1e293b;color:#f59e0b;border-radius:4px;padding:2px 8px;"
            f"font-size:0.65rem;font-weight:700;'>{ep['tier']}</span>"
            if ep["tier"] != "All tiers" else ""
        )

        with st.expander(
            f"{method}  {ep['path']} — {ep['summary']}",
            expanded=False,
        ):
            st.markdown(
                f"""<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
                <span style="background:{m_color}33;color:{m_color};border:1px solid {m_color}66;
                             border-radius:4px;padding:4px 12px;font-weight:700;font-family:monospace;">
                  {method}
                </span>
                <code style="color:#c9d1d9;background:#0a0e1a;padding:4px 12px;border-radius:4px;">
                  {ep['path']}
                </code>
                {tier_badge}
                </div>""",
                unsafe_allow_html=True,
            )

            st.markdown(ep["description"])

            if ep.get("body"):
                st.markdown("**Request body (JSON):**")
                body_lines = "\n".join(f'  "{k}": {v}' for k, v in ep["body"].items())
                st.code(f"{{\n{body_lines}\n}}", language="json")

            if ep.get("response"):
                st.markdown("**Response (JSON):**")
                resp_lines = "\n".join(f'  "{k}": {v}' for k, v in ep["response"].items())
                st.code(f"{{\n{resp_lines}\n}}", language="json")

            # Auth
            st.caption(f"Auth: `{ep['auth']}` · Tier: **{ep['tier']}**")

            # cURL example
            path_key = ep["path"].split("{")[0].rstrip("/")
            if path_key in _CURL_EXAMPLES:
                st.markdown("**cURL example:**")
                st.code(_CURL_EXAMPLES[path_key], language="bash")

    st.divider()

    # SDKs
    st.markdown("## 🛠 SDKs & Integration Examples")
    tab_py, tab_js, tab_gh = st.tabs(["Python", "JavaScript", "GitHub Actions"])

    with tab_py:
        st.code('''import requests

API_BASE = "https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app/api/v1"
TOKEN = "YOUR_JWT_TOKEN"

headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# Start scan
resp = requests.post(f"{API_BASE}/scan",
    json={"target_url": "https://example.com", "mode": "standard"},
    headers=headers)
job = resp.json()
print(f"Job ID: {job['job_id']}")

# Poll for result
import time
while True:
    result = requests.get(f"{API_BASE}/scan/{job['job_id']}", headers=headers).json()
    if result["status"] == "complete":
        print(f"Grade: {result['overall_grade']} ({result['overall_score']}/100)")
        break
    time.sleep(5)
''', language="python")

    with tab_js:
        st.code('''const API_BASE = "https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app/api/v1";
const TOKEN = "YOUR_JWT_TOKEN";

const headers = { "Authorization": `Bearer ${TOKEN}`, "Content-Type": "application/json" };

// Start scan
const { job_id } = await fetch(`${API_BASE}/scan`, {
  method: "POST",
  headers,
  body: JSON.stringify({ target_url: "https://example.com", mode: "standard" }),
}).then(r => r.json());

// Poll for result
const poll = async () => {
  const result = await fetch(`${API_BASE}/scan/${job_id}`, { headers }).then(r => r.json());
  if (result.status === "complete") return result;
  await new Promise(r => setTimeout(r, 5000));
  return poll();
};
const report = await poll();
console.log(`Grade: ${report.overall_grade} (${report.overall_score}/100)`);
''', language="javascript")

    with tab_gh:
        st.code('''# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"  # Every Monday at 6 AM

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Run AI Cyber Shield scan
        run: |
          JOB=$(curl -s -X POST \\
            -H "Authorization: Bearer ${{ secrets.ACS_TOKEN }}" \\
            -H "Content-Type: application/json" \\
            -d \'{"target_url":"${{ vars.SCAN_TARGET }}","mode":"standard"}\' \\
            https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app/api/v1/scan)

          JOB_ID=$(echo $JOB | jq -r .job_id)
          echo "Scan job: $JOB_ID"

          # Poll until complete
          for i in $(seq 1 24); do
            sleep 10
            RESULT=$(curl -s -H "Authorization: Bearer ${{ secrets.ACS_TOKEN }}" \\
              https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app/api/v1/scan/$JOB_ID)
            STATUS=$(echo $RESULT | jq -r .status)
            if [ "$STATUS" = "complete" ]; then
              GRADE=$(echo $RESULT | jq -r .overall_grade)
              SCORE=$(echo $RESULT | jq -r .overall_score)
              echo "Security Grade: $GRADE ($SCORE/100)"
              # Fail build if grade is F or D
              if [ "$GRADE" = "F" ] || [ "$GRADE" = "D" ]; then exit 1; fi
              break
            fi
          done
''', language="yaml")

"""
cyber_shield_pdf_app.py
Streamlit frontend with PDF export.

Five bugs fixed from the original submission
─────────────────────────────────────────────
Bug 1 — Wrong import paths (recurring)
  BEFORE: from guardrails   import sanitize_input   # ModuleNotFoundError
          from agent_engine import run_security_audit  # ModuleNotFoundError
  FIXED:  from tools.input_sanitizer       import sanitize_input
          from crew_pipeline_with_alerts   import run_security_audit

Bug 2 — sanitize_input() return type misuse (recurring)
  BEFORE: safe_input = sanitize_input(user_input)      # returns SanitizeResult
          run_security_audit(safe_input)               # expects str → TypeError
          Also: run_security_audit already calls sanitize_input internally,
          so this was double-sanitizing with a wrong-typed argument.
  FIXED:  Remove the external sanitize_input() call.
          run_security_audit(user_input) — pipeline handles it.
          Use sanitize_input() only for the pre-flight risk badge in the UI.

Bug 3 — run_security_audit() dict mishandled in two places
  BEFORE: st.session_state.report = run_security_audit(safe_input)
          # run_security_audit returns {"raw_output": str, "risk_score": int, ...}
          st.markdown(st.session_state.report)      # renders dict repr, not Markdown
          create_pdf(st.session_state.report)       # str.replace() on a dict → TypeError
  FIXED:  report_dict = run_security_audit(user_input)
          st.session_state.report = report_dict["raw_output"]   # store the string

Bug 4 — pdf.output(dest='S') removed in fpdf2 2.7+
  BEFORE: return pdf.output(dest='S')
          # dest='S' was deprecated in fpdf2 2.x and REMOVED in 2.7.3.
          # Raises: TypeError: output() got an unexpected keyword argument 'dest'
          # Even in older versions it returned a Latin-1 string, not bytes,
          # breaking st.download_button which requires bytes.
  FIXED:  return bytes(pdf.output())
          # fpdf2 2.x output() returns bytes with no arguments.

Bug 5 — Markdown stripping destroys code content
  BEFORE: clean_text = text_content.replace("#", "").replace("*", "")
          # "#" removal also strips:
          #   Python comments:  # this is a comment  →  this is a comment (OK-ish)
          #   C includes:       #include <stdio.h>   →  include <stdio.h>  (broken)
          #   Hex colours:      color: #ff0000       →  color: ff0000      (broken)
          #   C preprocessor:   #define MAX 100      →  define MAX 100     (broken)
          # "**bold**" → "bold" is actually correct, but:
          #   Python exponent:  2**8 = 256           →  2 = 256            (broken)
          #   Pointer deref:    **argv               →  argv               (broken)
  FIXED:  _strip_markdown() uses regex that targets only structural Markdown
          tokens at the START of lines (headers) or SURROUNDING words
          (bold/italic), never touches # or * inside code blocks.
"""

import re
import sys
from io import BytesIO
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv
sys.path.insert(0, str(Path(__file__).resolve().parent))
load_dotenv(override=False)

# FIX 1: correct import paths
from tools.input_sanitizer import sanitize_input       # for pre-flight UI badge only
from tools.pdf_exporter import create_pdf              # reuses standalone PDF utility
# run_security_audit imported lazily inside functions to avoid crewai module-level crash


# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Cyber Shield Agent",
    page_icon="🛡",
    layout="wide",
)

# ─────────────────────────────────────────────────────────────────────────────
# Demo Mode report — returned when no API key is configured
# ─────────────────────────────────────────────────────────────────────────────
_DEMO_REPORT = """\
## Executive Summary

**Target:** `demo/vulnerable_app.py`
**Scan Date:** 2026-06-19
**Scanner:** AI Cyber Shield v1.0 (Demo Mode)

| Severity | Count |
|----------|-------|
| CRITICAL | 1     |
| HIGH     | 1     |
| MEDIUM   | 1     |
| LOW      | 1     |

---

## Confirmed Findings

#### [CRITICAL] VID-1: SQL Injection via String Concatenation

| Field  | Value |
|--------|-------|
| CVSS   | 9.8   |
| Vector | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| OWASP  | A03:2021 — Injection |
| Line   | 14    |

**Vulnerable Code:**
```python
query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)
```

**Remediation:** Use parameterised queries with placeholders.

```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

---

#### [HIGH] VID-2: OS Command Injection in run_report()

| Field  | Value |
|--------|-------|
| CVSS   | 8.1   |
| Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| OWASP  | A03:2021 — Injection |
| Line   | 31    |

**Vulnerable Code:**
```python
os.system("generate_report.sh " + filename)
```

**Remediation:** Use `subprocess.run` with a list argument — never shell=True with user input.

```python
subprocess.run(["generate_report.sh", filename], check=True)
```

---

#### [MEDIUM] VID-3: Hardcoded Secret in Source

| Field  | Value |
|--------|-------|
| CVSS   | 5.5   |
| OWASP  | A02:2021 — Cryptographic Failures |
| Line   | 5     |

**Vulnerable Code:**
```python
SECRET_KEY = "abc123supersecret"
```

**Remediation:** Load from environment variable via `python-dotenv`.

---

#### [LOW] VID-4: Debug Mode Enabled in Production

| Field  | Value |
|--------|-------|
| CVSS   | 3.1   |
| OWASP  | A05:2021 — Security Misconfiguration |
| Line   | 2     |

**Remediation:** Set `DEBUG = os.getenv("DEBUG", "false").lower() == "true"`.

---

## Hardening Checklist

- [ ] Replace all string-concatenated queries with parameterised queries (VID-1)
- [ ] Replace os.system() calls with subprocess.run(list) (VID-2)
- [ ] Move all secrets to .env — never commit credentials (VID-3)
- [ ] Disable DEBUG in production via environment variable (VID-4)
- [ ] Add SAST to CI/CD pipeline (Bandit + Semgrep)
- [ ] Review OWASP ASVS Level 2 checklist before next release

---

*This is a DEMO report. Connect an API key to run a real scan on your code.*
"""

# ─────────────────────────────────────────────────────────────────────────────
# Session state
# ─────────────────────────────────────────────────────────────────────────────
if "report" not in st.session_state:
    st.session_state.report = None     # stores the Markdown STRING, not the dict
if "risk_meta" not in st.session_state:
    st.session_state.risk_meta = None  # stores {risk_score, detections, high_sev_findings}

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar — Demo Mode toggle
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ הגדרות")
    demo_mode = st.toggle("Demo Mode (ללא API Key)", value=True)
    if demo_mode:
        st.success("✅ Demo Mode פעיל\nהדוח הוא לדוגמה בלבד — ללא קריאת API.")
    else:
        st.info("🔑 Live Mode\nדורש ANTHROPIC_API_KEY ב-.env")
    st.divider()
    st.caption("AI Cyber Shield v1.0")

# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────
st.title("🛡 AI Cyber Shield — מערכת קצה לסוכני סייבר")
st.write(
    "סריקת קוד מקור ואתרים בזמן אמת, ניתוח חולשות, התראות Slack, והפקת דוחות PDF רשמיים."
)

# ─────────────────────────────────────────────────────────────────────────────
# Input
# ─────────────────────────────────────────────────────────────────────────────
user_input = st.text_area("הזן קוד מקור או כתובת URL לבדיקה:", height=200)

# Pre-flight risk indicator — shown before the user clicks Run
if user_input.strip():
    pre = sanitize_input(user_input)
    if pre.is_high_risk:
        st.warning(
            f"⚠️ קלט חשוד (risk score {pre.risk_score}/100) — "
            f"הצינור יסרב להריץ אינפוט זה. אותות: {', '.join(pre.detections)}"
        )
    elif pre.risk_score > 0:
        st.caption(f"ℹ️ אותות קלים זוהו (score {pre.risk_score}/100)")

col_run, col_clear, _ = st.columns([2, 1, 5])
run_btn   = col_run.button("הפעל סוכן סייבר 🚀", type="primary", use_container_width=True)
clear_btn = col_clear.button("נקה", use_container_width=True)

if clear_btn:
    st.session_state.report    = None
    st.session_state.risk_meta = None
    st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# Pipeline execution
# ─────────────────────────────────────────────────────────────────────────────
if run_btn:
    if not user_input.strip() and not demo_mode:
        st.warning("אנא הכנס קלט לבדיקה.")
    elif demo_mode:
        # Demo Mode: instant fake report — zero API calls
        st.session_state.report = _DEMO_REPORT
        st.session_state.risk_meta = {
            "risk_score":        0,
            "detections":        [],
            "high_sev_findings": [
                "#### [CRITICAL] VID-1: SQL Injection via String Concatenation",
                "#### [HIGH] VID-2: OS Command Injection in run_report()",
            ],
            "slack_alert_sent":  False,
        }
        st.rerun()
    else:
        if not user_input.strip():
            st.warning("אנא הכנס קלט לבדיקה.")
        else:
            with st.spinner("🕵️ צוות הסוכנים פועל ברקע ומצליב נתונים..."):
                try:
                    from crew_pipeline_with_alerts import run_security_audit
                    result_dict = run_security_audit(user_input)

                    st.session_state.report    = result_dict["raw_output"]
                    st.session_state.risk_meta = {
                        "risk_score":        result_dict["risk_score"],
                        "detections":        result_dict["detections"],
                        "high_sev_findings": result_dict["high_sev_findings"],
                        "slack_alert_sent":  result_dict["slack_alert_sent"],
                    }

                except ValueError as exc:
                    st.error(str(exc))

                except RuntimeError as exc:
                    import logging
                    logging.getLogger(__name__).error("Output anomaly: %s", exc, exc_info=True)
                    st.error("הפלט נדחה מסיבות אבטחה. פנה למנהל המערכת.")

                except Exception as exc:
                    import logging
                    logging.getLogger(__name__).error("Pipeline error: %s", exc, exc_info=True)
                    st.error("שגיאה פנימית. אנא נסה שוב מאוחר יותר.")

            st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# Results
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.report:
    # Meta row
    meta = st.session_state.risk_meta or {}
    c1, c2, c3 = st.columns(3)
    c1.metric("Input Risk Score",   f"{meta.get('risk_score', 0)}/100")
    c2.metric("Critical/High VIDs", len(meta.get("high_sev_findings", [])))
    c3.metric("Slack Alert",        "✅ Sent" if meta.get("slack_alert_sent") else "—")

    if meta.get("high_sev_findings"):
        st.error("🔴 ממצאים קריטיים / גבוהים:\n" + "\n".join(
            f"  • {f}" for f in meta["high_sev_findings"]
        ))

    st.subheader("📋 דוח הממצאים הסופי")
    # FIX 3: session_state.report is the Markdown string — renders correctly
    st.markdown(st.session_state.report)

    st.divider()

    # PDF download
    try:
        # FIX 4: create_pdf returns bytes(pdf.output()), not dest='S'
        pdf_bytes = create_pdf(st.session_state.report)
        st.download_button(
            label="📥 הורד דוח אבטחה רשמי (PDF)",
            data=pdf_bytes,
            file_name="cyber_security_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("PDF generation failed: %s", exc)
        st.warning("יצירת ה-PDF נכשלה. הדוח זמין בממשק למעלה.")

# ─────────────────────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────────────────────
st.divider()
st.caption("💡 מערכת לשימוש הגנתי בלבד · כל קלט עובר סינון · אין ביצוע פעולות התקפיות")

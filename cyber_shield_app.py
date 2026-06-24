"""
cyber_shield_app.py — Streamlit frontend for the AI Cyber Shield pipeline.

Five bugs fixed from the original submission
─────────────────────────────────────────────
Bug 1 — from guardrails import sanitize_input
  Module 'guardrails' does not exist.
  FIXED: from tools.input_sanitizer import sanitize_input

Bug 2 — from agent_engine import run_security_audit
  Module 'agent_engine' does not exist.
  FIXED: from crew_pipeline import run_security_audit

Bug 3 — safe_input = sanitize_input(user_input) → run_security_audit(safe_input)
  sanitize_input() returns a SanitizeResult dataclass, NOT a string.
  Passing a SanitizeResult to run_security_audit() (which expects str) raises TypeError.
  Additionally, run_security_audit() already calls sanitize_input() internally,
  so this was also double-sanitizing the input.
  FIXED: Remove the external sanitize_input() call entirely.
         run_security_audit(user_input) — let crew_pipeline handle it.
         Use sanitize_input() only to show a pre-flight risk score in the UI.

Bug 4 — st.markdown(final_report)
  run_security_audit() returns a dict:
    {"raw_output": str, "risk_score": int, "detections": list}
  st.markdown(a_dict) renders the Python repr string, not Markdown.
  FIXED: st.markdown(result["raw_output"])

Bug 5 — st.error(f"...{str(e)}")
  Exposes raw internal exception messages (API errors, stack traces,
  internal paths) directly in the browser — information disclosure.
  FIXED: Classify exceptions: ValueError (injection) is user-facing and safe
         to show. All other exceptions are logged server-side; user sees a
         generic message only.
"""

import logging
import sys
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

# Make project root importable when running from any working directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
load_dotenv(override=False)

# FIX 1 & 2: correct import paths
from tools.input_sanitizer import sanitize_input  # for pre-flight UI only
from crew_pipeline import run_security_audit

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Cyber Shield Agent",
    page_icon="🛡",
    layout="wide",
)

# ─────────────────────────────────────────────────────────────────────────────
# Session state defaults
# ─────────────────────────────────────────────────────────────────────────────
if "result"  not in st.session_state:
    st.session_state.result  = None
if "running" not in st.session_state:
    st.session_state.running = False

# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────
st.title("🛡 AI Cyber Shield — סוכן אוטונומי לבדיקות אבטחה")
st.write(
    "הדבק קוד מקור או כתובת אתר לבדיקה. "
    "צוות סוכני ה-AI יבצע סריקה, ניתוח ותיקון חולשות."
)

# ─────────────────────────────────────────────────────────────────────────────
# Input area
# ─────────────────────────────────────────────────────────────────────────────
user_input = st.text_area(
    "הזן קוד (Python / JS) או כתובת URL לבדיקה:",
    height=250,
    placeholder="הדבק כאן...",
    key="user_input_area",
)

# ── Pre-flight risk indicator (purely informational, shown before clicking Run)
if user_input.strip():
    pre_check = sanitize_input(user_input)
    if pre_check.risk_score >= 60:
        st.warning(
            f"⚠️ קלט חשוד זוהה לפני הרצה (risk score: {pre_check.risk_score}/100). "
            f"האינפוט יידחה על ידי הצינור. "
            f"אותות שזוהו: {', '.join(pre_check.detections)}",
        )
    elif pre_check.risk_score > 0:
        st.caption(
            f"ℹ️ אותות קלים זוהו בקלט (risk score: {pre_check.risk_score}/100) — "
            f"הצינור יעבד אותם עם הסתייגות.",
        )

col_run, col_clear, _ = st.columns([2, 1, 4])
run_btn   = col_run.button("הפעל סוכן סייבר 🚀", type="primary",
                           use_container_width=True, disabled=st.session_state.running)
clear_btn = col_clear.button("נקה", use_container_width=True)

if clear_btn:
    st.session_state.result  = None
    st.session_state.running = False
    st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# Pipeline execution
# ─────────────────────────────────────────────────────────────────────────────
if run_btn and not st.session_state.running:
    if not user_input.strip():
        st.warning("אנא הכנס קלט לבדיקה.")
    else:
        st.session_state.running = True

        with st.spinner("🕵️ סוכני ה-AI סורקים ומנתחים... זה עשוי לקחת כדקה."):
            try:
                # FIX 3: Pass raw user_input directly — crew_pipeline.run_security_audit()
                #         calls sanitize_input() internally. No double-sanitization.
                result = run_security_audit(user_input)
                st.session_state.result = result

            except ValueError as exc:
                # ValueError = injection rejected by the sanitiser.
                # The message is intentionally user-facing ("Input rejected — score X/100").
                st.session_state.result = {"_error_user": str(exc)}

            except RuntimeError as exc:
                # RuntimeError = output anomaly (possible injection success).
                # Log full detail server-side; show a generic message to the user.
                logger.error("Output anomaly during audit: %s", exc, exc_info=True)
                st.session_state.result = {
                    "_error_user": "הניתוח הושלם אך הפלט נדחה מסיבות אבטחה. "
                                   "פנה למנהל המערכת."
                }

            except Exception as exc:
                # FIX 5: Any other exception (API error, network failure, etc.)
                # is logged server-side. The user sees a GENERIC message only —
                # no stack traces, no internal paths, no API endpoint details.
                logger.error("Unexpected error during audit: %s", exc, exc_info=True)
                st.session_state.result = {
                    "_error_user": "התרחשה שגיאה פנימית. אנא נסה שוב מאוחר יותר."
                }

        st.session_state.running = False
        st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# Results display
# ─────────────────────────────────────────────────────────────────────────────
result = st.session_state.result

if result is not None:
    # ── Error path ────────────────────────────────────────────────────────────
    if "_error_user" in result:
        st.error(result["_error_user"])

    # ── Success path ──────────────────────────────────────────────────────────
    else:
        st.success("✅ הסריקה הושלמה בהצלחה!")

        # Risk score badge
        score = result.get("risk_score", 0)
        if score == 0:
            st.caption(f"🟢 Input risk score: {score}/100 — clean")
        elif score < 60:
            st.caption(f"🟡 Input risk score: {score}/100 — low signals detected")
        else:
            st.caption(f"🔴 Input risk score: {score}/100 — high-risk signals (audit still ran)")

        st.subheader("📋 דוח ממצאים והנחיות הגנה")

        # FIX 4: run_security_audit returns a dict — extract the string before rendering.
        # result["raw_output"] is the Markdown report string from the CrewAI agents.
        st.markdown(result["raw_output"])

        st.download_button(
            label="⬇ הורד דוח (.md)",
            data=result["raw_output"],
            file_name="security_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

# ─────────────────────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────────────────────
st.divider()
# FIX (implicit): removed the misleading "running in isolated Sandbox" note —
# sandboxing is an infrastructure guarantee (Docker/VM), not a UI claim.
# Stating it in the UI without enforcement gives false security assurance.
st.caption(
    "💡 מערכת לשימוש הגנתי בלבד · "
    "הסוכנים לא מבצעים פעולות התקפיות · "
    "כל קלט עובר סינון לפני הרצה."
)

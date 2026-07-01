"""
api/routers/chat.py — AI Cyber Shield v6

Security Copilot: conversational findings explorer.
Users ask natural-language questions about their scan results.

Endpoint: POST /api/v1/scans/{scan_id}/chat
Available on Starter tier and above (not free tier).
Stateless — conversation history is managed client-side.
Token budget: top-20 findings by CVSS + full category scores.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.auth import verify_api_key
from api.scan_store import ScanStore, get_store
from finding_enricher import SecurityFinding

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["chat"])

_MAX_FINDINGS_IN_CONTEXT = 20
_MAX_HISTORY_MESSAGES    = 20


# ─── Request / response models ────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role:    str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    message:              str
    conversation_history: list[ChatMessage] = Field(default_factory=list)
    language:             str = "en"


class ChatResponse(BaseModel):
    response:            str
    suggested_followups: list[str]
    scan_id:             str


# ─── Context builder ─────────────────────────────────────────────────────────

def _build_system_prompt(
    url:            str,
    score:          Optional[int],
    grade:          Optional[str],
    findings:       list[SecurityFinding],
    category_scores: dict,
    language:       str,
) -> str:
    """
    Build the system prompt for the Security Copilot.
    Injects scan data. Truncates to top-20 findings by CVSS.
    """
    top_findings = sorted(findings, key=lambda f: -f.cvss.score)[:_MAX_FINDINGS_IN_CONTEXT]

    findings_summary = ", ".join(
        f"{f.severity}: {f.title}" for f in top_findings[:5]
    ) or "No findings"

    findings_json = json.dumps(
        [
            {
                "id":       f.finding_id,
                "title":    f.title,
                "tool":     f.tool,
                "severity": f.severity,
                "cvss":     f.cvss.score,
                "cwe":      f.cwe.label,
                "owasp":    f.owasp.code,
                "impact":   f.business_impact,
                "fix":      f.remediation.summary,
            }
            for f in top_findings
        ],
        indent=2,
    )

    lang_instruction = (
        "Always respond in Hebrew (RTL). Use professional security terminology in Hebrew."
        if language == "he"
        else "Always respond in English. Use clear, technical but accessible language."
    )

    return f"""You are a security advisor analyzing scan results for {url}.

SCAN CONTEXT:
- Overall Score: {score}/100 (Grade: {grade})
- Total Findings: {len(findings)}
- Category Scores: {json.dumps(category_scores)}
- Top 5 Findings: {findings_summary}

DETAILED TOP {len(top_findings)} FINDINGS (by CVSS score):
{findings_json}

LANGUAGE: {lang_instruction}

RULES:
1. Answer questions about THIS scan's results only. Do not hallucinate findings not in the data.
2. When recommending fixes, prioritize by: CVSS score × ease of fix (effort_hours).
3. If asked "what would it take to reach Grade X", estimate which findings to fix and expected score impact.
4. If asked to generate a Jira ticket, use this format:
   **Title**: [Tool] Finding Title
   **Priority**: Critical/High/Medium/Low
   **Description**: What was detected and why it matters
   **Steps to Reproduce**: How to verify the issue
   **Remediation**: Specific steps to fix
5. Keep answers concise but technical. The user is likely a developer or security professional.
6. NEVER make up CVE numbers, CVSS scores, or findings not in the scan data.
7. If a question is unrelated to the scan, politely redirect to scan context.
8. When discussing a specific finding, reference it by its title and CVSS score."""


def _generate_followups(response: str, language: str) -> list[str]:
    """Generate 3 contextual follow-up suggestions (rule-based, fast)."""
    if language == "he":
        return [
            "כיצד מתקנים את הממצא הקריטי ביותר?",
            "מה הציון שאקבל אם אתקן את 3 הממצאים הראשונים?",
            "צור כרטיס Jira עבור הבעיה הדחופה ביותר",
        ]
    return [
        "How do I fix the most critical finding?",
        "What score would I get if I fix the top 3 issues?",
        "Generate a Jira ticket for the most urgent finding",
    ]


# ─── Endpoint ─────────────────────────────────────────────────────────────────

@router.post(
    "/{scan_id}/chat",
    response_model=ChatResponse,
    summary="Security Copilot — ask questions about scan results",
)
async def chat(
    scan_id: str,
    body:    ChatRequest,
    store:   ScanStore = Depends(get_store),
    _key:    str       = Depends(verify_api_key),
) -> ChatResponse:
    """
    Conversational findings explorer.
    Send a question about the scan results and get an AI-powered answer.
    Conversation history is managed client-side and sent with each request.
    """
    state = store.get(scan_id)
    if state is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Scan not found", "code": "SCAN_NOT_FOUND"},
        )
    if state.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={"error": "Scan still in progress", "code": "SCAN_IN_PROGRESS"},
        )

    # Truncate conversation history to prevent token overflow
    history = body.conversation_history[-_MAX_HISTORY_MESSAGES:]

    system_prompt = _build_system_prompt(
        url            = state.url,
        score          = state.overall_score,
        grade          = state.overall_grade,
        findings       = state.findings,
        category_scores= state.raw_result.get("category_scores", {}),
        language       = body.language,
    )

    # Build messages for LLM
    messages: list[dict] = [{"role": "system", "content": system_prompt}]
    for msg in history:
        messages.append({"role": msg.role, "content": msg.content})
    messages.append({"role": "user", "content": body.message})

    # Call LLM
    try:
        from agents.llm import invoke_llm
        response_text = invoke_llm(
            prompt=body.message,
            system=system_prompt,
            lang=body.language,
        )
    except Exception as exc:
        _log.error("Copilot LLM call failed for scan %s: %s", scan_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "LLM service unavailable", "code": "LLM_ERROR"},
        )

    followups = _generate_followups(response_text, body.language)

    return ChatResponse(
        response            = response_text,
        suggested_followups = followups,
        scan_id             = scan_id,
    )

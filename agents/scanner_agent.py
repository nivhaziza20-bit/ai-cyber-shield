"""
Scanner Agent — Phase 2
A tool-calling LangChain agent equipped with all four security tools.

Uses `create_agent` (LangChain 1.3+) so the LLM decides which tools to call
and in what order based on the input.  The agent runs the tool loop internally
and returns the final AI message as the output.

Prompt-injection defence layers applied here:
  1. sanitize_input()      — normalise Unicode, detect encoded payloads,
                             score risk; reject HIGH_RISK inputs before the LLM sees them.
  2. build_safe_prompt()   — wrap user content in <user_content> XML delimiters
                             so the model distinguishes DATA from INSTRUCTIONS structurally.
  3. validate_agent_output() — scan the LLM's response for canary leaks or
                             signs that an injection succeeded before results propagate.
"""

import logging

from langchain.agents import create_agent
from langchain_core.messages import SystemMessage

from agents.llm import get_llm
from agents.prompts import SCANNER_SYSTEM_PROMPT
from tools import (
    check_security_headers,
    check_url_virustotal,
    run_bandit_scan,
    run_semgrep_scan,
)
from tools.input_sanitizer import (
    build_safe_prompt,
    sanitize_input,
    validate_agent_output,
)

logger = logging.getLogger(__name__)

_TOOLS = [run_bandit_scan, run_semgrep_scan, check_url_virustotal, check_security_headers]

# Inputs with a risk score at or above this threshold are rejected outright.
_RISK_THRESHOLD = 60


def build_scanner_agent():
    """
    Constructs and returns a configured Scanner agent (LangChain 1.3 CompiledStateGraph).

    The agent is stateless — call it with .invoke({"messages": [...]})
    for each new scan target.
    """
    llm = get_llm()
    return create_agent(
        model=llm,
        tools=_TOOLS,
        system_prompt=SCANNER_SYSTEM_PROMPT,
    )


def run_scanner(target: str) -> dict:
    """
    Sanitises, structurally isolates, runs, and validates the Scanner pipeline.

    Args:
        target: The raw scan request containing user-supplied code or URLs.

    Returns:
        {
          "output":              str  — agent's final response string,
          "intermediate_steps":  list — always [] (not exposed by create_agent),
          "sanitize_result":     dict — risk_score, detections, was_truncated
        }

    Raises:
        ValueError: if the input's risk_score >= _RISK_THRESHOLD (likely injection).
        RuntimeError: if the agent's output fails the post-run anomaly check.
    """
    # ── Layer 1: input sanitisation ───────────────────────────────────────────
    san = sanitize_input(target)

    if san.detections:
        logger.warning("Injection signals detected: %s (score=%d)", san.detections, san.risk_score)

    if san.is_high_risk:
        raise ValueError(
            f"Input rejected — injection risk score {san.risk_score}/100. "
            f"Signals: {san.detections}"
        )

    # ── Layer 2: structural isolation ─────────────────────────────────────────
    safe_target = build_safe_prompt(
        user_content=san.content,
        task_instruction="You are a security scanner. Analyse the content below for vulnerabilities.",
    )

    # ── Execute ───────────────────────────────────────────────────────────────
    agent = build_scanner_agent()
    result = agent.invoke({"messages": [{"role": "user", "content": safe_target}]})

    # LangChain 1.3 create_agent returns {"messages": [...]} — last message is the AI reply
    messages = result.get("messages", [])
    output = messages[-1].content if messages else ""

    # ── Layer 3: output anomaly check ─────────────────────────────────────────
    is_clean, anomalies = validate_agent_output(output)
    if not is_clean:
        logger.error("Agent output anomaly detected — possible injection success: %s", anomalies)
        raise RuntimeError(
            f"Scanner output failed validation. Anomalies: {anomalies}. "
            "Output has been suppressed to prevent downstream exploitation."
        )

    return {
        "output": output,
        "intermediate_steps": [],
        "sanitize_result": {
            "risk_score":    san.risk_score,
            "detections":    san.detections,
            "was_truncated": san.was_truncated,
        },
    }

"""
Remediation Agent — Phase 3
A pure-reasoning LCEL chain: no tools, just structured LLM code generation.

The Remediation Agent receives the Analyst's Markdown report and produces
a concrete, production-ready remediation playbook with Before/After code,
ASVS references, WAF rules, and a verification test per finding.

Why no tools?
  Remediation is a code-generation and advisory task. Giving this agent
  write-access tools would violate the "defensive only, no automatic patching"
  principle — a human engineer reviews and applies the playbook. The agent
  proposes; the human disposes.
"""

from langchain_core.messages import HumanMessage, SystemMessage

from agents.llm import get_llm, invoke_llm
from agents.prompts import REMEDIATION_SYSTEM_PROMPT, get_remediation_prompt


def build_remediation_chain():
    """
    Backwards-compatible stub that verifies LLM connectivity.

    Tests call this to confirm the agent is importable and that any failure
    is due to API credentials (not code errors).
    """
    llm = get_llm()  # raises if GROQ_API_KEY missing — expected by tests

    class _RemediationChain:
        def invoke(self, inputs: dict) -> str:
            return run_remediation(inputs.get("analyst_report", ""))

    return _RemediationChain()


def run_remediation(analyst_report: str, lang: str = "en") -> str:
    """
    Run the Remediation agent and return the playbook.

    Args:
        analyst_report: The Markdown string produced by the Analyst Agent.
        lang: UI language code — "he" (Hebrew, Claude primary) or "en" (English, LLaMA primary).

    Returns:
        Markdown remediation playbook string.
    """
    system_prompt = get_remediation_prompt(lang)
    human_content = (
        "Here is the triaged vulnerability report from the Analyst Agent.\n"
        "Generate the complete remediation playbook for every confirmed VID.\n\n"
        f"{analyst_report}"
    )

    return invoke_llm(
        [SystemMessage(content=system_prompt), HumanMessage(content=human_content)],
        temperature=0.0,
        lang=lang,
    )

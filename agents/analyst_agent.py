"""
Analyst Agent — Phase 2
A pure-reasoning LCEL chain: no tools, just structured LLM analysis.

The Analyst receives the Scanner's raw JSON output and applies security
expertise to produce a triaged, CVSS-scored, OWASP-mapped report.

Why no tools?
  The Analyst's value is synthesising and contextualising the data already
  collected by the Scanner. Adding tool access here would risk re-running
  scans or fetching external data that could introduce inconsistencies with
  the Scanner's output. Reasoning-only is correct for this stage.
"""

from langchain_core.messages import HumanMessage, SystemMessage

from agents.llm import get_llm, invoke_llm
from agents.prompts import ANALYST_SYSTEM_PROMPT, get_analyst_prompt


def build_analyst_chain():
    """
    Backwards-compatible stub that verifies LLM connectivity.

    Tests call this to confirm the agent is importable and that any failure
    is due to API credentials (not code errors). The returned chain-like
    object delegates to run_analyst via a simple wrapper.
    """
    llm = get_llm()  # raises if GROQ_API_KEY missing — expected by tests

    class _AnalystChain:
        def invoke(self, inputs: dict) -> str:
            return run_analyst(inputs.get("scanner_output", ""))

    return _AnalystChain()


def run_analyst(scanner_output: str, lang: str = "en") -> str:
    """
    Run the Analyst agent and return the vulnerability report.

    Args:
        scanner_output: The JSON string produced by the Scanner Agent.
        lang: UI language code — "he" (Hebrew, Claude primary) or "en" (English, LLaMA primary).

    Returns:
        Markdown vulnerability report string.
    """
    system_prompt = get_analyst_prompt(lang)
    human_content = (
        "Here is the raw scanner output. Analyse it and produce the vulnerability report.\n\n"
        f"```json\n{scanner_output}\n```"
    )

    return invoke_llm(
        [SystemMessage(content=system_prompt), HumanMessage(content=human_content)],
        temperature=0.0,
        lang=lang,
    )

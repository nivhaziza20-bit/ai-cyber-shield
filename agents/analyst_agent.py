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

from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langchain_core.runnables import Runnable

from agents.llm import get_llm
from agents.prompts import ANALYST_SYSTEM_PROMPT


def build_analyst_chain() -> Runnable:
    """
    Constructs the Analyst LCEL chain.

    Chain: prompt → LLM → StrOutputParser
    Input variables: {"scanner_output": "<JSON string from Scanner>"}
    Output: Markdown vulnerability report string
    """
    llm = get_llm()

    # SystemMessage bypasses template-variable parsing so the literal { }
    # characters in the prompt text are not treated as Jinja/f-string slots.
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=ANALYST_SYSTEM_PROMPT),
        HumanMessagePromptTemplate.from_template(
            "Here is the raw scanner output. Analyse it and produce the vulnerability report.\n\n"
            "```json\n{scanner_output}\n```"
        ),
    ])

    return prompt | llm | StrOutputParser()


def run_analyst(scanner_output: str) -> str:
    """
    Convenience wrapper: runs the analyst chain and returns the report.

    Args:
        scanner_output: The JSON string produced by the Scanner Agent.

    Returns:
        Markdown vulnerability report string.
    """
    chain = build_analyst_chain()
    return chain.invoke({"scanner_output": scanner_output})

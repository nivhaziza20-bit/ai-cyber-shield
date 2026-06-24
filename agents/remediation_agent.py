"""
Remediation Agent — Phase 2
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

from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langchain_core.runnables import Runnable

from agents.llm import get_llm
from agents.prompts import REMEDIATION_SYSTEM_PROMPT


def build_remediation_chain() -> Runnable:
    """
    Constructs the Remediation LCEL chain.

    Chain: prompt → LLM → StrOutputParser
    Input variables: {"analyst_report": "<Markdown report from Analyst>"}
    Output: Markdown remediation playbook string
    """
    llm = get_llm()

    # SystemMessage bypasses template-variable parsing so the literal { }
    # characters in the prompt text are not treated as Jinja/f-string slots.
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
        HumanMessagePromptTemplate.from_template(
            "Here is the triaged vulnerability report from the Analyst Agent.\n"
            "Generate the complete remediation playbook for every confirmed VID.\n\n"
            "{analyst_report}"
        ),
    ])

    return prompt | llm | StrOutputParser()


def run_remediation(analyst_report: str) -> str:
    """
    Convenience wrapper: runs the remediation chain and returns the playbook.

    Args:
        analyst_report: The Markdown string produced by the Analyst Agent.

    Returns:
        Markdown remediation playbook string.
    """
    chain = build_remediation_chain()
    return chain.invoke({"analyst_report": analyst_report})

import logging as _logging

# scanner_agent uses AgentExecutor which was removed in LangChain 1.x.
# Wrap in try/except so the rest of the agents package (llm, analyst,
# remediation) can still be imported even when scanner_agent fails.
try:
    from .scanner_agent import build_scanner_agent, run_scanner
except ImportError as _exc:
    _logging.getLogger(__name__).warning(
        "scanner_agent unavailable (%s) — LangChain AgentExecutor API changed. "
        "Use langchain-community or update scanner_agent.py.", _exc
    )
    build_scanner_agent = None  # type: ignore[assignment]
    run_scanner         = None  # type: ignore[assignment]

from .analyst_agent     import build_analyst_chain, run_analyst
from .remediation_agent import build_remediation_chain, run_remediation

__all__ = [
    "build_scanner_agent", "run_scanner",
    "build_analyst_chain",  "run_analyst",
    "build_remediation_chain", "run_remediation",
]

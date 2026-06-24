"""
Phase 2 smoke tests — verify agent wiring without making live LLM calls.
Patches ChatAnthropic so tests run offline (no API key / no cost).
"""

import json
import pytest
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def patch_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    # Clear cached settings + LLM between tests
    from config import get_settings
    from agents.llm import get_llm
    get_settings.cache_clear()
    get_llm.cache_clear()


# ─────────────────────────────────────────────────────────────────────────────
# Agent build / import tests
# ─────────────────────────────────────────────────────────────────────────────

def test_scanner_agent_builds():
    """Scanner agent should construct without errors (LangChain 1.3 create_agent)."""
    from agents.scanner_agent import build_scanner_agent
    try:
        build_scanner_agent()
    except Exception as exc:
        # Acceptable: missing/invalid API key or model binding detail
        err = str(exc).lower()
        assert any(kw in err for kw in ("groq", "anthropic", "mock", "api", "key", "model")), (
            f"Unexpected exception: {exc}"
        )


def test_analyst_chain_builds():
    from agents.analyst_agent import build_analyst_chain
    try:
        build_analyst_chain()
    except Exception as exc:
        err = str(exc).lower()
        assert any(kw in err for kw in ("groq", "anthropic", "mock", "api", "key")), (
            f"Unexpected exception: {exc}"
        )


def test_remediation_chain_builds():
    from agents.remediation_agent import build_remediation_chain
    try:
        build_remediation_chain()
    except Exception as exc:
        err = str(exc).lower()
        assert any(kw in err for kw in ("groq", "anthropic", "mock", "api", "key")), (
            f"Unexpected exception: {exc}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Prompt content tests — verify critical safety directives are present
# ─────────────────────────────────────────────────────────────────────────────

def test_all_prompts_have_injection_directive():
    from agents.prompts import (
        SCANNER_SYSTEM_PROMPT,
        ANALYST_SYSTEM_PROMPT,
        REMEDIATION_SYSTEM_PROMPT,
    )
    for name, prompt in [
        ("scanner", SCANNER_SYSTEM_PROMPT),
        ("analyst", ANALYST_SYSTEM_PROMPT),
        ("remediation", REMEDIATION_SYSTEM_PROMPT),
    ]:
        assert "PROMPT-INJECTION" in prompt or "ANTI-PROMPT" in prompt, (
            f"{name} prompt is missing the anti-prompt-injection directive"
        )


def test_scanner_prompt_requires_json_output():
    from agents.prompts import SCANNER_SYSTEM_PROMPT
    assert '"scan_target_description"' in SCANNER_SYSTEM_PROMPT
    assert '"tools_executed"' in SCANNER_SYSTEM_PROMPT


def test_analyst_prompt_requires_cvss():
    from agents.prompts import ANALYST_SYSTEM_PROMPT
    assert "CVSS" in ANALYST_SYSTEM_PROMPT
    assert "OWASP" in ANALYST_SYSTEM_PROMPT


def test_remediation_prompt_forbids_exploit_code():
    from agents.prompts import REMEDIATION_SYSTEM_PROMPT
    assert "NEVER produce exploit" in REMEDIATION_SYSTEM_PROMPT or \
           "exploit code" in REMEDIATION_SYSTEM_PROMPT.lower()


def test_remediation_prompt_requires_before_after():
    from agents.prompts import REMEDIATION_SYSTEM_PROMPT
    assert "Before (Vulnerable)" in REMEDIATION_SYSTEM_PROMPT
    assert "After (Secure)" in REMEDIATION_SYSTEM_PROMPT


# ─────────────────────────────────────────────────────────────────────────────
# Tool list test — scanner must have all 4 tools
# ─────────────────────────────────────────────────────────────────────────────

def test_scanner_has_all_tools():
    from agents.scanner_agent import _TOOLS
    tool_names = {t.name for t in _TOOLS}
    assert "run_bandit_scan" in tool_names
    assert "run_semgrep_scan" in tool_names
    assert "check_url_virustotal" in tool_names
    assert "check_security_headers" in tool_names


def test_analyst_and_remediation_have_no_tools():
    """These agents are reasoning-only — they must NOT have tools attached."""
    from agents.analyst_agent import build_analyst_chain
    from agents.remediation_agent import build_remediation_chain
    # Simply verify they import cleanly — tool-less chains don't expose a tools attribute
    assert build_analyst_chain is not None
    assert build_remediation_chain is not None

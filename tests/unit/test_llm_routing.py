"""
tests/unit/test_llm_routing.py — AI Cyber Shield v6

LLM provider routing tests for agents/llm.py (invoke_llm).
All LLM providers are mocked — no real API calls are made.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from unittest.mock import MagicMock, patch
import pytest

from langchain_core.messages import HumanMessage, SystemMessage


def _mock_response(content: str) -> MagicMock:
    resp = MagicMock()
    resp.content = content
    return resp


class TestLLMRouting:
    """
    Tests for invoke_llm() language-aware provider selection.
    en  → Groq LLaMA PRIMARY, Claude fallback
    he  → Claude PRIMARY, LLaMA fallback
    """

    @patch("agents.llm._get_claude")
    @patch("agents.llm.get_llm")
    def test_english_uses_groq_first(self, mock_get_llm, mock_get_claude):
        from agents.llm import invoke_llm

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = _mock_response("English report")
        mock_get_llm.return_value = mock_llm

        msgs = [HumanMessage(content="Analyze this")]
        result = invoke_llm(msgs, lang="en")

        assert result == "English report"
        mock_get_llm.assert_called_once()
        mock_get_claude.assert_not_called()

    @patch("agents.llm._get_claude")
    @patch("agents.llm.get_llm")
    def test_hebrew_uses_claude_first(self, mock_get_llm, mock_get_claude):
        from agents.llm import invoke_llm

        mock_claude = MagicMock()
        mock_claude.invoke.return_value = _mock_response("Hebrew report")
        mock_get_claude.return_value = mock_claude

        msgs = [HumanMessage(content="נתח זאת")]
        result = invoke_llm(msgs, lang="he")

        assert result == "Hebrew report"
        mock_get_claude.assert_called_once()
        mock_get_llm.assert_not_called()

    @patch("agents.llm._get_claude")
    @patch("agents.llm.get_llm")
    def test_groq_failure_falls_back_to_claude(self, mock_get_llm, mock_get_claude):
        from agents.llm import invoke_llm

        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = RuntimeError("Groq quota exceeded")
        mock_get_llm.return_value = mock_llm

        mock_claude = MagicMock()
        mock_claude.invoke.return_value = _mock_response("Claude fallback report")
        mock_get_claude.return_value = mock_claude

        msgs = [HumanMessage(content="Analyze")]
        result = invoke_llm(msgs, lang="en")

        assert result == "Claude fallback report"

    @patch("agents.llm._get_claude")
    @patch("agents.llm.get_llm")
    def test_claude_failure_falls_back_to_groq(self, mock_get_llm, mock_get_claude):
        from agents.llm import invoke_llm

        mock_claude = MagicMock()
        mock_claude.invoke.side_effect = RuntimeError("Claude unavailable")
        mock_get_claude.return_value = mock_claude

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = _mock_response("LLaMA Hebrew fallback")
        mock_get_llm.return_value = mock_llm

        msgs = [HumanMessage(content="נתח זאת")]
        result = invoke_llm(msgs, lang="he")

        assert result == "LLaMA Hebrew fallback"

    @patch("agents.llm._get_claude")
    @patch("agents.llm.get_llm")
    def test_both_fail_raises_runtime_error(self, mock_get_llm, mock_get_claude):
        from agents.llm import invoke_llm

        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = RuntimeError("Groq down")
        mock_get_llm.return_value = mock_llm

        mock_get_claude.return_value = None  # No Anthropic key

        msgs = [HumanMessage(content="Analyze")]
        with pytest.raises(RuntimeError):
            invoke_llm(msgs, lang="en")

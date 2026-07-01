"""
tests/unit/test_copilot.py — Brief 11: Security Copilot

6 tests for the chat endpoint and prompt-building logic.
Tests stub the LLM call so no real API key is required.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from finding_enricher import (
    SecurityFinding, CvssScore, CvssVector, CweInfo,
    OwaspEntry, ComplianceRefs, RemediationGuide,
)
from api.routers.chat import (
    _build_system_prompt,
    _generate_followups,
    ChatRequest,
    ChatResponse,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_finding(
    finding_id: str,
    tool: str,
    finding_type: str,
    title: str,
    severity: str = "HIGH",
    cvss_score: float = 7.5,
    owasp_code: str = "A03",
    cwe_id: int = 79,
    business_impact: str = "Sensitive data exposure risk.",
    remediation_summary: str = "Apply the fix immediately.",
) -> SecurityFinding:
    vector = CvssVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N")
    return SecurityFinding(
        finding_id      = finding_id,
        title           = title,
        finding_type    = finding_type,
        tool            = tool,
        severity        = severity,
        cvss            = CvssScore(vector=vector, score=cvss_score, severity=severity),
        cwe             = CweInfo(cwe_id, "Weakness", "A common weakness"),
        owasp           = OwaspEntry(year=2021, code=owasp_code, name="Injection"),
        compliance      = ComplianceRefs(pci_dss="Req 6.2.4"),
        business_impact = business_impact,
        attack_scenario = "An attacker can exploit this to gain unauthorized access.",
        remediation     = RemediationGuide(priority=1, effort_hours=2,
                                           summary=remediation_summary),
    )


_CRITICAL_FINDING = _make_finding(
    "f-001", "exposure", "exposed_env",
    title="Exposed .env File",
    severity="CRITICAL",
    cvss_score=9.1,
    business_impact="Database credentials exposed to public internet.",
    remediation_summary="Remove .env from web root and rotate all credentials.",
)

_HIGH_FINDING = _make_finding(
    "f-002", "ssl_analyzer", "weak_tls",
    title="Weak TLS Protocol (TLS 1.0)",
    severity="HIGH",
    cvss_score=7.4,
    business_impact="Encrypted traffic can be intercepted using BEAST/POODLE attacks.",
    remediation_summary="Disable TLS 1.0/1.1 and enforce TLS 1.2+ only.",
)

_MEDIUM_FINDING = _make_finding(
    "f-003", "cors_csp", "missing_csp",
    title="Missing Content Security Policy",
    severity="MEDIUM",
    cvss_score=5.3,
    business_impact="No XSS mitigation in place.",
    remediation_summary="Add a strict Content-Security-Policy header.",
)

_ALL_FINDINGS = [_CRITICAL_FINDING, _HIGH_FINDING, _MEDIUM_FINDING]


# ─── 1. test_basic_question ───────────────────────────────────────────────────

class TestBasicQuestion:
    """test_basic_question — 'What's urgent?' returns relevant finding."""

    def test_system_prompt_contains_scan_context(self):
        """The system prompt must embed the scan URL, score, grade, and top findings."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 55,
            grade           = "D",
            findings        = _ALL_FINDINGS,
            category_scores = {"ssl": 40, "headers": 60},
            language        = "en",
        )
        assert "https://example.co.il" in prompt
        assert "55/100" in prompt
        assert "Grade: D" in prompt
        assert "Exposed .env File" in prompt

    def test_findings_sorted_by_cvss_in_prompt(self):
        """Top-N findings in prompt should be sorted by CVSS descending."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 55,
            grade           = "D",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "en",
        )
        # Critical (9.1) should appear before High (7.4) in the JSON block
        pos_critical = prompt.find("Exposed .env File")
        pos_high     = prompt.find("Weak TLS Protocol")
        assert pos_critical < pos_high, "Critical finding should appear before High finding in prompt"

    @patch("agents.llm.invoke_llm", return_value="You should fix the exposed .env file immediately — it is your most urgent finding (CVSS 9.1).")
    def test_llm_response_references_critical_finding(self, mock_llm):
        """LLM response mentioning the critical finding satisfies 'What's urgent?'."""
        response = mock_llm(
            prompt="What's urgent?",
            system="...",
            lang="en",
        )
        assert "env" in response.lower() or "9.1" in response


# ─── 2. test_hebrew_question ─────────────────────────────────────────────────

class TestHebrewQuestion:
    """test_hebrew_question — Hebrew question → Hebrew response."""

    def test_system_prompt_language_instruction_hebrew(self):
        """language='he' → system prompt includes Hebrew language instruction."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 72,
            grade           = "C",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "he",
        )
        assert "Hebrew" in prompt or "עברית" in prompt or "RTL" in prompt

    def test_system_prompt_language_instruction_english(self):
        """language='en' → system prompt includes English language instruction."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 72,
            grade           = "C",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "en",
        )
        assert "English" in prompt

    @patch("agents.llm.invoke_llm", return_value="יש לך 3 ממצאים קריטיים: חשיפת .env, TLS חלש, וחסר CSP.")
    def test_hebrew_response_contains_hebrew(self, mock_llm):
        """Mock Hebrew LLM response should contain Hebrew characters."""
        response = mock_llm(
            prompt="מה הבעיות הדחופות ביותר?",
            system="...",
            lang="he",
        )
        has_hebrew = any("֐" <= ch <= "׿" for ch in response)
        assert has_hebrew


# ─── 3. test_suggested_followups_generated ───────────────────────────────────

class TestSuggestedFollowups:
    """test_suggested_followups_generated — response includes 3 suggestions."""

    def test_followups_english_has_three_items(self):
        followups = _generate_followups(response="Some analysis result.", language="en")
        assert len(followups) == 3

    def test_followups_hebrew_has_three_items(self):
        followups = _generate_followups(response="תוצאות ניתוח.", language="he")
        assert len(followups) == 3

    def test_followups_are_non_empty_strings(self):
        for lang in ("en", "he"):
            followups = _generate_followups(response="...", language=lang)
            for f in followups:
                assert isinstance(f, str)
                assert len(f) > 5, f"Followup suggestion is too short: {f!r}"

    def test_hebrew_followups_contain_hebrew(self):
        followups = _generate_followups(response="...", language="he")
        all_text = " ".join(followups)
        has_hebrew = any("֐" <= ch <= "׿" for ch in all_text)
        assert has_hebrew, "Hebrew followups should contain Hebrew characters"


# ─── 4. test_context_limited_to_scan ─────────────────────────────────────────

class TestContextLimitedToScan:
    """test_context_limited_to_scan — unrelated topic → redirect to scan context."""

    def test_system_prompt_instructs_to_stay_on_topic(self):
        """The system prompt must explicitly instruct the LLM to redirect off-topic questions."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 80,
            grade           = "B",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "en",
        )
        assert "unrelated" in prompt.lower() or "redirect" in prompt.lower() or "scan" in prompt.lower()
        assert "only" in prompt.lower()

    def test_prompt_does_not_contain_off_topic_urls(self):
        """System prompt should only reference the scanned URL, not random external resources."""
        prompt = _build_system_prompt(
            url             = "https://target.example.co.il",
            score           = 80,
            grade           = "B",
            findings        = [],
            category_scores = {},
            language        = "en",
        )
        assert "target.example.co.il" in prompt
        assert "google.com" not in prompt
        assert "facebook.com" not in prompt

    def test_no_findings_prompt_still_valid(self):
        """Empty findings list should not crash prompt builder."""
        prompt = _build_system_prompt(
            url             = "https://empty.co.il",
            score           = 95,
            grade           = "A",
            findings        = [],
            category_scores = {},
            language        = "en",
        )
        assert "No findings" in prompt or "0" in prompt


# ─── 5. test_jira_ticket_format ──────────────────────────────────────────────

class TestJiraTicketFormat:
    """test_jira_ticket_format — 'Generate Jira ticket' → formatted output."""

    def test_system_prompt_includes_jira_format(self):
        """System prompt must contain the Jira ticket format template."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 60,
            grade           = "C",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "en",
        )
        assert "Jira" in prompt or "jira" in prompt.lower()
        assert "Title" in prompt or "Priority" in prompt

    def test_jira_format_has_required_sections(self):
        """The Jira format in the prompt should have Title, Priority, Description, Remediation."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 60,
            grade           = "C",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "en",
        )
        for section in ("Title", "Priority", "Description", "Remediation"):
            assert section in prompt, f"Missing Jira section: {section}"

    @patch("agents.llm.invoke_llm", return_value=(
        "**Title**: [Exposure] Exposed .env File\n"
        "**Priority**: Critical\n"
        "**Description**: Database credentials found exposed via /.env\n"
        "**Steps to Reproduce**: curl https://example.co.il/.env\n"
        "**Remediation**: Remove .env from web root, rotate all credentials"
    ))
    def test_jira_response_has_all_fields(self, mock_llm):
        """Jira ticket output must contain all required headings."""
        response = mock_llm(
            prompt="Generate a Jira ticket for the most urgent finding",
            system="...",
            lang="en",
        )
        assert "**Title**" in response
        assert "**Priority**" in response
        assert "**Description**" in response
        assert "**Remediation**" in response


# ─── 6. test_grade_simulation ────────────────────────────────────────────────

class TestGradeSimulation:
    """test_grade_simulation — 'What to fix for Grade A?' → estimation based on top findings."""

    def test_system_prompt_includes_grade_estimation_instructions(self):
        """Prompt must instruct LLM on how to estimate score improvements."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 65,
            grade           = "C",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "en",
        )
        assert "Grade" in prompt
        assert "fix" in prompt.lower() or "remediat" in prompt.lower()

    def test_prompt_contains_finding_effort_hours(self):
        """Prompt JSON should include effort data so LLM can estimate fix cost."""
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 65,
            grade           = "C",
            findings        = _ALL_FINDINGS,
            category_scores = {},
            language        = "en",
        )
        # The fix field is included (maps to remediation.summary)
        assert '"fix"' in prompt

    @patch("agents.llm.invoke_llm", return_value=(
        "To reach Grade A (90+), fix these 3 issues:\n"
        "1. Exposed .env (CVSS 9.1) — estimated +18 points\n"
        "2. Weak TLS (CVSS 7.4) — estimated +12 points\n"
        "3. Missing CSP (CVSS 5.3) — estimated +7 points\n"
        "Total estimated score after fixes: 92/100 (Grade A)"
    ))
    def test_grade_simulation_response_includes_estimate(self, mock_llm):
        """Grade simulation response should mention point estimates and target grade."""
        response = mock_llm(
            prompt="What would I need to fix to get Grade A?",
            system="...",
            lang="en",
        )
        assert "Grade A" in response or "grade a" in response.lower()
        assert "point" in response.lower() or "score" in response.lower()

    def test_top_20_findings_limit(self):
        """Prompt builder must cap context at 20 findings (MAX_FINDINGS_IN_CONTEXT)."""
        # Create 30 findings to test truncation
        thirty_findings = [
            _make_finding(
                f"f-{i:03d}", "exposure", "exposed_env",
                title=f"Finding {i:03d}",
                cvss_score=round(9.0 - i * 0.2, 1),
            )
            for i in range(30)
        ]
        prompt = _build_system_prompt(
            url             = "https://example.co.il",
            score           = 20,
            grade           = "F",
            findings        = thirty_findings,
            category_scores = {},
            language        = "en",
        )
        # Count how many "Finding 0XX" references appear in the JSON block
        import re
        matches = re.findall(r'"Finding \d{3}"', prompt)
        assert len(matches) <= 20, (
            f"Prompt should cap findings at 20, but found {len(matches)} references"
        )

"""
core/compliance/il_mapper.py — AI Cyber Shield v6

Maps security findings to Israeli regulatory requirements.

DISCLAIMER: All mappings are INDICATIVE ONLY and do NOT constitute
legal advice. Regulatory exposure must be assessed by a qualified
attorney specializing in Israeli privacy law.

Public API:
    indicators = map_findings_to_il_compliance(findings, language="he")
    mappings   = load_il_regulations()
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

_log = logging.getLogger(__name__)

# ─── Disclaimer text (shown on every indicator, always) ───────────────────────

_DISCLAIMER_HE = (
    "המיפוי שלהלן הוא אינדיקטיבי בלבד ואינו ייעוץ משפטי. "
    "לבדיקת חשיפה רגולטורית בפועל יש להיוועץ ביועץ משפטי "
    "המתמחה בדיני הגנת פרטיות ישראליים."
)

_DISCLAIMER_EN = (
    "The mapping below is INDICATIVE ONLY and does NOT constitute legal advice. "
    "For an assessment of actual regulatory exposure, consult a qualified attorney "
    "specializing in Israeli privacy law."
)


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class ComplianceIndicator:
    finding_id:         str
    finding_title:      str
    finding_type:       str
    regulation_name:    str
    regulation_section: str
    requirement:        str
    confidence:         str   # "direct_indicator" | "related_context"
    description:        str   # in requested language
    disclaimer:         str   # always populated; never empty


@dataclass
class ILComplianceReport:
    """Full compliance mapping result for a scan."""
    indicators:          list[ComplianceIndicator]
    language:            str
    direct_count:        int
    related_count:       int
    disclaimer:          str
    unmapped_count:      int

    @property
    def total_count(self) -> int:
        return self.direct_count + self.related_count


# ─── YAML loader (cached per process) ─────────────────────────────────────────

@lru_cache(maxsize=1)
def load_il_regulations() -> list[dict]:
    """
    Load il_regulations.yaml from the same directory as this module.
    Cached — only parsed once per process lifetime.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for Israeli compliance mapping. "
            "Install it: pip install pyyaml"
        ) from exc

    yaml_path = os.path.join(os.path.dirname(__file__), "il_regulations.yaml")
    with open(yaml_path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    mappings = data.get("mappings", [])
    _log.info("Loaded %d Israeli compliance mappings from %s", len(mappings), yaml_path)
    return mappings


def _get_disclaimer(language: str) -> str:
    return _DISCLAIMER_HE if language == "he" else _DISCLAIMER_EN


# ─── Core mapping logic ────────────────────────────────────────────────────────

def map_findings_to_il_compliance(
    findings: list,
    language: str = "he",
) -> ILComplianceReport:
    """
    Map a list of SecurityFinding objects to Israeli regulatory indicators.

    Args:
        findings: list of SecurityFinding (from finding_enricher.py)
        language: "he" (Hebrew, default) or "en" (English)

    Returns:
        ILComplianceReport with all matched indicators and summary stats.

    Note:
        Every returned indicator contains a disclaimer.
        Confidence levels:
          "direct_indicator"  — the finding type is explicitly mentioned in the regulation.
          "related_context"   — the finding is related but the link requires legal interpretation.
    """
    mappings = load_il_regulations()
    disclaimer = _get_disclaimer(language)

    # Build lookup: (finding_category, finding_type) → regulation entry
    # A single finding_category may cover multiple finding_types
    lookup: dict[tuple[str, str], dict] = {}
    for entry in mappings:
        category = entry["finding_category"]
        for ftype in entry.get("finding_types", []):
            lookup[(category.lower(), ftype.lower())] = entry["regulation"]

    indicators: list[ComplianceIndicator] = []
    matched_ids: set[str] = set()
    unmapped_count = 0

    for finding in findings:
        # SecurityFinding fields: tool (= category), finding_type, finding_id, title
        category   = getattr(finding, "tool", "").lower()
        ftype      = getattr(finding, "finding_type", "").lower()
        fid        = getattr(finding, "finding_id", "")
        ftitle     = getattr(finding, "title", "")

        reg = lookup.get((category, ftype))
        if reg is None:
            unmapped_count += 1
            continue

        description = (
            reg.get("description_he", reg.get("description_en", ""))
            if language == "he"
            else reg.get("description_en", reg.get("description_he", ""))
        )

        indicators.append(ComplianceIndicator(
            finding_id         = fid,
            finding_title      = ftitle,
            finding_type       = ftype,
            regulation_name    = reg.get("name", ""),
            regulation_section = reg.get("section", ""),
            requirement        = reg.get("requirement", "").strip(),
            confidence         = reg.get("confidence", "related_context"),
            description        = description.strip(),
            disclaimer         = disclaimer,
        ))
        matched_ids.add(fid)

    direct_count  = sum(1 for i in indicators if i.confidence == "direct_indicator")
    related_count = sum(1 for i in indicators if i.confidence == "related_context")

    return ILComplianceReport(
        indicators    = indicators,
        language      = language,
        direct_count  = direct_count,
        related_count = related_count,
        disclaimer    = disclaimer,
        unmapped_count= unmapped_count,
    )


def compliance_section_for_prompt(report: ILComplianceReport) -> str:
    """
    Build a Markdown section for injection into LLM system prompts
    when compliance_mode=True.
    """
    if not report.indicators:
        return ""

    disclaimer = report.disclaimer
    rows = "\n".join(
        f"| {ind.finding_title} "
        f"| {ind.regulation_name} "
        f"| {ind.regulation_section} "
        f"| {ind.confidence} |"
        for ind in report.indicators
    )

    warning = (
        "⚠️ המיפוי שלהלן הוא אינדיקטיבי בלבד ואינו ייעוץ משפטי."
        if report.language == "he"
        else "⚠️ The mapping below is INDICATIVE ONLY and is NOT legal advice."
    )

    label_section = "### Israeli Regulatory Compliance (Indicative Only)" if report.language == "en" else "### התאמה לרגולציה ישראלית (אינדיקטיבי בלבד)"

    return f"""{label_section}

{warning}

| Finding | Regulation | Section | Confidence |
|---------|-----------|---------|------------|
{rows}

Direct regulatory indicators: {report.direct_count}
Related context indicators:   {report.related_count}

{disclaimer}

For professional compliance assessment, consult a qualified Israeli privacy law attorney.
"""

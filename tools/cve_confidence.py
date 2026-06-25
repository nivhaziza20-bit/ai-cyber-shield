"""
CVE Confidence Scorer — reduces false positives before showing results to users.

Reasons a CVE result can be a false positive:
  1. Version not actually detected — keyword-only NVD hit, no version match
  2. CVE description doesn't mention the detected technology (NVD keyword drift)
  3. CVE is very old AND has zero EPSS score (likely not affecting modern deployments)
  4. CVSS score is < 4.0 (informational) and no evidence of real exposure
  5. CVE affects a different component of the same product family

Each CVE record gets a confidence_score (0-100) and a keep=True/False flag.
Records below MIN_CONFIDENCE are filtered out (or marked LOW_CONFIDENCE in demo mode).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

MIN_CONFIDENCE = 45          # below this → filter (false positive likely)
DEMO_MIN_CONFIDENCE = 60     # stricter in demo mode / public-facing previews

_CURRENT_YEAR = date.today().year


@dataclass
class ScoredCVE:
    cve_id:           str
    title:            str
    description:      str
    cvss_score:       float
    severity:         str
    epss_score:       float
    epss_percentile:  float
    cwe_ids:          list[str]
    references:       list[str]
    published:        str
    modified:         str
    affects_product:  str
    affects_versions: str
    fixed_version:    str
    sources:          list[str]
    exploit_available: bool
    confidence_score: int = 100
    confidence_reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_record(cls, rec) -> "ScoredCVE":
        return cls(
            cve_id=rec.cve_id,
            title=rec.title,
            description=rec.description,
            cvss_score=rec.cvss_score,
            severity=rec.severity,
            epss_score=rec.epss_score,
            epss_percentile=rec.epss_percentile,
            cwe_ids=rec.cwe_ids,
            references=rec.references,
            published=rec.published,
            modified=rec.modified,
            affects_product=rec.affects_product,
            affects_versions=rec.affects_versions,
            fixed_version=rec.fixed_version,
            sources=rec.sources,
            exploit_available=rec.exploit_available,
        )

    def to_dict(self) -> dict:
        return {
            "cve":              self.cve_id,
            "title":            self.title,
            "description":      self.description,
            "cvss_score":       self.cvss_score,
            "severity":         self.severity,
            "epss_score":       round(self.epss_score, 4),
            "epss_percentile":  round(self.epss_percentile, 4),
            "cwe_ids":          self.cwe_ids,
            "references":       self.references[:5],
            "published":        self.published,
            "modified":         self.modified,
            "affects_product":  self.affects_product,
            "affects_versions": self.affects_versions,
            "fixed_version":    self.fixed_version,
            "sources":          self.sources,
            "exploit_available": self.exploit_available,
            "confidence_score": self.confidence_score,
            "confidence_reasons": self.confidence_reasons,
        }


def _pub_year(published: str) -> int:
    try:
        return int(published[:4])
    except (ValueError, TypeError):
        return _CURRENT_YEAR


def _tech_mentioned(text: str, tech_name: str) -> bool:
    """Check if the technology is mentioned in the CVE text."""
    # Build variant list (jQuery → jquery, JQuery, JQUERY)
    variants = {tech_name, tech_name.lower(), tech_name.upper(), tech_name.title()}
    # Handle common aliases
    aliases = {
        "jquery": ["jquery"],
        "wordpress": ["wordpress", "wp-", "wp "],
        "apache": ["apache http", "httpd", "apache web"],
        "nginx": ["nginx"],
        "django": ["django"],
        "flask": ["flask"],
        "laravel": ["laravel"],
        "drupal": ["drupal"],
        "express.js": ["express", "expressjs"],
        "react": ["react.js", "reactjs", "react "],
        "vue.js": ["vue.js", "vuejs", "vue "],
        "angular": ["angular", "angularjs"],
    }
    search_terms = variants | set(aliases.get(tech_name.lower(), []))
    haystack = (text or "").lower()
    return any(term.lower() in haystack for term in search_terms)


def score_cve(rec, tech_name: str, detected_version: str | None) -> ScoredCVE:
    """
    Calculate a confidence score for a CVE record against the detected technology/version.
    Returns a ScoredCVE with confidence_score (0-100).
    """
    scored = ScoredCVE.from_record(rec)
    reasons: list[str] = []
    penalty = 0

    # ── Source quality ────────────────────────────────────────────────────────
    # OSV  = exact version match in package ecosystem → strongest signal
    # GitHub = advisory with version range → medium confidence
    # NVD  = keyword-only full-text search → weaker baseline (many false positives)
    nvd_only = "osv" not in scored.sources and "github" not in scored.sources

    if "osv" in scored.sources:
        reasons.append("OSV: exact version match confirmed")
        penalty -= 15  # confidence bonus
    elif "github" in scored.sources and detected_version:
        reasons.append("GitHub Advisory: version range checked")
        penalty -= 5
    else:
        reasons.append("NVD keyword match — version not exact (false-positive risk)")
        penalty += 25  # raised from 20 — NVD keyword hits are frequently off-topic

    # NVD-only + no version detected = compounded uncertainty
    if nvd_only and not detected_version:
        reasons.append("NVD keyword + no detected version — cannot confirm impact")
        penalty += 10

    # ── Technology mention check ──────────────────────────────────────────────
    combined_text = f"{scored.title} {scored.description}"
    if not _tech_mentioned(combined_text, tech_name):
        reasons.append(f"CVE description does not mention '{tech_name}' — possible keyword drift")
        penalty += 25

    # ── Version availability ──────────────────────────────────────────────────
    if not detected_version:
        reasons.append("No version detected — cannot confirm version-specific impact")
        penalty += 15
    elif scored.affects_versions and detected_version not in scored.affects_versions:
        # If fixed_version is lower than detected, CVE is likely patched
        fixed = scored.fixed_version
        if fixed:
            try:
                from packaging.version import Version
                if Version(detected_version) >= Version(fixed):
                    reasons.append(f"Detected version {detected_version} >= fix version {fixed} — likely patched")
                    penalty += 40
            except Exception:
                pass

    # ── Age penalty ───────────────────────────────────────────────────────────
    pub_year = _pub_year(scored.published)
    age = _CURRENT_YEAR - pub_year
    if age > 5 and scored.epss_score < 0.05:
        reasons.append(f"CVE from {pub_year} ({age} years old) with low EPSS — outdated risk")
        penalty += 20
    elif age > 3 and scored.epss_score < 0.02:
        reasons.append(f"CVE from {pub_year} with very low exploitation probability")
        penalty += 10

    # ── CVSS threshold ────────────────────────────────────────────────────────
    if scored.cvss_score < 4.0 and scored.epss_score < 0.1:
        reasons.append("Low CVSS + low EPSS — informational only")
        penalty += 15

    # ── EPSS boost (high confidence signal) ──────────────────────────────────
    if scored.epss_score > 0.3:
        reasons.append(f"High EPSS ({scored.epss_score:.2%}) — actively exploited in the wild")
        penalty -= 20
    if scored.exploit_available:
        penalty -= 10

    # ── Multi-source confirmation ─────────────────────────────────────────────
    if len(scored.sources) > 1:
        reasons.append(f"Confirmed by {len(scored.sources)} independent sources")
        penalty -= 10

    scored.confidence_score = max(0, min(100, 100 - penalty))
    scored.confidence_reasons = reasons
    return scored


def filter_false_positives(
    records: list,
    tech_name: str,
    detected_version: str | None,
    demo_mode: bool = False,
) -> tuple[list[ScoredCVE], list[ScoredCVE]]:
    """
    Score all CVE records and split into (kept, filtered_out).

    kept:         confidence >= threshold — real findings to show user
    filtered_out: below threshold — likely false positives (debug only)
    """
    threshold = DEMO_MIN_CONFIDENCE if demo_mode else MIN_CONFIDENCE
    kept: list[ScoredCVE] = []
    filtered_out: list[ScoredCVE] = []

    for rec in records:
        scored = score_cve(rec, tech_name, detected_version)
        if scored.confidence_score >= threshold:
            kept.append(scored)
        else:
            filtered_out.append(scored)

    # Sort kept: CRITICAL→HIGH→MEDIUM→LOW, then EPSS desc, then confidence desc
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    kept.sort(key=lambda r: (_order.get(r.severity, 4), -r.epss_score, -r.confidence_score))

    return kept, filtered_out

"""
api/models.py — AI Cyber Shield v6

Pydantic v2 request/response models for the REST API.
Flat (not nested) so they serialise cleanly to JSON without custom encoders.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class ScanMode(str, Enum):
    standard = "standard"
    pt       = "pt"


class ScanStatus(str, Enum):
    queued   = "queued"
    running  = "running"
    complete = "complete"
    failed   = "failed"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ─────────────────────────────────────────────────────────────────────────────
# Scan request / response
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url:                  str
    mode:                 ScanMode = ScanMode.standard
    label:                Optional[str] = None
    notify_webhook_url:   Optional[str] = None   # POSTed when scan completes

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http:// or https://")
        if not parsed.netloc:
            raise ValueError("URL must include a hostname")
        return v

    @field_validator("notify_webhook_url")
    @classmethod
    def validate_webhook(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("notify_webhook_url must be a valid http/https URL")
        return v


class ScanResponse(BaseModel):
    scan_id:          str
    url:              str
    mode:             ScanMode
    status:           ScanStatus
    label:            Optional[str]  = None
    started_at:       Optional[str]  = None
    completed_at:     Optional[str]  = None
    overall_score:    Optional[int]  = None
    overall_grade:    Optional[str]  = None
    finding_count:    Optional[int]  = None
    error_message:    Optional[str]  = None


class ScanListResponse(BaseModel):
    scans:    list[ScanResponse]
    total:    int
    page:     int
    per_page: int


# ─────────────────────────────────────────────────────────────────────────────
# Finding response (flat structure — no nested dataclasses)
# ─────────────────────────────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    finding_id:            str
    title:                 str
    finding_type:          str
    tool:                  str
    severity:              str
    # CVSS
    cvss_score:            float
    cvss_vector:           str
    cvss_severity:         str
    # CWE
    cwe_id:                int
    cwe_label:             str
    cwe_name:              str
    cwe_url:               str
    # OWASP
    owasp_code:            str
    owasp_year:            int
    owasp_name:            str
    owasp_label:           str
    # Compliance
    compliance_pci_dss:    str
    compliance_soc2_cc:    str
    compliance_iso_27001:  str
    compliance_nist_csf:   str
    compliance_owasp_asvs: str
    # Impact
    business_impact:       str
    attack_scenario:       str
    # Remediation
    remediation_priority:     int
    remediation_effort_hours: float
    remediation_summary:      str
    remediation_code_before:  str
    remediation_code_after:   str
    remediation_references:   list[str]
    # Context
    endpoint:     str
    parameter:    str
    evidence:     str
    confirmed:    bool
    confidence:   float
    sarif_rule_id:   str
    scan_timestamp:  str


class FindingsListResponse(BaseModel):
    findings:    list[FindingResponse]
    total:       int
    page:        int
    per_page:    int
    scan_id:     str
    filters_applied: dict


class SummaryResponse(BaseModel):
    scan_id:          str
    total:            int
    confirmed:        int
    by_severity:      dict
    top_cvss_score:   float
    owasp_categories: list[str]
    cwe_ids:          list[str]


# ─────────────────────────────────────────────────────────────────────────────
# Schedule models
# ─────────────────────────────────────────────────────────────────────────────

class ScheduleRequest(BaseModel):
    url:                str
    cron_expression:    str = Field(..., examples=["0 * * * *"])
    label:              Optional[str] = None
    notify_webhook_url: Optional[str] = None
    notify_slack_webhook: Optional[str] = None
    is_active:          bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("URL must be a valid http/https URL")
        return v

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        parts = v.strip().split()
        if len(parts) not in (5, 6):
            raise ValueError(
                "cron_expression must have 5 fields (min hour dom mon dow) "
                "or 6 (sec min hour dom mon dow)"
            )
        return v


class ScheduleResponse(BaseModel):
    schedule_id:          str
    url:                  str
    cron_expression:      str
    label:                Optional[str] = None
    notify_webhook_url:   Optional[str] = None
    notify_slack_webhook: Optional[str] = None
    is_active:            bool
    created_at:           str
    last_run_at:          Optional[str] = None
    next_run_at:          Optional[str] = None
    last_scan_id:         Optional[str] = None


class ScheduleListResponse(BaseModel):
    schedules: list[ScheduleResponse]
    total:     int


# ─────────────────────────────────────────────────────────────────────────────
# Generic responses
# ─────────────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status:  str = "ok"
    version: str = "6.0.0"
    tools:   int = 17


class ErrorResponse(BaseModel):
    error:   str
    code:    str
    detail:  Optional[str] = None

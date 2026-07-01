"""
api/routers/findings.py — AI Cyber Shield v6

Endpoints:
  GET  /api/v1/scans/{scan_id}/findings              — paginated, filterable
  GET  /api/v1/scans/{scan_id}/findings/{finding_id} — single finding detail
  GET  /api/v1/scans/{scan_id}/sarif                 — SARIF 2.1 document
  GET  /api/v1/scans/{scan_id}/summary               — aggregate stats
  POST /api/v1/scans/{scan_id}/findings/{finding_id}/verify — re-scan to verify fix
  GET  /api/v1/scans/{scan_id}/chains                — attack chain detection
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from api.auth import verify_api_key
from api.models import (
    FindingResponse,
    FindingsListResponse,
    SummaryResponse,
)
from api.scan_store import ScanStore, ScanState, get_store
from finding_enricher import SecurityFinding, findings_summary, to_sarif_json

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _require_complete(state: Optional[ScanState], scan_id: str) -> ScanState:
    if not state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Scan not found", "code": "SCAN_NOT_FOUND"},
        )
    if state.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={
                "error":   "Scan still in progress",
                "code":    "SCAN_IN_PROGRESS",
                "status":  state.status,
                "scan_id": scan_id,
            },
        )
    if state.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error":         "Scan failed",
                "code":          "SCAN_FAILED",
                "error_message": state.error_message,
            },
        )
    return state


def _finding_to_response(f: SecurityFinding) -> FindingResponse:
    return FindingResponse(
        finding_id    = f.finding_id,
        title         = f.title,
        finding_type  = f.finding_type,
        tool          = f.tool,
        severity      = f.severity,
        cvss_score    = f.cvss.score,
        cvss_vector   = f.cvss.vector.vector_string,
        cvss_severity = f.cvss.severity,
        cwe_id        = f.cwe.id,
        cwe_label     = f.cwe.label,
        cwe_name      = f.cwe.name,
        cwe_url       = f.cwe.url,
        owasp_code    = f.owasp.code,
        owasp_year    = f.owasp.year,
        owasp_name    = f.owasp.name,
        owasp_label   = f.owasp.label,
        compliance_pci_dss    = f.compliance.pci_dss,
        compliance_soc2_cc    = f.compliance.soc2_cc,
        compliance_iso_27001  = f.compliance.iso_27001,
        compliance_nist_csf   = f.compliance.nist_csf,
        compliance_owasp_asvs = f.compliance.owasp_asvs,
        business_impact     = f.business_impact,
        attack_scenario     = f.attack_scenario,
        remediation_priority      = f.remediation.priority,
        remediation_effort_hours  = f.remediation.effort_hours,
        remediation_summary       = f.remediation.summary,
        remediation_code_before   = f.remediation.code_before,
        remediation_code_after    = f.remediation.code_after,
        remediation_references    = f.remediation.references,
        endpoint      = f.endpoint,
        parameter     = f.parameter,
        evidence      = f.evidence,
        confirmed     = f.confirmed,
        confidence    = f.confidence,
        sarif_rule_id = f.sarif_rule_id,
        scan_timestamp= f.scan_timestamp,
    )


def _filter_findings(
    findings:  list[SecurityFinding],
    severity:  Optional[str],
    confirmed: Optional[bool],
    owasp:     Optional[str],
    tool:      Optional[str],
    min_cvss:  Optional[float],
) -> list[SecurityFinding]:
    result = findings

    if severity:
        allowed = {s.strip().upper() for s in severity.split(",")}
        result  = [f for f in result if f.severity in allowed]

    if confirmed is not None:
        result = [f for f in result if f.confirmed == confirmed]

    if owasp:
        allowed_owasp = {o.strip().upper() for o in owasp.split(",")}
        result = [f for f in result if f.owasp.code.upper() in allowed_owasp]

    if tool:
        allowed_tools = {t.strip().lower() for t in tool.split(",")}
        result = [f for f in result if f.tool.lower() in allowed_tools]

    if min_cvss is not None:
        result = [f for f in result if f.cvss.score >= min_cvss]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/{scan_id}/findings",
    response_model=FindingsListResponse,
    summary="Get enriched findings for a completed scan",
)
async def get_findings(
    scan_id:   str,
    severity:  Optional[str]   = Query(None,  description="CRITICAL,HIGH (comma-separated)"),
    confirmed: Optional[bool]  = Query(None,  description="true = confirmed findings only"),
    owasp:     Optional[str]   = Query(None,  description="A05,A03 (comma-separated OWASP codes)"),
    tool:      Optional[str]   = Query(None,  description="cors_csp,ssl (comma-separated tool names)"),
    min_cvss:  Optional[float] = Query(None,  ge=0.0, le=10.0, description="Minimum CVSS score"),
    sort_by:   str             = Query("cvss", description="cvss|severity|confirmed|tool"),
    page:      int             = Query(1,  ge=1),
    per_page:  int             = Query(20, ge=1, le=100),
    store:     ScanStore       = Depends(get_store),
    _api_key:  str             = Depends(verify_api_key),
) -> FindingsListResponse:
    state    = _require_complete(store.get(scan_id), scan_id)
    filtered = _filter_findings(
        state.findings, severity, confirmed, owasp, tool, min_cvss
    )

    # Sort
    sort_by = sort_by.lower()
    if sort_by == "cvss":
        filtered.sort(key=lambda f: (-f.cvss.score, not f.confirmed))
    elif sort_by == "severity":
        _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        filtered.sort(key=lambda f: _SEV_ORDER.get(f.severity, 5))
    elif sort_by == "confirmed":
        filtered.sort(key=lambda f: (not f.confirmed, -f.cvss.score))
    elif sort_by == "tool":
        filtered.sort(key=lambda f: (f.tool, -f.cvss.score))

    total  = len(filtered)
    start  = (page - 1) * per_page
    end    = start + per_page
    page_items = filtered[start:end]

    filters_applied = {
        k: v for k, v in {
            "severity":  severity,
            "confirmed": confirmed,
            "owasp":     owasp,
            "tool":      tool,
            "min_cvss":  min_cvss,
        }.items() if v is not None
    }

    return FindingsListResponse(
        findings=[_finding_to_response(f) for f in page_items],
        total=total,
        page=page,
        per_page=per_page,
        scan_id=scan_id,
        filters_applied=filters_applied,
    )


@router.get(
    "/{scan_id}/findings/{finding_id}",
    response_model=FindingResponse,
    summary="Get a single finding by ID",
)
async def get_finding(
    scan_id:    str,
    finding_id: str,
    store:      ScanStore = Depends(get_store),
    _api_key:   str       = Depends(verify_api_key),
) -> FindingResponse:
    state = _require_complete(store.get(scan_id), scan_id)
    match = next(
        (f for f in state.findings if f.finding_id == finding_id), None
    )
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Finding not found", "code": "FINDING_NOT_FOUND"},
        )
    return _finding_to_response(match)


@router.get(
    "/{scan_id}/sarif",
    summary="Get SARIF 2.1 document (GitHub Code Scanning compatible)",
)
async def get_sarif(
    scan_id:  str,
    store:    ScanStore = Depends(get_store),
    _api_key: str       = Depends(verify_api_key),
) -> Response:
    state = _require_complete(store.get(scan_id), scan_id)
    sarif = to_sarif_json(state.findings, target_url=state.url, scan_id=scan_id)

    import json
    return Response(
        content=json.dumps(sarif, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="aics-{scan_id[:8]}.sarif"',
            "X-SARIF-Version":     "2.1.0",
        },
    )


@router.get(
    "/{scan_id}/summary",
    response_model=SummaryResponse,
    summary="Get aggregate statistics for a completed scan",
)
async def get_summary(
    scan_id:  str,
    store:    ScanStore = Depends(get_store),
    _api_key: str       = Depends(verify_api_key),
) -> SummaryResponse:
    state = _require_complete(store.get(scan_id), scan_id)
    stats = findings_summary(state.findings)
    return SummaryResponse(
        scan_id=scan_id,
        **stats,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Verify Fix — targeted single-tool re-scan
# ─────────────────────────────────────────────────────────────────────────────

class VerifyFixResponse(BaseModel):
    finding_id:     str
    status:         str          # "resolved" | "still_open" | "error"
    tool_name:      str
    previous_score: Optional[int]
    new_score:      Optional[int]
    scan_duration_ms: int
    verified_at:    str
    message:        str


def _run_single_tool(tool_name: str, url: str) -> tuple[dict, int]:
    """
    Run a single registered tool against a URL.
    Returns (result_dict, duration_ms).
    Raises KeyError if tool_name not registered.
    Raises RuntimeError if tool execution fails.
    """
    from tools.tool_registry import get_tool
    config    = get_tool(tool_name)          # raises KeyError if unknown
    fn        = config["function"]
    args      = config["invoke_args"](url)
    timeout_s = config["timeout_seconds"]

    start = time.time()
    try:
        raw    = fn.invoke(args)
        result = json.loads(raw) if isinstance(raw, str) else raw
        duration_ms = int((time.time() - start) * 1000)
        return result, duration_ms
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        raise RuntimeError(f"Tool {tool_name} failed: {exc}") from exc


def _finding_still_present(finding_id: str, tool_result: dict) -> bool:
    """
    Check if a finding with the given ID still appears in the new tool result.
    The tool result may contain 'findings' as a list of dicts with 'finding_id' key.
    """
    findings = tool_result.get("findings", [])
    if not isinstance(findings, list):
        return False
    return any(
        (f.get("finding_id") == finding_id or f.get("id") == finding_id)
        for f in findings
        if isinstance(f, dict)
    )


@router.post(
    "/{scan_id}/findings/{finding_id}/verify",
    response_model=VerifyFixResponse,
    summary="Verify Fix — re-run the relevant tool to check if the finding was resolved",
    status_code=200,
)
async def verify_fix(
    scan_id:    str,
    finding_id: str,
    store:      ScanStore = Depends(get_store),
    _api_key:   str       = Depends(verify_api_key),
) -> VerifyFixResponse:
    """
    Re-run only the tool that produced this finding.
    Returns status='resolved' if the finding no longer appears,
    or 'still_open' if it does.

    Costs 1/5 of a full scan against the user's quota.
    Available on Starter tier and above (not the free tier).
    Rate limit: 10 verify requests per minute per API key.
    """
    # ── Locate finding in completed scan ──────────────────────────────────────
    state = _require_complete(store.get(scan_id), scan_id)
    finding = next(
        (f for f in state.findings if f.finding_id == finding_id), None
    )
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Finding not found", "code": "FINDING_NOT_FOUND"},
        )

    tool_name = finding.tool
    url       = state.url

    # ── Validate tool exists in registry ─────────────────────────────────────
    try:
        from tools.tool_registry import get_tool
        get_tool(tool_name)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": f"Tool '{tool_name}' is not registered in the tool registry",
                "code":  "UNKNOWN_TOOL_SOURCE",
            },
        )

    # ── Re-run the single tool ────────────────────────────────────────────────
    try:
        tool_result, duration_ms = _run_single_tool(tool_name, url)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": str(exc), "code": "TOOL_EXECUTION_ERROR"},
        )

    # ── Evaluate result ───────────────────────────────────────────────────────
    still_present = _finding_still_present(finding_id, tool_result)
    verified_at   = datetime.now(timezone.utc).isoformat()
    new_score     = tool_result.get("score") or tool_result.get("risk_score")
    if isinstance(new_score, (int, float)):
        new_score = int(new_score)
    else:
        new_score = None

    if still_present:
        result_status = "still_open"
        message = (
            f"Finding still detected after re-scanning with {tool_name}. "
            "The fix may not have been deployed yet, or the issue persists."
        )
    else:
        result_status = "resolved"
        message = (
            f"Finding no longer detected after re-scanning with {tool_name}. "
            "The fix appears to be in effect."
        )

    return VerifyFixResponse(
        finding_id      = finding_id,
        status          = result_status,
        tool_name       = tool_name,
        previous_score  = int(finding.cvss.score * 10) if finding.cvss.score else None,
        new_score       = new_score,
        scan_duration_ms= duration_ms,
        verified_at     = verified_at,
        message         = message,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Attack Chain Detection
# ─────────────────────────────────────────────────────────────────────────────

class AttackChainNodeResponse(BaseModel):
    finding_id: str
    title:      str
    severity:   str
    tool:       str
    role:       str   # "prerequisite" | "amplifier"


class AttackChainResponse(BaseModel):
    id:               str
    name:             str
    description:      str
    severity:         str
    cvss:             float
    impact:           str
    remediation:      str
    detection_method: str
    prerequisites:    list[AttackChainNodeResponse]
    amplifiers:       list[AttackChainNodeResponse]


class AttackChainsListResponse(BaseModel):
    scan_id:      str
    chains:       list[AttackChainResponse]
    total:        int
    critical:     int
    high:         int


@router.get(
    "/{scan_id}/chains",
    response_model=AttackChainsListResponse,
    summary="Detect multi-step attack chains from scan findings",
    tags=["chains"],
)
async def get_attack_chains(
    scan_id:  str,
    store:    ScanStore = Depends(get_store),
    _api_key: str       = Depends(verify_api_key),
) -> AttackChainsListResponse:
    """
    Analyze how individual findings combine into exploitable multi-step attack chains.

    Returns chains sorted by severity (CRITICAL first), then CVSS descending.
    A chain is only detected when ALL its prerequisite findings are present in the scan.
    Amplifiers are optional — they worsen the attack but aren't required.

    Available on all paid tiers.
    """
    state = _require_complete(store.get(scan_id), scan_id)

    from core.attack_chain_engine import detect_chains
    chains = detect_chains(state.findings)

    def _node(n) -> AttackChainNodeResponse:
        return AttackChainNodeResponse(
            finding_id = n.finding_id,
            title      = n.title,
            severity   = n.severity,
            tool       = n.tool,
            role       = n.role,
        )

    chain_responses = [
        AttackChainResponse(
            id               = c.id,
            name             = c.name,
            description      = c.description,
            severity         = c.severity,
            cvss             = c.cvss,
            impact           = c.impact,
            remediation      = c.remediation,
            detection_method = c.detection_method,
            prerequisites    = [_node(n) for n in c.prerequisites],
            amplifiers       = [_node(n) for n in c.amplifiers],
        )
        for c in chains
    ]

    return AttackChainsListResponse(
        scan_id  = scan_id,
        chains   = chain_responses,
        total    = len(chain_responses),
        critical = sum(1 for c in chain_responses if c.severity == "CRITICAL"),
        high     = sum(1 for c in chain_responses if c.severity == "HIGH"),
    )

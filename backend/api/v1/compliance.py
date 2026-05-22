"""
AML Monitoring System — Compliance API Endpoints
FINMA GwG Art.9 STR and BaFin GwG §43 SAR generation endpoints.

Endpoints:
  POST /api/v1/compliance/sar            — Generate & store a SAR/STR
  GET  /api/v1/compliance/finma-report   — Retrieve FINMA STR by ID
  GET  /api/v1/compliance/bafin-report   — Retrieve BaFin SAR by ID
  GET  /api/v1/compliance/reports        — List all compliance reports
  GET  /api/v1/compliance/stats          — Compliance statistics

Access:
  - POST: requires compliance_officer role
  - GET:  requires aml_analyst or compliance_officer role
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from backend.core.auth import require_roles
from backend.config.logging_config import get_logger
from backend.utils.compliance_reporter import (
    ComplianceReport,
    ReportType,
    SuspicionCategory,
    generate_bafin_sar,
    generate_finma_str,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/compliance", tags=["Compliance"])

# ── In-memory report store (replace with DB in production) ───────────────────
_REPORT_STORE: Dict[str, Dict[str, Any]] = {}


# ── Request / Response Models ─────────────────────────────────────────────────

class SARRequest(BaseModel):
    """Request body for generating a Suspicious Activity Report."""

    alert_id: str = Field(..., description="Alert ID that triggered this SAR")
    report_type: str = Field(
        default="FINMA_STR",
        description="FINMA_STR (Switzerland) or BAFIN_SAR (Germany)",
    )
    transactions: List[Dict[str, Any]] = Field(
        ..., min_length=1, description="One or more suspicious transactions"
    )
    subject: Optional[Dict[str, Any]] = Field(
        default=None, description="Subject / account holder details"
    )
    suspicion_categories: Optional[List[str]] = Field(
        default=None, description="Suspicion categories (SuspicionCategory enum values)"
    )
    ml_scores: Optional[Dict[str, float]] = Field(
        default=None, description="ML model scores: {anomaly_score, risk_score}"
    )

    @field_validator("report_type")
    @classmethod
    def validate_report_type(cls, v: str) -> str:
        allowed = {rt.value for rt in ReportType}
        if v.upper() not in allowed:
            raise ValueError(f"report_type must be one of {allowed}")
        return v.upper()

    @field_validator("suspicion_categories")
    @classmethod
    def validate_categories(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        allowed = {sc.value for sc in SuspicionCategory}
        for cat in v:
            if cat.upper() not in allowed:
                raise ValueError(f"Unknown suspicion category '{cat}'. Allowed: {allowed}")
        return [c.upper() for c in v]


class ReportListItem(BaseModel):
    report_id: str
    report_type: str
    status: str
    created_at: str
    regulatory_ref: str
    transaction_count: int
    total_amount: float
    currency: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/sar",
    summary="Generate Suspicious Activity Report (SAR / STR)",
    description=(
        "Generates a FINMA GwG Art.9 STR (Switzerland) or BaFin GwG §43 SAR (Germany). "
        "Requires **compliance_officer** role. "
        "Reports are stored internally and can be retrieved via GET /compliance/finma-report or /bafin-report."
    ),
    status_code=201,
)
async def generate_sar(
    request: Request,
    body: SARRequest,
    current_user: dict = Depends(require_roles(["compliance_officer"])),
) -> JSONResponse:
    """Generate and store a compliance report (SAR/STR)."""
    submitted_by = current_user.get("sub", "compliance_officer")

    try:
        if body.report_type == ReportType.BAFIN_SAR.value:
            report = generate_bafin_sar(
                alert_id=body.alert_id,
                transactions=body.transactions,
                subject=body.subject,
                categories=body.suspicion_categories,
                ml_scores=body.ml_scores,
                submitted_by=submitted_by,
            )
        else:
            report = generate_finma_str(
                alert_id=body.alert_id,
                transactions=body.transactions,
                subject=body.subject,
                categories=body.suspicion_categories,
                ml_scores=body.ml_scores,
                submitted_by=submitted_by,
            )

        # Store report
        _REPORT_STORE[report.report_id] = report.to_dict()

        lang = request.headers.get("Accept-Language", "en").lower()
        msg_de = f"Verdachtsmeldung {report.report_id} erfolgreich erstellt."
        msg_en = f"Compliance report {report.report_id} generated successfully."

        logger.info(
            "SAR/STR generated via API",
            report_id=report.report_id,
            report_type=body.report_type,
            submitted_by=submitted_by,
            alert_id=body.alert_id,
        )

        return JSONResponse(
            status_code=201,
            content={
                "report_id": report.report_id,
                "report_type": report.report_type,
                "status": report.status,
                "regulatory_ref": report.regulatory_ref,
                "report_hash": report.report_hash,
                "created_at": report.created_at,
                "narrative": report.narrative_de if lang.startswith("de") else report.narrative_en,
                "indicators": (
                    report.suspicion.indicators_de
                    if (report.suspicion and lang.startswith("de"))
                    else (report.suspicion.indicators_en if report.suspicion else [])
                ),
                "message_de": msg_de,
                "message_en": msg_en,
            },
        )

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error("SAR generation failed", error=str(e), alert_id=body.alert_id)
        raise HTTPException(status_code=500, detail="Report generation failed.")


@router.get(
    "/finma-report",
    summary="Retrieve FINMA STR by ID",
    description="Retrieve a previously generated FINMA GwG Art.9 Suspicious Transaction Report.",
)
async def get_finma_report(
    report_id: str = Query(..., description="Report ID (FINMA-STR-YYYYMMDD-XXXXXXXX)"),
    current_user: dict = Depends(require_roles(["aml_analyst", "compliance_officer"])),
) -> JSONResponse:
    """Retrieve a FINMA STR by its report ID."""
    report = _REPORT_STORE.get(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail={
                "message_de": f"Bericht '{report_id}' nicht gefunden.",
                "message_en": f"Report '{report_id}' not found.",
            },
        )
    if report.get("report_type") != ReportType.FINMA_STR.value:
        raise HTTPException(
            status_code=400,
            detail={
                "message_de": "Bericht ist kein FINMA-STR.",
                "message_en": "Report is not a FINMA STR.",
            },
        )
    return JSONResponse(content=report)


@router.get(
    "/bafin-report",
    summary="Retrieve BaFin SAR by ID",
    description="Retrieve a previously generated BaFin GwG §43 Suspicious Activity Report.",
)
async def get_bafin_report(
    report_id: str = Query(..., description="Report ID (BAFIN-SAR-YYYYMMDD-XXXXXXXX)"),
    current_user: dict = Depends(require_roles(["aml_analyst", "compliance_officer"])),
) -> JSONResponse:
    """Retrieve a BaFin SAR by its report ID."""
    report = _REPORT_STORE.get(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail={
                "message_de": f"Bericht '{report_id}' nicht gefunden.",
                "message_en": f"Report '{report_id}' not found.",
            },
        )
    if report.get("report_type") != ReportType.BAFIN_SAR.value:
        raise HTTPException(
            status_code=400,
            detail={
                "message_de": "Bericht ist kein BaFin-SAR.",
                "message_en": "Report is not a BaFin SAR.",
            },
        )
    return JSONResponse(content=report)


@router.get(
    "/reports",
    summary="List all compliance reports",
    description="List all generated SAR/STR reports with summary metadata.",
)
async def list_reports(
    report_type: Optional[str] = Query(default=None, description="Filter by FINMA_STR or BAFIN_SAR"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(require_roles(["aml_analyst", "compliance_officer"])),
) -> JSONResponse:
    """List compliance reports with optional type filter and pagination."""
    reports = list(_REPORT_STORE.values())

    if report_type:
        reports = [r for r in reports if r.get("report_type") == report_type.upper()]

    # Sort by created_at descending
    reports.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    total = len(reports)
    page = reports[offset: offset + limit]

    summary = []
    for r in page:
        txns = r.get("transactions", [])
        total_amount = sum(float(t.get("amount", 0)) for t in txns)
        currencies = list({t.get("currency", "?") for t in txns})
        summary.append({
            "report_id": r.get("report_id"),
            "report_type": r.get("report_type"),
            "status": r.get("status"),
            "created_at": r.get("created_at"),
            "regulatory_ref": r.get("regulatory_ref"),
            "transaction_count": len(txns),
            "total_amount": round(total_amount, 2),
            "currency": currencies[0] if len(currencies) == 1 else str(currencies),
        })

    return JSONResponse(content={
        "total": total,
        "limit": limit,
        "offset": offset,
        "reports": summary,
    })


@router.get(
    "/stats",
    summary="Compliance statistics",
    description="Aggregate statistics across all generated compliance reports.",
)
async def compliance_stats(
    current_user: dict = Depends(require_roles(["aml_analyst", "compliance_officer"])),
) -> JSONResponse:
    """Return compliance statistics: counts, types, amounts."""
    all_reports = list(_REPORT_STORE.values())

    finma_count = sum(1 for r in all_reports if r.get("report_type") == ReportType.FINMA_STR.value)
    bafin_count = sum(1 for r in all_reports if r.get("report_type") == ReportType.BAFIN_SAR.value)

    total_amount_sar = sum(
        float(t.get("amount", 0))
        for r in all_reports
        for t in r.get("transactions", [])
    )

    category_counts: Dict[str, int] = {}
    for r in all_reports:
        suspicion = r.get("suspicion") or {}
        for cat in suspicion.get("categories", []):
            category_counts[cat] = category_counts.get(cat, 0) + 1

    return JSONResponse(content={
        "total_reports": len(all_reports),
        "finma_str_count": finma_count,
        "bafin_sar_count": bafin_count,
        "total_amount_reported": round(total_amount_sar, 2),
        "suspicion_category_distribution": category_counts,
        "as_of": datetime.now(timezone.utc).isoformat(),
        "regulatory_frameworks": [
            "FINMA GwG Art. 9 — Schweiz",
            "BaFin GwG §43 — Deutschland",
            "FATF Recommendation 20 — STR",
            "AMLD6 — EU 6th Anti-Money Laundering Directive",
        ],
    })

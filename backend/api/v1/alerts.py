"""
AML Monitoring System — Alerts API Router
Full AML alert lifecycle management with false-positive tracking and SAR support.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from prometheus_client import Counter, Gauge

from backend.config.logging_config import get_logger
from backend.core.rbac import Permission, require_permission
from backend.models.account import UserInDB
from backend.models.alert import (
    AlertDetailResponse,
    AlertListResponse,
    AlertResponse,
    AlertSeverity,
    AlertStatsResponse,
    AlertStatus,
    AlertUpdate,
    AMLTypology,
)
from backend.services.alert_service import AlertService
from backend.services.audit_service import AuditService

logger = get_logger(__name__)
router = APIRouter(prefix="/alerts", tags=["AML Alerts"])

# ── Prometheus Metrics ────────────────────────────────────────────────────────
alerts_open = Gauge("aml_alerts_open_total", "Currently open AML alerts", ["severity"])
alerts_resolved = Counter("aml_alerts_resolved_total", "Resolved alerts", ["resolution"])
false_positive_rate = Gauge("aml_false_positive_rate", "Rolling false positive rate")


def _get_lang(request: Request) -> str:
    accept = request.headers.get("Accept-Language", "de")
    return "de" if accept.startswith("de") else "en"


@router.get(
    "",
    response_model=AlertListResponse,
    summary="List AML alerts",
    description="Returns paginated AML alerts. Supports filtering by status, severity, typology, date range.",
)
async def list_alerts(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[AlertStatus] = Query(None, alias="status"),
    severity: Optional[AlertSeverity] = None,
    typology: Optional[AMLTypology] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    assigned_to_me: bool = False,
    include_false_positives: bool = False,
    current_user: UserInDB = Depends(require_permission(Permission.ALERTS_READ)),
    alert_service: AlertService = Depends(AlertService),
) -> AlertListResponse:
    lang = _get_lang(request)
    return await alert_service.list_alerts(
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        severity=severity,
        typology=typology,
        from_date=from_date,
        to_date=to_date,
        assigned_to=current_user.username if assigned_to_me else None,
        include_false_positives=include_false_positives,
        lang=lang,
    )


@router.get(
    "/stats",
    response_model=AlertStatsResponse,
    summary="Alert dashboard statistics",
)
async def get_alert_stats(
    current_user: UserInDB = Depends(require_permission(Permission.ALERTS_READ)),
    alert_service: AlertService = Depends(AlertService),
) -> AlertStatsResponse:
    """Returns KPIs for the Power BI / Grafana dashboard: counts, FP rate, trends."""
    return await alert_service.get_stats()


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Get alert detail with SHAP explanation",
)
async def get_alert(
    alert_id: str,
    request: Request,
    current_user: UserInDB = Depends(require_permission(Permission.ALERTS_READ)),
    alert_service: AlertService = Depends(AlertService),
) -> AlertDetailResponse:
    lang = _get_lang(request)
    alert = await alert_service.get_alert(alert_id, lang=lang)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "alert_not_found",
                "message_de": f"Alert {alert_id} nicht gefunden.",
                "message_en": f"Alert {alert_id} not found.",
            },
        )
    return alert


@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert status (resolve, escalate, mark false positive)",
)
async def update_alert(
    alert_id: str,
    update: AlertUpdate,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: UserInDB = Depends(require_permission(Permission.ALERTS_WRITE)),
    alert_service: AlertService = Depends(AlertService),
    audit_service: AuditService = Depends(AuditService),
) -> AlertResponse:
    """
    Update alert. Analysts can:
    - Mark as RESOLVED (with notes)
    - Mark as FALSE_POSITIVE (with reason — feeds model retraining)
    - ESCALATE (with reason — triggers immediate compliance notification)
    - Add analyst notes

    False positive data is stored and used in weekly model retraining.
    """
    lang = _get_lang(request)

    # Enforce: only compliance_officer can mark SAR_FILED
    if update.status == AlertStatus.SAR_FILED and not current_user.is_compliance_officer:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "sar_restricted",
                "message_de": "Nur Compliance-Beauftragter darf SAR-Status setzen.",
                "message_en": "Only compliance officer can set SAR_FILED status.",
            },
        )

    result = await alert_service.update_alert(
        alert_id=alert_id,
        update=update,
        analyst=current_user.username,
        lang=lang,
    )
    if not result:
        raise HTTPException(status_code=404, detail={"error": "alert_not_found"})

    # Update Prometheus metrics
    if update.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.SAR_FILED):
        alerts_resolved.labels(resolution=update.status.value).inc()
        if update.is_false_positive:
            # Recalculate FP rate asynchronously
            background_tasks.add_task(alert_service.update_fp_rate_metric)

    background_tasks.add_task(
        audit_service.log,
        action="alert.updated",
        actor=current_user.username,
        resource_id=alert_id,
        details={
            "new_status": update.status.value if update.status else None,
            "is_false_positive": update.is_false_positive,
        },
    )
    return result


@router.post(
    "/{alert_id}/assign",
    response_model=AlertResponse,
    summary="Assign alert to an analyst",
)
async def assign_alert(
    alert_id: str,
    analyst_username: str,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(require_permission(Permission.ALERTS_WRITE)),
    alert_service: AlertService = Depends(AlertService),
    audit_service: AuditService = Depends(AuditService),
) -> AlertResponse:
    """Assign an open alert to a specific analyst."""
    result = await alert_service.assign_alert(alert_id, analyst_username)
    if not result:
        raise HTTPException(status_code=404, detail={"error": "alert_not_found"})

    background_tasks.add_task(
        audit_service.log,
        action="alert.assigned",
        actor=current_user.username,
        resource_id=alert_id,
        details={"assigned_to": analyst_username},
    )
    return result


@router.get(
    "/{alert_id}/history",
    summary="Get alert audit history",
)
async def get_alert_history(
    alert_id: str,
    current_user: UserInDB = Depends(require_permission(Permission.AUDIT_READ)),
    audit_service: AuditService = Depends(AuditService),
) -> list:
    """Returns the full immutable audit trail for this alert."""
    return await audit_service.get_resource_history("alert", alert_id)

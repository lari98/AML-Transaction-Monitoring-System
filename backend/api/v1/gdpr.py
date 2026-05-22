"""
AML Monitoring System — GDPR/DSGVO API Router
Data subject rights: erasure, portability, audit, retention.
FINMA retention: 10 years | GDPR deletion SLA: 24 hours
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel

from backend.config.logging_config import get_logger
from backend.core.rbac import Permission, require_permission, Role, require_role
from backend.models.account import UserInDB
from backend.services.audit_service import AuditService
from backend.services.gdpr_service import GDPRService

logger = get_logger(__name__)
router = APIRouter(prefix="/gdpr", tags=["GDPR / DSGVO"])


class DeletionRequest(BaseModel):
    account_id: str
    requestor_name: str
    requestor_email: str
    request_reason: str
    legal_basis: str = "GDPR Article 17 - Right to Erasure"
    confirm_deletion: bool


class DeletionResponse(BaseModel):
    request_id: str
    account_id_masked: str
    status: str
    requested_at: datetime
    scheduled_deletion_at: datetime
    confirmation_message_de: str
    confirmation_message_en: str
    audit_reference: str


class DataExportResponse(BaseModel):
    request_id: str
    account_id_masked: str
    export_url: str
    expires_at: datetime
    data_categories: list[str]
    format: str
    is_anonymized: bool


class RetentionStatus(BaseModel):
    total_accounts: int
    accounts_past_retention: int
    scheduled_deletions_pending: int
    last_purge_run: Optional[datetime]
    next_purge_scheduled: Optional[datetime]
    retention_policy_de: str
    retention_policy_en: str


@router.post(
    "/delete/{account_id}",
    response_model=DeletionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request data erasure (GDPR Art. 17 / DSGVO §17)",
)
async def request_deletion(
    account_id: str,
    request_body: DeletionRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: UserInDB = Depends(require_permission(Permission.GDPR_DELETE)),
    gdpr_service: GDPRService = Depends(GDPRService),
    audit_service: AuditService = Depends(AuditService),
) -> DeletionResponse:
    """
    Initiate GDPR data erasure for an account.

    Workflow:
    1. Validate account exists and is not subject to legal hold (AML investigation)
    2. Check FINMA retention requirements (cannot delete if retention period active)
    3. Schedule deletion for 24 hours (allows reversal)
    4. Send confirmation to requestor
    5. Log immutable audit trail entry
    6. Execute deletion at scheduled time (data_admin background job)

    Note: Accounts under active AML investigation CANNOT be deleted until
    investigation is closed (legal hold applies per FINMA circular 2017/1).
    """
    if not request_body.confirm_deletion:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "confirmation_required",
                "message_de": "Löschbestätigung ist erforderlich.",
                "message_en": "Deletion confirmation is required.",
            },
        )

    result = await gdpr_service.schedule_deletion(
        account_id=account_id,
        requestor=current_user.username,
        request_data=request_body,
    )

    if result.get("error") == "legal_hold":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "legal_hold_active",
                "message_de": "Konto unterliegt einer rechtlichen Sperrung (AML-Untersuchung läuft). Löschung nicht möglich.",
                "message_en": "Account is under legal hold (active AML investigation). Deletion not possible.",
                "hold_expires": result.get("hold_expires"),
            },
        )

    if result.get("error") == "retention_active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "retention_period_active",
                "message_de": f"Aufbewahrungsfrist läuft noch bis {result.get('retention_until')}. Löschung nach FINMA nicht zulässig.",
                "message_en": f"Retention period active until {result.get('retention_until')}. Deletion not permitted under FINMA rules.",
                "retention_until": result.get("retention_until"),
            },
        )

    # Schedule actual deletion as background task
    background_tasks.add_task(
        gdpr_service.execute_scheduled_deletion, result["request_id"]
    )

    # Mandatory audit log for GDPR deletion requests
    await audit_service.log(
        action="gdpr.deletion_requested",
        actor=current_user.username,
        resource_id=account_id,
        details={
            "request_id": result["request_id"],
            "legal_basis": request_body.legal_basis,
            "scheduled_at": result["scheduled_deletion_at"],
        },
        severity="HIGH",
    )

    from backend.core.security import pii_encryption
    return DeletionResponse(
        request_id=result["request_id"],
        account_id_masked=pii_encryption.mask(account_id, visible_chars=4),
        status="SCHEDULED",
        requested_at=result["requested_at"],
        scheduled_deletion_at=result["scheduled_deletion_at"],
        confirmation_message_de=(
            f"Löschantrag wurde angenommen. Daten werden am "
            f"{result['scheduled_deletion_at'].strftime('%d.%m.%Y um %H:%M')} gelöscht. "
            f"Referenz: {result['request_id']}"
        ),
        confirmation_message_en=(
            f"Deletion request accepted. Data will be erased on "
            f"{result['scheduled_deletion_at'].strftime('%Y-%m-%d at %H:%M')}. "
            f"Reference: {result['request_id']}"
        ),
        audit_reference=result["audit_reference"],
    )


@router.get(
    "/export/{account_id}",
    response_model=DataExportResponse,
    summary="Export account data (GDPR Art. 20 - Right to Portability)",
)
async def export_account_data(
    account_id: str,
    anonymized: bool = True,
    current_user: UserInDB = Depends(require_permission(Permission.GDPR_EXPORT)),
    gdpr_service: GDPRService = Depends(GDPRService),
    audit_service: AuditService = Depends(AuditService),
) -> DataExportResponse:
    """
    Generate a portable data export for a data subject.
    Export is anonymized by default. Compliance officers can request
    the full identified export for regulatory purposes.
    """
    # Only compliance_officer can get non-anonymized exports
    if not anonymized and not current_user.is_compliance_officer:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "non_anonymized_restricted",
                "message_de": "Nicht-anonymisierter Export nur für Compliance-Beauftrage.",
                "message_en": "Non-anonymized export restricted to compliance officers.",
            },
        )

    result = await gdpr_service.generate_export(account_id, anonymized=anonymized)

    await audit_service.log(
        action="gdpr.data_exported",
        actor=current_user.username,
        resource_id=account_id,
        details={"anonymized": anonymized, "export_url": "***"},
        severity="MEDIUM",
    )

    from backend.core.security import pii_encryption
    return DataExportResponse(
        request_id=result["request_id"],
        account_id_masked=pii_encryption.mask(account_id, visible_chars=4),
        export_url=result["export_url"],
        expires_at=result["expires_at"],
        data_categories=result["categories"],
        format="JSON",
        is_anonymized=anonymized,
    )


@router.get(
    "/retention/status",
    response_model=RetentionStatus,
    summary="View data retention status and upcoming deletions",
)
async def get_retention_status(
    current_user: UserInDB = Depends(require_permission(Permission.GDPR_AUDIT)),
    gdpr_service: GDPRService = Depends(GDPRService),
) -> RetentionStatus:
    """Overview of data retention compliance across all accounts."""
    stats = await gdpr_service.get_retention_status()
    return RetentionStatus(
        total_accounts=stats["total_accounts"],
        accounts_past_retention=stats["past_retention"],
        scheduled_deletions_pending=stats["pending_deletions"],
        last_purge_run=stats.get("last_purge"),
        next_purge_scheduled=stats.get("next_purge"),
        retention_policy_de=(
            "Transaktionsdaten: 10 Jahre (FINMA); Protokolle: 7 Jahre; "
            "Kundenprofile: 5 Jahre nach Kontoschließung."
        ),
        retention_policy_en=(
            "Transaction data: 10 years (FINMA); Audit logs: 7 years; "
            "Customer profiles: 5 years after account closure."
        ),
    )


@router.delete(
    "/cancel/{request_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel a pending deletion request",
)
async def cancel_deletion(
    request_id: str,
    current_user: UserInDB = Depends(require_permission(Permission.GDPR_DELETE)),
    gdpr_service: GDPRService = Depends(GDPRService),
    audit_service: AuditService = Depends(AuditService),
) -> None:
    """Cancel a deletion request before the 24-hour window expires."""
    cancelled = await gdpr_service.cancel_deletion(request_id)
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "request_not_found_or_already_executed",
                "message_de": "Löschanfrage nicht gefunden oder bereits ausgeführt.",
                "message_en": "Deletion request not found or already executed.",
            },
        )
    await audit_service.log(
        action="gdpr.deletion_cancelled",
        actor=current_user.username,
        resource_id=request_id,
        details={},
        severity="MEDIUM",
    )

"""
AML Monitoring System — Transaction API Router
POST /api/v1/transactions         — ingest single transaction
POST /api/v1/transactions/bulk    — bulk ingest (up to 1000)
GET  /api/v1/transactions         — list with filters
GET  /api/v1/transactions/{id}    — transaction detail + scoring
POST /api/v1/transactions/{id}/rescore — force re-score
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from prometheus_client import Counter, Histogram

from backend.config.logging_config import get_logger
from backend.core.rbac import Permission, require_permission
from backend.models.account import UserInDB
from backend.models.transaction import (
    BulkIngestRequest,
    BulkIngestResponse,
    RiskLevel,
    ScoringResult,
    TransactionDetailResponse,
    TransactionIngest,
    TransactionListResponse,
    TransactionResponse,
    TransactionStatus,
)
from backend.services.audit_service import AuditService
from backend.services.ml_service import MLService

logger = get_logger(__name__)
router = APIRouter(prefix="/transactions", tags=["Transactions"])

# ── Prometheus Metrics ────────────────────────────────────────────────────────
txn_ingested = Counter(
    "aml_transactions_ingested_total", "Total transactions ingested", ["currency", "type"]
)
txn_flagged = Counter(
    "aml_transactions_flagged_total", "Total transactions flagged", ["risk_level"]
)
scoring_duration = Histogram(
    "aml_scoring_duration_seconds", "ML scoring duration", buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
)


def _get_lang(request: Request) -> str:
    """Extract preferred language from Accept-Language header."""
    accept = request.headers.get("Accept-Language", "de")
    return "de" if accept.startswith("de") else "en"


@router.post(
    "",
    response_model=TransactionDetailResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest and score a single transaction",
    description="Ingests a transaction, runs ML scoring pipeline, and returns risk assessment.",
)
async def ingest_transaction(
    transaction: TransactionIngest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: UserInDB = Depends(require_permission(Permission.TRANSACTIONS_SCORE)),
    ml_service: MLService = Depends(MLService),
    audit_service: AuditService = Depends(AuditService),
) -> TransactionDetailResponse:
    """
    Ingest a transaction and run the full AML scoring pipeline.

    - Runs Isolation Forest anomaly detection
    - Assigns DBSCAN cluster
    - Computes composite risk score with SHAP explanation
    - Creates alert if risk_score ≥ threshold
    - Logs audit trail entry
    """
    lang = _get_lang(request)
    logger.info("Transaction received", transaction_id=transaction.transaction_id)

    # Score the transaction
    import time
    t0 = time.perf_counter()
    scoring: ScoringResult = await ml_service.score_transaction(transaction)
    elapsed = time.perf_counter() - t0
    scoring_duration.observe(elapsed)

    txn_ingested.labels(
        currency=transaction.currency,
        type=transaction.transaction_type.value,
    ).inc()

    if scoring.is_flagged:
        txn_flagged.labels(risk_level=scoring.risk_level.value).inc()
        background_tasks.add_task(
            ml_service.create_alert_async, transaction, scoring
        )

    # Audit log
    background_tasks.add_task(
        audit_service.log,
        action="transaction.ingested",
        actor=current_user.username,
        resource_id=transaction.transaction_id,
        details={
            "risk_score": scoring.risk_score,
            "is_flagged": scoring.is_flagged,
            "risk_level": scoring.risk_level.value,
        },
    )

    explanation = scoring.explanation_de if lang == "de" else scoring.explanation_en
    features = scoring.top_features_de if lang == "de" else scoring.top_features_en

    from backend.core.security import pii_encryption
    return TransactionDetailResponse(
        transaction_id=transaction.transaction_id,
        timestamp=transaction.timestamp,
        amount=transaction.amount,
        currency=transaction.currency,
        transaction_type=transaction.transaction_type,
        status=TransactionStatus.FLAGGED if scoring.is_flagged else TransactionStatus.SCORED,
        source_iban_masked=pii_encryption.mask_iban(transaction.source_iban),
        target_iban_masked=pii_encryption.mask_iban(transaction.target_iban) if transaction.target_iban else None,
        source_country=transaction.source_country,
        target_country=transaction.target_country,
        risk_score=scoring.risk_score,
        risk_level=scoring.risk_level,
        is_flagged=scoring.is_flagged,
        explanation=explanation,
        cluster_id=scoring.cluster_id,
        scored_at=scoring.scored_at,
        confidence=scoring.confidence,
        top_features=features,
        anomaly_score=scoring.anomaly_score,
        aml_typology=scoring.aml_typology,
        model_version=scoring.model_version,
    )


@router.post(
    "/bulk",
    response_model=BulkIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Bulk ingest transactions (max 1000)",
)
async def bulk_ingest(
    payload: BulkIngestRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(require_permission(Permission.TRANSACTIONS_SCORE)),
    ml_service: MLService = Depends(MLService),
) -> BulkIngestResponse:
    """Bulk ingest — transactions are scored asynchronously via Celery."""
    batch_id = str(uuid.uuid4())
    logger.info(
        "Bulk ingest received",
        batch_id=batch_id,
        count=len(payload.transactions),
        source=payload.source_system,
    )

    # Queue for async scoring
    background_tasks.add_task(
        ml_service.score_batch_async, payload.transactions, batch_id
    )

    return BulkIngestResponse(
        batch_id=batch_id,
        received=len(payload.transactions),
        queued=len(payload.transactions),
        rejected=0,
    )


@router.get(
    "",
    response_model=TransactionListResponse,
    summary="List transactions with filters",
)
async def list_transactions(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    risk_level: Optional[RiskLevel] = None,
    flagged_only: bool = False,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    currency: Optional[str] = None,
    source_country: Optional[str] = None,
    current_user: UserInDB = Depends(require_permission(Permission.TRANSACTIONS_READ)),
    ml_service: MLService = Depends(MLService),
) -> TransactionListResponse:
    """List transactions with optional filtering. PII is masked in all responses."""
    lang = _get_lang(request)
    results = await ml_service.list_transactions(
        page=page,
        page_size=page_size,
        risk_level=risk_level,
        flagged_only=flagged_only,
        from_date=from_date,
        to_date=to_date,
        currency=currency,
        source_country=source_country,
        lang=lang,
    )
    return results


@router.get(
    "/{transaction_id}",
    response_model=TransactionDetailResponse,
    summary="Get transaction detail with ML explanation",
)
async def get_transaction(
    transaction_id: str,
    request: Request,
    current_user: UserInDB = Depends(require_permission(Permission.TRANSACTIONS_READ)),
    ml_service: MLService = Depends(MLService),
) -> TransactionDetailResponse:
    """Get a specific transaction with full ML scoring detail and SHAP explanation."""
    lang = _get_lang(request)
    result = await ml_service.get_transaction(transaction_id, lang=lang)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "transaction_not_found",
                "message_de": f"Transaktion {transaction_id} nicht gefunden.",
                "message_en": f"Transaction {transaction_id} not found.",
            },
        )
    return result


@router.post(
    "/{transaction_id}/rescore",
    response_model=TransactionDetailResponse,
    summary="Force re-score a transaction with latest model",
)
async def rescore_transaction(
    transaction_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(require_permission(Permission.TRANSACTIONS_SCORE)),
    ml_service: MLService = Depends(MLService),
    audit_service: AuditService = Depends(AuditService),
) -> TransactionDetailResponse:
    """Re-score a transaction using the latest production model version."""
    lang = _get_lang(request)
    result = await ml_service.rescore_transaction(transaction_id, lang=lang)
    if not result:
        raise HTTPException(status_code=404, detail={"error": "transaction_not_found"})

    background_tasks.add_task(
        audit_service.log,
        action="transaction.rescored",
        actor=current_user.username,
        resource_id=transaction_id,
        details={"new_risk_score": result.risk_score},
    )
    return result

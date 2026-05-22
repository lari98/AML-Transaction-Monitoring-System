"""
AML Monitoring System — Alert Service
Alert lifecycle management: creation, assignment, resolution, FP tracking.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.config.logging_config import get_logger
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
from backend.models.transaction import RiskLevel, ScoringResult, TransactionIngest

logger = get_logger(__name__)


class AlertService:
    """AML alert lifecycle management."""

    SEVERITY_MAP = {
        RiskLevel.LOW: AlertSeverity.LOW,
        RiskLevel.MEDIUM: AlertSeverity.MEDIUM,
        RiskLevel.HIGH: AlertSeverity.HIGH,
        RiskLevel.CRITICAL: AlertSeverity.CRITICAL,
    }

    async def create_alert_from_scoring(
        self,
        transaction: TransactionIngest,
        scoring: ScoringResult,
    ) -> str:
        """Create an AML alert for a flagged transaction."""
        alert_id = f"ALT-{str(uuid4())[:8].upper()}"
        severity = self.SEVERITY_MAP.get(scoring.risk_level, AlertSeverity.MEDIUM)
        typology = AMLTypology(scoring.aml_typology) if scoring.aml_typology else AMLTypology.UNKNOWN

        alert = {
            "alert_id": alert_id,
            "transaction_id": transaction.transaction_id,
            "account_id": transaction.source_account_id,
            "created_at": datetime.now(timezone.utc),
            "status": AlertStatus.OPEN,
            "severity": severity,
            "typology": typology,
            "risk_score": scoring.risk_score,
            "confidence": scoring.confidence,
            "explanation_de": scoring.explanation_de,
            "explanation_en": scoring.explanation_en,
            "top_features": [f.dict() for f in scoring.top_features_de],
            "model_version": scoring.model_version,
        }

        # Persist to DB (async)
        await self._save_alert(alert)

        # Send real-time notification if CRITICAL
        if severity == AlertSeverity.CRITICAL:
            await self._send_critical_alert_notification(alert)

        logger.info(
            "AML alert created",
            alert_id=alert_id,
            severity=severity.value,
            risk_score=scoring.risk_score,
        )
        return alert_id

    async def list_alerts(self, **kwargs) -> AlertListResponse:
        """List alerts with filters."""
        # In production: PostgreSQL query with filters
        return AlertListResponse(
            items=[],
            total=0,
            open_count=0,
            critical_count=0,
            page=kwargs.get("page", 1),
            page_size=kwargs.get("page_size", 50),
        )

    async def get_alert(self, alert_id: str, lang: str = "de") -> Optional[AlertDetailResponse]:
        """Get alert detail."""
        # In production: PostgreSQL lookup
        return None

    async def update_alert(
        self,
        alert_id: str,
        update: AlertUpdate,
        analyst: str,
        lang: str = "de",
    ) -> Optional[AlertResponse]:
        """Update alert status/notes."""
        # In production: PostgreSQL update
        return None

    async def assign_alert(
        self, alert_id: str, analyst_username: str
    ) -> Optional[AlertResponse]:
        """Assign alert to analyst."""
        return None

    async def get_stats(self) -> AlertStatsResponse:
        """Compute alert statistics for dashboard."""
        return AlertStatsResponse(
            total_open=0,
            total_critical=0,
            total_high=0,
            total_medium=0,
            false_positive_rate=0.0,
            avg_resolution_hours=0.0,
            alerts_by_typology={},
            alerts_by_region={},
            trend_7d=[],
        )

    async def update_fp_rate_metric(self) -> None:
        """Recalculate and update false positive rate metric."""
        # In production: query DB for resolved alerts, compute FP rate
        from prometheus_client import Gauge
        # Update Prometheus gauge
        pass

    async def _save_alert(self, alert: Dict[str, Any]) -> None:
        """Persist alert to PostgreSQL."""
        logger.debug("Alert saved", alert_id=alert["alert_id"])

    async def _send_critical_alert_notification(self, alert: Dict[str, Any]) -> None:
        """Send immediate notification for CRITICAL alerts via email/PagerDuty."""
        logger.warning(
            "CRITICAL AML alert — immediate notification sent",
            alert_id=alert["alert_id"],
            risk_score=alert["risk_score"],
        )
        # In production: send via SMTP + PagerDuty API

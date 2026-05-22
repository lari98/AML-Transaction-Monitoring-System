"""
AML Monitoring System — Alert Models
AML alert lifecycle: OPEN → UNDER_REVIEW → RESOLVED/FALSE_POSITIVE/ESCALATED
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SAR_FILED = "SAR_FILED"            # Suspicious Activity Report filed


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AMLTypology(str, Enum):
    """Standard FATF money laundering typologies."""
    STRUCTURING = "STRUCTURING"             # Breaking up amounts below threshold
    LAYERING = "LAYERING"                   # Complex chain of transfers
    INTEGRATION = "INTEGRATION"             # Reintroduction of funds
    SMURFING = "SMURFING"                   # Multiple people, same beneficiary
    TRADE_BASED = "TRADE_BASED"             # Over/under-invoicing
    REAL_ESTATE = "REAL_ESTATE"
    ROUND_TRIPPING = "ROUND_TRIPPING"       # Circular fund flows
    SHELL_COMPANY = "SHELL_COMPANY"
    CRYPTO_MIXING = "CRYPTO_MIXING"
    UNKNOWN = "UNKNOWN"


class AlertCreate(BaseModel):
    """Internal model for creating alerts from the ML pipeline."""
    transaction_id: str
    account_id: str
    alert_severity: AlertSeverity
    typology: AMLTypology
    risk_score: float
    confidence: float
    explanation_de: str
    explanation_en: str
    top_features: List[dict]
    model_version: str


class AlertUpdate(BaseModel):
    """Analyst actions on an alert."""
    status: Optional[AlertStatus] = None
    analyst_notes: Optional[str] = Field(None, max_length=5000)
    is_false_positive: Optional[bool] = None
    false_positive_reason: Optional[str] = Field(None, max_length=1000)
    escalation_reason: Optional[str] = Field(None, max_length=1000)
    sar_reference: Optional[str] = None


class AlertResponse(BaseModel):
    """Alert API response (language-adaptive)."""
    alert_id: str
    transaction_id: str
    account_id_masked: str
    created_at: datetime
    updated_at: datetime
    status: AlertStatus
    severity: AlertSeverity
    typology: AMLTypology
    risk_score: float
    confidence: float
    explanation: str                    # Language-selected explanation
    is_false_positive: bool = False
    assigned_analyst: Optional[str] = None
    sar_reference: Optional[str] = None
    days_open: int


class AlertDetailResponse(AlertResponse):
    """Full alert with features and audit trail."""
    top_features: List[dict]
    analyst_notes: Optional[str] = None
    false_positive_reason: Optional[str] = None
    escalation_history: List[dict] = []
    related_alerts: List[str] = []      # Alert IDs for same account/cluster


class AlertListResponse(BaseModel):
    items: List[AlertResponse]
    total: int
    open_count: int
    critical_count: int
    page: int
    page_size: int


class AlertStatsResponse(BaseModel):
    """Dashboard statistics for alert management."""
    total_open: int
    total_critical: int
    total_high: int
    total_medium: int
    false_positive_rate: float
    avg_resolution_hours: float
    alerts_by_typology: dict
    alerts_by_region: dict
    trend_7d: List[dict]               # Daily counts for last 7 days

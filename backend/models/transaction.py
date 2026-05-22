"""
AML Monitoring System — Transaction Models
Pydantic models for transaction ingestion, scoring, and response.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class TransactionType(str, Enum):
    WIRE_TRANSFER = "WIRE_TRANSFER"
    SEPA_CREDIT = "SEPA_CREDIT"
    SEPA_DIRECT_DEBIT = "SEPA_DIRECT_DEBIT"
    CASH_DEPOSIT = "CASH_DEPOSIT"
    CASH_WITHDRAWAL = "CASH_WITHDRAWAL"
    CARD_PAYMENT = "CARD_PAYMENT"
    SWIFT = "SWIFT"
    INTERNAL_TRANSFER = "INTERNAL_TRANSFER"
    CRYPTO_EXCHANGE = "CRYPTO_EXCHANGE"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TransactionStatus(str, Enum):
    PENDING = "PENDING"
    SCORED = "SCORED"
    FLAGGED = "FLAGGED"
    CLEARED = "CLEARED"
    BLOCKED = "BLOCKED"
    UNDER_REVIEW = "UNDER_REVIEW"


class Jurisdiction(str, Enum):
    CH = "CH"   # Switzerland
    DE = "DE"   # Germany
    AT = "AT"   # Austria
    LI = "LI"   # Liechtenstein
    LU = "LU"   # Luxembourg
    NL = "NL"
    BE = "BE"
    FR = "FR"
    IT = "IT"
    GB = "GB"
    US = "US"
    OTHER = "OTHER"
    HIGH_RISK = "HIGH_RISK"  # FATF high-risk jurisdictions


# ── Inbound Transaction (from stream/API) ─────────────────────────────────────
class TransactionIngest(BaseModel):
    """Raw transaction as received from core banking or streaming."""

    transaction_id: str = Field(..., description="Unique transaction reference (BIC/TRN)")
    timestamp: datetime
    amount: Decimal = Field(..., gt=0, lt=Decimal("1000000000"))
    currency: str = Field(..., min_length=3, max_length=3, pattern="^[A-Z]{3}$")
    transaction_type: TransactionType
    source_account_id: str = Field(..., description="Internal account ID (encrypted)")
    source_iban: str = Field(..., description="Source IBAN (will be encrypted at storage)")
    source_bic: Optional[str] = None
    source_country: str = Field(..., min_length=2, max_length=2)
    target_account_id: Optional[str] = None
    target_iban: Optional[str] = None
    target_bic: Optional[str] = None
    target_country: Optional[str] = Field(None, min_length=2, max_length=2)
    description: Optional[str] = Field(None, max_length=500)
    reference: Optional[str] = Field(None, max_length=200)
    channel: Optional[str] = None           # online, branch, atm, api
    ip_address: Optional[str] = None        # Will be masked at storage
    device_fingerprint: Optional[str] = None

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v):
        allowed = {"CHF", "EUR", "USD", "GBP", "JPY", "CNY", "AED", "RUB"}
        if v not in allowed:
            raise ValueError(f"Unsupported currency: {v}")
        return v

    @field_validator("source_iban", "target_iban", mode="before")
    @classmethod
    def validate_iban_format(cls, v):
        if v is None:
            return v
        clean = v.replace(" ", "").upper()
        if len(clean) < 15 or len(clean) > 34:
            raise ValueError("Invalid IBAN length")
        return clean


# ── ML Scoring Result ─────────────────────────────────────────────────────────
class SHAPFeature(BaseModel):
    feature: str
    impact: float
    value: str  # Human-readable value


class ScoringResult(BaseModel):
    """Output of the ML pipeline for a single transaction."""

    transaction_id: str
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    cluster_id: int
    cluster_label: str               # e.g., "structuring_pattern", "normal"
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: RiskLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    is_flagged: bool
    top_features_de: List[SHAPFeature]
    top_features_en: List[SHAPFeature]
    explanation_de: str
    explanation_en: str
    aml_typology: Optional[str] = None   # e.g., "STRUCTURING", "LAYERING"
    model_version: str
    scored_at: datetime


# ── API Response Models ───────────────────────────────────────────────────────
class TransactionResponse(BaseModel):
    """Transaction response — PII is masked by default."""

    transaction_id: str
    timestamp: datetime
    amount: Decimal
    currency: str
    transaction_type: TransactionType
    status: TransactionStatus
    source_iban_masked: str           # e.g., CH93****5290
    target_iban_masked: Optional[str] = None
    source_country: str
    target_country: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    is_flagged: bool = False
    explanation: Optional[str] = None  # Language-specific
    cluster_id: Optional[int] = None
    scored_at: Optional[datetime] = None


class TransactionDetailResponse(TransactionResponse):
    """Detailed response — includes SHAP features. Requires ALERTS_READ permission."""

    confidence: Optional[float] = None
    top_features: Optional[List[SHAPFeature]] = None
    anomaly_score: Optional[float] = None
    aml_typology: Optional[str] = None
    model_version: Optional[str] = None


class TransactionListResponse(BaseModel):
    items: List[TransactionResponse]
    total: int
    page: int
    page_size: int
    has_more: bool


class BulkIngestRequest(BaseModel):
    """Bulk transaction ingestion (max 1000 per request)."""
    transactions: List[TransactionIngest] = Field(..., max_length=1000)
    source_system: str = Field(..., description="Sending system identifier")
    batch_id: Optional[str] = None


class BulkIngestResponse(BaseModel):
    batch_id: str
    received: int
    queued: int
    rejected: int
    errors: List[dict] = []

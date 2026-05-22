"""
AML Monitoring System — Account & User Models
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class CustomerRiskCategory(str, Enum):
    LOW = "LOW"
    STANDARD = "STANDARD"
    HIGH = "HIGH"
    PEP = "PEP"                    # Politically Exposed Person
    SANCTIONS = "SANCTIONS"        # OFAC/EU sanctions list


class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    FROZEN = "FROZEN"              # Regulatory freeze
    CLOSED = "CLOSED"
    UNDER_REVIEW = "UNDER_REVIEW"


class AccountRiskProfile(BaseModel):
    """Risk profile for a bank account — GDPR-masked."""
    account_id: str
    risk_category: CustomerRiskCategory
    risk_score: float = Field(..., ge=0.0, le=1.0)
    cluster_id: Optional[int] = None
    cluster_label: Optional[str] = None
    status: AccountStatus
    country: str
    account_type: str
    total_alerts: int
    open_alerts: int
    false_positive_rate: float
    last_transaction_at: Optional[datetime] = None
    last_scored_at: Optional[datetime] = None
    # PII fields — masked by default
    account_holder_masked: str         # "Max M***"
    iban_masked: str                   # "CH93****5290"


class AccountRiskProfileDetail(AccountRiskProfile):
    """Full profile — requires ACCOUNTS_PII_READ permission."""
    account_holder_name: str
    iban: str
    date_of_birth: Optional[str] = None
    kyc_status: str
    kyc_last_reviewed: Optional[datetime] = None
    pep_check_date: Optional[datetime] = None
    sanctions_check_date: Optional[datetime] = None
    expected_transaction_volume: Optional[float] = None
    transaction_history_summary: dict = {}


# ── User/Auth Models ──────────────────────────────────────────────────────────
class UserInDB(BaseModel):
    """Internal user representation from JWT payload."""
    id: str
    username: str
    roles: List[str] = []
    is_active: bool = True
    jti: str = ""                  # JWT ID for blacklisting

    @property
    def is_compliance_officer(self) -> bool:
        return "compliance_officer" in self.roles

    @property
    def is_auditor(self) -> bool:
        return "auditor" in self.roles


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    roles: List[str]


class LoginRequest(BaseModel):
    username: str
    password: str = Field(..., min_length=8)

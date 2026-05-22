"""
AML Monitoring System — Test Configuration & Fixtures
Shared fixtures for all test modules.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient

# Set test environment BEFORE importing app modules
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-chars-minimum-here")
os.environ.setdefault("PII_ENCRYPTION_KEY", "test-pii-key-32-chars-minimum-here")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test_db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")  # DB 15 for tests
os.environ.setdefault("MLFLOW_TRACKING_URI", "http://localhost:5000")
os.environ.setdefault("MASK_PII_IN_LOGS", "true")


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_transaction() -> dict:
    """A realistic normal Swiss bank transaction."""
    return {
        "transaction_id": "TXN-TEST001ABCDEF",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": "2500.00",
        "currency": "CHF",
        "transaction_type": "WIRE_TRANSFER",
        "source_account_id": "acc-source-001",
        "source_iban": "CH9300762011623852957",
        "source_bic": "UBSWCHZH80A",
        "source_country": "CH",
        "target_account_id": "acc-target-001",
        "target_iban": "DE89370400440532013000",
        "target_bic": "DEUTDEDBXXX",
        "target_country": "DE",
        "description": "Überweisung Miete August",
        "channel": "online",
    }


@pytest.fixture
def structuring_transaction() -> dict:
    """A structuring pattern transaction (just below CHF 10,000)."""
    return {
        "transaction_id": "TXN-STRUCT001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": "9850.00",
        "currency": "CHF",
        "transaction_type": "CASH_DEPOSIT",
        "source_account_id": "acc-suspicious-001",
        "source_iban": "CH5604835012345678009",
        "source_bic": "ZKBKCHZZ80A",
        "source_country": "CH",
        "target_iban": "CH5604835012345678009",
        "target_country": "CH",
        "description": "Bareinzahlung",
        "channel": "branch",
    }


@pytest.fixture
def high_risk_transaction() -> dict:
    """A transaction to a FATF high-risk jurisdiction (North Korea)."""
    return {
        "transaction_id": "TXN-HIGHRISK001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": "75000.00",
        "currency": "EUR",
        "transaction_type": "WIRE_TRANSFER",
        "source_account_id": "acc-suspicious-002",
        "source_iban": "DE89370400440532013000",
        "source_bic": "DEUTDEDBXXX",
        "source_country": "DE",
        "target_country": "KP",
        "description": "Zahlung",
        "channel": "online",
    }


@pytest.fixture
def account_history_normal() -> dict:
    """Behavioral history for a normal account."""
    return {
        "avg_amount_30d": 2000.0, "std_amount_30d": 800.0,
        "max_amount_30d": 8000.0, "median_amount_30d": 1500.0,
        "max_amount_ever": 25000.0, "txn_count_1h": 0, "txn_count_24h": 1,
        "txn_count_7d": 4, "txn_count_30d": 15, "total_amount_1h": 0,
        "total_amount_24h": 2500.0, "avg_daily_txns": 0.5,
        "txn_count_same_beneficiary_24h": 1, "known_countries": ["CH", "DE"],
        "known_beneficiaries": ["DE89370400440532013000"],
        "unique_target_countries_30d": 2, "cross_border_ratio_30d": 0.1,
        "avg_txn_hour_30d": 11.0, "beneficiary_concentration_30d": 0.3,
        "new_beneficiaries_7d": 0, "same_beneficiary_amount_ratio_24h": 0.0,
        "cash_ratio_30d": 0.02, "account_age_days": 1200,
        "account_risk_score": 0.1, "recent_pattern_change": 0.0,
        "alerts_30d": 0, "false_positive_rate": 0.5,
        "kyc_risk_category_encoded": 1, "device_fingerprint_new": 0,
        "ip_country_mismatch": 0,
    }


@pytest.fixture
def account_history_suspicious() -> dict:
    """Behavioral history showing suspicious patterns."""
    return {
        "avg_amount_30d": 1000.0, "std_amount_30d": 300.0,
        "max_amount_30d": 9900.0, "median_amount_30d": 800.0,
        "max_amount_ever": 9950.0, "txn_count_1h": 5, "txn_count_24h": 12,
        "txn_count_7d": 25, "txn_count_30d": 80, "total_amount_1h": 48000.0,
        "total_amount_24h": 78000.0, "avg_daily_txns": 0.5,
        "txn_count_same_beneficiary_24h": 8, "known_countries": ["CH"],
        "known_beneficiaries": [], "unique_target_countries_30d": 8,
        "cross_border_ratio_30d": 0.7, "avg_txn_hour_30d": 3.0,
        "beneficiary_concentration_30d": 0.85, "new_beneficiaries_7d": 6,
        "same_beneficiary_amount_ratio_24h": 0.9, "cash_ratio_30d": 0.6,
        "account_age_days": 45, "account_risk_score": 0.85,
        "recent_pattern_change": 0.8, "alerts_30d": 3,
        "false_positive_rate": 0.0, "kyc_risk_category_encoded": 2,
        "device_fingerprint_new": 1, "ip_country_mismatch": 1,
    }


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.setex = AsyncMock(return_value=True)
    redis.exists = AsyncMock(return_value=0)
    redis.incr = AsyncMock(return_value=1)
    redis.expire = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.ping = AsyncMock(return_value=True)
    return redis


@pytest.fixture
def mock_ml_models():
    """Mock ML models to avoid loading real MLflow models in tests."""
    with patch("backend.ml.anomaly_detector.AnomalyDetector.load_model") as mock_load, \
         patch("backend.ml.risk_scorer.RiskScorer.load_model") as mock_risk_load:
        mock_load.return_value = None
        mock_risk_load.return_value = None
        yield


@pytest_asyncio.fixture
async def test_client(mock_redis, mock_ml_models) -> AsyncGenerator:
    """Async HTTP test client for FastAPI."""
    with patch("backend.services.cache_service.get_redis", return_value=mock_redis), \
         patch("backend.services.cache_service.init_redis", return_value=None), \
         patch("backend.services.cache_service.close_redis", return_value=None):
        from backend.main import create_app
        app = create_app()
        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client


@pytest.fixture
def auth_headers_analyst() -> dict:
    """JWT auth headers for AML analyst role."""
    from backend.core.security import create_access_token
    token = create_access_token(
        subject="analyst@bank.de",
        roles=["aml_analyst"],
    )
    return {"Authorization": f"Bearer {token}", "Accept-Language": "en"}


@pytest.fixture
def auth_headers_compliance() -> dict:
    """JWT auth headers for compliance officer role."""
    from backend.core.security import create_access_token
    token = create_access_token(
        subject="compliance@bank.de",
        roles=["compliance_officer"],
    )
    return {"Authorization": f"Bearer {token}", "Accept-Language": "de"}


@pytest.fixture
def auth_headers_readonly() -> dict:
    """JWT auth headers for read-only role."""
    from backend.core.security import create_access_token
    token = create_access_token(
        subject="viewer@bank.de",
        roles=["readonly"],
    )
    return {"Authorization": f"Bearer {token}"}

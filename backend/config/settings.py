"""
AML Monitoring System — Application Settings
Production-grade configuration with Azure Key Vault integration.
"""
from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from typing import List, Optional

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Language(str, Enum):
    DE = "de"
    EN = "en"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────
    APP_ENV: Environment = Environment.PRODUCTION
    APP_NAME: str = "AML Transaction Monitoring System"
    APP_VERSION: str = "1.0.0"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    DEBUG: bool = False
    DEFAULT_LANGUAGE: Language = Language.DE

    # ── Security ─────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(..., min_length=32)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    BCRYPT_ROUNDS: int = 12
    API_KEY_HEADER: str = "X-API-Key"
    ALLOWED_HOSTS: List[str] = ["localhost"]
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # ── Rate Limiting ────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 200

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(..., description="PostgreSQL async URL")
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_POOL_TIMEOUT: int = 30
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None

    # ── Azure ────────────────────────────────────────────────────────────
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_STORAGE_ACCOUNT: Optional[str] = None
    AZURE_STORAGE_KEY: Optional[str] = None
    AZURE_BLOB_CONTAINER: str = "aml-transactions"
    AZURE_KEY_VAULT_URL: Optional[str] = None
    AZURE_MONITOR_WORKSPACE_ID: Optional[str] = None

    # ── Databricks / MLflow ──────────────────────────────────────────────
    DATABRICKS_HOST: Optional[str] = None
    DATABRICKS_TOKEN: Optional[str] = None
    DATABRICKS_CLUSTER_ID: Optional[str] = None
    DATABRICKS_CATALOG: str = "aml_catalog"
    DATABRICKS_SCHEMA: str = "transactions"
    MLFLOW_TRACKING_URI: str = "http://localhost:5000"

    # ── Kafka ────────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_TOPIC_TRANSACTIONS: str = "aml.transactions.raw"
    KAFKA_TOPIC_ALERTS: str = "aml.alerts.realtime"
    KAFKA_TOPIC_SCORED: str = "aml.transactions.scored"
    KAFKA_CONSUMER_GROUP: str = "aml-monitoring-group"

    # ── ML Models ────────────────────────────────────────────────────────
    MODEL_REGISTRY_URI: str = "mlflow://aml-model-registry"
    ANOMALY_MODEL_NAME: str = "aml_isolation_forest"
    CLUSTER_MODEL_NAME: str = "aml_dbscan"
    RISK_MODEL_NAME: str = "aml_risk_scorer"
    MODEL_STAGE: str = "Production"
    ANOMALY_THRESHOLD: float = 0.65
    RISK_HIGH_THRESHOLD: float = 0.80
    RISK_MEDIUM_THRESHOLD: float = 0.50
    SHAP_EXPLAIN_TOP_N: int = 10
    MODEL_CACHE_TTL_SECONDS: int = 3600

    # ── GDPR / DSGVO ─────────────────────────────────────────────────────
    PII_ENCRYPTION_KEY: str = Field(..., min_length=32)
    DATA_RETENTION_DAYS: int = 3650          # 10 years (FINMA)
    AUDIT_LOG_RETENTION_DAYS: int = 2555     # 7 years
    GDPR_DELETE_DELAY_HOURS: int = 24
    MASK_PII_IN_LOGS: bool = True
    ANONYMIZE_EXPORT: bool = True

    # ── Monitoring ───────────────────────────────────────────────────────
    PROMETHEUS_PORT: int = 9090
    GRAFANA_PORT: int = 3000
    ALERT_WEBHOOK_URL: Optional[str] = None
    SENTRY_DSN: Optional[str] = None

    # ── Email ────────────────────────────────────────────────────────────
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    ALERT_EMAIL_FROM: str = "aml-alerts@bank.de"
    ALERT_EMAIL_TO: List[str] = []

    # ── Power BI ─────────────────────────────────────────────────────────
    POWERBI_WORKSPACE_ID: Optional[str] = None
    POWERBI_DATASET_ID: Optional[str] = None
    POWERBI_TENANT_ID: Optional[str] = None
    POWERBI_CLIENT_ID: Optional[str] = None
    POWERBI_CLIENT_SECRET: Optional[str] = None

    @field_validator("CORS_ORIGINS", "ALLOWED_HOSTS", "ALERT_EMAIL_TO", mode="before")
    @classmethod
    def parse_list(cls, v):
        if isinstance(v, str):
            # Handle JSON array strings from env
            import json
            try:
                return json.loads(v)
            except Exception:
                return [x.strip() for x in v.split(",")]
        return v

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == Environment.DEVELOPMENT

    @property
    def database_url_sync(self) -> str:
        """Synchronous database URL for Alembic migrations."""
        return self.DATABASE_URL.replace("asyncpg", "psycopg2")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings instance. Use dependency injection in FastAPI."""
    return Settings()

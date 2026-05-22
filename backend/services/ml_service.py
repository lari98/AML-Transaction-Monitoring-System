"""
AML Monitoring System — ML Orchestration Service
Orchestrates anomaly detection → clustering → risk scoring → explanation pipeline.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings
from backend.ml.anomaly_detector import AnomalyDetector, get_anomaly_detector
from backend.ml.explainer import SHAPExplainer, get_explainer
from backend.ml.risk_scorer import RiskScorer, get_risk_scorer
from backend.models.transaction import (
    RiskLevel,
    ScoringResult,
    TransactionDetailResponse,
    TransactionIngest,
    TransactionListResponse,
    TransactionStatus,
)

logger = get_logger(__name__)
settings = get_settings()

# Feature names must match AnomalyDetector.extract_features() order
FEATURE_NAMES = [
    "amount", "log_amount", "amount_vs_30d_avg", "amount_zscore",
    "near_threshold_90pct", "near_threshold_95pct", "near_threshold",
    "max_amount_30d", "median_amount_30d", "amount_vs_max_ever",
    "txn_count_1h", "txn_count_24h", "txn_count_7d", "txn_count_30d",
    "total_amount_1h", "total_amount_24h", "txn_count_vs_daily_avg",
    "txn_count_same_beneficiary_24h",
    "is_new_country", "is_high_risk_jurisdiction", "is_source_high_risk",
    "unique_target_countries_30d", "is_cross_border", "cross_border_ratio_30d",
    "hour_of_day", "is_after_hours", "is_weekend", "is_bank_holiday",
    "day_of_week", "avg_txn_hour_30d", "hour_deviation",
    "is_new_beneficiary", "beneficiary_concentration_30d", "new_beneficiaries_7d",
    "same_beneficiary_amount_ratio_24h", "is_cash", "cash_ratio_30d",
    "account_age_days", "account_risk_score", "recent_pattern_change",
    "alerts_30d", "false_positive_rate", "kyc_risk_category_encoded",
    "is_online_channel", "is_atm_channel", "device_fingerprint_new", "ip_country_mismatch",
]


class MLService:
    """
    Full ML scoring pipeline orchestrator.

    Pipeline:
    1. Fetch account history context
    2. Extract 47 features
    3. Anomaly detection (Isolation Forest)
    4. Cluster assignment (DBSCAN)
    5. Risk scoring (LightGBM)
    6. SHAP explanation generation (DE + EN)
    7. Persist result
    """

    def __init__(self):
        self._anomaly_detector: Optional[AnomalyDetector] = None
        self._risk_scorer: Optional[RiskScorer] = None
        self._explainer: Optional[SHAPExplainer] = None
        self._cluster_risk_map: dict = {}

    @classmethod
    async def load_models(cls) -> None:
        """Load all ML models at application startup."""
        logger.info("Loading ML models...")
        await get_anomaly_detector()
        await get_risk_scorer()
        get_explainer()
        logger.info("All ML models loaded successfully")

    async def score_transaction(self, transaction: TransactionIngest) -> ScoringResult:
        """
        Run the full ML pipeline on a single transaction.
        Target: < 500ms p99 latency.
        """
        detector = await get_anomaly_detector()
        scorer = await get_risk_scorer()
        explainer = get_explainer()

        # 1. Fetch account history (cache-first)
        account_history = await self._get_account_history(transaction.source_account_id)

        # 2. Extract features
        txn_dict = {
            "amount": float(transaction.amount),
            "timestamp": transaction.timestamp,
            "transaction_type": transaction.transaction_type.value,
            "source_country": transaction.source_country,
            "target_country": transaction.target_country,
            "target_iban": transaction.target_iban,
            "channel": transaction.channel,
            "ip_address": transaction.ip_address,
        }
        feature_vector = detector.extract_features(txn_dict, account_history)

        # 3. Anomaly detection
        anomaly_result = detector.score(feature_vector)

        # 4. Cluster assignment
        cluster_id, cluster_label, cluster_risk = await self._get_cluster_assignment(
            feature_vector
        )

        # 5. Build feature dict for risk scorer
        features_dict = dict(zip(FEATURE_NAMES, feature_vector[0].tolist()))

        # 6. Risk scoring
        risk_result = scorer.score(
            anomaly_score=anomaly_result.anomaly_score,
            cluster_id=cluster_id,
            cluster_risk=cluster_risk,
            features=features_dict,
        )

        # 7. SHAP explanation (only for flagged transactions to save latency)
        if risk_result.risk_score >= settings.RISK_MEDIUM_THRESHOLD:
            features_de, features_en, explanation_de, explanation_en = explainer.explain(
                feature_vector=feature_vector,
                feature_names=FEATURE_NAMES,
                risk_score=risk_result.risk_score,
                typology=risk_result.aml_typology,
            )
        else:
            features_de, features_en = [], []
            explanation_de = "Transaktion ohne auffällige Merkmale."
            explanation_en = "Transaction with no significant anomaly."

        is_flagged = risk_result.risk_score >= settings.ANOMALY_THRESHOLD

        result = ScoringResult(
            transaction_id=transaction.transaction_id,
            anomaly_score=anomaly_result.anomaly_score,
            cluster_id=cluster_id,
            cluster_label=cluster_label,
            risk_score=risk_result.risk_score,
            risk_level=risk_result.risk_level,
            confidence=risk_result.confidence,
            is_flagged=is_flagged,
            top_features_de=features_de,
            top_features_en=features_en,
            explanation_de=explanation_de,
            explanation_en=explanation_en,
            aml_typology=risk_result.aml_typology,
            model_version=f"AD:{detector._model_version}|RS:{scorer._model_version}",
            scored_at=datetime.now(timezone.utc),
        )

        # Persist asynchronously
        asyncio.create_task(self._persist_scoring_result(transaction, result))
        return result

    async def score_batch_async(
        self,
        transactions: List[TransactionIngest],
        batch_id: str,
    ) -> None:
        """Score a batch of transactions asynchronously (Celery task in production)."""
        logger.info("Batch scoring started", batch_id=batch_id, count=len(transactions))
        for txn in transactions:
            try:
                await self.score_transaction(txn)
            except Exception as e:
                logger.error("Failed to score transaction", txn_id=txn.transaction_id, error=str(e))

    async def create_alert_async(
        self,
        transaction: TransactionIngest,
        scoring: ScoringResult,
    ) -> None:
        """Create AML alert for a flagged transaction."""
        from backend.services.alert_service import AlertService
        alert_svc = AlertService()
        await alert_svc.create_alert_from_scoring(transaction, scoring)

    async def list_transactions(self, **kwargs) -> TransactionListResponse:
        """Query persisted transactions with filters."""
        # In production: query PostgreSQL via SQLAlchemy
        # Returning mock response for architecture demonstration
        return TransactionListResponse(
            items=[],
            total=0,
            page=kwargs.get("page", 1),
            page_size=kwargs.get("page_size", 50),
            has_more=False,
        )

    async def get_transaction(
        self, transaction_id: str, lang: str = "de"
    ) -> Optional[TransactionDetailResponse]:
        """Fetch a scored transaction by ID."""
        # In production: query PostgreSQL
        return None

    async def rescore_transaction(
        self, transaction_id: str, lang: str = "de"
    ) -> Optional[TransactionDetailResponse]:
        """Re-score a transaction with the latest production model."""
        # In production: fetch from DB, re-run pipeline
        return None

    async def _get_account_history(self, account_id: str) -> dict:
        """Fetch pre-computed account behavioral statistics from Redis cache or DB."""
        try:
            from backend.services.cache_service import get_redis
            redis = await get_redis()
            cached = await redis.get(f"account:history:{account_id}")
            if cached:
                import json
                return json.loads(cached)
        except Exception:
            pass

        # Fallback: return neutral defaults
        return {
            "avg_amount_30d": 1000.0,
            "std_amount_30d": 500.0,
            "max_amount_30d": 10000.0,
            "median_amount_30d": 800.0,
            "max_amount_ever": 50000.0,
            "txn_count_1h": 0,
            "txn_count_24h": 1,
            "txn_count_7d": 5,
            "txn_count_30d": 20,
            "total_amount_1h": 0.0,
            "total_amount_24h": 1000.0,
            "avg_daily_txns": 1.0,
            "txn_count_same_beneficiary_24h": 0,
            "known_countries": ["CH", "DE"],
            "known_beneficiaries": [],
            "unique_target_countries_30d": 2,
            "cross_border_ratio_30d": 0.1,
            "avg_txn_hour_30d": 12.0,
            "beneficiary_concentration_30d": 0.3,
            "new_beneficiaries_7d": 0,
            "same_beneficiary_amount_ratio_24h": 0.0,
            "cash_ratio_30d": 0.05,
            "account_age_days": 730,
            "account_risk_score": 0.2,
            "recent_pattern_change": 0.0,
            "alerts_30d": 0,
            "false_positive_rate": 0.5,
            "kyc_risk_category_encoded": 1,
            "device_fingerprint_new": 0,
            "ip_country_mismatch": 0,
        }

    async def _get_cluster_assignment(self, feature_vector) -> tuple:
        """Assign transaction to DBSCAN behavioral cluster."""
        # In production: load cluster centroids from Redis/MLflow
        # Simplified assignment for architecture demonstration
        anomaly_magnitude = float(abs(feature_vector[0, 3]))  # z-score feature
        if anomaly_magnitude > 3.0:
            return 1, "high_risk_cluster", 0.85
        elif anomaly_magnitude > 1.5:
            return 2, "elevated_risk_cluster", 0.55
        else:
            return 0, "normal_behavior", 0.15

    async def _persist_scoring_result(
        self,
        transaction: TransactionIngest,
        result: ScoringResult,
    ) -> None:
        """Persist scoring result to PostgreSQL (async, non-blocking)."""
        # In production: SQLAlchemy async insert
        logger.debug(
            "Scoring result persisted",
            transaction_id=transaction.transaction_id,
            risk_score=result.risk_score,
            is_flagged=result.is_flagged,
        )

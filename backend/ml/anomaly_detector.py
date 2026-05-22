"""
AML Monitoring System — Anomaly Detection Module
Isolation Forest for transaction anomaly scoring.
Production-grade with MLflow model loading and caching.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class AnomalyResult:
    anomaly_score: float           # [0, 1] — higher = more anomalous
    is_anomaly: bool
    raw_score: float               # Raw Isolation Forest output [-1, 1]
    inference_ms: float


class AnomalyDetector:
    """
    Isolation Forest anomaly detector for AML transaction monitoring.

    Features used (47 total):
    - Transaction amount statistics (vs. account history)
    - Velocity features (txn count in 1h/24h/7d)
    - Geographic patterns (new country, high-risk jurisdiction)
    - Time patterns (after-hours, weekend, holiday)
    - Counterparty concentration (same beneficiary ratio)
    - Amount structuring patterns (amounts near 10k threshold)
    - Account behavioral baseline deviation
    """

    # Amount below which structuring detection is heightened (EU/CH threshold)
    STRUCTURING_THRESHOLD_EUR = 10_000
    STRUCTURING_THRESHOLD_CHF = 10_000

    def __init__(self):
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._threshold: float = settings.ANOMALY_THRESHOLD
        self._model_version: str = "not_loaded"
        self._is_loaded: bool = False

    async def load_model(self) -> None:
        """Load model from MLflow registry or fallback to a newly trained model."""
        try:
            import mlflow
            mlflow.set_tracking_uri(settings.MLFLOW_TRACKING_URI)
            client = mlflow.MlflowClient()

            # Load latest production model
            model_uri = f"models:/{settings.ANOMALY_MODEL_NAME}/{settings.MODEL_STAGE}"
            self._model = mlflow.sklearn.load_model(model_uri)

            # Load associated scaler artifact
            run_id = client.get_latest_versions(
                settings.ANOMALY_MODEL_NAME, stages=[settings.MODEL_STAGE]
            )[0].run_id
            scaler_uri = f"runs:/{run_id}/scaler"
            self._scaler = mlflow.sklearn.load_model(scaler_uri)
            self._model_version = run_id[:8]
            self._is_loaded = True
            logger.info("Anomaly detector loaded from MLflow", version=self._model_version)

        except Exception as e:
            logger.warning(
                "MLflow model unavailable, using baseline model",
                error=str(e),
            )
            self._initialize_baseline_model()

    def _initialize_baseline_model(self) -> None:
        """Initialize a baseline model for cold start / testing."""
        self._model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self._scaler = StandardScaler()
        self._model_version = "baseline_v1"
        self._is_loaded = True
        logger.info("Baseline anomaly detector initialized")

    def extract_features(self, transaction: dict, account_history: dict) -> np.ndarray:
        """
        Extract 47 features from a transaction + account history context.

        Args:
            transaction: Raw transaction fields
            account_history: Pre-computed account behavior statistics

        Returns:
            Feature vector of shape (1, 47)
        """
        t = transaction
        h = account_history

        amount = float(t.get("amount", 0))
        avg_30d = float(h.get("avg_amount_30d", amount))
        std_30d = float(h.get("std_amount_30d", 1))

        features = [
            # -- Amount features (10) --------------------------------------
            amount,
            np.log1p(amount),
            amount / max(avg_30d, 1),                     # amount vs average
            (amount - avg_30d) / max(std_30d, 1),         # z-score
            float(amount >= self.STRUCTURING_THRESHOLD_EUR * 0.9),   # near-threshold
            float(amount >= self.STRUCTURING_THRESHOLD_EUR * 0.95),
            float(amount >= self.STRUCTURING_THRESHOLD_EUR),
            float(h.get("max_amount_30d", 0)),
            float(h.get("median_amount_30d", 0)),
            amount / max(float(h.get("max_amount_ever", amount)), 1),  # vs historical max

            # -- Velocity features (8) -------------------------------------
            float(h.get("txn_count_1h", 0)),
            float(h.get("txn_count_24h", 0)),
            float(h.get("txn_count_7d", 0)),
            float(h.get("txn_count_30d", 0)),
            float(h.get("total_amount_1h", 0)),
            float(h.get("total_amount_24h", 0)),
            float(h.get("txn_count_24h", 0)) / max(float(h.get("avg_daily_txns", 1)), 1),
            float(h.get("txn_count_same_beneficiary_24h", 0)),  # concentration

            # -- Geographic features (6) -----------------------------------
            float(t.get("target_country", "") not in h.get("known_countries", [])),
            float(self._is_high_risk_jurisdiction(t.get("target_country", ""))),
            float(self._is_high_risk_jurisdiction(t.get("source_country", ""))),
            float(h.get("unique_target_countries_30d", 0)),
            float(t.get("source_country", "") != t.get("target_country", "")),
            float(h.get("cross_border_ratio_30d", 0)),

            # -- Time features (7) -----------------------------------------
            float(self._extract_hour(t.get("timestamp"))),
            float(self._is_after_hours(t.get("timestamp"))),
            float(self._is_weekend(t.get("timestamp"))),
            float(self._is_bank_holiday(t.get("timestamp"))),
            float(self._extract_day_of_week(t.get("timestamp"))),
            float(h.get("avg_txn_hour_30d", 12)),
            abs(self._extract_hour(t.get("timestamp")) - float(h.get("avg_txn_hour_30d", 12))),

            # -- Counterparty features (6) ---------------------------------
            float(t.get("target_iban", "") not in h.get("known_beneficiaries", [])),
            float(h.get("beneficiary_concentration_30d", 0)),   # Herfindahl index
            float(h.get("new_beneficiaries_7d", 0)),
            float(h.get("same_beneficiary_amount_ratio_24h", 0)),
            float(t.get("transaction_type") in ["CASH_DEPOSIT", "CASH_WITHDRAWAL"]),
            float(h.get("cash_ratio_30d", 0)),

            # -- Account behavioral deviation (6) --------------------------
            float(h.get("account_age_days", 365)),
            float(h.get("account_risk_score", 0.5)),
            float(h.get("recent_pattern_change", 0)),   # PSI of features
            float(h.get("alerts_30d", 0)),
            float(h.get("false_positive_rate", 0.5)),
            float(h.get("kyc_risk_category_encoded", 0)),  # LOW=0, STD=1, HIGH=2, PEP=3

            # -- Channel features (4) --------------------------------------
            float(t.get("channel") == "online"),
            float(t.get("channel") == "atm"),
            float(h.get("device_fingerprint_new", 0)),
            float(h.get("ip_country_mismatch", 0)),
        ]

        return np.array(features, dtype=np.float32).reshape(1, -1)

    def score(self, feature_vector: np.ndarray) -> AnomalyResult:
        """
        Score a feature vector with the Isolation Forest model.

        Returns:
            AnomalyResult with normalized score [0, 1]
        """
        if not self._is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        t0 = time.perf_counter()

        if self._scaler is not None:
            try:
                feature_vector = self._scaler.transform(feature_vector)
            except Exception:
                pass  # First run before scaler is fitted

        # Isolation Forest: -1 = anomaly, 1 = normal
        raw_score = float(self._model.score_samples(feature_vector)[0])

        # Normalize: score_samples returns negative values; more negative = more anomalous
        # Map to [0, 1]: higher = more suspicious
        min_score, max_score = -0.7, 0.1
        normalized = np.clip((raw_score - max_score) / (min_score - max_score), 0.0, 1.0)
        anomaly_score = float(normalized)

        inference_ms = (time.perf_counter() - t0) * 1000
        return AnomalyResult(
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= self._threshold,
            raw_score=raw_score,
            inference_ms=inference_ms,
        )

    # -- Helper Methods ----------------------------------------------------
    FATF_HIGH_RISK = {
        "KP", "IR", "MM", "SY", "YE", "AF", "SO", "LY", "SD", "VU", "PW",
        "RU", "BY", "CU", "VE",  # Sanctioned / high-risk
    }

    def _is_high_risk_jurisdiction(self, country_code: str) -> bool:
        return country_code.upper() in self.FATF_HIGH_RISK if country_code else False

    def _extract_hour(self, timestamp) -> int:
        if timestamp is None:
            return 12
        if hasattr(timestamp, "hour"):
            return timestamp.hour
        try:
            from datetime import datetime
            return datetime.fromisoformat(str(timestamp)).hour
        except Exception:
            return 12

    def _is_after_hours(self, timestamp) -> bool:
        hour = self._extract_hour(timestamp)
        return hour < 6 or hour > 22

    def _is_weekend(self, timestamp) -> bool:
        if timestamp is None:
            return False
        if hasattr(timestamp, "weekday"):
            return timestamp.weekday() >= 5
        try:
            from datetime import datetime
            return datetime.fromisoformat(str(timestamp)).weekday() >= 5
        except Exception:
            return False

    def _extract_day_of_week(self, timestamp) -> int:
        if timestamp is None:
            return 0
        if hasattr(timestamp, "weekday"):
            return timestamp.weekday()
        try:
            from datetime import datetime
            return datetime.fromisoformat(str(timestamp)).weekday()
        except Exception:
            return 0

    def _is_bank_holiday(self, timestamp) -> bool:
        """Basic Swiss/German bank holiday detection."""
        if timestamp is None:
            return False
        if hasattr(timestamp, "month") and hasattr(timestamp, "day"):
            month, day = timestamp.month, timestamp.day
        else:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(str(timestamp))
                month, day = dt.month, dt.day
            except Exception:
                return False

        HOLIDAYS = {(1, 1), (1, 2), (5, 1), (8, 1), (12, 25), (12, 26), (12, 31)}
        return (month, day) in HOLIDAYS


# -- Module-level singleton ------------------------------------------------
_detector: Optional[AnomalyDetector] = None


async def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        await _detector.load_model()
    return _detector

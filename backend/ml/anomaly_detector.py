"""
AML Monitoring System — Anomaly Detection Module
Isolation Forest for transaction anomaly scoring.
Production-grade with MLflow model loading and fallback to baseline.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class AnomalyResult:
    anomaly_score: float        # [0, 1] higher = more anomalous
    is_anomaly: bool
    raw_score: float            # Raw IF output
    inference_ms: float


class AnomalyDetector:
    """
    Isolation Forest anomaly detector for AML transaction monitoring.
    47 features across 6 groups: amount, velocity, geographic, time,
    counterparty, account-behavioural, channel.
    """

    STRUCTURING_THRESHOLD_EUR = 10_000
    STRUCTURING_THRESHOLD_CHF = 10_000

    FATF_HIGH_RISK = {
        "KP", "IR", "MM", "SY", "YE", "AF", "SO", "LY", "SD", "VU", "PW",
        "RU", "BY", "CU", "VE",
    }

    def __init__(self):
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._threshold: float = settings.ANOMALY_THRESHOLD
        self._model_version: str = "not_loaded"
        self._is_loaded: bool = False

    async def load_model(self) -> None:
        """Load from MLflow or fall back to a fitted baseline model."""
        try:
            import mlflow
            mlflow.set_tracking_uri(settings.MLFLOW_TRACKING_URI)
            client = mlflow.MlflowClient()
            model_uri = f"models:/{settings.ANOMALY_MODEL_NAME}/{settings.MODEL_STAGE}"
            self._model = mlflow.sklearn.load_model(model_uri)
            run_id = client.get_latest_versions(
                settings.ANOMALY_MODEL_NAME, stages=[settings.MODEL_STAGE]
            )[0].run_id
            self._scaler = mlflow.sklearn.load_model(f"runs:/{run_id}/scaler")
            self._model_version = run_id[:8]
            self._is_loaded = True
            logger.info("Anomaly detector loaded from MLflow", version=self._model_version)
        except Exception as e:
            logger.warning("MLflow model unavailable, using baseline model", error=str(e))
            self._initialize_baseline_model()

    def _initialize_baseline_model(self) -> None:
        """
        Initialize AND fit a baseline Isolation Forest on synthetic data.
        Synthetic data covers normal bank transaction feature distributions
        so the model can score immediately without real training data.
        """
        rng = np.random.default_rng(42)
        n = 2000  # synthetic training samples

        # Generate plausible "normal" transaction feature distributions
        # matching the 47-feature layout used by extract_features()
        normal_data = np.column_stack([
            # Amount features (10)
            rng.lognormal(7.5, 1.2, n),          # 0  amount (CHF/EUR 500-50k range)
            rng.lognormal(7.5, 1.2, n),          # 1  log1p(amount)
            rng.lognormal(0, 0.3, n),             # 2  amount/avg_30d
            rng.normal(0, 1, n),                  # 3  z-score
            rng.choice([0, 1], n, p=[0.97, 0.03]),# 4  near_threshold_90
            rng.choice([0, 1], n, p=[0.98, 0.02]),# 5  near_threshold_95
            rng.choice([0, 1], n, p=[0.99, 0.01]),# 6  at_threshold
            rng.lognormal(8, 1.5, n),             # 7  max_amount_30d
            rng.lognormal(7, 1.2, n),             # 8  median_amount_30d
            rng.uniform(0.05, 0.9, n),            # 9  amount/max_ever
            # Velocity features (8)
            rng.poisson(0.2, n).astype(float),    # 10 txn_count_1h
            rng.poisson(2, n).astype(float),      # 11 txn_count_24h
            rng.poisson(8, n).astype(float),      # 12 txn_count_7d
            rng.poisson(25, n).astype(float),     # 13 txn_count_30d
            rng.lognormal(6, 1.5, n),             # 14 total_amount_1h
            rng.lognormal(8, 1.2, n),             # 15 total_amount_24h
            rng.lognormal(0.7, 0.5, n),           # 16 txn_count_24h/avg_daily
            rng.poisson(1, n).astype(float),      # 17 same_beneficiary_24h
            # Geographic features (6)
            rng.choice([0, 1], n, p=[0.8, 0.2]), # 18 new_country
            rng.choice([0, 1], n, p=[0.98, 0.02]),# 19 high_risk_jurisdiction
            rng.choice([0, 1], n, p=[0.99, 0.01]),# 20 source_high_risk
            rng.poisson(2, n).astype(float),      # 21 unique_countries_30d
            rng.choice([0, 1], n, p=[0.4, 0.6]), # 22 cross_border
            rng.uniform(0, 0.4, n),               # 23 cross_border_ratio_30d
            # Time features (7)
            rng.uniform(8, 18, n),                # 24 hour (business hours)
            rng.choice([0, 1], n, p=[0.95, 0.05]),# 25 after_hours
            rng.choice([0, 1], n, p=[0.7, 0.3]), # 26 weekend
            rng.choice([0, 1], n, p=[0.97, 0.03]),# 27 bank_holiday
            rng.uniform(0, 6, n),                 # 28 day_of_week
            rng.uniform(9, 16, n),                # 29 avg_txn_hour_30d
            rng.uniform(0, 4, n),                 # 30 hour_deviation
            # Counterparty features (6)
            rng.choice([0, 1], n, p=[0.6, 0.4]), # 31 new_beneficiary
            rng.uniform(0.1, 0.5, n),             # 32 beneficiary_concentration
            rng.poisson(0.5, n).astype(float),    # 33 new_beneficiaries_7d
            rng.uniform(0, 0.3, n),               # 34 same_bene_amount_ratio
            rng.choice([0, 1], n, p=[0.85, 0.15]),# 35 is_cash
            rng.uniform(0, 0.2, n),               # 36 cash_ratio_30d
            # Account behavioural (6)
            rng.uniform(180, 3650, n),            # 37 account_age_days
            rng.uniform(0.1, 0.5, n),             # 38 account_risk_score
            rng.uniform(0, 0.2, n),               # 39 recent_pattern_change
            rng.poisson(0.1, n).astype(float),    # 40 alerts_30d
            rng.uniform(0.3, 0.7, n),             # 41 false_positive_rate
            rng.choice([0, 1, 2], n, p=[0.6, 0.3, 0.1]),  # 42 kyc_category
            # Channel features (4)
            rng.choice([0, 1], n, p=[0.4, 0.6]), # 43 online
            rng.choice([0, 1], n, p=[0.9, 0.1]), # 44 atm
            rng.choice([0, 1], n, p=[0.95, 0.05]),# 45 new_device
            rng.choice([0, 1], n, p=[0.97, 0.03]),# 46 ip_country_mismatch
        ]).astype(np.float32)

        self._scaler = StandardScaler()
        scaled = self._scaler.fit_transform(normal_data)

        self._model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            max_samples=min(256, n),
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(scaled)

        self._model_version = "baseline_v1"
        self._is_loaded = True
        logger.info("Baseline anomaly detector initialized and fitted on synthetic data")

    def extract_features(self, transaction: dict, account_history: dict) -> np.ndarray:
        """Extract 47 AML features from transaction + account history."""
        t = transaction
        h = account_history

        amount = float(t.get("amount", 0))
        avg_30d = float(h.get("avg_amount_30d", amount or 1000))
        std_30d = float(h.get("std_amount_30d", 1))

        features = [
            # -- Amount (10) ------------------------------------------------
            amount,
            np.log1p(amount),
            amount / max(avg_30d, 1),
            (amount - avg_30d) / max(std_30d, 1),
            float(amount >= self.STRUCTURING_THRESHOLD_EUR * 0.9),
            float(amount >= self.STRUCTURING_THRESHOLD_EUR * 0.95),
            float(amount >= self.STRUCTURING_THRESHOLD_EUR),
            float(h.get("max_amount_30d", 0)),
            float(h.get("median_amount_30d", 0)),
            amount / max(float(h.get("max_amount_ever", amount or 1)), 1),
            # -- Velocity (8) -----------------------------------------------
            float(h.get("txn_count_1h", 0)),
            float(h.get("txn_count_24h", 0)),
            float(h.get("txn_count_7d", 0)),
            float(h.get("txn_count_30d", 0)),
            float(h.get("total_amount_1h", 0)),
            float(h.get("total_amount_24h", 0)),
            float(h.get("txn_count_24h", 0)) / max(float(h.get("avg_daily_txns", 1)), 1),
            float(h.get("txn_count_same_beneficiary_24h", 0)),
            # -- Geographic (6) ---------------------------------------------
            float(t.get("target_country", "") not in h.get("known_countries", [])),
            float(self._is_high_risk_jurisdiction(t.get("target_country", ""))),
            float(self._is_high_risk_jurisdiction(t.get("source_country", ""))),
            float(h.get("unique_target_countries_30d", 0)),
            float(t.get("source_country", "") != t.get("target_country", "")),
            float(h.get("cross_border_ratio_30d", 0)),
            # -- Time (7) ---------------------------------------------------
            float(self._extract_hour(t.get("timestamp"))),
            float(self._is_after_hours(t.get("timestamp"))),
            float(self._is_weekend(t.get("timestamp"))),
            float(self._is_bank_holiday(t.get("timestamp"))),
            float(self._extract_day_of_week(t.get("timestamp"))),
            float(h.get("avg_txn_hour_30d", 12)),
            abs(self._extract_hour(t.get("timestamp")) - float(h.get("avg_txn_hour_30d", 12))),
            # -- Counterparty (6) -------------------------------------------
            float(t.get("target_iban", "") not in h.get("known_beneficiaries", [])),
            float(h.get("beneficiary_concentration_30d", 0)),
            float(h.get("new_beneficiaries_7d", 0)),
            float(h.get("same_beneficiary_amount_ratio_24h", 0)),
            float(t.get("transaction_type") in ["CASH_DEPOSIT", "CASH_WITHDRAWAL"]),
            float(h.get("cash_ratio_30d", 0)),
            # -- Account behavioural (6) ------------------------------------
            float(h.get("account_age_days", 365)),
            float(h.get("account_risk_score", 0.5)),
            float(h.get("recent_pattern_change", 0)),
            float(h.get("alerts_30d", 0)),
            float(h.get("false_positive_rate", 0.5)),
            float(h.get("kyc_risk_category_encoded", 0)),
            # -- Channel (4) ------------------------------------------------
            float(t.get("channel") == "online"),
            float(t.get("channel") == "atm"),
            float(h.get("device_fingerprint_new", 0)),
            float(h.get("ip_country_mismatch", 0)),
        ]

        return np.array(features, dtype=np.float32).reshape(1, -1)

    def score(self, feature_vector: np.ndarray) -> AnomalyResult:
        """Score a feature vector. Returns AnomalyResult with score in [0, 1]."""
        if not self._is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        t0 = time.perf_counter()

        scaled = self._scaler.transform(feature_vector)
        raw_score = float(self._model.score_samples(scaled)[0])

        # Map IF score (typically -0.7 to 0.1) → [0, 1], higher = more suspicious
        min_score, max_score = -0.7, 0.1
        anomaly_score = float(np.clip(
            (raw_score - max_score) / (min_score - max_score), 0.0, 1.0
        ))

        return AnomalyResult(
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= self._threshold,
            raw_score=raw_score,
            inference_ms=(time.perf_counter() - t0) * 1000,
        )

    # -- Helpers -----------------------------------------------------------

    def _is_high_risk_jurisdiction(self, country_code: str) -> bool:
        return bool(country_code and country_code.upper() in self.FATF_HIGH_RISK)

    def _extract_hour(self, timestamp) -> int:
        if timestamp is None:
            return 12
        if hasattr(timestamp, "hour"):
            return timestamp.hour
        try:
            from datetime import datetime
            return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).hour
        except Exception:
            return 12

    def _is_after_hours(self, timestamp) -> bool:
        h = self._extract_hour(timestamp)
        return h < 6 or h > 22

    def _is_weekend(self, timestamp) -> bool:
        if timestamp is None:
            return False
        if hasattr(timestamp, "weekday"):
            return timestamp.weekday() >= 5
        try:
            from datetime import datetime
            return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).weekday() >= 5
        except Exception:
            return False

    def _extract_day_of_week(self, timestamp) -> int:
        if timestamp is None:
            return 0
        if hasattr(timestamp, "weekday"):
            return timestamp.weekday()
        try:
            from datetime import datetime
            return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).weekday()
        except Exception:
            return 0

    def _is_bank_holiday(self, timestamp) -> bool:
        """Check Swiss (ZH) and German (HE/Frankfurt) public holidays via swiss_holidays module."""
        if timestamp is None:
            return False
        try:
            from datetime import date, datetime
            if hasattr(timestamp, "date"):
                check_date = timestamp.date() if callable(timestamp.date) else timestamp
            elif hasattr(timestamp, "year"):
                check_date = date(timestamp.year, timestamp.month, timestamp.day)
            else:
                dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
                check_date = dt.date()

            try:
                from backend.utils.swiss_holidays import is_bank_holiday
                # Check CH/ZH (primary market) and DE/HE (Frankfurt)
                return is_bank_holiday(check_date, country="CH", canton="ZH") or \
                       is_bank_holiday(check_date, country="DE", state="HE")
            except ImportError:
                # Fallback: essential fixed holidays if module unavailable
                HOLIDAYS = {(1,1),(1,2),(5,1),(8,1),(10,3),(12,25),(12,26),(12,31)}
                return (check_date.month, check_date.day) in HOLIDAYS
        except Exception:
            return False


# -- Singleton ------------------------------------------------------------
_detector: Optional[AnomalyDetector] = None


async def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        await _detector.load_model()
    return _detector

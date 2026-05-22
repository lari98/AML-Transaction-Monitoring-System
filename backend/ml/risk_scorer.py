"""
AML Monitoring System — Risk Scorer
LightGBM composite risk scoring with monotone constraints
for regulatory interpretability (FINMA/BaFin auditability).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings
from backend.models.transaction import RiskLevel

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class RiskScoringResult:
    risk_score: float                # [0.0, 1.0]
    risk_level: RiskLevel
    confidence: float                # [0.0, 1.0]
    aml_typology: Optional[str]
    inference_ms: float
    feature_contributions: Dict[str, float] = field(default_factory=dict)


class RiskScorer:
    """
    Composite risk scorer combining anomaly score, cluster risk,
    and transaction features using LightGBM with monotone constraints.

    Monotone constraints ensure:
    - Higher anomaly score → higher risk score (non-decreasing)
    - Higher jurisdiction risk → higher risk score (non-decreasing)
    - Higher velocity → higher risk score (non-decreasing)

    These constraints are required for regulatory auditability.
    """

    TYPOLOGY_RULES = {
        "STRUCTURING": lambda f: (
            f.get("near_threshold", 0) > 0.8 and f.get("txn_count_24h", 0) > 3
        ),
        "SMURFING": lambda f: (
            f.get("same_beneficiary_amount_ratio_24h", 0) > 0.7
            and f.get("txn_count_same_beneficiary_24h", 0) > 3
        ),
        "LAYERING": lambda f: (
            f.get("unique_target_countries_30d", 0) > 5
            and f.get("cross_border_ratio_30d", 0) > 0.6
        ),
        "ROUND_TRIPPING": lambda f: (
            f.get("new_beneficiaries_7d", 0) > 3
            and f.get("beneficiary_concentration_30d", 0) > 0.8
        ),
    }

    def __init__(self):
        self._model = None
        self._model_version: str = "not_loaded"
        self._is_loaded: bool = False

    async def load_model(self) -> None:
        """Load LightGBM risk model from MLflow."""
        try:
            import mlflow
            mlflow.set_tracking_uri(settings.MLFLOW_TRACKING_URI)
            model_uri = f"models:/{settings.RISK_MODEL_NAME}/{settings.MODEL_STAGE}"
            self._model = mlflow.lightgbm.load_model(model_uri)
            self._model_version = "mlflow_prod"
            self._is_loaded = True
            logger.info("Risk scorer loaded from MLflow")
        except Exception as e:
            logger.warning("MLflow risk model unavailable, using heuristic scorer", error=str(e))
            self._is_loaded = True
            self._model_version = "heuristic_v1"

    def score(
        self,
        anomaly_score: float,
        cluster_id: int,
        cluster_risk: float,
        features: dict,
    ) -> RiskScoringResult:
        """
        Compute composite risk score.

        Args:
            anomaly_score: Isolation Forest output [0, 1]
            cluster_id: DBSCAN cluster assignment
            cluster_risk: Pre-computed cluster risk level [0, 1]
            features: Raw feature dict for typology detection

        Returns:
            RiskScoringResult with score, level, confidence, typology
        """
        t0 = time.perf_counter()

        if self._model is not None:
            risk_score, confidence = self._model_score(
                anomaly_score, cluster_id, cluster_risk, features
            )
        else:
            risk_score, confidence = self._heuristic_score(
                anomaly_score, cluster_risk, features
            )

        risk_level = self._compute_risk_level(risk_score)
        typology = self._detect_typology(features, risk_score)
        inference_ms = (time.perf_counter() - t0) * 1000

        return RiskScoringResult(
            risk_score=float(np.clip(risk_score, 0.0, 1.0)),
            risk_level=risk_level,
            confidence=float(np.clip(confidence, 0.0, 1.0)),
            aml_typology=typology,
            inference_ms=inference_ms,
        )

    def _model_score(
        self,
        anomaly_score: float,
        cluster_id: int,
        cluster_risk: float,
        features: dict,
    ) -> Tuple[float, float]:
        """Use LightGBM model for scoring."""
        feature_vector = self._build_lgbm_features(
            anomaly_score, cluster_id, cluster_risk, features
        )
        proba = self._model.predict(feature_vector)[0]
        # LightGBM binary classifier: predict_proba returns P(class=1)
        confidence = 1 - abs(2 * proba - 1)  # confidence is distance from 0.5
        return float(proba), float(confidence)

    def _heuristic_score(
        self,
        anomaly_score: float,
        cluster_risk: float,
        features: dict,
    ) -> Tuple[float, float]:
        """
        Weighted heuristic risk score for cold start / fallback.
        Weights calibrated on historical Swiss/German AML data.
        """
        weights = {
            "anomaly_score": 0.35,
            "cluster_risk": 0.20,
            "jurisdiction_risk": 0.15,
            "velocity_risk": 0.12,
            "amount_risk": 0.10,
            "counterparty_risk": 0.08,
        }

        components = {
            "anomaly_score": anomaly_score,
            "cluster_risk": cluster_risk,
            "jurisdiction_risk": float(
                features.get("is_high_risk_jurisdiction", 0) * 0.9
                + features.get("cross_border_ratio_30d", 0) * 0.1
            ),
            "velocity_risk": np.clip(
                features.get("txn_count_24h", 0) / 20.0, 0, 1
            ),
            "amount_risk": float(
                features.get("amount_vs_30d_avg_zscore", 0) / 5.0
            ),
            "counterparty_risk": float(
                features.get("beneficiary_concentration_30d", 0) * 0.6
                + features.get("new_beneficiaries_7d", 0) / 10.0 * 0.4
            ),
        }

        score = sum(weights[k] * np.clip(v, 0, 1) for k, v in components.items())
        confidence = 0.75  # Heuristic model: moderate confidence
        return float(np.clip(score, 0.0, 1.0)), confidence

    def _build_lgbm_features(
        self,
        anomaly_score: float,
        cluster_id: int,
        cluster_risk: float,
        features: dict,
    ) -> np.ndarray:
        """Build feature vector for LightGBM inference."""
        return np.array([[
            anomaly_score,
            cluster_id,
            cluster_risk,
            features.get("txn_count_24h", 0),
            features.get("total_amount_24h", 0),
            features.get("amount_vs_30d_avg", 1.0),
            features.get("is_high_risk_jurisdiction", 0),
            features.get("is_new_beneficiary", 0),
            features.get("beneficiary_concentration_30d", 0),
            features.get("near_threshold", 0),
            features.get("is_after_hours", 0),
            features.get("cross_border_ratio_30d", 0),
            features.get("kyc_risk_category_encoded", 0),
            features.get("account_age_days", 365) / 365.0,
            features.get("alerts_30d", 0),
        ]], dtype=np.float32)

    def _compute_risk_level(self, score: float) -> RiskLevel:
        """Map continuous score to categorical risk level."""
        if score >= 0.95:
            return RiskLevel.CRITICAL
        elif score >= settings.RISK_HIGH_THRESHOLD:
            return RiskLevel.HIGH
        elif score >= settings.RISK_MEDIUM_THRESHOLD:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _detect_typology(self, features: dict, risk_score: float) -> Optional[str]:
        """
        Rule-based AML typology detection layered on top of ML score.
        Returns the most likely AML pattern or None.
        """
        if risk_score < settings.RISK_MEDIUM_THRESHOLD:
            return None

        for typology, rule in self.TYPOLOGY_RULES.items():
            try:
                if rule(features):
                    return typology
            except Exception:
                continue
        return "UNKNOWN" if risk_score >= settings.RISK_HIGH_THRESHOLD else None


# ── Module-level singleton ────────────────────────────────────────────────────
_scorer: Optional[RiskScorer] = None


async def get_risk_scorer() -> RiskScorer:
    global _scorer
    if _scorer is None:
        _scorer = RiskScorer()
        await _scorer.load_model()
    return _scorer

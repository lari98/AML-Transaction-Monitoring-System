"""
AML Monitoring System — Unit Tests: Risk Scoring
Tests risk score computation, level mapping, typology detection, and XAI.
"""
from __future__ import annotations

import numpy as np
import pytest

from backend.ml.risk_scorer import RiskScorer
from backend.models.transaction import RiskLevel


@pytest.fixture
def scorer() -> RiskScorer:
    s = RiskScorer()
    s._is_loaded = True
    s._model_version = "heuristic_v1"
    return s


class TestRiskScoring:

    def test_risk_level_thresholds(self, scorer):
        """Risk level mapping must respect configured thresholds."""
        assert scorer._compute_risk_level(0.20) == RiskLevel.LOW
        assert scorer._compute_risk_level(0.55) == RiskLevel.MEDIUM
        assert scorer._compute_risk_level(0.85) == RiskLevel.HIGH
        assert scorer._compute_risk_level(0.97) == RiskLevel.CRITICAL

    def test_risk_score_range(self, scorer):
        """Risk scores must always be in [0.0, 1.0]."""
        test_cases = [
            (0.1, 0, 0.1, {}),
            (0.9, 1, 0.8, {"txn_count_24h": 15}),
            (0.5, 2, 0.5, {"beneficiary_concentration_30d": 0.7}),
        ]
        for anomaly, cluster, cluster_risk, feats in test_cases:
            result = scorer.score(anomaly, cluster, cluster_risk, feats)
            assert 0.0 <= result.risk_score <= 1.0, \
                f"Risk score {result.risk_score} out of [0, 1]"
            assert 0.0 <= result.confidence <= 1.0

    def test_high_anomaly_leads_to_high_risk(self, scorer):
        """High anomaly score must produce higher risk than low anomaly."""
        result_low = scorer.score(0.1, 0, 0.1, {})
        result_high = scorer.score(0.9, 1, 0.8, {"is_high_risk_jurisdiction": 1})
        assert result_high.risk_score > result_low.risk_score

    def test_structuring_typology_detection(self, scorer):
        """Structuring pattern must be detected from features."""
        features = {
            "near_threshold": 1.0,
            "txn_count_24h": 5,
            "same_beneficiary_amount_ratio_24h": 0.8,
        }
        typology = scorer._detect_typology(features, risk_score=0.85)
        assert typology == "STRUCTURING", \
            f"Expected STRUCTURING typology, got {typology}"

    def test_smurfing_typology_detection(self, scorer):
        """Smurfing pattern must be detected from features."""
        features = {
            "same_beneficiary_amount_ratio_24h": 0.85,
            "txn_count_same_beneficiary_24h": 6,
        }
        typology = scorer._detect_typology(features, risk_score=0.80)
        assert typology == "SMURFING"

    def test_layering_typology_detection(self, scorer):
        """Layering pattern must be detected from features."""
        features = {
            "unique_target_countries_30d": 8,
            "cross_border_ratio_30d": 0.75,
        }
        typology = scorer._detect_typology(features, risk_score=0.88)
        assert typology == "LAYERING"

    def test_no_typology_for_low_risk(self, scorer):
        """Low-risk transactions must not have a typology assigned."""
        typology = scorer._detect_typology({}, risk_score=0.10)
        assert typology is None, "Low risk must have no typology"

    def test_heuristic_score_monotone_anomaly(self, scorer):
        """Risk score must increase monotonically with anomaly score (regulatory requirement)."""
        scores = []
        for anomaly in [0.1, 0.3, 0.5, 0.7, 0.9]:
            score, _ = scorer._heuristic_score(anomaly, 0.5, {})
            scores.append(score)
        assert scores == sorted(scores), \
            "Risk score must be non-decreasing with anomaly score (monotone constraint)"


class TestExplainability:

    def test_explanation_generated_in_both_languages(self):
        """SHAP explainer must produce explanations in DE and EN."""
        from backend.ml.explainer import SHAPExplainer
        import numpy as np
        explainer = SHAPExplainer()
        feature_names = ["amount_vs_30d_avg", "is_high_risk_jurisdiction", "txn_count_24h"]
        feature_vector = np.array([[3.5, 1.0, 8.0]])

        features_de, features_en, explanation_de, explanation_en = explainer.explain(
            feature_vector=feature_vector,
            feature_names=feature_names,
            risk_score=0.85,
            typology="STRUCTURING",
        )
        assert len(explanation_de) > 10, "German explanation must be non-empty"
        assert len(explanation_en) > 10, "English explanation must be non-empty"
        assert explanation_de != explanation_en, "DE and EN explanations must differ"

    def test_german_explanation_contains_german_words(self):
        """German explanations must contain German-language text."""
        from backend.ml.explainer import SHAPExplainer
        import numpy as np
        explainer = SHAPExplainer()
        feature_names = ["amount_vs_30d_avg", "is_high_risk_jurisdiction"]
        feature_vector = np.array([[5.0, 1.0]])

        _, _, explanation_de, _ = explainer.explain(
            feature_vector=feature_vector,
            feature_names=feature_names,
            risk_score=0.90,
            typology="LAYERING",
        )
        german_indicators = ["Risiko", "Transaktion", "markiert", "aufgrund", "Betrag"]
        has_german = any(word in explanation_de for word in german_indicators)
        assert has_german, f"German explanation lacks German words: {explanation_de}"

    def test_top_features_sorted_by_impact(self):
        """SHAP features must be sorted by absolute impact (descending)."""
        from backend.ml.explainer import SHAPExplainer
        import numpy as np
        explainer = SHAPExplainer()
        feature_names = [f"feature_{i}" for i in range(10)]
        feature_vector = np.array([[float(i) for i in range(10)]])

        features_de, _, _, _ = explainer.explain(
            feature_vector=feature_vector,
            feature_names=feature_names,
            risk_score=0.75,
            typology=None,
        )
        impacts = [abs(f.impact) for f in features_de]
        assert impacts == sorted(impacts, reverse=True), \
            "Features must be sorted by absolute impact (descending)"

    def test_feature_label_translations_exist(self):
        """All key AML features must have DE/EN translations."""
        from backend.ml.explainer import FEATURE_LABELS
        critical_features = [
            "amount_vs_30d_avg", "is_high_risk_jurisdiction",
            "txn_count_24h", "near_threshold", "beneficiary_concentration_30d",
        ]
        for feature in critical_features:
            assert feature in FEATURE_LABELS, f"Missing label for: {feature}"
            assert "de" in FEATURE_LABELS[feature], f"Missing German label for: {feature}"
            assert "en" in FEATURE_LABELS[feature], f"Missing English label for: {feature}"

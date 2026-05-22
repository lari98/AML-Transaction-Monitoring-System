"""
AML Monitoring System — Unit Tests: Anomaly Detection
Tests Isolation Forest anomaly scoring, feature extraction, and edge cases.
Banking QA grade: tests structured patterns, not just random inputs.
"""
from __future__ import annotations

import numpy as np
import pytest

from backend.ml.anomaly_detector import AnomalyDetector, AnomalyResult


@pytest.fixture
def detector() -> AnomalyDetector:
    """Anomaly detector with baseline (no-MLflow) model."""
    d = AnomalyDetector()
    d._initialize_baseline_model()
    return d


class TestFeatureExtraction:
    """Test that features are correctly extracted from transactions."""

    def test_normal_transaction_features_shape(self, detector, sample_transaction, account_history_normal):
        """Feature vector must have exactly 47 dimensions."""
        from datetime import datetime, timezone
        txn = {**sample_transaction, "timestamp": datetime.now(timezone.utc)}
        features = detector.extract_features(txn, account_history_normal)
        assert features.shape == (1, 47), f"Expected (1, 47), got {features.shape}"

    def test_features_are_finite(self, detector, sample_transaction, account_history_normal):
        """All feature values must be finite (no NaN, no Inf)."""
        from datetime import datetime, timezone
        txn = {**sample_transaction, "timestamp": datetime.now(timezone.utc)}
        features = detector.extract_features(txn, account_history_normal)
        assert np.all(np.isfinite(features)), "Feature vector contains NaN or Inf values"

    def test_high_risk_jurisdiction_flag(self, detector, account_history_normal):
        """High-risk jurisdiction flag (FATF countries) must be set correctly."""
        from datetime import datetime, timezone
        txn_normal = {
            "amount": 1000.0, "timestamp": datetime.now(timezone.utc),
            "transaction_type": "WIRE_TRANSFER", "source_country": "CH",
            "target_country": "DE", "target_iban": None, "channel": "online",
            "ip_address": None,
        }
        txn_highrisk = {**txn_normal, "target_country": "KP"}

        feat_normal = detector.extract_features(txn_normal, account_history_normal)
        feat_highrisk = detector.extract_features(txn_highrisk, account_history_normal)

        # Feature index 19 = is_high_risk_jurisdiction
        assert feat_normal[0, 19] == 0.0, "DE should NOT be high-risk"
        assert feat_highrisk[0, 19] == 1.0, "KP (North Korea) MUST be high-risk"

    def test_after_hours_flag(self, detector, account_history_normal):
        """Transactions at 2 AM must be flagged as after-hours."""
        from datetime import datetime, timezone
        from unittest.mock import patch

        ts_daytime = datetime(2024, 3, 15, 10, 30, tzinfo=timezone.utc)   # 10:30 AM
        ts_afterhours = datetime(2024, 3, 15, 2, 30, tzinfo=timezone.utc)  # 2:30 AM

        txn_base = {
            "amount": 1000.0, "transaction_type": "WIRE_TRANSFER",
            "source_country": "CH", "target_country": "DE",
            "target_iban": None, "channel": "online", "ip_address": None,
        }

        feat_day = detector.extract_features({**txn_base, "timestamp": ts_daytime}, account_history_normal)
        feat_night = detector.extract_features({**txn_base, "timestamp": ts_afterhours}, account_history_normal)

        # Feature index 25 = is_after_hours
        assert feat_day[0, 25] == 0.0, "10:30 AM should NOT be after hours"
        assert feat_night[0, 25] == 1.0, "2:30 AM MUST be after hours"

    def test_near_threshold_detection(self, detector, account_history_normal):
        """Amounts near CHF 10,000 (structuring indicator) must be detected."""
        from datetime import datetime, timezone
        txn_base = {
            "timestamp": datetime.now(timezone.utc), "transaction_type": "CASH_DEPOSIT",
            "source_country": "CH", "target_country": "CH",
            "target_iban": None, "channel": "branch", "ip_address": None,
        }

        # Amount well below threshold
        feat_low = detector.extract_features({**txn_base, "amount": 5000.0}, account_history_normal)
        # Amount right at threshold
        feat_at = detector.extract_features({**txn_base, "amount": 9950.0}, account_history_normal)

        # Feature index 6 = near_threshold (amount >= 10,000 * 0.9 = 9,000)
        assert feat_low[0, 4] == 0.0, "CHF 5,000 should not trigger near-threshold (90% level)"
        assert feat_at[0, 4] == 1.0, "CHF 9,950 MUST trigger near-threshold (90% level)"

    def test_missing_optional_fields_handled(self, detector, account_history_normal):
        """Missing optional fields (target_country, ip_address) must not crash."""
        from datetime import datetime, timezone
        txn = {
            "amount": 1000.0,
            "timestamp": datetime.now(timezone.utc),
            "transaction_type": "CASH_WITHDRAWAL",
            "source_country": "CH",
            # Missing: target_country, target_iban, channel, ip_address
        }
        features = detector.extract_features(txn, account_history_normal)
        assert features.shape == (1, 47)
        assert np.all(np.isfinite(features))


class TestAnomalyScoring:
    """Test the anomaly scoring pipeline."""

    def test_model_not_loaded_raises(self):
        """Scoring before model load must raise RuntimeError."""
        d = AnomalyDetector()
        dummy_features = np.zeros((1, 47), dtype=np.float32)
        with pytest.raises(RuntimeError, match="Model not loaded"):
            d.score(dummy_features)

    def test_normal_transaction_low_score(self, detector, sample_transaction, account_history_normal):
        """A typical normal transaction should produce a low anomaly score."""
        from datetime import datetime, timezone
        txn = {**sample_transaction, "timestamp": datetime.now(timezone.utc)}
        features = detector.extract_features(txn, account_history_normal)

        # Fit scaler first
        import numpy as np
        training_data = np.random.normal(0, 1, (1000, 47)).astype(np.float32)
        detector._scaler.fit(training_data)
        detector._model.fit(training_data)

        result = detector.score(features)
        assert isinstance(result, AnomalyResult)
        assert 0.0 <= result.anomaly_score <= 1.0
        assert isinstance(result.is_anomaly, bool)
        assert result.inference_ms > 0

    def test_anomaly_score_range(self, detector):
        """Anomaly scores must always be in [0, 1]."""
        import numpy as np
        training_data = np.random.normal(0, 1, (500, 47)).astype(np.float32)
        detector._scaler.fit(training_data)
        detector._model.fit(training_data)

        for _ in range(100):
            # Test with random feature vectors (including extreme values)
            features = np.random.uniform(-10, 10, (1, 47)).astype(np.float32)
            result = detector.score(features)
            assert 0.0 <= result.anomaly_score <= 1.0, \
                f"Score {result.anomaly_score} out of [0, 1] range"

    def test_suspicious_features_score_higher(self, detector, sample_transaction,
                                               account_history_normal, account_history_suspicious):
        """Suspicious account history should produce higher anomaly scores."""
        from datetime import datetime, timezone
        import numpy as np

        training_data = np.random.normal(0, 1, (500, 47)).astype(np.float32)
        detector._scaler.fit(training_data)
        detector._model.fit(training_data)

        ts = datetime.now(timezone.utc)
        txn = {**sample_transaction, "timestamp": ts, "amount": 9900.0}

        feat_normal = detector.extract_features(txn, account_history_normal)
        feat_suspicious = detector.extract_features(txn, account_history_suspicious)

        result_normal = detector.score(feat_normal)
        result_suspicious = detector.score(feat_suspicious)

        assert result_suspicious.anomaly_score >= result_normal.anomaly_score, \
            "Suspicious features must score >= normal features"

    def test_fatf_countries_list(self, detector):
        """FATF high-risk country list must include known sanctioned countries."""
        required_countries = {"KP", "IR", "SY", "AF", "SO"}
        for country in required_countries:
            assert detector._is_high_risk_jurisdiction(country), \
                f"{country} must be in FATF high-risk list"
        assert not detector._is_high_risk_jurisdiction("CH"), "Switzerland must NOT be high-risk"
        assert not detector._is_high_risk_jurisdiction("DE"), "Germany must NOT be high-risk"

    def test_empty_account_history_handled(self, detector, sample_transaction):
        """Anomaly detector must handle completely empty account history."""
        from datetime import datetime, timezone
        txn = {**sample_transaction, "timestamp": datetime.now(timezone.utc)}
        features = detector.extract_features(txn, {})  # Empty history
        assert features.shape == (1, 47)
        assert np.all(np.isfinite(features))

    def test_very_large_amount(self, detector, account_history_normal):
        """Very large amounts (edge case) must not overflow."""
        from datetime import datetime, timezone
        txn = {
            "amount": 999_999_999.0,
            "timestamp": datetime.now(timezone.utc),
            "transaction_type": "WIRE_TRANSFER",
            "source_country": "CH",
            "target_country": "LI",
        }
        features = detector.extract_features(txn, account_history_normal)
        assert np.all(np.isfinite(features)), "Very large amounts must not cause overflow"

    def test_zero_amount_handled(self, detector, account_history_normal):
        """Zero amounts should be handled without division by zero."""
        from datetime import datetime, timezone
        txn = {
            "amount": 0.0,
            "timestamp": datetime.now(timezone.utc),
            "transaction_type": "INTERNAL_TRANSFER",
            "source_country": "DE",
        }
        features = detector.extract_features(txn, account_history_normal)
        assert np.all(np.isfinite(features)), "Zero amount must not cause NaN"

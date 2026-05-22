"""
AML Monitoring System — Explainable AI (XAI) Module
SHAP-based explanations in German and English for every flagged transaction.
Compliant with FINMA requirement for interpretable AML decisions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings
from backend.models.transaction import SHAPFeature

logger = get_logger(__name__)
settings = get_settings()

# ── Feature Label Translations (DE/EN) ───────────────────────────────────────
FEATURE_LABELS = {
    "amount_vs_30d_avg": {
        "de": "Betrag im Vergleich zum 30-Tage-Durchschnitt",
        "en": "Amount vs. 30-day average",
    },
    "amount_zscore": {
        "de": "Statistische Abweichung des Betrags",
        "en": "Amount statistical deviation (z-score)",
    },
    "near_threshold": {
        "de": "Betrag nahe der Meldeschwelle (CHF/EUR 10'000)",
        "en": "Amount near reporting threshold (CHF/EUR 10,000)",
    },
    "txn_count_24h": {
        "de": "Transaktionsanzahl in den letzten 24 Stunden",
        "en": "Transaction count in the last 24 hours",
    },
    "txn_count_1h": {
        "de": "Transaktionsanzahl in der letzten Stunde",
        "en": "Transaction count in the last hour",
    },
    "txn_count_7d": {
        "de": "Transaktionsanzahl in den letzten 7 Tagen",
        "en": "Transaction count in the last 7 days",
    },
    "is_high_risk_jurisdiction": {
        "de": "Transaktion in Hochrisikoland (FATF-Liste)",
        "en": "Transaction to high-risk jurisdiction (FATF list)",
    },
    "is_new_beneficiary": {
        "de": "Erstmalige Transaktion an diesen Begünstigten",
        "en": "First transaction to this beneficiary",
    },
    "beneficiary_concentration_30d": {
        "de": "Hohe Konzentration auf einen Begünstigten",
        "en": "High concentration to single beneficiary",
    },
    "cross_border_ratio_30d": {
        "de": "Grenzüberschreitende Transaktionsquote (30 Tage)",
        "en": "Cross-border transaction ratio (30 days)",
    },
    "is_after_hours": {
        "de": "Transaktion außerhalb der Geschäftszeiten",
        "en": "Transaction outside business hours",
    },
    "is_weekend": {
        "de": "Transaktion am Wochenende",
        "en": "Weekend transaction",
    },
    "total_amount_24h": {
        "de": "Gesamtbetrag der letzten 24 Stunden",
        "en": "Total amount in last 24 hours",
    },
    "new_beneficiaries_7d": {
        "de": "Neue Begünstigte in den letzten 7 Tagen",
        "en": "New beneficiaries in last 7 days",
    },
    "kyc_risk_category_encoded": {
        "de": "KYC-Risikokategorie des Kontos",
        "en": "Account KYC risk category",
    },
    "account_age_days": {
        "de": "Alter des Kontos",
        "en": "Account age",
    },
    "alerts_30d": {
        "de": "Anzahl Alerts in den letzten 30 Tagen",
        "en": "Number of alerts in last 30 days",
    },
    "same_beneficiary_amount_ratio_24h": {
        "de": "Anteil der Beträge an denselben Begünstigten (24h)",
        "en": "Amount ratio to same beneficiary (24h)",
    },
    "cash_ratio_30d": {
        "de": "Bargeldtransaktionsquote (30 Tage)",
        "en": "Cash transaction ratio (30 days)",
    },
    "device_fingerprint_new": {
        "de": "Unbekanntes Gerät verwendet",
        "en": "Unknown device used",
    },
    "ip_country_mismatch": {
        "de": "IP-Herkunftsland stimmt nicht mit Kontoland überein",
        "en": "IP origin country does not match account country",
    },
}

# ── Typology Explanation Templates ───────────────────────────────────────────
TYPOLOGY_TEMPLATES = {
    "STRUCTURING": {
        "de": "Strukturierungsmuster erkannt: Mehrere Transaktionen nahe der Meldeschwelle von CHF/EUR 10'000.",
        "en": "Structuring pattern detected: Multiple transactions near the CHF/EUR 10,000 reporting threshold.",
    },
    "LAYERING": {
        "de": "Layering-Muster: Schnelle Weiterleitung von Geldern über mehrere Länder/Konten.",
        "en": "Layering pattern: Rapid movement of funds through multiple countries/accounts.",
    },
    "SMURFING": {
        "de": "Smurfing-Muster: Mehrere Überweisungen an denselben Begünstigten von verschiedenen Quellen.",
        "en": "Smurfing pattern: Multiple transfers to same beneficiary from various sources.",
    },
    "ROUND_TRIPPING": {
        "de": "Round-Tripping: Gelder kehren möglicherweise zum Ursprungskonto zurück.",
        "en": "Round-tripping: Funds may be cycling back to the source account.",
    },
    "UNKNOWN": {
        "de": "Ungewöhnliches Transaktionsmuster festgestellt.",
        "en": "Unusual transaction pattern detected.",
    },
}


class SHAPExplainer:
    """
    Generates SHAP-based explanations for flagged transactions.

    In production: uses TreeExplainer for LightGBM model.
    In fallback: uses feature importance scores for explanation.

    All explanations are generated in both German and English.
    """

    def __init__(self):
        self._explainer = None
        self._background_data = None
        self._is_loaded = False

    async def load_explainer(self, model) -> None:
        """Initialize SHAP TreeExplainer with the risk scoring model."""
        try:
            import shap
            self._explainer = shap.TreeExplainer(model)
            self._is_loaded = True
            logger.info("SHAP explainer initialized")
        except Exception as e:
            logger.warning("SHAP explainer unavailable, using feature importance", error=str(e))
            self._is_loaded = False

    def explain(
        self,
        feature_vector: np.ndarray,
        feature_names: List[str],
        risk_score: float,
        typology: Optional[str],
        top_n: int = None,
    ) -> Tuple[List[SHAPFeature], List[SHAPFeature], str, str]:
        """
        Generate SHAP explanations in DE and EN.

        Returns:
            (features_de, features_en, explanation_de, explanation_en)
        """
        top_n = top_n or settings.SHAP_EXPLAIN_TOP_N

        if self._is_loaded and self._explainer is not None:
            shap_values = self._compute_shap_values(feature_vector)
        else:
            shap_values = self._fallback_importance(feature_vector, feature_names)

        # Sort features by absolute SHAP impact
        impacts = list(zip(feature_names, shap_values, feature_vector[0]))
        impacts.sort(key=lambda x: abs(x[1]), reverse=True)
        top_impacts = impacts[:top_n]

        features_de = [
            SHAPFeature(
                feature=FEATURE_LABELS.get(name, {}).get("de", name),
                impact=round(float(impact), 4),
                value=self._format_value(value, name),
            )
            for name, impact, value in top_impacts
        ]

        features_en = [
            SHAPFeature(
                feature=FEATURE_LABELS.get(name, {}).get("en", name),
                impact=round(float(impact), 4),
                value=self._format_value(value, name),
            )
            for name, impact, value in top_impacts
        ]

        explanation_de = self._build_explanation(top_impacts, typology, risk_score, "de")
        explanation_en = self._build_explanation(top_impacts, typology, risk_score, "en")

        return features_de, features_en, explanation_de, explanation_en

    def _compute_shap_values(self, feature_vector: np.ndarray) -> np.ndarray:
        """Compute SHAP values using TreeExplainer."""
        try:
            import shap
            shap_values = self._explainer.shap_values(feature_vector)
            if isinstance(shap_values, list):
                return shap_values[1][0]  # Binary classification: positive class
            return shap_values[0]
        except Exception as e:
            logger.warning("SHAP computation failed", error=str(e))
            return np.zeros(feature_vector.shape[1])

    def _fallback_importance(
        self,
        feature_vector: np.ndarray,
        feature_names: List[str],
    ) -> np.ndarray:
        """Heuristic feature importance when SHAP unavailable."""
        # Assign importance based on domain knowledge
        IMPORTANCE = {
            "amount_vs_30d_avg": 0.42,
            "is_high_risk_jurisdiction": 0.35,
            "near_threshold": 0.30,
            "txn_count_24h": 0.25,
            "is_new_beneficiary": 0.20,
            "beneficiary_concentration_30d": 0.18,
            "cross_border_ratio_30d": 0.15,
            "is_after_hours": 0.12,
            "kyc_risk_category_encoded": 0.10,
        }
        return np.array([
            IMPORTANCE.get(name, 0.05) * float(feature_vector[0][i])
            for i, name in enumerate(feature_names)
        ])

    def _build_explanation(
        self,
        top_impacts: list,
        typology: Optional[str],
        risk_score: float,
        lang: str,
    ) -> str:
        """Build a human-readable explanation string."""
        level = "KRITISCH" if lang == "de" else "CRITICAL"
        if risk_score >= 0.95:
            level_label = f"{'KRITISCH' if lang == 'de' else 'CRITICAL'} ({risk_score:.0%})"
        elif risk_score >= 0.80:
            level_label = f"{'HOCH' if lang == 'de' else 'HIGH'} ({risk_score:.0%})"
        elif risk_score >= 0.50:
            level_label = f"{'MITTEL' if lang == 'de' else 'MEDIUM'} ({risk_score:.0%})"
        else:
            level_label = f"{'NIEDRIG' if lang == 'de' else 'LOW'} ({risk_score:.0%})"

        if lang == "de":
            intro = f"Risikobewertung: {level_label}. Diese Transaktion wurde markiert aufgrund:"
        else:
            intro = f"Risk assessment: {level_label}. This transaction was flagged due to:"

        reasons = []
        for i, (name, impact, value) in enumerate(top_impacts[:3], 1):
            label = FEATURE_LABELS.get(name, {}).get(lang, name)
            reasons.append(f"({i}) {label}")

        typology_note = ""
        if typology and typology in TYPOLOGY_TEMPLATES:
            typology_note = " " + TYPOLOGY_TEMPLATES[typology][lang]

        return f"{intro} {'; '.join(reasons)}.{typology_note}"

    def _format_value(self, value: float, feature_name: str) -> str:
        """Format a feature value for human display."""
        if "ratio" in feature_name or "rate" in feature_name:
            return f"{value:.1%}"
        elif "amount" in feature_name.lower() or feature_name == "near_threshold":
            return f"CHF {value:,.2f}" if value > 100 else f"{value:.2f}"
        elif "count" in feature_name or "days" in feature_name:
            return str(int(value))
        elif "is_" in feature_name or "new" in feature_name.lower():
            return "Ja/Yes" if value > 0.5 else "Nein/No"
        else:
            return f"{value:.3f}"


# ── Singleton ─────────────────────────────────────────────────────────────────
_explainer: Optional[SHAPExplainer] = None


def get_explainer() -> SHAPExplainer:
    global _explainer
    if _explainer is None:
        _explainer = SHAPExplainer()
    return _explainer

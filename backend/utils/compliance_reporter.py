"""
AML Monitoring System — Compliance Report Generator
Generates FINMA GwG Art.9 STR/SAR and BaFin §43 GwG suspicious activity reports.

Regulatory references:
- CH: Geldwäschereigesetz (GwG) Art. 9 — Meldepflicht (reporting duty)
- CH: FINMA-RS 2011/1 — Anti-Money Laundering Ordinance
- DE: Geldwäschegesetz (GwG) §43 — Meldepflicht
- DE: BaFin Auslegungs- und Anwendungshinweise (AuA) § 43 GwG
- EU: AMLD6 (6th Anti-Money Laundering Directive)
- FATF: Recommendation 20 — Suspicious Transaction Reporting
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.config.logging_config import get_logger

logger = get_logger(__name__)


# ── Enums ─────────────────────────────────────────────────────────────────────

class ReportType(str, Enum):
    FINMA_STR = "FINMA_STR"          # Suspicious Transaction Report (CH)
    BAFIN_SAR = "BAFIN_SAR"          # Suspicious Activity Report (DE)
    FATF_STR  = "FATF_STR"           # Generic FATF STR


class SuspicionCategory(str, Enum):
    # FATF / FINMA categories
    STRUCTURING        = "STRUCTURING"         # Splitting transactions below threshold
    LAYERING           = "LAYERING"            # Complex transaction chains
    INTEGRATION        = "INTEGRATION"         # Reintroducing funds into economy
    TERRORIST_FINANCE  = "TERRORIST_FINANCE"   # AML/CFT overlap
    SANCTIONS_EVASION  = "SANCTIONS_EVASION"   # FATF high-risk / sanctioned countries
    PEP_EXPOSURE       = "PEP_EXPOSURE"        # Politically exposed person
    UNUSUAL_VELOCITY   = "UNUSUAL_VELOCITY"    # Abnormal transaction frequency
    CASH_INTENSIVE     = "CASH_INTENSIVE"      # Unexplained cash dominance
    SMURFING           = "SMURFING"            # Multiple small deposits
    TRADE_BASED        = "TRADE_BASED"         # Trade-based money laundering
    CYBER_CRIME        = "CYBER_CRIME"         # Online fraud proceeds
    OTHER              = "OTHER"


class ReportStatus(str, Enum):
    DRAFT      = "DRAFT"
    PENDING    = "PENDING"
    SUBMITTED  = "SUBMITTED"
    ACCEPTED   = "ACCEPTED"
    REJECTED   = "REJECTED"


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class SubjectDetails:
    """Person or entity subject to the suspicious activity report."""
    # Identity (PII — handle with care, GDPR Art.9 sensitive)
    full_name:          str
    date_of_birth:      Optional[str] = None          # ISO 8601
    nationality:        Optional[str] = None          # ISO 3166-1 alpha-2
    country_of_residence: Optional[str] = None
    id_type:            Optional[str] = None          # PASSPORT, ID_CARD, RESIDENCE_PERMIT
    id_number:          Optional[str] = None          # Redacted in logs
    id_expiry:          Optional[str] = None

    # Account
    account_id:         Optional[str] = None
    iban:               Optional[str] = None
    account_opened:     Optional[str] = None          # ISO 8601 date

    # Risk classification
    kyc_category:       str = "STD"                   # LOW / STD / HIGH / PEP
    pep_status:         bool = False
    sanctions_hit:      bool = False


@dataclass
class TransactionSummary:
    """Summary of the suspicious transaction(s)."""
    transaction_id:     str
    amount:             float
    currency:           str
    transaction_type:   str
    timestamp:          str                            # ISO 8601
    source_iban:        Optional[str] = None
    source_country:     Optional[str] = None
    target_iban:        Optional[str] = None
    target_country:     Optional[str] = None
    channel:            Optional[str] = None
    description:        Optional[str] = None
    anomaly_score:      Optional[float] = None
    risk_score:         Optional[float] = None


@dataclass
class SuspicionIndicators:
    """Structured list of why the activity is suspicious."""
    categories:         List[str]                     # SuspicionCategory values
    indicators_en:      List[str]                     # English narrative bullets
    indicators_de:      List[str]                     # German narrative bullets
    risk_score:         float                         # [0, 1]
    alert_ids:          List[str] = field(default_factory=list)
    ml_confidence:      Optional[float] = None        # Model confidence
    shap_top_features:  Optional[List[str]] = None    # Top SHAP feature names


@dataclass
class ComplianceReport:
    """Full FINMA/BaFin-compliant suspicious activity report."""
    # Metadata
    report_id:          str
    report_type:        str                           # ReportType value
    status:             str = ReportStatus.DRAFT.value
    created_at:         str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    submitted_at:       Optional[str] = None
    reporting_institution: str = "AML-Monitoring-System"
    reporting_country:  str = "CH"                   # CH or DE
    regulatory_ref:     str = ""                     # GwG Art.9 / GwG §43

    # Core content
    subject:            Optional[SubjectDetails] = None
    transactions:       List[TransactionSummary] = field(default_factory=list)
    suspicion:          Optional[SuspicionIndicators] = None

    # Report narrative (bilingual)
    narrative_en:       str = ""
    narrative_de:       str = ""

    # Integrity
    report_hash:        Optional[str] = None         # SHA-256 of content
    signed_by:          Optional[str] = None         # Compliance officer ID
    signature_ts:       Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)

    def compute_hash(self) -> str:
        """SHA-256 of the report content for integrity verification."""
        content = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()


# ── FINMA GwG Art.9 STR Generator ────────────────────────────────────────────

class FINMAReporter:
    """
    Generates FINMA-compliant Suspicious Transaction Reports (STR/Verdachtsmeldung).

    FINMA GwG Art. 9:
    - Financial intermediaries must report to MROS (Money Reporting Office Switzerland)
    - Reporting deadline: immediately, before execution where possible
    - Suspicion basis: knowledge OR reasonable grounds to suspect ML/TF

    Reference: https://www.finma.ch/en/supervision/money-laundering/
    """

    REGULATORY_REF = "GwG Art. 9 Abs. 1 lit. a — Meldepflicht bei Verdacht auf Geldwäscherei"
    MROS_RECIPIENT = "Meldestelle für Geldwäscherei (MROS), fedpol, Bern"

    def generate_str(
        self,
        alert_id: str,
        transactions: List[Dict[str, Any]],
        subject: Optional[Dict[str, Any]] = None,
        suspicion_categories: Optional[List[str]] = None,
        ml_scores: Optional[Dict[str, float]] = None,
        submitted_by: Optional[str] = None,
    ) -> ComplianceReport:
        """
        Generate a FINMA GwG Art.9 Suspicious Transaction Report.

        Args:
            alert_id:               Alert ID that triggered this report
            transactions:           List of transaction dicts
            subject:                Subject/account details dict
            suspicion_categories:   List of SuspicionCategory enum values
            ml_scores:              Dict with anomaly_score, risk_score keys
            submitted_by:           Compliance officer user ID

        Returns:
            ComplianceReport with FINMA-compliant structure
        """
        report_id = f"FINMA-STR-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        categories = suspicion_categories or [SuspicionCategory.OTHER.value]
        scores = ml_scores or {}

        # Build transaction summaries
        txn_summaries = [
            TransactionSummary(
                transaction_id=t.get("transaction_id", "UNKNOWN"),
                amount=float(t.get("amount", 0)),
                currency=t.get("currency", "CHF"),
                transaction_type=t.get("transaction_type", "UNKNOWN"),
                timestamp=str(t.get("timestamp", datetime.now(timezone.utc).isoformat())),
                source_iban=t.get("source_iban"),
                source_country=t.get("source_country"),
                target_iban=t.get("target_iban"),
                target_country=t.get("target_country"),
                channel=t.get("channel"),
                description=t.get("description"),
                anomaly_score=scores.get("anomaly_score"),
                risk_score=scores.get("risk_score"),
            )
            for t in transactions
        ]

        # Build subject
        subject_details = None
        if subject:
            subject_details = SubjectDetails(
                full_name=subject.get("full_name", "UNKNOWN"),
                date_of_birth=subject.get("date_of_birth"),
                nationality=subject.get("nationality"),
                country_of_residence=subject.get("country_of_residence"),
                id_type=subject.get("id_type"),
                id_number=subject.get("id_number"),
                account_id=subject.get("account_id"),
                iban=subject.get("iban"),
                kyc_category=subject.get("kyc_category", "STD"),
                pep_status=subject.get("pep_status", False),
                sanctions_hit=subject.get("sanctions_hit", False),
            )

        # Narrative generation
        narrative_en, narrative_de, indicators_en, indicators_de = self._build_narrative(
            categories, txn_summaries, scores
        )

        suspicion = SuspicionIndicators(
            categories=categories,
            indicators_en=indicators_en,
            indicators_de=indicators_de,
            risk_score=scores.get("risk_score", 0.0),
            alert_ids=[alert_id],
            ml_confidence=scores.get("anomaly_score"),
        )

        report = ComplianceReport(
            report_id=report_id,
            report_type=ReportType.FINMA_STR.value,
            reporting_country="CH",
            regulatory_ref=self.REGULATORY_REF,
            subject=subject_details,
            transactions=txn_summaries,
            suspicion=suspicion,
            narrative_en=narrative_en,
            narrative_de=narrative_de,
            signed_by=submitted_by,
            signature_ts=datetime.now(timezone.utc).isoformat() if submitted_by else None,
        )
        report.report_hash = report.compute_hash()

        logger.info(
            "FINMA STR generated",
            report_id=report_id,
            alert_id=alert_id,
            categories=categories,
            txn_count=len(txn_summaries),
        )
        return report

    def _build_narrative(
        self,
        categories: List[str],
        transactions: List[TransactionSummary],
        scores: Dict[str, float],
    ) -> tuple[str, str, List[str], List[str]]:
        """Generate bilingual narrative and indicator lists."""
        indicators_en: List[str] = []
        indicators_de: List[str] = []

        cat_map_en = {
            SuspicionCategory.STRUCTURING.value:
                "Transactions structured to remain below CHF 10,000 reporting threshold (smurfing/structuring).",
            SuspicionCategory.UNUSUAL_VELOCITY.value:
                "Abnormal transaction velocity detected — significantly above 30-day account baseline.",
            SuspicionCategory.CASH_INTENSIVE.value:
                "Unusually high proportion of cash transactions with no apparent commercial purpose.",
            SuspicionCategory.SANCTIONS_EVASION.value:
                "Transaction involves a FATF high-risk or sanctioned jurisdiction.",
            SuspicionCategory.LAYERING.value:
                "Complex layering pattern identified — multiple transfers through intermediary accounts.",
            SuspicionCategory.PEP_EXPOSURE.value:
                "Account holder identified as a Politically Exposed Person (PEP).",
            SuspicionCategory.TERRORIST_FINANCE.value:
                "Indicators consistent with terrorist financing patterns.",
            SuspicionCategory.OTHER.value:
                "Suspicious activity detected by automated ML screening; manual review required.",
        }
        cat_map_de = {
            SuspicionCategory.STRUCTURING.value:
                "Transaktionen strukturiert um unter der CHF 10'000-Meldeschwelle zu bleiben (Smurfing/Structuring).",
            SuspicionCategory.UNUSUAL_VELOCITY.value:
                "Abnormale Transaktionsgeschwindigkeit — deutlich über dem 30-Tage-Kontobasiswert.",
            SuspicionCategory.CASH_INTENSIVE.value:
                "Ungewöhnlich hoher Baranteil ohne erkennbaren geschäftlichen Zweck.",
            SuspicionCategory.SANCTIONS_EVASION.value:
                "Transaktion betrifft ein FATF-Hochrisiko- oder Sanktionsland.",
            SuspicionCategory.LAYERING.value:
                "Komplexes Layering-Muster — mehrere Überweisungen über Zwischenkonten.",
            SuspicionCategory.PEP_EXPOSURE.value:
                "Kontoinhaber als politisch exponierte Person (PEP) identifiziert.",
            SuspicionCategory.TERRORIST_FINANCE.value:
                "Indikatoren konsistent mit Terrorismusfinanzierungsmustern.",
            SuspicionCategory.OTHER.value:
                "Verdächtige Aktivität durch automatisiertes ML-Screening erkannt; manuelle Prüfung erforderlich.",
        }

        for cat in categories:
            if cat in cat_map_en:
                indicators_en.append(cat_map_en[cat])
                indicators_de.append(cat_map_de[cat])

        if scores.get("anomaly_score", 0) > 0.7:
            indicators_en.append(
                f"ML anomaly score: {scores['anomaly_score']:.2f}/1.00 (threshold: 0.70) — high confidence."
            )
            indicators_de.append(
                f"ML-Anomalie-Score: {scores['anomaly_score']:.2f}/1.00 (Schwelle: 0.70) — hohe Konfidenz."
            )

        total_amount = sum(t.amount for t in transactions)
        txn_count = len(transactions)
        currencies = list({t.currency for t in transactions})

        narrative_en = (
            f"This report is filed pursuant to {self.REGULATORY_REF}. "
            f"The financial intermediary has reasonable grounds to suspect money laundering activity "
            f"involving {txn_count} transaction(s) totalling {total_amount:,.2f} "
            f"{currencies[0] if len(currencies) == 1 else str(currencies)}. "
            f"Suspicion categories: {', '.join(categories)}. "
            f"The transactions were flagged by the institution's automated AML monitoring system "
            f"and confirmed by a compliance officer. "
            f"This report is submitted to: {self.MROS_RECIPIENT}."
        )
        narrative_de = (
            f"Diese Meldung erfolgt gemäß {self.REGULATORY_REF}. "
            f"Das Finanzinstitut hat begründeten Verdacht auf Geldwäscherei im Zusammenhang mit "
            f"{txn_count} Transaktion(en) im Gesamtbetrag von {total_amount:,.2f} "
            f"{currencies[0] if len(currencies) == 1 else str(currencies)}. "
            f"Verdachtskategorien: {', '.join(categories)}. "
            f"Die Transaktionen wurden durch das automatisierte AML-Monitoring-System des Instituts "
            f"markiert und von einem Compliance-Officer bestätigt. "
            f"Diese Meldung wird übermittelt an: {self.MROS_RECIPIENT}."
        )

        return narrative_en, narrative_de, indicators_en, indicators_de


# ── BaFin GwG §43 SAR Generator ──────────────────────────────────────────────

class BaFinReporter:
    """
    Generates BaFin-compliant Suspicious Activity Reports (Verdachtsmeldung).

    BaFin GwG §43:
    - Reports go to Financial Intelligence Unit (FIU) via goAML portal
    - Reporting deadline: immediately (unverzüglich)
    - Tipping-off prohibition: §47 GwG (Verbot der Informationsweitergabe)

    Reference: https://www.bafin.de/geldwaesche
    """

    REGULATORY_REF = "GwG §43 Abs. 1 — Pflicht zur Erstattung von Verdachtsmeldungen"
    FIU_RECIPIENT  = "Financial Intelligence Unit (FIU), Generalzolldirektion, Köln"
    PORTAL         = "goAML Web Portal (https://goaml.fiu.bund.de)"

    def generate_sar(
        self,
        alert_id: str,
        transactions: List[Dict[str, Any]],
        subject: Optional[Dict[str, Any]] = None,
        suspicion_categories: Optional[List[str]] = None,
        ml_scores: Optional[Dict[str, float]] = None,
        submitted_by: Optional[str] = None,
    ) -> ComplianceReport:
        """
        Generate a BaFin GwG §43 Suspicious Activity Report.

        Args and Returns: same structure as FINMAReporter.generate_str()
        """
        report_id = f"BAFIN-SAR-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        categories = suspicion_categories or [SuspicionCategory.OTHER.value]
        scores = ml_scores or {}

        txn_summaries = [
            TransactionSummary(
                transaction_id=t.get("transaction_id", "UNKNOWN"),
                amount=float(t.get("amount", 0)),
                currency=t.get("currency", "EUR"),
                transaction_type=t.get("transaction_type", "UNKNOWN"),
                timestamp=str(t.get("timestamp", datetime.now(timezone.utc).isoformat())),
                source_iban=t.get("source_iban"),
                source_country=t.get("source_country"),
                target_iban=t.get("target_iban"),
                target_country=t.get("target_country"),
                channel=t.get("channel"),
                description=t.get("description"),
                anomaly_score=scores.get("anomaly_score"),
                risk_score=scores.get("risk_score"),
            )
            for t in transactions
        ]

        subject_details = None
        if subject:
            subject_details = SubjectDetails(
                full_name=subject.get("full_name", "UNKNOWN"),
                date_of_birth=subject.get("date_of_birth"),
                nationality=subject.get("nationality"),
                country_of_residence=subject.get("country_of_residence"),
                id_type=subject.get("id_type"),
                id_number=subject.get("id_number"),
                account_id=subject.get("account_id"),
                iban=subject.get("iban"),
                kyc_category=subject.get("kyc_category", "STD"),
                pep_status=subject.get("pep_status", False),
                sanctions_hit=subject.get("sanctions_hit", False),
            )

        narrative_en, narrative_de, indicators_en, indicators_de = self._build_bafin_narrative(
            categories, txn_summaries, scores
        )

        suspicion = SuspicionIndicators(
            categories=categories,
            indicators_en=indicators_en,
            indicators_de=indicators_de,
            risk_score=scores.get("risk_score", 0.0),
            alert_ids=[alert_id],
            ml_confidence=scores.get("anomaly_score"),
        )

        report = ComplianceReport(
            report_id=report_id,
            report_type=ReportType.BAFIN_SAR.value,
            reporting_country="DE",
            regulatory_ref=self.REGULATORY_REF,
            subject=subject_details,
            transactions=txn_summaries,
            suspicion=suspicion,
            narrative_en=narrative_en,
            narrative_de=narrative_de,
            signed_by=submitted_by,
            signature_ts=datetime.now(timezone.utc).isoformat() if submitted_by else None,
        )
        report.report_hash = report.compute_hash()

        logger.info(
            "BaFin SAR generated",
            report_id=report_id,
            alert_id=alert_id,
            categories=categories,
        )
        return report

    def _build_bafin_narrative(
        self,
        categories: List[str],
        transactions: List[TransactionSummary],
        scores: Dict[str, float],
    ) -> tuple[str, str, List[str], List[str]]:
        """Generate BaFin-style bilingual narrative."""
        indicators_en: List[str] = []
        indicators_de: List[str] = []

        cat_de = {
            SuspicionCategory.STRUCTURING.value:
                "Strukturierung von Transaktionen unterhalb der EUR 10.000-Meldeschwelle nach §43 GwG.",
            SuspicionCategory.UNUSUAL_VELOCITY.value:
                "Ungewöhnliche Transaktionsfrequenz — signifikant über dem Kundenprofil.",
            SuspicionCategory.CASH_INTENSIVE.value:
                "Hoher Baranteil ohne plausible wirtschaftliche Erklärung.",
            SuspicionCategory.SANCTIONS_EVASION.value:
                "Transaktion involviert ein Sanktions- oder Hochrisikoland gemäß FATF.",
            SuspicionCategory.LAYERING.value:
                "Komplexes Transaktionsmuster konsistent mit dem Layering-Stadium der Geldwäsche.",
            SuspicionCategory.PEP_EXPOSURE.value:
                "Vertragspartner als politisch exponierte Person (PEP) gem. §1 Abs. 12 GwG eingestuft.",
            SuspicionCategory.OTHER.value:
                "Ungewöhnliche Transaktion durch automatisiertes AML-System gemeldet — manuelle Prüfung veranlasst.",
        }
        cat_en = {
            SuspicionCategory.STRUCTURING.value:
                "Transactions structured to avoid EUR 10,000 reporting threshold under §43 GwG.",
            SuspicionCategory.UNUSUAL_VELOCITY.value:
                "Unusual transaction frequency — significantly above customer profile baseline.",
            SuspicionCategory.CASH_INTENSIVE.value:
                "High proportion of cash transactions without plausible economic explanation.",
            SuspicionCategory.SANCTIONS_EVASION.value:
                "Transaction involves a sanctioned or FATF high-risk country.",
            SuspicionCategory.LAYERING.value:
                "Complex transaction pattern consistent with the layering stage of money laundering.",
            SuspicionCategory.PEP_EXPOSURE.value:
                "Contracting party classified as Politically Exposed Person (PEP) per §1(12) GwG.",
            SuspicionCategory.OTHER.value:
                "Unusual transaction flagged by automated AML system — manual review initiated.",
        }

        for cat in categories:
            indicators_de.append(cat_de.get(cat, f"Verdachtsindikator: {cat}"))
            indicators_en.append(cat_en.get(cat, f"Suspicion indicator: {cat}"))

        total = sum(t.amount for t in transactions)
        n = len(transactions)
        currencies = list({t.currency for t in transactions})
        cur = currencies[0] if len(currencies) == 1 else str(currencies)

        narrative_de = (
            f"Verdachtsmeldung gemäß {self.REGULATORY_REF}. "
            f"Das verpflichtete Unternehmen meldet {n} Transaktion(en) im Gesamtbetrag von "
            f"{total:,.2f} {cur} als verdächtig im Sinne des Geldwäschegesetzes. "
            f"Verdachtskategorien: {', '.join(categories)}. "
            f"Übermittlung erfolgt unverzüglich über das {self.PORTAL} an: {self.FIU_RECIPIENT}. "
            f"Hinweisgeberschutz und Informationsverbot gem. §47 GwG werden eingehalten."
        )
        narrative_en = (
            f"Suspicious activity report pursuant to {self.REGULATORY_REF}. "
            f"The obliged entity reports {n} transaction(s) totalling {total:,.2f} {cur} "
            f"as suspicious within the meaning of the German Anti-Money Laundering Act (GwG). "
            f"Suspicion categories: {', '.join(categories)}. "
            f"Submitted immediately via {self.PORTAL} to: {self.FIU_RECIPIENT}. "
            f"Non-disclosure requirements per §47 GwG are observed."
        )

        return narrative_en, narrative_de, indicators_en, indicators_de


# ── Module-level convenience ──────────────────────────────────────────────────

_finma_reporter = FINMAReporter()
_bafin_reporter = BaFinReporter()


def generate_finma_str(
    alert_id: str,
    transactions: List[Dict[str, Any]],
    subject: Optional[Dict[str, Any]] = None,
    categories: Optional[List[str]] = None,
    ml_scores: Optional[Dict[str, float]] = None,
    submitted_by: Optional[str] = None,
) -> ComplianceReport:
    """Convenience wrapper for FINMA GwG Art.9 STR generation."""
    return _finma_reporter.generate_str(
        alert_id=alert_id,
        transactions=transactions,
        subject=subject,
        suspicion_categories=categories,
        ml_scores=ml_scores,
        submitted_by=submitted_by,
    )


def generate_bafin_sar(
    alert_id: str,
    transactions: List[Dict[str, Any]],
    subject: Optional[Dict[str, Any]] = None,
    categories: Optional[List[str]] = None,
    ml_scores: Optional[Dict[str, float]] = None,
    submitted_by: Optional[str] = None,
) -> ComplianceReport:
    """Convenience wrapper for BaFin GwG §43 SAR generation."""
    return _bafin_reporter.generate_sar(
        alert_id=alert_id,
        transactions=transactions,
        subject=subject,
        suspicion_categories=categories,
        ml_scores=ml_scores,
        submitted_by=submitted_by,
    )

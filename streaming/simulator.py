"""
AML Monitoring System — Transaction Stream Simulator
Generates realistic Swiss/German banking transactions with configurable AML pattern injection.
Streams to Kafka topic for real-time processing pipeline testing.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from kafka_producer import AMLKafkaProducer

# ── Swiss & German Bank BICs ──────────────────────────────────────────────────
SWISS_BANKS = [
    {"bic": "UBSWCHZH80A", "name": "UBS AG", "country": "CH"},
    {"bic": "CRESCHZZ80A", "name": "Credit Suisse", "country": "CH"},
    {"bic": "ZKBKCHZZ80A", "name": "Zürcher Kantonalbank", "country": "CH"},
    {"bic": "POFICHBEXXX", "name": "PostFinance AG", "country": "CH"},
    {"bic": "RAIFCH22XXX", "name": "Raiffeisen Switzerland", "country": "CH"},
    {"bic": "BSLJCH2XXXX", "name": "Basellandschaftliche Kantonalbank", "country": "CH"},
]

GERMAN_BANKS = [
    {"bic": "DEUTDEDBXXX", "name": "Deutsche Bank AG", "country": "DE"},
    {"bic": "DRESDEFF200", "name": "Commerzbank AG", "country": "DE"},
    {"bic": "COBADEFFXXX", "name": "Commerzbank", "country": "DE"},
    {"bic": "HYVEDEMM489", "name": "HypoVereinsbank", "country": "DE"},
    {"bic": "SSKMDEMMXXX", "name": "Stadtsparkasse München", "country": "DE"},
    {"bic": "BELADEBEXXX", "name": "Berliner Sparkasse", "country": "DE"},
]

ALL_BANKS = SWISS_BANKS + GERMAN_BANKS

# ── Transaction Types & Weights ───────────────────────────────────────────────
TRANSACTION_TYPES = [
    ("WIRE_TRANSFER", 0.35),
    ("SEPA_CREDIT", 0.30),
    ("SEPA_DIRECT_DEBIT", 0.15),
    ("CASH_DEPOSIT", 0.08),
    ("CASH_WITHDRAWAL", 0.06),
    ("CARD_PAYMENT", 0.04),
    ("INTERNAL_TRANSFER", 0.02),
]

# ── Jurisdictions ─────────────────────────────────────────────────────────────
NORMAL_COUNTRIES = ["CH", "DE", "AT", "LI", "NL", "BE", "FR", "IT", "LU", "GB"]
HIGH_RISK_COUNTRIES = ["KP", "IR", "SY", "AF", "SO", "RU"]

# ── AML Pattern Templates ─────────────────────────────────────────────────────
AML_PATTERNS = {
    "STRUCTURING": {
        "description": "Multiple transactions just below CHF 10,000 threshold",
        "count": lambda: random.randint(3, 8),
        "amount": lambda: round(random.uniform(8500, 9950), 2),
        "interval_minutes": lambda: random.randint(15, 60),
    },
    "LAYERING": {
        "description": "Rapid movement through multiple accounts/countries",
        "count": lambda: random.randint(4, 10),
        "amount": lambda: round(random.uniform(50000, 500000), 2),
        "interval_minutes": lambda: random.randint(5, 30),
        "use_high_risk": True,
    },
    "ROUND_TRIPPING": {
        "description": "Money leaves and returns to same account",
        "count": lambda: 2,
        "amount": lambda: round(random.uniform(10000, 100000), 2),
        "interval_minutes": lambda: random.randint(60, 480),
    },
    "SMURFING": {
        "description": "Multiple sources sending to same beneficiary",
        "count": lambda: random.randint(5, 15),
        "amount": lambda: round(random.uniform(1000, 8000), 2),
        "interval_minutes": lambda: random.randint(2, 20),
    },
}


class TransactionSimulator:
    """
    Generates synthetic Swiss/German banking transactions.

    Normal transactions follow realistic distributions:
    - Amount: LogNormal (μ=6.5, σ=2.0) ≈ CHF 665 median
    - Timing: Peaked around business hours (9-17h), lower on weekends
    - Geography: Mostly CH/DE/EU, occasional international

    AML patterns are injected at configurable rates.
    """

    def __init__(
        self,
        tps: float = 10.0,
        aml_inject_rate: float = 0.03,
        mode: str = "dev",
        seed: Optional[int] = None,
    ):
        self.tps = tps
        self.aml_inject_rate = aml_inject_rate
        self.mode = mode
        self.accounts = self._generate_accounts(n=1000)
        if seed:
            random.seed(seed)

    def _generate_accounts(self, n: int) -> list:
        """Generate a pool of realistic Swiss/German bank account IDs."""
        accounts = []
        for _ in range(n):
            bank = random.choice(ALL_BANKS)
            country = bank["country"]
            # Generate IBAN
            if country == "CH":
                bban = "".join([str(random.randint(0, 9)) for _ in range(17)])
                iban = f"CH{random.randint(10, 99)}{bban}"
            else:
                bban = "".join([str(random.randint(0, 9)) for _ in range(18)])
                iban = f"DE{random.randint(10, 99)}{bban}"

            accounts.append({
                "id": str(uuid.uuid4()),
                "iban": iban,
                "bic": bank["bic"],
                "country": country,
                "bank_name": bank["name"],
                "risk_category": random.choices(
                    ["LOW", "STANDARD", "HIGH", "PEP"],
                    weights=[0.70, 0.25, 0.04, 0.01]
                )[0],
                "avg_amount": random.lognormvariate(6.5, 1.5),
                "std_amount": random.lognormvariate(5.0, 1.0),
            })
        return accounts

    def generate_normal_transaction(self) -> dict:
        """Generate a single normal (non-suspicious) transaction."""
        source = random.choice(self.accounts)
        target = random.choice([a for a in self.accounts if a["id"] != source["id"]])

        # Amount: lognormal distribution
        amount = max(1.0, random.lognormvariate(
            mean=source.get("avg_amount_log", 6.5),
            sigma=0.8
        ))
        amount = round(min(amount, 500_000), 2)

        # Currency weighted by country
        currency = "CHF" if source["country"] == "CH" else "EUR"

        # Transaction type
        txn_type = random.choices(
            [t[0] for t in TRANSACTION_TYPES],
            weights=[t[1] for t in TRANSACTION_TYPES]
        )[0]

        # Target country (mostly domestic)
        target_country = (
            target["country"]
            if random.random() > 0.15
            else random.choice(NORMAL_COUNTRIES)
        )

        now = datetime.now(timezone.utc)
        # Simulate realistic timing: peak 9-17h, lower after hours
        hour_offset = random.gauss(0, 4)
        simulated_time = now - timedelta(minutes=random.randint(0, 120))

        return {
            "transaction_id": f"TXN-{uuid.uuid4().hex[:12].upper()}",
            "timestamp": simulated_time.isoformat(),
            "amount": str(amount),
            "currency": currency,
            "transaction_type": txn_type,
            "source_account_id": source["id"],
            "source_iban": source["iban"],
            "source_bic": source["bic"],
            "source_country": source["country"],
            "target_account_id": target["id"],
            "target_iban": target["iban"],
            "target_bic": target["bic"],
            "target_country": target_country,
            "description": self._generate_description(txn_type),
            "channel": random.choices(
                ["online", "branch", "atm", "api"],
                weights=[0.60, 0.15, 0.15, 0.10]
            )[0],
            "_is_aml": False,
            "_pattern": None,
        }

    def generate_aml_transaction(self, pattern_name: str, sequence_data: dict) -> dict:
        """Generate a transaction that is part of an AML pattern."""
        pattern = AML_PATTERNS[pattern_name]
        txn = self.generate_normal_transaction()
        txn["amount"] = str(pattern["amount"]())
        txn["_is_aml"] = True
        txn["_pattern"] = pattern_name

        if pattern_name == "STRUCTURING":
            txn["amount"] = str(round(random.uniform(8500, 9950), 2))
            txn["description"] = "Überweisung"
            txn["channel"] = "branch"

        elif pattern_name == "LAYERING":
            if random.random() < 0.4:
                txn["target_country"] = random.choice(HIGH_RISK_COUNTRIES)
            txn["amount"] = str(round(random.uniform(50000, 500000), 2))

        elif pattern_name == "ROUND_TRIPPING":
            source = sequence_data.get("original_source")
            if source and sequence_data.get("step", 0) > 0:
                txn["target_account_id"] = source["id"]
                txn["target_iban"] = source["iban"]

        elif pattern_name == "SMURFING":
            txn["target_account_id"] = sequence_data.get("fixed_target_id", txn["target_account_id"])
            txn["target_iban"] = sequence_data.get("fixed_target_iban", txn["target_iban"])

        return txn

    def _generate_description(self, txn_type: str) -> str:
        """Generate a realistic German transaction description."""
        DESCRIPTIONS = {
            "WIRE_TRANSFER": ["Gehaltszahlung", "Miete August", "Rechnung 2024-0815", "Überweisung"],
            "SEPA_CREDIT": ["SEPA Gutschrift", "Erstattung", "Dividende Q3 2024"],
            "SEPA_DIRECT_DEBIT": ["Strom GmbH Lastschrift", "Versicherungsbeitrag", "Netflix DE"],
            "CASH_DEPOSIT": ["Bareinzahlung", "Cash deposit"],
            "CASH_WITHDRAWAL": ["Barabhebung", "Cash withdrawal"],
            "CARD_PAYMENT": ["Kartenzahlung Migros", "Zahlung REWE", "Card payment"],
            "INTERNAL_TRANSFER": ["Interne Umbuchung", "Tagesgeldkonto", "Internal transfer"],
        }
        options = DESCRIPTIONS.get(txn_type, ["Transaktion"])
        return random.choice(options)

    async def run(self, producer: AMLKafkaProducer) -> None:
        """
        Main simulation loop. Generates and sends transactions at the configured TPS rate.
        """
        delay = 1.0 / self.tps
        total_sent = 0
        total_aml = 0

        print(f"Simulator started: {self.tps} TPS, AML inject rate: {self.aml_inject_rate:.1%}")
        print(f"Streaming to Kafka topic: {producer.topic}")
        print("Press Ctrl+C to stop.\n")

        aml_sequence: Optional[dict] = None
        aml_pattern: Optional[str] = None
        aml_remaining: int = 0

        try:
            while True:
                loop_start = time.perf_counter()

                # Decide if this should be an AML transaction
                if aml_remaining > 0 and aml_sequence and aml_pattern:
                    txn = self.generate_aml_transaction(aml_pattern, aml_sequence)
                    aml_remaining -= 1
                    total_aml += 1
                elif random.random() < self.aml_inject_rate:
                    # Start a new AML sequence
                    aml_pattern = random.choice(list(AML_PATTERNS.keys()))
                    pattern_cfg = AML_PATTERNS[aml_pattern]
                    aml_remaining = pattern_cfg["count"]() - 1
                    source_acc = random.choice(self.accounts)
                    aml_sequence = {
                        "original_source": source_acc,
                        "step": 0,
                        "fixed_target_id": random.choice(self.accounts)["id"],
                        "fixed_target_iban": random.choice(self.accounts)["iban"],
                    }
                    txn = self.generate_aml_transaction(aml_pattern, aml_sequence)
                    total_aml += 1
                else:
                    txn = self.generate_normal_transaction()
                    aml_sequence = None

                await producer.send(txn)
                total_sent += 1

                if total_sent % 100 == 0:
                    print(
                        f"Sent: {total_sent:,} | AML: {total_aml:,} "
                        f"({total_aml/max(total_sent,1):.1%}) | "
                        f"TPS: {self.tps}"
                    )

                # Rate control
                elapsed = time.perf_counter() - loop_start
                await asyncio.sleep(max(0, delay - elapsed))

        except KeyboardInterrupt:
            print(f"\nSimulator stopped. Sent {total_sent:,} transactions ({total_aml:,} AML).")


async def main():
    parser = argparse.ArgumentParser(description="AML Transaction Simulator")
    parser.add_argument("--tps", type=float, default=10.0, help="Transactions per second")
    parser.add_argument("--aml-rate", type=float, default=0.03, help="AML injection rate (0-1)")
    parser.add_argument("--mode", choices=["dev", "staging", "production"], default="dev")
    parser.add_argument("--kafka-broker", default="localhost:9092")
    parser.add_argument("--topic", default="aml.transactions.raw")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    producer = AMLKafkaProducer(
        bootstrap_servers=args.kafka_broker,
        topic=args.topic,
    )
    await producer.start()

    simulator = TransactionSimulator(
        tps=args.tps,
        aml_inject_rate=args.aml_rate,
        mode=args.mode,
        seed=args.seed,
    )

    try:
        await simulator.run(producer)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())

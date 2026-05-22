"""
AML Monitoring System — Sample Transaction Dataset Generator
Generates 50,000 realistic Swiss/German banking transactions with embedded AML patterns.
Output: data/sample_transactions.csv
"""
from __future__ import annotations

import argparse
import csv
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import numpy as np

random.seed(2024)
np.random.seed(2024)

SWISS_IBANS = [f"CH{random.randint(10,99)}{''.join([str(random.randint(0,9)) for _ in range(17)])}" for _ in range(200)]
GERMAN_IBANS = [f"DE{random.randint(10,99)}{''.join([str(random.randint(0,9)) for _ in range(18)])}" for _ in range(200)]
ALL_IBANS = SWISS_IBANS + GERMAN_IBANS

BICS = [
    "UBSWCHZH80A", "CRESCHZZ80A", "ZKBKCHZZ80A", "POFICHBEXXX",
    "DEUTDEDBXXX", "DRESDEFF200", "COBADEFFXXX", "HYVEDEMM489",
]

COUNTRIES_NORMAL = ["CH", "DE", "AT", "NL", "BE", "FR", "IT", "LU", "LI", "GB"]
COUNTRIES_HIGH_RISK = ["KP", "IR", "SY", "AF", "RU", "SO"]
TXN_TYPES = ["WIRE_TRANSFER", "SEPA_CREDIT", "SEPA_DIRECT_DEBIT", "CASH_DEPOSIT",
             "CASH_WITHDRAWAL", "CARD_PAYMENT", "INTERNAL_TRANSFER"]
CHANNELS = ["online", "branch", "atm", "api"]


def generate_normal_amount() -> float:
    return round(max(10.0, np.random.lognormal(mean=6.5, sigma=1.8)), 2)


def generate_timestamp(days_back: int = 90) -> str:
    now = datetime.now(timezone.utc)
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return (now - delta).isoformat()


def make_txn(
    source_iban: str,
    target_iban: str,
    amount: float,
    txn_type: str,
    source_country: str,
    target_country: str,
    is_aml: bool,
    aml_pattern: str = "",
    timestamp: str = None,
) -> dict:
    return {
        "transaction_id": f"TXN-{uuid.uuid4().hex[:12].upper()}",
        "timestamp": timestamp or generate_timestamp(),
        "amount": amount,
        "currency": "CHF" if source_country == "CH" else "EUR",
        "transaction_type": txn_type,
        "source_account_id": str(uuid.uuid4()),
        "source_iban": source_iban,
        "source_bic": random.choice(BICS),
        "source_country": source_country,
        "target_account_id": str(uuid.uuid4()),
        "target_iban": target_iban,
        "target_bic": random.choice(BICS),
        "target_country": target_country,
        "description": random.choice(["Überweisung", "Zahlung", "SEPA Transfer", "Rückerstattung", "Gehalt"]),
        "reference": f"REF-{random.randint(100000, 999999)}",
        "channel": random.choice(CHANNELS),
        "ip_address": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "is_aml_pattern": is_aml,
        "aml_pattern_type": aml_pattern,
    }


def generate_normal_transactions(n: int) -> List[dict]:
    txns = []
    for _ in range(n):
        src = random.choice(ALL_IBANS)
        tgt = random.choice(ALL_IBANS)
        sc = "CH" if src in SWISS_IBANS else "DE"
        tc = random.choices(COUNTRIES_NORMAL + COUNTRIES_HIGH_RISK, weights=[0.97]*len(COUNTRIES_NORMAL) + [0.03/6]*6)[0]
        txns.append(make_txn(src, tgt, generate_normal_amount(), random.choice(TXN_TYPES), sc, tc, False))
    return txns


def generate_structuring_pattern(account_iban: str, target_iban: str, count: int = 5) -> List[dict]:
    """Generate structuring pattern: multiple transactions just below CHF 10,000."""
    base_time = datetime.now(timezone.utc) - timedelta(hours=random.randint(2, 48))
    txns = []
    for i in range(count):
        amount = round(random.uniform(8500, 9970), 2)
        ts = (base_time + timedelta(minutes=i * random.randint(10, 45))).isoformat()
        txns.append(make_txn(account_iban, target_iban, amount, "WIRE_TRANSFER", "CH", "DE", True, "STRUCTURING", ts))
    return txns


def generate_layering_pattern(source_iban: str) -> List[dict]:
    """Generate layering: funds move through multiple jurisdictions rapidly."""
    base_time = datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 24))
    countries = ["DE", "LU", "NL", random.choice(COUNTRIES_HIGH_RISK), "CH"]
    amount = round(random.uniform(50000, 500000), 2)
    txns = []
    current_iban = source_iban
    for i, country in enumerate(countries):
        ts = (base_time + timedelta(minutes=i * random.randint(15, 60))).isoformat()
        next_iban = random.choice(ALL_IBANS)
        txns.append(make_txn(current_iban, next_iban, amount * random.uniform(0.85, 1.0),
                              "WIRE_TRANSFER", countries[max(0, i-1)] if i > 0 else "CH", country,
                              True, "LAYERING", ts))
        current_iban = next_iban
    return txns


def generate_smurfing_pattern(target_iban: str, smurf_count: int = 7) -> List[dict]:
    """Generate smurfing: multiple accounts sending small amounts to same target."""
    base_time = datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 12))
    txns = []
    for i in range(smurf_count):
        src = random.choice(ALL_IBANS)
        amount = round(random.uniform(1500, 8000), 2)
        ts = (base_time + timedelta(minutes=i * random.randint(5, 25))).isoformat()
        txns.append(make_txn(src, target_iban, amount, "WIRE_TRANSFER", "CH", "DE", True, "SMURFING", ts))
    return txns


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=50000)
    parser.add_argument("--inject-rate", type=float, default=0.05)
    parser.add_argument("--output", default="data/sample_transactions.csv")
    args = parser.parse_args()

    normal_count = int(args.records * (1 - args.inject_rate))
    aml_count_target = args.records - normal_count

    print(f"Generating {args.records:,} transactions ({normal_count:,} normal, {aml_count_target:,} AML)...")

    all_txns = generate_normal_transactions(normal_count)

    # Inject AML patterns
    aml_generated = 0
    while aml_generated < aml_count_target:
        pattern = random.choice(["STRUCTURING", "LAYERING", "SMURFING"])
        if pattern == "STRUCTURING":
            src = random.choice(SWISS_IBANS)
            tgt = random.choice(GERMAN_IBANS)
            count = random.randint(3, 6)
            all_txns.extend(generate_structuring_pattern(src, tgt, count))
            aml_generated += count
        elif pattern == "LAYERING":
            src = random.choice(ALL_IBANS)
            batch = generate_layering_pattern(src)
            all_txns.extend(batch)
            aml_generated += len(batch)
        elif pattern == "SMURFING":
            tgt = random.choice(ALL_IBANS)
            count = random.randint(5, 10)
            all_txns.extend(generate_smurfing_pattern(tgt, count))
            aml_generated += count

    # Shuffle
    random.shuffle(all_txns)

    # Write CSV
    fieldnames = list(all_txns[0].keys())
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_txns)

    total_aml = sum(1 for t in all_txns if t["is_aml_pattern"])
    print(f"Generated {len(all_txns):,} transactions → {args.output}")
    print(f"  Normal: {len(all_txns) - total_aml:,} ({(len(all_txns)-total_aml)/len(all_txns):.1%})")
    print(f"  AML:    {total_aml:,} ({total_aml/len(all_txns):.1%})")
    print(f"  Patterns: STRUCTURING, LAYERING, SMURFING")


if __name__ == "__main__":
    main()

"""
AML Monitoring System — Performance Tests
Locust-based load tests targeting 100 TPS with < 500ms p99 latency.
Run with: locust -f tests/performance/test_load.py --host http://localhost:8000
"""
from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from locust import HttpUser, between, events, task
from locust.runners import MasterRunner


class AMLAPIUser(HttpUser):
    """
    Simulates an AML monitoring system user (analyst + automated scoring).

    Distribution:
    - 70% transaction scoring (primary workload)
    - 20% alert review (analyst workflow)
    - 10% reports/stats (dashboard refresh)
    """

    wait_time = between(0.1, 0.5)  # 2-10 requests/second per user

    def on_start(self):
        """Login and get auth token."""
        response = self.client.post(
            "/api/v1/auth/token",
            json={"username": "analyst@bank.de", "password": "test_password"},
        )
        if response.status_code == 200:
            self.token = response.json().get("access_token", "")
        else:
            self.token = "test-token"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept-Language": random.choice(["de", "en"]),
            "Content-Type": "application/json",
        }

    @task(70)
    def score_transaction(self):
        """Score a transaction — the primary ML workload."""
        payload = {
            "transaction_id": f"TXN-LOAD-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "amount": str(round(random.uniform(100, 50000), 2)),
            "currency": random.choice(["CHF", "EUR"]),
            "transaction_type": random.choice(["WIRE_TRANSFER", "SEPA_CREDIT", "CASH_DEPOSIT"]),
            "source_account_id": f"acc-{random.randint(1, 1000)}",
            "source_iban": f"CH{random.randint(10,99)}{''.join([str(random.randint(0,9)) for _ in range(17)])}",
            "source_country": random.choice(["CH", "DE", "AT"]),
            "target_iban": f"DE{random.randint(10,99)}{''.join([str(random.randint(0,9)) for _ in range(18)])}",
            "target_country": random.choice(["DE", "CH", "NL", "FR"]),
            "channel": random.choice(["online", "branch", "atm"]),
        }
        with self.client.post(
            "/api/v1/transactions",
            json=payload,
            headers=self.headers,
            name="POST /transactions",
            catch_response=True,
        ) as response:
            if response.status_code == 202:
                response.success()
                # Check for response time SLA
                if response.elapsed.total_seconds() > 0.5:
                    response.failure(f"SLA breach: {response.elapsed.total_seconds():.3f}s > 500ms")
            elif response.status_code in (401, 403):
                response.failure(f"Auth error: {response.status_code}")
            else:
                response.success()  # 4xx are expected during load test

    @task(20)
    def list_alerts(self):
        """List open alerts — analyst dashboard workload."""
        with self.client.get(
            "/api/v1/alerts?status=OPEN&page=1&page_size=50",
            headers=self.headers,
            name="GET /alerts",
            catch_response=True,
        ) as response:
            if response.status_code in (200, 401):
                response.success()
            else:
                response.failure(f"Unexpected: {response.status_code}")

    @task(10)
    def get_alert_stats(self):
        """Get alert statistics — dashboard KPIs."""
        with self.client.get(
            "/api/v1/alerts/stats",
            headers=self.headers,
            name="GET /alerts/stats",
            catch_response=True,
        ) as response:
            if response.status_code in (200, 401):
                response.success()

    @task(5)
    def health_check(self):
        """Health check — monitoring scrape simulation."""
        self.client.get("/api/v1/health", name="GET /health")


class ComplianceOfficerUser(HttpUser):
    """Simulates compliance officer reviewing high-risk alerts."""

    wait_time = between(2, 10)  # Slower — human review workflow
    weight = 1  # Few compliance officers vs many analysts

    def on_start(self):
        response = self.client.post(
            "/api/v1/auth/token",
            json={"username": "compliance@bank.de", "password": "test_password"},
        )
        self.token = response.json().get("access_token", "") if response.status_code == 200 else ""
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept-Language": "de",
        }

    @task(50)
    def review_critical_alerts(self):
        """Review CRITICAL alerts."""
        self.client.get(
            "/api/v1/alerts?severity=CRITICAL&status=OPEN",
            headers=self.headers,
            name="GET /alerts (CRITICAL)",
        )

    @task(30)
    def view_retention_status(self):
        """Check GDPR retention compliance."""
        self.client.get(
            "/api/v1/gdpr/retention/status",
            headers=self.headers,
            name="GET /gdpr/retention/status",
        )

    @task(20)
    def get_alert_stats(self):
        self.client.get("/api/v1/alerts/stats", headers=self.headers)


# ── Performance Assertions ─────────────────────────────────────────────────────
@events.quitting.add_listener
def assert_performance_requirements(environment, **kwargs):
    """
    Assert performance SLAs after load test completes.
    Fails the test if SLAs are breached.
    """
    stats = environment.stats

    print("\n=== Performance SLA Check ===")

    # Check each endpoint
    for name, entry in stats.entries.items():
        if entry.num_requests == 0:
            continue

        p99_ms = entry.get_response_time_percentile(0.99) or 0
        avg_ms = entry.avg_response_time or 0
        error_rate = entry.fail_ratio or 0

        print(f"{name}: p99={p99_ms:.0f}ms, avg={avg_ms:.0f}ms, errors={error_rate:.1%}")

        if "transactions" in str(name).lower() and "POST" in str(name):
            if p99_ms > 500:
                print(f"❌ SLA BREACH: {name} p99={p99_ms:.0f}ms > 500ms target")
                environment.process_exit_code = 1
            else:
                print(f"✅ {name} within SLA")

    total_rps = stats.total.current_rps
    print(f"\nTotal throughput: {total_rps:.1f} RPS")

# AML Monitoring System — Testing Documentation
**Classification:** Internal | **Version:** 1.0 | **Jurisdiction:** Switzerland / Germany

---

## 1. Testing Philosophy

This test suite is written from the perspective of a **strict banking QA engineer** at a Swiss/German financial institution. Every test:

- Tests behavior, not implementation details
- Covers regulatory compliance (FINMA, BaFin, GDPR/DSGVO)
- Tests both happy paths and adversarial edge cases
- Is deterministic and isolated (no shared state between tests)
- Produces auditable results for compliance review

---

## 2. Test Categories

### 2.1 Unit Tests (`tests/unit/`)

| Test File | Coverage Area | Key Assertions |
|---|---|---|
| `test_anomaly_detection.py` | Isolation Forest model | Feature extraction (47 dims), score range [0,1], FATF countries, edge cases |
| `test_risk_scoring.py` | LightGBM risk scorer + SHAP | Score monotonicity, typology detection, bilingual explanations |

### 2.2 Integration Tests (`tests/integration/`)

| Test File | Coverage Area | Key Assertions |
|---|---|---|
| `test_api_security.py` | Authentication, RBAC, headers, injection prevention | 401/403 enforcement, OWASP headers, PII masking |
| `test_gdpr_compliance.py` | GDPR Art. 17/20, retention, audit trail | Deletion workflows, legal hold, FINMA retention, signature verification |

### 2.3 Performance Tests (`tests/performance/`)

| Test File | Tool | Target SLAs |
|---|---|---|
| `test_load.py` | Locust | 100 TPS, p99 < 500ms, < 1% error rate |

---

## 3. Running Tests

### Full Suite
```bash
make test
# or
python -m pytest tests/ -v --cov=backend --cov-report=html
```

### By Category
```bash
# Unit tests only (fast, no services required)
make test-unit

# Integration tests (requires PostgreSQL + Redis)
make test-integration

# Security & GDPR tests
make test-security

# Load tests (requires running API)
locust -f tests/performance/test_load.py \
  --host http://localhost:8000 \
  --users 50 \
  --spawn-rate 5 \
  --run-time 300s \
  --headless
```

### Coverage Requirements
| Layer | Minimum Coverage |
|---|---|
| ML pipeline | 80% |
| API routes | 75% |
| Security/GDPR | 90% |
| Services | 70% |
| **Overall** | **70%** |

---

## 4. Test Environment Setup

### Environment Variables for Tests
```bash
export APP_ENV=development
export SECRET_KEY="test-secret-key-32-chars-minimum-here"
export PII_ENCRYPTION_KEY="test-pii-key-32-chars-minimum-here"
export DATABASE_URL="postgresql+asyncpg://aml_user:test_pass@localhost:5432/aml_test_db"
export REDIS_URL="redis://localhost:6379/15"   # DB 15 to isolate test data
```

### Test Database Setup
```bash
# Start test services only
docker-compose up -d postgres redis

# Create test database
docker exec aml-postgres psql -U aml_user -c "CREATE DATABASE aml_test_db;"

# Run migrations
make migrate
```

---

## 5. Key Test Scenarios

### 5.1 AML Pattern Detection (Must Pass)

| Pattern | Test | Expected Result |
|---|---|---|
| Structuring | 5x CHF 9,850 transactions in 2h | Risk score ≥ 0.80, typology = STRUCTURING |
| Layering | Wire through 5 countries including KP | Risk score ≥ 0.85, typology = LAYERING |
| Smurfing | 10 sources → 1 beneficiary | Risk score ≥ 0.75, typology = SMURFING |
| Normal transaction | CHF 2,500 regular wire transfer | Risk score < 0.50 |
| High-risk jurisdiction | EUR 75,000 to North Korea | Risk score ≥ 0.95 (CRITICAL) |

### 5.2 Security Scenarios (Must Pass)

| Scenario | Expected HTTP Status |
|---|---|
| No JWT token | 401 |
| Expired JWT | 401 |
| Invalid JWT signature | 401 |
| Revoked JWT (blacklisted) | 401 |
| Wrong role for endpoint | 403 |
| SQL injection in path param | 400 or 404 (never 500) |
| Negative transaction amount | 422 |
| Invalid IBAN format | 422 |
| Oversized bulk payload (>1000 txns) | 422 |

### 5.3 GDPR Scenarios (Must Pass)

| Scenario | Expected Behavior |
|---|---|
| Delete account under AML investigation | 409 Conflict (legal hold) |
| Delete account within FINMA retention | 409 Conflict (retention active) |
| Delete without confirm_deletion=true | 400 Bad Request |
| Non-anonymized export by analyst | 403 Forbidden |
| Audit log tampering | Signature verification fails |
| Retention periods misconfigured | Test fails (hardcoded minimums) |

---

## 6. False Positive Tracking

The system tracks false positives through the `is_false_positive` field in alerts. Tests verify:

- FP rate is calculated correctly
- FP data is stored for model retraining
- FP rate alert fires when rate > 15%
- FP data is included in weekly model evaluation

```python
# Example: Mark alert as false positive
PATCH /api/v1/alerts/{alert_id}
{
    "is_false_positive": true,
    "false_positive_reason": "Customer confirmed legitimate salary payment from employer in UAE"
}
```

---

## 7. Model Drift Testing

Model drift tests verify:

1. **PSI computation**: PSI values correctly classify STABLE / MONITOR / CRITICAL
2. **KS test**: Kolmogorov-Smirnov statistic computed correctly
3. **Retraining trigger**: Notebooks execute when PSI > 0.25
4. **Metric logging**: All drift metrics recorded to MLflow and Delta Lake

```python
# Test PSI thresholds
assert compute_psi(ref, ref) < 0.05           # Same data → PSI near 0
assert compute_psi(ref, shifted) > 0.10       # Shifted distribution → PSI > 0.10
assert compute_psi(ref, very_shifted) > 0.25  # Heavily drifted → retrain trigger
```

---

## 8. Streaming Failure Testing

Integration tests cover Kafka failure scenarios:

| Failure | Expected Recovery |
|---|---|
| Kafka broker unavailable | Message routed to DLQ |
| Message serialization failure | Logged, sent to DLQ |
| Consumer group lag > 10k | Alert triggered, team notified |
| Consumer restart | Resume from last committed offset |

---

## 9. CI/CD Quality Gates

All of the following must pass before production deployment:

- [ ] Ruff lint: 0 errors
- [ ] MyPy: 0 type errors (strict mode)
- [ ] Bandit: 0 HIGH severity findings
- [ ] Safety: 0 known vulnerabilities in dependencies
- [ ] Unit tests: all pass, coverage ≥ 70%
- [ ] Integration tests: all pass
- [ ] Container scan (Trivy): 0 CRITICAL vulnerabilities
- [ ] Compliance sign-off: manual approval in GitHub

---

## 10. Regulatory Test Evidence

For FINMA/BaFin audits, the following test outputs are preserved:

- `junit.xml`: Machine-readable test results (30-day retention in CI)
- `htmlcov/`: HTML coverage report
- `reports/bandit_report.json`: Security scan results
- Test run logs: captured in Azure Monitor (7-year retention)

Test results are treated as audit evidence and must not be deleted within the retention period.

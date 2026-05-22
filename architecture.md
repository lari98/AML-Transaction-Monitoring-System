# System Architecture — AML Transaction Monitoring System
**Version:** 1.0 | **Classification:** Internal – Confidential | **Jurisdiction:** Switzerland / Germany

---

## 1. High-Level Architecture

The platform follows a **lambda-architecture** hybrid pattern: a high-throughput streaming path for real-time detection and a batch path for model retraining, regulatory reporting, and deep-pattern analysis.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          DATA SOURCES                                    │
│  Core Banking  │  SWIFT/SEPA  │  Card Networks  │  External Watchlists   │
└────────┬───────────────┬──────────────┬─────────────────┬───────────────┘
         │               │              │                 │
         ▼               ▼              ▼                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     INGESTION LAYER (Azure Data Factory)                 │
│         Batch jobs │ CDC connectors │ REST webhooks │ File drops         │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │     Apache Kafka Cluster      │
                    │  Topics:                      │
                    │  • aml.transactions.raw       │
                    │  • aml.transactions.scored    │
                    │  • aml.alerts.realtime        │
                    │  • aml.audit.events           │
                    └──────────┬──────────┬─────────┘
                               │          │
              ┌────────────────▼──┐  ┌────▼────────────────────┐
              │  SPEED PATH       │  │  BATCH PATH              │
              │  Spark Streaming  │  │  Databricks Jobs         │
              │  • Real-time score│  │  • Feature engineering   │
              │  • Alert trigger  │  │  • Model retraining      │
              │  • Live dashboard │  │  • Regulatory reports    │
              └────────┬──────────┘  └──────────────────────────┘
                       │
         ┌─────────────▼──────────────────────────────────┐
         │              ML INFERENCE ENGINE                 │
         │                                                  │
         │  ┌─────────────────┐  ┌───────────────────────┐ │
         │  │ Anomaly Detector │  │ Clustering Engine     │ │
         │  │ (Isolation      │  │ (DBSCAN + HDBSCAN)    │ │
         │  │  Forest)        │  │                       │ │
         │  └────────┬────────┘  └────────────┬──────────┘ │
         │           │                        │             │
         │  ┌────────▼────────────────────────▼──────────┐ │
         │  │           Risk Scorer (GBM + SHAP)          │ │
         │  │   Score: 0.0–1.0 │ Confidence │ Explanation │ │
         │  └────────────────────────────────────────────┘ │
         └─────────────────────────┬──────────────────────┘
                                   │
         ┌─────────────────────────▼──────────────────────────┐
         │                FastAPI Backend                       │
         │                                                      │
         │  /api/v1/transactions  /api/v1/alerts                │
         │  /api/v1/accounts      /api/v1/reports               │
         │  /api/v1/gdpr          /api/v1/admin                 │
         │                                                      │
         │  ├── JWT Auth + RBAC                                 │
         │  ├── PII Masking Middleware                          │
         │  ├── Audit Logging (immutable)                       │
         │  └── Multilingual (DE/EN)                           │
         └──────────────┬─────────────────────────────────────┘
                        │
         ┌──────────────┼──────────────────────────────────────┐
         │              │                                        │
         ▼              ▼                                        ▼
   ┌───────────┐  ┌───────────────┐                    ┌──────────────┐
   │PostgreSQL │  │  Redis Cache  │                    │ Azure Blob   │
   │(Alerts,   │  │  (Sessions,   │                    │ Storage      │
   │ Accounts, │  │   Rate limits,│                    │ (Raw txns,   │
   │ Audit)    │  │   Model cache)│                    │  Reports)    │
   └───────────┘  └───────────────┘                    └──────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                              │
│                                                                        │
│  ┌─────────────────────┐   ┌──────────────────────────────────────┐  │
│  │   Power BI Service  │   │   Grafana + Prometheus               │  │
│  │  • Suspicious accts │   │  • API latency & throughput          │  │
│  │  • AML alert trends │   │  • Model drift (PSI)                 │  │
│  │  • Regional heatmap │   │  • False positive rate               │  │
│  │  • Confidence dist. │   │  • Alert volume by region            │  │
│  │  • Operational KPIs │   │  • GDPR deletion queue               │  │
│  └─────────────────────┘   └──────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. ML Model Architecture

### 2.1 Anomaly Detection (Isolation Forest)
- **Algorithm:** Isolation Forest with `n_estimators=200`, `contamination=0.05`
- **Features:** 47 engineered features (velocity, amount ratios, geo-patterns, time-of-day, counterparty concentration)
- **Output:** Anomaly score `[-1, 1]` → normalized to `[0, 1]`
- **Threshold:** Configurable per risk appetite (default: 0.65)
- **Retraining:** Weekly, triggered by PSI > 0.25 or F1 drop > 5%

### 2.2 Behavioral Clustering (DBSCAN)
- **Algorithm:** DBSCAN with `eps=0.5`, `min_samples=10`
- **Purpose:** Group accounts into behavioral clusters; detect cluster-shift
- **Output:** Cluster ID + cluster risk rating
- **AML Patterns Detected:**
  - Structuring (Smurfing): multiple sub-threshold transactions
  - Layering: rapid fund movement across accounts
  - Integration: large one-time deposits post-layering
  - Round-tripping: funds looped through shell entities

### 2.3 Risk Scorer (Gradient Boosting + SHAP)
- **Algorithm:** LightGBM with monotone constraints for regulatory interpretability
- **Input:** Anomaly score + cluster label + 47 behavioral features
- **Output:** Risk score `[0.0, 1.0]` + confidence interval + top-10 SHAP features
- **Thresholds:**
  - LOW: `< 0.50`
  - MEDIUM: `0.50–0.79`
  - HIGH: `0.80–0.94`
  - CRITICAL: `≥ 0.95`

### 2.4 Explainability (SHAP)
Every flagged transaction receives a human-readable explanation in DE/EN:

```json
{
  "risk_score": 0.87,
  "risk_level": "HIGH",
  "confidence": 0.92,
  "explanation_de": "Transaktion wurde markiert aufgrund: (1) Ungewöhnlich hoher Betrag für diesen Kunden, (2) Erste Transaktion in diese Jurisdiktion, (3) Strukturierungsmuster erkannt.",
  "explanation_en": "Transaction flagged due to: (1) Unusually high amount for this customer, (2) First transaction to this jurisdiction, (3) Structuring pattern detected.",
  "top_features": [
    {"feature": "amount_vs_30d_avg", "impact": 0.42, "value": 12.3},
    {"feature": "jurisdiction_risk", "impact": 0.31, "value": "HIGH"},
    {"feature": "txn_velocity_24h", "impact": 0.19, "value": 7}
  ]
}
```

---

## 3. Data Flow

### 3.1 Real-Time Path (< 500ms SLA)
```
Transaction received → Kafka topic → Spark Streaming consumer
→ Feature extraction (47 features, ~80ms)
→ Isolation Forest score (~30ms)
→ DBSCAN cluster lookup (~10ms)
→ Risk scorer + SHAP explanation (~150ms)
→ Decision: PASS / FLAG / BLOCK
→ If flagged: write alert to PostgreSQL + push to Kafka alerts topic
→ WebSocket push to dashboard
→ Email/PagerDuty notification if CRITICAL
Total: ~350ms avg, ~500ms p99
```

### 3.2 Batch Path (nightly)
```
Delta Lake raw transactions
→ Feature engineering (Spark)
→ Model evaluation (PSI, F1, precision/recall)
→ Conditional retraining if drift detected
→ MLflow model promotion (Staging → Production)
→ Regulatory report generation (SAR, CTR)
→ Power BI dataset refresh
```

---

## 4. Security Architecture

### 4.1 Authentication & Authorization
- **Identity Provider:** Azure Active Directory (SAML 2.0 / OIDC)
- **API Auth:** JWT Bearer tokens (RS256, 60-min expiry)
- **RBAC Roles:** `compliance_officer`, `aml_analyst`, `risk_manager`, `auditor`, `data_admin`, `readonly`
- **MFA:** Required for all compliance_officer and data_admin roles
- **API Rate Limiting:** 100 req/min per user, 10k/min per IP (Redis-backed)

### 4.2 Data Protection
- **PII at Rest:** AES-256-GCM (Azure Key Vault managed keys)
- **PII in Transit:** TLS 1.3 minimum
- **PII in Logs:** Automatically masked (regex patterns for IBAN, name, DOB)
- **PII in API:** Returned masked unless role = `compliance_officer`
- **Encryption Keys:** Rotated every 90 days; stored in Azure Key Vault

### 4.3 Network Security
- **API Gateway:** Azure API Management (WAF enabled)
- **VNet:** All services in private VNet, no public endpoints
- **NSG:** Allow-list only; deny-all default
- **Bastion:** Azure Bastion for management access (no SSH direct)

---

## 5. GDPR / DSGVO Compliance

| Requirement | Implementation |
|---|---|
| **Data Minimisation** | Only transaction data required by AML law is stored |
| **Purpose Limitation** | AML monitoring only; separate consent for analytics |
| **Right to Erasure** | `DELETE /api/v1/gdpr/delete/{account_id}` — 24h SLA |
| **Data Portability** | `GET /api/v1/gdpr/export/{account_id}` — anonymized JSON |
| **Audit Trail** | Immutable append-only log; signed with HMAC-SHA256 |
| **Retention** | Transactions: 10y (FINMA); Logs: 7y; Profiles: 5y after closure |
| **PII Masking** | Applied at ingestion; reversible only with compliance_officer role |
| **Third-Party Sharing** | Prohibited without explicit consent; logged when mandated by law |
| **DPA** | Data Processing Agreement with all Azure sub-processors |

---

## 6. Monitoring & Observability

### Metrics (Prometheus)
- `aml_transactions_processed_total` — counter by status
- `aml_model_inference_duration_seconds` — histogram
- `aml_alerts_generated_total` — counter by risk level
- `aml_false_positive_rate` — gauge
- `aml_model_psi_score` — gauge (Population Stability Index)
- `aml_api_requests_total` — counter by endpoint + status

### Alerts (Alertmanager → PagerDuty)
| Alert | Condition | Severity |
|---|---|---|
| High false-positive rate | FP rate > 15% | Warning |
| Model drift detected | PSI > 0.25 | Critical |
| Streaming lag | Kafka consumer lag > 10k messages | Critical |
| CRITICAL AML alert | Risk score ≥ 0.95 | Page immediately |
| GDPR deletion SLA | Pending deletions > 24h | Warning |
| API error rate | 5xx rate > 1% | Critical |

---

## 7. Azure Infrastructure

```
Resource Group: rg-aml-monitoring-prod
│
├── Azure Kubernetes Service (AKS)          — API + streaming containers
├── Azure Databricks Workspace              — ML training + batch jobs
├── Azure Event Hubs / Kafka               — Transaction streaming
├── Azure Database for PostgreSQL           — Flexible Server (HA)
├── Azure Cache for Redis                  — Sessions, rate limiting
├── Azure Blob Storage                     — Raw transaction archive
├── Azure Key Vault                        — Secrets, encryption keys
├── Azure Container Registry              — Docker images
├── Azure API Management                  — Gateway + WAF
├── Azure Monitor + Log Analytics         — Observability
├── Azure Active Directory                — Identity + RBAC
└── Azure Data Factory                    — Batch ingestion pipelines
```

---

## 8. Disaster Recovery

| Component | RPO | RTO | Strategy |
|---|---|---|---|
| PostgreSQL | 5 min | 15 min | Azure HA + geo-replication |
| Kafka | 0 | 5 min | Multi-broker, 3x replication |
| ML Models | 24h | 1h | MLflow registry + Azure Blob backup |
| API Service | 0 | 2 min | AKS + HPA auto-scaling |
| Blob Storage | 0 | Instant | ZRS (Zone-Redundant Storage) |

**RTO target:** 15 minutes for full platform recovery
**RPO target:** 5 minutes maximum data loss

---

## 9. Deployment Pipeline

```
Developer push → GitHub Actions CI:
  ├── Lint (ruff) + Type check (mypy)
  ├── Security scan (bandit + safety)
  ├── Unit tests (pytest)
  ├── Integration tests (docker-compose test env)
  ├── Container build + scan (Trivy)
  └── Push to Azure Container Registry

Main branch merge → CD:
  ├── Deploy to Staging (auto)
  ├── Smoke tests + API contract tests
  ├── Manual approval gate (compliance sign-off)
  └── Deploy to Production (blue-green, zero downtime)
```

---

*Document Owner: AML Technology Team | Review Cycle: Quarterly | Next Review: Q3 2026*

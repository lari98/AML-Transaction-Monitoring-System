# AML Transaction Monitoring System
### Production-Grade Anti-Money Laundering Platform for Swiss & German Banking
**Built to UBS / SIX Group Standards | FINMA & BaFin Compliant | GDPR/DSGVO Ready**

---

## Overview

The **AML Transaction Monitoring System** is an enterprise AI platform designed for Swiss and German financial institutions to detect, score, explain, and report suspicious financial activity in real time. It combines streaming transaction ingestion, machine learning–based anomaly detection, explainable AI risk scoring, and multilingual (German/English) compliance dashboards into a single unified platform.

This system is modeled after platforms used at **UBS**, **Deutsche Bank**, **SIX Group**, and **Commerzbank** — built for production deployment on Microsoft Azure with Databricks ML.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AML Monitoring Platform                          │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  Transaction │───▶│    Kafka     │───▶│  Databricks Spark    │  │
│  │  Simulator   │    │  Streaming   │    │  Stream Processing   │  │
│  └──────────────┘    └──────────────┘    └──────────┬───────────┘  │
│                                                     │              │
│  ┌──────────────────────────────────────────────────▼───────────┐  │
│  │                    ML Pipeline (MLflow)                       │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │  │
│  │  │  Isolation  │  │    DBSCAN    │  │   Risk Scorer +    │  │  │
│  │  │   Forest    │  │  Clustering  │  │   SHAP Explainer   │  │  │
│  │  └─────────────┘  └──────────────┘  └────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│  ┌───────────────────────────▼──────────────────────────────────┐  │
│  │               FastAPI Backend (REST + WebSocket)             │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │  │
│  │  │  Alerts  │  │  GDPR/   │  │  Audit   │  │  Reports   │  │  │
│  │  │   API    │  │  Delete  │  │   Log    │  │    API     │  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│  ┌───────────────┐   ┌───────▼──────────┐   ┌─────────────────┐   │
│  │  Azure Blob   │   │   Power BI       │   │  Prometheus +   │   │
│  │  Storage      │   │  Dashboards      │   │  Grafana        │   │
│  └───────────────┘   └──────────────────┘   └─────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
aml-monitoring-system/
├── backend/                        # FastAPI application
│   ├── api/v1/                     # REST API endpoints
│   │   ├── transactions.py         # Transaction ingestion & scoring
│   │   ├── alerts.py               # AML alert management
│   │   ├── accounts.py             # Account risk profiles
│   │   ├── reports.py              # Regulatory reports (SAR, CTR)
│   │   └── gdpr.py                 # GDPR/DSGVO data rights
│   ├── core/                       # Security, auth, RBAC
│   │   ├── security.py             # JWT, encryption, secrets
│   │   ├── auth.py                 # Authentication flows
│   │   └── rbac.py                 # Role-based access control
│   ├── models/                     # Pydantic & DB models
│   ├── services/                   # Business logic layer
│   │   ├── ml_service.py           # ML inference orchestration
│   │   ├── alert_service.py        # Alert lifecycle management
│   │   ├── audit_service.py        # Immutable audit trails
│   │   └── gdpr_service.py         # GDPR compliance workflows
│   ├── ml/                         # ML inference modules
│   │   ├── anomaly_detector.py     # Isolation Forest inference
│   │   ├── clustering.py           # DBSCAN cluster assignment
│   │   ├── risk_scorer.py          # Composite risk scoring
│   │   └── explainer.py            # SHAP explainability engine
│   ├── middleware/                 # Logging, auth middleware
│   └── config/                     # Settings & logging config
├── databricks/
│   ├── notebooks/
│   │   ├── 01_data_ingestion.py    # Delta Lake ingestion
│   │   ├── 02_feature_engineering.py
│   │   ├── 03_anomaly_detection.py # Isolation Forest training
│   │   ├── 04_clustering.py        # DBSCAN clustering
│   │   ├── 05_risk_scoring.py      # Risk model training
│   │   ├── 06_model_training.py    # MLflow experiment tracking
│   │   └── 07_model_evaluation.py  # Drift detection & eval
│   └── mlflow/
│       └── experiment_config.py
├── streaming/
│   ├── simulator.py                # Transaction stream generator
│   ├── kafka_producer.py           # Kafka message producer
│   └── stream_processor.py        # Real-time stream consumer
├── data/
│   ├── sample_transactions.csv     # 50k Swiss/German transactions
│   ├── sample_accounts.csv         # Account profiles
│   └── generators/
│       ├── transaction_generator.py
│       └── aml_pattern_generator.py
├── monitoring/
│   ├── prometheus/prometheus.yml
│   ├── grafana/dashboards/aml_dashboard.json
│   └── alerts/alert_rules.yml
├── tests/
│   ├── unit/                       # ML model unit tests
│   ├── integration/                # API, security, GDPR tests
│   ├── performance/                # Load tests
│   └── docs/testing_documentation.md
├── ci-cd/.github/workflows/
│   ├── ci.yml                      # PR checks
│   └── cd.yml                      # Deployment pipeline
├── infrastructure/
│   ├── azure/main.bicep            # Azure IaC
│   └── terraform/                  # Terraform alternative
├── locales/
│   ├── de/messages.json            # German translations
│   └── en/messages.json            # English translations
├── docker-compose.yml
├── Makefile
├── README.md
└── architecture.md
```

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Streaming** | Apache Kafka + Spark Structured Streaming | Real-time transaction ingestion |
| **ML Training** | Databricks ML + MLflow | Model training, versioning, registry |
| **Anomaly Detection** | Isolation Forest (scikit-learn) | Detect unusual transactions |
| **Clustering** | DBSCAN | Group suspicious behavior patterns |
| **Risk Scoring** | Gradient Boosting + SHAP | Explainable risk scores |
| **Backend API** | FastAPI + Python 3.11 | REST endpoints + WebSocket alerts |
| **Database** | PostgreSQL 15 + Redis | Persistence + caching |
| **Storage** | Azure Blob Storage | Raw transaction archive |
| **Auth** | JWT + RBAC | Fine-grained access control |
| **Dashboards** | Power BI + Grafana | Operational & executive views |
| **Monitoring** | Prometheus + Azure Monitor | Metrics, drift detection, alerting |
| **CI/CD** | GitHub Actions | Automated test, build, deploy |
| **Container** | Docker + Docker Compose | Local & cloud deployment |
| **Cloud** | Microsoft Azure | Production infrastructure |
| **Compliance** | GDPR/DSGVO, FINMA, BaFin | Swiss & German regulatory |

---

## Compliance & Regulatory

### FINMA (Swiss Financial Market Supervisory Authority)
- Transaction monitoring per FINMA Circular 2017/1
- SAR (Suspicious Activity Report) generation
- 10-year audit trail retention (configurable)
- Immediate alert escalation for FATF high-risk jurisdictions

### BaFin (German Federal Financial Supervisory Authority)
- GwG (Geldwäschegesetz) compliance
- STR (Suspicious Transaction Report) filing
- KYC risk categorization integration
- EU AMLD6 pattern detection

### GDPR / DSGVO
- PII masking at ingestion (AES-256 encryption)
- Right-to-erasure workflow with audit confirmation
- Data retention enforcement (configurable per jurisdiction)
- Role-based access with least-privilege principle
- Immutable audit trails (tamper-evident logging)

---

## Quick Start

### Prerequisites
- Docker 24+ and Docker Compose
- Python 3.11+
- Azure CLI (for cloud deployment)

### Local Development

```bash
# 1. Clone and configure
git clone https://github.com/your-org/aml-monitoring-system
cd aml-monitoring-system
make env                    # Copy .env.example → .env
# Edit .env with your credentials

# 2. Generate sample data
make seed-data              # Creates 50k Swiss/German transactions

# 3. Start all services
make build
make up

# 4. Access the system
# API Documentation:  http://localhost:8000/docs
# API (German):       http://localhost:8000/docs?lang=de
# Grafana:            http://localhost:3000  (admin/admin)
# Prometheus:         http://localhost:9090

# 5. Run the transaction simulator
make dev-stream

# 6. Run all tests
make test
```

---

## API Authentication

The API uses JWT Bearer tokens with RBAC. Available roles:

| Role | Access Level |
|---|---|
| `compliance_officer` | Full read/write + GDPR actions |
| `aml_analyst` | Read alerts, update false positives |
| `risk_manager` | Read reports, export data |
| `auditor` | Read-only audit logs |
| `data_admin` | GDPR delete workflows only |
| `readonly` | Dashboard data only |

```bash
# Get token
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst@bank.de", "password": "CHANGE_ME"}'

# Use token
curl http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer <token>" \
  -H "Accept-Language: de"
```

---

## Multilingual Support (DE/EN)

All API responses, alert messages, and dashboard labels support German and English:

```bash
# German response
curl http://localhost:8000/api/v1/alerts/ALT-001 \
  -H "Accept-Language: de"

# English response
curl http://localhost:8000/api/v1/alerts/ALT-001 \
  -H "Accept-Language: en"
```

Risk explanations, SHAP feature labels, and audit messages are all translated.

---

## Testing

```bash
make test               # Full suite
make test-unit          # ML model tests
make test-security      # API security & GDPR
make test-performance   # Load tests (Locust)
make test-coverage      # HTML coverage report
```

See `tests/docs/testing_documentation.md` for full QA documentation.

---

## Deployment

### Azure Production
```bash
# Provision infrastructure
cd infrastructure/terraform
terraform init && terraform plan && terraform apply

# Deploy via CI/CD
git push origin main    # Triggers GitHub Actions CD pipeline
```

### Environment Promotion
```
Development → Staging → UAT → Production
     ↑              ↑
  make dev    GitHub Actions
```

---

## Monitoring & Alerts

- **Prometheus** scrapes API metrics at `/metrics`
- **Grafana** dashboards: AML operations, model performance, system health
- **Azure Monitor** for production alerting + PagerDuty integration
- **Model drift** detected via PSI (Population Stability Index) — auto-retraining triggered

---

## License & Security Disclosure

Internal use only. All PII is encrypted. Report security vulnerabilities to: `security@bank.de`

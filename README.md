# AML Transaction Monitoring System

> **Production-grade Anti-Money Laundering platform for Swiss and German banks.**  
> Modelled after UBS / SIX Group workflows. Built for portfolio demonstration and job applications at CH/DE financial institutions.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-26%20passing-brightgreen)]()
[![Compliance](https://img.shields.io/badge/Compliance-FINMA%20%7C%20BaFin%20%7C%20GDPR-orange)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()

---

## What It Does

| Capability | Implementation |
|-----------|---------------|
| **Real-time transaction scoring** | Isolation Forest (47 features) + LightGBM + SHAP explanations |
| **AML alert management** | Rule-based + ML alerts with severity tiers and bilingual (DE/EN) narratives |
| **FINMA GwG Art.9 STR** | Automated suspicious transaction report generation for MROS |
| **BaFin GwG §43 SAR** | Suspicious activity reports for FIU via goAML, §47 non-disclosure |
| **GDPR Art.17/20** | Right to erasure (pseudonymisation) + data portability |
| **IBAN validation** | ISO 13616 mod-97 + CH/DE/AT/LI bank registry lookup |
| **Swiss holiday calendar** | All 26 cantons (ZH, GE, BS, BE, LU, VD, AG, TG, SG, TI) |
| **German holiday calendar** | All 16 Bundesländer |
| **Live HTML dashboard** | Chart.js, DE/EN language toggle, live scoring form |
| **JWT/RBAC** | 6 roles: aml_analyst, compliance_officer, model_developer, auditor, readonly, admin |
| **PII encryption** | Fernet AES-128 at rest, HMAC-SHA256 audit log signing |

---

## Quick Start

```bash
git clone https://github.com/lari98/AML-Transaction-Monitoring-System.git
cd AML-Transaction-Monitoring-System
pip install -r requirements.txt
cp .env.example .env
PYTHONPATH=. uvicorn backend.main:app --reload --port 8000
```

Then open `dashboard/index.html` in your browser.

**→ Full guide: [DEMO.md](DEMO.md)**

---

## Project Structure

```
aml-monitoring-system/
├── backend/
│   ├── api/v1/
│   │   ├── transactions.py     # POST /transactions — score & ingest
│   │   ├── alerts.py           # GET/PATCH /alerts — alert management
│   │   ├── compliance.py       # POST /compliance/sar — SAR/STR generation
│   │   ├── gdpr.py             # DELETE /gdpr/erasure, GET /gdpr/export
│   │   └── router.py           # API v1 router + auth endpoints
│   ├── core/
│   │   ├── auth.py             # JWT decode, RBAC dependency injection
│   │   └── security.py         # Token creation, password hashing
│   ├── ml/
│   │   ├── anomaly_detector.py # IsolationForest, 47-feature extractor
│   │   └── risk_scorer.py      # LightGBM + SHAP + heuristic fallback
│   ├── utils/
│   │   ├── iban_validator.py   # ISO 13616 mod-97 IBAN validation
│   │   ├── bank_registry.py    # CH IID / DE BLZ bank registry
│   │   ├── swiss_holidays.py   # CH canton + DE state holiday calendar
│   │   └── compliance_reporter.py # FINMA STR + BaFin SAR generators
│   └── config/
│       ├── settings.py         # Pydantic BaseSettings, env vars
│       └── logging_config.py   # Structlog JSON logging, PII masking
├── tests/
│   ├── unit/
│   │   └── test_anomaly_detection.py  # 26 unit tests (banking QA grade)
│   └── conftest.py             # Shared fixtures (CH/DE transaction samples)
├── dashboard/
│   └── index.html              # Self-contained live dashboard
├── DEMO.md                     # Step-by-step local run guide
└── docs/
    └── portfolio_summary.md    # Technical decisions for interviews
```

---

## API Reference

Base URL: `http://localhost:8000`  
Interactive docs: `http://localhost:8000/docs`

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/auth/token` | — | Get JWT token |
| `POST` | `/api/v1/transactions` | analyst+ | Score transaction |
| `GET` | `/api/v1/alerts` | analyst+ | List AML alerts |
| `PATCH` | `/api/v1/alerts/{id}` | analyst+ | Update alert status |
| `POST` | `/api/v1/compliance/sar` | compliance_officer | Generate FINMA STR / BaFin SAR |
| `GET` | `/api/v1/compliance/reports` | analyst+ | List compliance reports |
| `GET` | `/api/v1/compliance/stats` | analyst+ | Compliance statistics |
| `GET` | `/api/v1/gdpr/export/{account_id}` | analyst+ | GDPR Art.20 export |
| `DELETE` | `/api/v1/gdpr/erasure/{account_id}` | compliance_officer | GDPR Art.17 erasure |
| `GET` | `/api/v1/health` | — | Health check |

---

## Compliance Framework

| Regulation | Coverage |
|-----------|---------|
| **FINMA GwG Art.9** | STR generation, MROS reporting, 10-year retention |
| **BaFin GwG §43** | SAR generation, FIU via goAML, §47 tipping-off prohibition |
| **GDPR/DSGVO Art.17** | Right to erasure via PII pseudonymisation |
| **GDPR/DSGVO Art.20** | Data portability (JSON export) |
| **FATF Rec. 20** | Suspicious transaction reporting framework |
| **AMLD6** | 6th EU Anti-Money Laundering Directive typologies |
| **ISO 13616** | IBAN structure and checksum validation |

---

## Version History

| Version | Release | Highlights |
|---------|---------|-----------|
| **v1.0.0** | 2024-Q1 | Portfolio release — complete docs, DEMO.md, GitHub Release |
| v0.4.0 | 2024-Q1 | IBAN validator, bank registry, CH/DE holiday calendars, FINMA/BaFin SAR API |
| v0.3.0 | 2024-Q1 | Live HTML dashboard with DE/EN i18n, Chart.js, IBAN validator UI |
| v0.2.0 | 2024-Q1 | FastAPI server, ML pipeline fitted at startup, live transaction scoring |
| v0.1.0 | 2024-Q1 | Core ML, RBAC, GDPR endpoints — all 26 unit tests passing |

---

## For Interviewers

See **[docs/portfolio_summary.md](docs/portfolio_summary.md)** for:
- Why IsolationForest over DBSCAN or deep learning
- How the FINMA/BaFin dual compliance framework works
- The 47-feature AML engineering rationale
- Scalability path to 1M transactions/day
- False positive rate control strategy

---

*Built with: FastAPI · scikit-learn · LightGBM · SHAP · Chart.js · structlog*  
*Target: AML/Compliance Engineer roles at Swiss and German banks*

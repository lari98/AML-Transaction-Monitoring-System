# AML Transaction Monitoring System — Local Demo Guide

> **Portfolio project** — Production-grade AML system modelled after UBS / SIX Group workflows.  
> Compliance: FINMA GwG Art.9 · BaFin GwG §43 · GDPR/DSGVO Art.17/20 · FATF Recommendation 20

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.10+ | `python3 --version` |
| pip | latest | `pip3 install --upgrade pip` |
| Git | any | for cloning |

---

## 1 — Clone & Install

```bash
git clone https://github.com/lari98/AML-Transaction-Monitoring-System.git
cd AML-Transaction-Monitoring-System
pip3 install -r requirements.txt
```

---

## 2 — Configure Environment

```bash
# Copy example env (safe defaults for local demo)
cp .env.example .env
```

Key variables (already set in `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Enables demo mode |
| `SECRET_KEY` | `dev-secret-key-32chars-minimum!` | JWT signing key |
| `PII_ENCRYPTION_KEY` | `dev-pii-key-32chars-minimum-!!` | Fernet AES-128 for PII |
| `ANOMALY_THRESHOLD` | `0.65` | Isolation Forest threshold |

---

## 3 — Run All Tests

```bash
PYTHONPATH=. pytest tests/unit/ -v
```

Expected: **26 passed** ✅

---

## 4 — Start the API Server

```bash
PYTHONPATH=. uvicorn backend.main:app --reload --port 8000
```

Server starts at: **http://localhost:8000**  
API docs (Swagger): **http://localhost:8000/docs**  
OpenAPI JSON: **http://localhost:8000/openapi.json**

---

## 5 — Open the Live Dashboard

Open `dashboard/index.html` in any browser — no server required for the dashboard itself.

The dashboard will automatically connect to `http://localhost:8000` and:
- Load live transaction metrics
- Score transactions in real-time
- Validate IBANs (CH/DE/AT/LI)
- Display active AML alerts
- Show compliance status panel

**Language toggle**: Switch between 🇩🇪 Deutsch and 🇬🇧 English with the button in the header.

---

## 6 — Demo API Calls

### Authenticate (get JWT token)

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst@bank.de", "password": "demo"}'
```

Demo users:
| Email | Password | Role |
|-------|----------|------|
| `analyst@bank.de` | `demo` | `aml_analyst` |
| `compliance@bank.de` | `demo` | `compliance_officer` |

### Score a Transaction (save token as `$TOKEN`)

```bash
export TOKEN="<access_token from above>"

curl -X POST http://localhost:8000/api/v1/transactions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "TXN-DEMO-001",
    "amount": "9850.00",
    "currency": "CHF",
    "transaction_type": "CASH_DEPOSIT",
    "source_account_id": "acc-001",
    "source_iban": "CH9300762011623852957",
    "source_country": "CH",
    "target_iban": "CH9300762011623852957",
    "target_country": "CH",
    "channel": "branch"
  }'
```

Expected response: `HTTP 202` with `anomaly_score`, `risk_score`, and SHAP explanations.

### Generate a FINMA STR (compliance officer only)

```bash
export COMP_TOKEN="<token for compliance@bank.de>"

curl -X POST http://localhost:8000/api/v1/compliance/sar \
  -H "Authorization: Bearer $COMP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept-Language: de" \
  -d '{
    "alert_id": "ALT-20240315-001",
    "report_type": "FINMA_STR",
    "transactions": [{
      "transaction_id": "TXN-DEMO-001",
      "amount": 9850.00,
      "currency": "CHF",
      "transaction_type": "CASH_DEPOSIT",
      "source_country": "CH",
      "target_country": "CH",
      "channel": "branch"
    }],
    "suspicion_categories": ["STRUCTURING", "CASH_INTENSIVE"]
  }'
```

### Validate an IBAN

```bash
curl http://localhost:8000/api/v1/transactions/validate-iban/CH9300762011623852957 \
  -H "Authorization: Bearer $TOKEN"
```

### List Active Alerts

```bash
curl http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer $TOKEN"
```

---

## 7 — System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Dashboard (HTML)                      │
│    Chart.js · DE/EN i18n · IBAN validator · Live scoring │
└────────────────────────┬────────────────────────────────┘
                         │ REST / JSON
┌────────────────────────▼────────────────────────────────┐
│                FastAPI (uvicorn, ASGI)                   │
│  /api/v1/transactions  /alerts  /compliance  /gdpr       │
│  JWT/RBAC (6 roles) · Rate limiting · Audit logging      │
└────────┬───────────────────────────┬────────────────────┘
         │                           │
┌────────▼──────────┐     ┌──────────▼────────────────────┐
│  ML Pipeline      │     │  Compliance Engine             │
│  IsolationForest  │     │  FINMA GwG Art.9 STR generator │
│  47 features      │     │  BaFin GwG §43 SAR generator   │
│  LightGBM + SHAP  │     │  IBAN validator (ISO 13616)    │
│  Drift detection  │     │  Swiss/German holiday calendar  │
└────────┬──────────┘     └──────────┬────────────────────┘
         │                           │
┌────────▼───────────────────────────▼────────────────────┐
│  Data Layer (demo: in-memory / production: PostgreSQL)   │
│  Redis cache · Fernet PII encryption · HMAC audit logs   │
└─────────────────────────────────────────────────────────┘
```

---

## 8 — Key Compliance Features

| Feature | Implementation |
|---------|---------------|
| FINMA GwG Art.9 | STR generator, bilingual DE/EN, MROS-ready |
| BaFin GwG §43 | SAR generator, goAML format, §47 non-disclosure |
| GDPR Art.17 | Right to erasure endpoint (`DELETE /gdpr/erasure`) |
| GDPR Art.20 | Data portability endpoint (`GET /gdpr/export`) |
| PII encryption | Fernet AES-128 at rest; HMAC-SHA256 audit log signing |
| FATF countries | 15 high-risk/sanctioned jurisdictions flagged |
| Structuring | Near-CHF/EUR 10,000 detection (90%, 95%, 100% bands) |
| Swiss holidays | All 26 cantons (ZH, GE, BS, BE, LU, VD, AG, TG, SG, TI) |
| German holidays | All 16 Bundesländer (Feiertagsgesetze) |
| IBAN validation | ISO 13616 mod-97 + bank registry (CH IID / DE BLZ) |

---

## Version History

| Version | Features |
|---------|----------|
| v0.1.0 | All 26 unit tests passing — anomaly detection, RBAC, GDPR |
| v0.2.0 | Live FastAPI server with real ML scoring pipeline |
| v0.3.0 | Live HTML dashboard — stakeholder-ready, DE/EN i18n |
| v0.4.0 | Swiss/German market: IBAN validator, bank registry, holiday calendar, FINMA/BaFin SAR |
| v1.0.0 | Portfolio release — complete documentation, GitHub Release |

---

*Built with FastAPI · scikit-learn · LightGBM · SHAP · Chart.js*  
*Compliance: FINMA · BaFin · GDPR · FATF · ISO 13616*

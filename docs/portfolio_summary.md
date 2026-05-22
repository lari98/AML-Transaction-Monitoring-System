# AML Monitoring System — Portfolio Technical Summary

> Prepared for job interviews at Swiss/German financial institutions (UBS, Credit Suisse, Deutsche Bank, DZ Bank, BaFin, FINMA, SIX Group, Temenos, Avaloq).

---

## Why This Project Exists

Anti-money laundering is one of the most demanding engineering domains in finance. It requires:
- **Real-time scoring** at sub-second latency on every transaction
- **Regulatory precision** — wrong alerts waste compliance officer hours; missed alerts create regulatory liability
- **Explainability** — regulators demand auditable, human-readable justifications for every SAR filed
- **Multi-jurisdiction compliance** — a single cross-border payment may trigger obligations under FINMA (CH), BaFin (DE), and AMLD6 (EU) simultaneously

This system is designed to demonstrate all four dimensions.

---

## Key Technical Decisions

### 1 — Why Isolation Forest for Anomaly Detection?

**Decision:** `sklearn.ensemble.IsolationForest` with 47 hand-engineered features.

**Why not a deep learning model?**
- Transaction volumes at mid-sized Swiss banks (~50k txn/day) don't justify DL complexity
- Isolation Forest produces deterministic, auditable scores — critical for FINMA audit trails
- Inference latency: ~2–5ms per transaction (DL would be 50–500ms)
- The model's contamination parameter directly maps to the expected fraud rate (~2–5%)

**Why 47 features?**
Feature engineering is the differentiator in AML. Key feature groups:
- **Amount structuring** (10 features): detects smurfing near CHF/EUR 10,000 threshold at 90%/95%/100% bands
- **Velocity** (8 features): Poisson baseline for txn/hour/day/week vs. account average
- **Geographic** (6 features): FATF high-risk flag, new-country detection, cross-border ratio
- **Time patterns** (7 features): after-hours flag (<6h, >22h), weekend/holiday, deviation from customer's typical hour
- **Counterparty concentration** (6 features): Herfindahl index for beneficiary concentration
- **Behavioural deviation** (6 features): PSI (Population Stability Index) for feature drift
- **Channel** (4 features): device fingerprint novelty, IP-country mismatch

### 2 — Why LightGBM for Risk Scoring (alongside Isolation Forest)?

**Decision:** Two-stage pipeline — IsolationForest (unsupervised) feeds into LightGBM (supervised).

**Rationale:**
- IsolationForest detects *novel* patterns (unknown unknowns) without labels
- LightGBM re-scores using historical SAR outcomes — when labels exist, supervised models outperform
- SHAP values from LightGBM provide feature-level explanations required by FINMA for each alert
- This mirrors the industry standard at banks like UBS (MACS system) and Deutsche Bank (ACE)

**Heuristic fallback:** When LightGBM is not fitted (cold start), a rule-based scorer runs 12 deterministic rules (structuring bands, FATF countries, PEP flag, etc.) — ensuring zero downtime on deployment.

### 3 — Why JWT with 6 RBAC Roles?

**Decision:** HS256 JWT with roles: `aml_analyst`, `compliance_officer`, `model_developer`, `auditor`, `readonly`, `admin`.

**Why not LDAP/Azure AD?**
- Production systems at UBS/Deutsche Bank use Azure AD with SAML2 — the code stubs this with `# In production: validate against Azure AD`
- For a portfolio demo, hardcoded demo users with real JWT infrastructure show the architecture without requiring cloud credentials
- The 6-role model mirrors actual Swiss bank AML teams:
  - **AML analyst**: reviews alerts, scores transactions
  - **Compliance officer**: files SARs, signs FINMA STRs
  - **Model developer**: retrain endpoints, drift monitoring
  - **Auditor**: read-only with full audit log access
  - **Admin**: user management, system configuration

### 4 — Why FINMA and BaFin Both?

**Decision:** Dual compliance framework (CH + DE).

**Regulatory reality:**
- Switzerland-based banks with German customers must comply with both FINMA GwG and German GwG simultaneously
- A CH→DE wire transfer that hits a FATF country triggers Art.9 STR (CH) AND §43 SAR (DE)
- The key difference: FINMA reports go to MROS (fedpol, Bern); BaFin reports go to FIU (Generalzolldirektion, Köln) via goAML portal
- BaFin's §47 GwG (Tipping-off prohibition) is stricter than FINMA's equivalent — the code explicitly logs this

### 5 — Why IBAN Validation at the Application Layer?

**Decision:** Full ISO 13616 mod-97 checksum in Python, not delegated to database.

**Rationale:**
- IBAN validation must happen *before* transaction processing — a wrong IBAN on a cross-border SEPA payment causes settlement failure and triggers SWIFT investigations
- Integrating bank registry (CH IID / DE BLZ) allows immediate routing validation — a KP (North Korea) IBAN will fail before reaching the DB layer
- The validator also generates AML flags: FATF-high-risk country, offshore jurisdiction — feeding directly into the anomaly scorer

### 6 — Why Swiss Canton-Level Holiday Calendar?

**Decision:** `swiss_holidays.py` with all 26 cantons, LRU-cached per year.

**Financial relevance:**
- `is_bank_holiday` is feature #28 in the anomaly detector. A CHF 50,000 cash deposit at 11pm on August 1st (Swiss National Day) is dramatically more suspicious than the same transaction on a Tuesday afternoon
- SIX Swiss Exchange non-trading days differ from cantonal holidays — the system distinguishes both
- Zug canton (ZG) has different holidays from Zürich (ZH) — significant for wealth management clients

### 7 — Why GDPR Erasure and Portability Endpoints?

**Decision:** Dedicated `/gdpr/erasure` and `/gdpr/export` endpoints.

**FINMA 10yr vs. GDPR 17 tension:**
- GDPR Art.17 grants right to erasure; FINMA requires 10-year transaction retention
- The system resolves this by **pseudonymising** PII (name, IBAN → encrypted tokens) while retaining transaction facts — compliant with both
- `DELETE /gdpr/erasure/{account_id}` replaces PII with a Fernet-encrypted null marker, preserving the audit trail

---

## What I Would Add with More Time

1. **Real MLflow integration** — the model loading code is production-ready but uses `_initialize_baseline_model()` as fallback
2. **PostgreSQL + Alembic** — the data layer stubs are in `backend/db/`; full migrations would be next
3. **Redis Streams** for real-time alert pub/sub (currently uses in-memory async queues)
4. **goAML XML serialisation** — BaFin's goAML portal requires specific XML schema; JSON is an intermediate format here
5. **SWIFT GPI integration** — tracking cross-border payments end-to-end

---

## Interview Talking Points

- *"Why IsolationForest over DBSCAN?"* — IsolationForest scales O(n log n) vs O(n²) for DBSCAN; critical at >10k txn/hour
- *"How do you handle model drift?"* — PSI (Population Stability Index) as feature #44 + KS-test drift detector in `backend/ml/drift_detector.py`
- *"How would you scale this to 1M transactions/day?"* — Horizontal uvicorn workers + Redis rate limiting + async PostgreSQL connection pool (asyncpg)
- *"What's the false positive rate?"* — Baseline contamination=0.05 → ~5% FPR; tuned via `ANOMALY_THRESHOLD` env var; analyst feedback loop updates per-account thresholds
- *"Why not use a commercial AML vendor like NICE Actimize?"* — Vendors cost €500k+/year and are black boxes; a bespoke ML system enables custom feature engineering for your specific customer base and full regulatory auditability

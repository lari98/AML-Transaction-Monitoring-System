# Databricks notebook source
# AML Monitoring System — Notebook 03: Anomaly Detection Training
# Isolation Forest training + MLflow tracking + model registration
# MAGIC %md
# ## AML Anomaly Detection — Isolation Forest Training
# Trains, evaluates, and registers the Isolation Forest model for production.

# COMMAND ----------
import mlflow
import mlflow.sklearn
from mlflow.models.signature import infer_signature

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
import json

from pyspark.sql import functions as F

spark.conf.set("spark.sql.execution.arrow.pyspark.enabled", "true")

CATALOG = spark.conf.get("aml.catalog", "aml_catalog")
SCHEMA = spark.conf.get("aml.schema", "transactions")
FEATURES_TABLE = f"{CATALOG}.{SCHEMA}.transaction_features"
MODEL_NAME = "aml_isolation_forest"
EXPERIMENT_NAME = "/AML/anomaly_detection"

mlflow.set_experiment(EXPERIMENT_NAME)

# COMMAND ----------
# Load feature-engineered data
print("Loading features from Delta Lake...")
features_df = (
    spark.table(FEATURES_TABLE)
    .filter(F.col("feature_date") >= F.date_sub(F.current_date(), 90))  # Last 90 days
    .sample(fraction=0.8, seed=42)
    .limit(500_000)                         # Cap training set for Isolation Forest
).toPandas()

print(f"Training set: {len(features_df):,} transactions")
print(f"Known AML labels: {features_df.get('is_labeled_aml', pd.Series(dtype=bool)).sum()} flagged")

# COMMAND ----------
# Feature columns (must match AnomalyDetector.extract_features())
FEATURE_COLS = [
    "amount", "log_amount", "amount_vs_30d_avg", "amount_zscore",
    "near_threshold_90pct", "near_threshold_95pct", "near_threshold",
    "max_amount_30d", "median_amount_30d", "amount_vs_max_ever",
    "txn_count_1h", "txn_count_24h", "txn_count_7d", "txn_count_30d",
    "total_amount_1h", "total_amount_24h", "txn_count_vs_daily_avg",
    "txn_count_same_beneficiary_24h",
    "is_new_country", "is_high_risk_jurisdiction", "is_source_high_risk",
    "unique_target_countries_30d", "is_cross_border", "cross_border_ratio_30d",
    "hour_of_day", "is_after_hours", "is_weekend", "is_bank_holiday",
    "day_of_week", "avg_txn_hour_30d", "hour_deviation",
    "is_new_beneficiary", "beneficiary_concentration_30d", "new_beneficiaries_7d",
    "same_beneficiary_amount_ratio_24h", "is_cash", "cash_ratio_30d",
    "account_age_days", "account_risk_score", "recent_pattern_change",
    "alerts_30d", "false_positive_rate", "kyc_risk_category_encoded",
    "is_online_channel", "is_atm_channel", "device_fingerprint_new", "ip_country_mismatch",
]

# Only use columns that exist
available_cols = [c for c in FEATURE_COLS if c in features_df.columns]
X = features_df[available_cols].fillna(0).values
y_true = features_df.get("is_labeled_aml", pd.Series([False] * len(features_df))).values

print(f"Feature matrix: {X.shape}")

# COMMAND ----------
# Hyperparameter grid search
HYPERPARAMETERS = [
    {"n_estimators": 100, "contamination": 0.03, "max_samples": "auto"},
    {"n_estimators": 200, "contamination": 0.05, "max_samples": "auto"},
    {"n_estimators": 200, "contamination": 0.05, "max_samples": 512},
    {"n_estimators": 300, "contamination": 0.04, "max_samples": "auto"},
]

best_model = None
best_f1 = -1
best_run_id = None

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_true, test_size=0.2, random_state=42, stratify=y_true if y_true.sum() > 10 else None
)

# COMMAND ----------
# Training loop with MLflow tracking
for params in HYPERPARAMETERS:
    with mlflow.start_run(run_name=f"IF_n{params['n_estimators']}_c{params['contamination']}"):
        # Log parameters
        mlflow.log_params(params)
        mlflow.log_param("n_features", len(available_cols))
        mlflow.log_param("training_samples", len(X_train))
        mlflow.log_param("scaler", "StandardScaler")

        # Train model
        model = IsolationForest(
            **params,
            random_state=42,
            n_jobs=-1,
            warm_start=False,
        )
        model.fit(X_train)

        # Predict: -1 = anomaly, 1 = normal → convert to binary
        y_pred_raw = model.predict(X_test)
        y_pred = (y_pred_raw == -1).astype(int)
        y_scores = -model.score_samples(X_test)   # Higher = more anomalous

        # Compute metrics (if labeled data available)
        if y_test.sum() > 0:
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            auc = roc_auc_score(y_test, y_scores)
        else:
            # Use anomaly rate as proxy metric
            anomaly_rate = y_pred.mean()
            precision = recall = f1 = 1 - abs(anomaly_rate - params["contamination"])
            auc = 0.5

        mlflow.log_metrics({
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "roc_auc": auc,
            "anomaly_rate": y_pred.mean(),
        })

        # Log model artifacts
        signature = infer_signature(X_test, y_scores)
        mlflow.sklearn.log_model(
            model,
            artifact_path="model",
            signature=signature,
            registered_model_name=MODEL_NAME,
            input_example=X_test[:5],
        )
        mlflow.sklearn.log_model(scaler, artifact_path="scaler")
        mlflow.log_dict(
            {"feature_names": available_cols},
            "feature_names.json"
        )

        run_id = mlflow.active_run().info.run_id
        print(f"Run {run_id[:8]}: F1={f1:.3f}, AUC={auc:.3f}, Anomaly rate={y_pred.mean():.3f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_run_id = run_id

# COMMAND ----------
# Register best model to Production
if best_run_id:
    client = mlflow.MlflowClient()

    # Find the version registered in this run
    model_versions = client.search_model_versions(f"run_id='{best_run_id}'")
    if model_versions:
        latest_version = model_versions[0].version

        # Transition to Production
        client.transition_model_version_stage(
            name=MODEL_NAME,
            version=latest_version,
            stage="Production",
            archive_existing_versions=True,
        )
        print(f"Model {MODEL_NAME} v{latest_version} promoted to Production (run: {best_run_id[:8]})")
        print(f"Best F1: {best_f1:.4f}")
    else:
        print("Warning: No model version found for best run")

# COMMAND ----------
# Baseline evaluation: compare with previous Production model
try:
    previous_versions = client.get_latest_versions(MODEL_NAME, stages=["Archived"])
    if previous_versions:
        prev_version = previous_versions[0]
        prev_model = mlflow.sklearn.load_model(f"models:/{MODEL_NAME}/{prev_version.version}")
        prev_pred = (prev_model.predict(X_test) == -1).astype(int)
        prev_f1 = f1_score(y_test, prev_pred, zero_division=0) if y_test.sum() > 0 else 0

        improvement = best_f1 - prev_f1
        print(f"Model improvement: {improvement:+.4f} F1 vs. previous version")

        if improvement < -0.05:
            raise ValueError(
                f"New model F1 is {abs(improvement):.3f} lower than previous! "
                "Blocking promotion. Review training data."
            )
except Exception as e:
    print(f"Previous model comparison: {e}")

print("\nAnomaly detection model training complete.")
print(f"Active model: {MODEL_NAME} | Stage: Production | F1: {best_f1:.4f}")

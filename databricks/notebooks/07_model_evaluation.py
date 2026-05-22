# Databricks notebook source
# AML Monitoring System — Notebook 07: Model Evaluation & Drift Detection
# Production monitoring: PSI, F1 tracking, auto-retraining trigger

# MAGIC %md
# ## AML Model Drift Detection & Evaluation
# Scheduled nightly to detect concept drift and trigger retraining.

# COMMAND ----------
import mlflow
import numpy as np
import pandas as pd
from pyspark.sql import functions as F
from scipy.stats import ks_2samp
import json

CATALOG = spark.conf.get("aml.catalog", "aml_catalog")
SCHEMA = spark.conf.get("aml.schema", "transactions")
PSI_THRESHOLD = float(spark.conf.get("aml.psi_threshold", "0.25"))
F1_DROP_THRESHOLD = float(spark.conf.get("aml.f1_drop_threshold", "0.05"))

FEATURES_TABLE = f"{CATALOG}.{SCHEMA}.transaction_features"
SCORES_TABLE = f"{CATALOG}.{SCHEMA}.transaction_scores"
DRIFT_TABLE = f"{CATALOG}.{SCHEMA}.model_drift_metrics"

mlflow.set_experiment("/AML/model_monitoring")

# COMMAND ----------
# Population Stability Index (PSI) calculation
def compute_psi(expected: np.ndarray, actual: np.ndarray, buckets: int = 10) -> float:
    """
    Compute Population Stability Index between reference and current distributions.
    PSI < 0.1: Stable | 0.1-0.25: Monitor | > 0.25: Retrain
    """
    def safe_log(x):
        return np.log(x) if x > 0 else 0

    bins = np.percentile(expected, np.linspace(0, 100, buckets + 1))
    bins[0] = -np.inf
    bins[-1] = np.inf

    exp_counts, _ = np.histogram(expected, bins=bins)
    act_counts, _ = np.histogram(actual, bins=bins)

    exp_pct = (exp_counts + 0.5) / (len(expected) + 0.5 * buckets)
    act_pct = (act_counts + 0.5) / (len(actual) + 0.5 * buckets)

    psi = np.sum((act_pct - exp_pct) * np.vectorize(safe_log)(act_pct / exp_pct))
    return float(psi)


# COMMAND ----------
# Load reference period (training data — last 90 days)
print("Loading reference and current scoring distributions...")

reference_df = (
    spark.table(SCORES_TABLE)
    .filter(
        (F.col("scored_at") >= F.date_sub(F.current_date(), 90))
        & (F.col("scored_at") < F.date_sub(F.current_date(), 7))
    )
    .select("anomaly_score", "risk_score", "confidence")
    .toPandas()
)

current_df = (
    spark.table(SCORES_TABLE)
    .filter(F.col("scored_at") >= F.date_sub(F.current_date(), 7))
    .select("anomaly_score", "risk_score", "confidence")
    .toPandas()
)

print(f"Reference window: {len(reference_df):,} scores")
print(f"Current window:   {len(current_df):,} scores")

# COMMAND ----------
# Compute drift metrics
drift_metrics = {}

with mlflow.start_run(run_name="drift_detection_daily"):
    for col in ["anomaly_score", "risk_score", "confidence"]:
        if col in reference_df.columns and col in current_df.columns:
            ref = reference_df[col].dropna().values
            cur = current_df[col].dropna().values

            if len(ref) > 10 and len(cur) > 10:
                psi = compute_psi(ref, cur)
                ks_stat, ks_pvalue = ks_2samp(ref, cur)

                drift_metrics[col] = {
                    "psi": psi,
                    "ks_statistic": ks_stat,
                    "ks_pvalue": ks_pvalue,
                    "ref_mean": float(ref.mean()),
                    "cur_mean": float(cur.mean()),
                    "ref_std": float(ref.std()),
                    "cur_std": float(cur.std()),
                }

                mlflow.log_metrics({
                    f"psi_{col}": psi,
                    f"ks_stat_{col}": ks_stat,
                    f"ks_pvalue_{col}": ks_pvalue,
                    f"mean_shift_{col}": float(cur.mean() - ref.mean()),
                })

                drift_level = (
                    "STABLE" if psi < 0.1
                    else "MONITOR" if psi < PSI_THRESHOLD
                    else "CRITICAL"
                )
                print(f"{col}: PSI={psi:.4f} [{drift_level}], KS p-value={ks_pvalue:.4f}")

    mlflow.log_dict(drift_metrics, "drift_metrics.json")

# COMMAND ----------
# False Positive Rate tracking
fp_stats = (
    spark.table(f"{CATALOG}.{SCHEMA}.aml_alerts")
    .filter(F.col("created_at") >= F.date_sub(F.current_date(), 30))
    .groupBy()
    .agg(
        F.count("*").alias("total_alerts"),
        F.sum(F.col("is_false_positive").cast("int")).alias("false_positives"),
        F.avg("risk_score").alias("avg_risk_score"),
        F.countDistinct("account_id").alias("unique_accounts_flagged"),
    )
    .collect()[0]
)

fp_rate = (fp_stats["false_positives"] / max(fp_stats["total_alerts"], 1)) * 100
print(f"\n30-Day Alert Stats:")
print(f"  Total alerts:     {fp_stats['total_alerts']:,}")
print(f"  False positives:  {fp_stats['false_positives']:,} ({fp_rate:.1f}%)")
print(f"  Avg risk score:   {fp_stats['avg_risk_score']:.3f}")

# Warning if FP rate > 15%
if fp_rate > 15:
    print(f"WARNING: High false positive rate: {fp_rate:.1f}%")

# COMMAND ----------
# Drift Decision & Retraining Trigger
max_psi = max((v["psi"] for v in drift_metrics.values()), default=0)
should_retrain = max_psi > PSI_THRESHOLD or fp_rate > 15

print(f"\n{'='*50}")
print(f"Drift Analysis Summary")
print(f"{'='*50}")
print(f"Max PSI:           {max_psi:.4f} (threshold: {PSI_THRESHOLD})")
print(f"FP Rate (30d):     {fp_rate:.1f}% (threshold: 15%)")
print(f"Retrain trigger:   {'YES' if should_retrain else 'NO'}")
print(f"{'='*50}")

if should_retrain:
    print("\nTriggering model retraining pipeline...")
    # In production: trigger via Databricks REST API or Jobs API
    dbutils.notebook.run(
        "/AML/03_anomaly_detection",
        timeout_seconds=3600,
        arguments={"triggered_by": "drift_detection", "psi_score": str(max_psi)},
    )
    dbutils.notebook.run(
        "/AML/05_risk_scoring",
        timeout_seconds=3600,
        arguments={"triggered_by": "drift_detection"},
    )
    print("Retraining pipeline launched successfully.")
else:
    print("\nModels are stable. No retraining required.")

# COMMAND ----------
# Write drift metrics to Delta for Power BI dashboard
drift_rows = [
    {
        "metric_date": pd.Timestamp.now(),
        "feature": col,
        "psi": metrics["psi"],
        "ks_statistic": metrics["ks_statistic"],
        "ks_pvalue": metrics["ks_pvalue"],
        "ref_mean": metrics["ref_mean"],
        "cur_mean": metrics["cur_mean"],
        "drift_level": "CRITICAL" if metrics["psi"] >= PSI_THRESHOLD else "STABLE",
        "fp_rate_30d": fp_rate,
        "retrain_triggered": should_retrain,
    }
    for col, metrics in drift_metrics.items()
]

if drift_rows:
    drift_pdf = pd.DataFrame(drift_rows)
    drift_sdf = spark.createDataFrame(drift_pdf)
    drift_sdf.write.format("delta").mode("append").saveAsTable(DRIFT_TABLE)
    print(f"\nDrift metrics written to {DRIFT_TABLE}")

print("\nModel evaluation notebook complete.")

# Databricks notebook source
# AML Monitoring System — Notebook 01: Data Ingestion
# Delta Lake ingestion for Swiss/German banking transactions
# MAGIC %md
# ## AML Transaction Ingestion — Delta Lake
# Ingests raw transactions from Azure Blob Storage into Delta Lake with:
# - PII encryption at write time
# - Schema validation and data quality checks
# - Partitioning by (year, month, source_country)
# - GDPR-compliant PII handling

# COMMAND ----------
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    DecimalType, StringType, StructField, StructType, TimestampType,
)
from delta.tables import DeltaTable
import mlflow

spark = SparkSession.builder.getOrCreate()
spark.conf.set("spark.sql.shuffle.partitions", "200")
spark.conf.set("spark.databricks.delta.optimizeWrite.enabled", "true")
spark.conf.set("spark.databricks.delta.autoCompact.enabled", "true")

# COMMAND ----------
# Configuration
CATALOG = spark.conf.get("aml.catalog", "aml_catalog")
SCHEMA = spark.conf.get("aml.schema", "transactions")
STORAGE_ACCOUNT = spark.conf.get("aml.storage_account", "amltxnmonitoring")
CONTAINER = spark.conf.get("aml.container", "aml-transactions")
BLOB_PATH = f"abfss://{CONTAINER}@{STORAGE_ACCOUNT}.dfs.core.windows.net"

RAW_TABLE = f"{CATALOG}.{SCHEMA}.transactions_raw"
BRONZE_TABLE = f"{CATALOG}.{SCHEMA}.transactions_bronze"
PII_KEY = dbutils.secrets.get(scope="aml-kv", key="pii-encryption-key")

# COMMAND ----------
# Transaction Schema (matches TransactionIngest Pydantic model)
TRANSACTION_SCHEMA = StructType([
    StructField("transaction_id", StringType(), False),
    StructField("timestamp", TimestampType(), False),
    StructField("amount", DecimalType(18, 2), False),
    StructField("currency", StringType(), False),
    StructField("transaction_type", StringType(), False),
    StructField("source_account_id", StringType(), False),
    StructField("source_iban", StringType(), True),
    StructField("source_bic", StringType(), True),
    StructField("source_country", StringType(), False),
    StructField("target_account_id", StringType(), True),
    StructField("target_iban", StringType(), True),
    StructField("target_bic", StringType(), True),
    StructField("target_country", StringType(), True),
    StructField("description", StringType(), True),
    StructField("reference", StringType(), True),
    StructField("channel", StringType(), True),
    StructField("ip_address", StringType(), True),
])

# COMMAND ----------
# Read from Azure Blob Storage (Auto Loader for incremental)
raw_stream = (
    spark.readStream
    .format("cloudFiles")
    .option("cloudFiles.format", "json")
    .option("cloudFiles.schemaLocation", f"{BLOB_PATH}/schemas/transactions")
    .option("cloudFiles.inferColumnTypes", "true")
    .option("cloudFiles.maxFilesPerTrigger", 10000)
    .schema(TRANSACTION_SCHEMA)
    .load(f"{BLOB_PATH}/raw/transactions/")
)

# COMMAND ----------
# Data Quality & Validation
def apply_data_quality(df):
    """Apply data quality rules aligned with FINMA transaction monitoring."""
    return (
        df
        # Drop exact duplicates
        .dropDuplicates(["transaction_id"])
        # Filter invalid amounts
        .filter(F.col("amount") > 0)
        .filter(F.col("amount") < 1_000_000_000)
        # Validate currencies
        .filter(F.col("currency").isin("CHF", "EUR", "USD", "GBP", "JPY", "AED", "CNY"))
        # Validate IBAN format (basic check)
        .filter(
            F.col("source_iban").isNull()
            | F.length(F.col("source_iban")).between(15, 34)
        )
        # Add ingestion metadata
        .withColumn("ingested_at", F.current_timestamp())
        .withColumn("ingestion_source", F.input_file_name())
        .withColumn(
            "data_quality_flags",
            F.when(F.col("description").isNull(), F.lit("missing_description"))
            .otherwise(F.lit(None).cast(StringType()))
        )
    )

# COMMAND ----------
# PII Encryption at Write Time (UDF using Fernet)
from pyspark.sql.functions import udf
from cryptography.fernet import Fernet
import base64, hashlib

def make_fernet(key_str: str) -> Fernet:
    key_bytes = hashlib.sha256(key_str.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))

FERNET = make_fernet(PII_KEY)

@udf(returnType=StringType())
def encrypt_pii(value):
    """Encrypt PII field using Fernet AES-128-CBC."""
    if value is None:
        return None
    return FERNET.encrypt(value.encode()).decode()

@udf(returnType=StringType())
def mask_iban(iban):
    """Mask IBAN for display: show first 4 and last 4 chars."""
    if iban is None:
        return None
    clean = iban.replace(" ", "")
    if len(clean) < 8:
        return "****"
    return f"{clean[:4]}{'*' * (len(clean) - 8)}{clean[-4:]}"

@udf(returnType=StringType())
def mask_ip(ip):
    """Mask last octet of IP address."""
    if ip is None:
        return None
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.*"
    return "***"

# COMMAND ----------
# Apply transformations and write to Bronze Delta table
def process_batch(batch_df, batch_id):
    """Process each micro-batch: validate, encrypt PII, write to Delta."""
    clean_df = apply_data_quality(batch_df)

    encrypted_df = (
        clean_df
        .withColumn("source_iban_encrypted", encrypt_pii(F.col("source_iban")))
        .withColumn("source_iban_masked", mask_iban(F.col("source_iban")))
        .withColumn("target_iban_encrypted", encrypt_pii(F.col("target_iban")))
        .withColumn("target_iban_masked", mask_iban(F.col("target_iban")))
        .withColumn("ip_address_masked", mask_ip(F.col("ip_address")))
        .withColumn("source_account_id_encrypted", encrypt_pii(F.col("source_account_id")))
        # Drop raw PII before persistence
        .drop("source_iban", "target_iban", "ip_address", "source_account_id")
        # Partition columns
        .withColumn("year", F.year("timestamp"))
        .withColumn("month", F.month("timestamp"))
    )

    # Merge into Delta (upsert by transaction_id)
    if DeltaTable.isDeltaTable(spark, BRONZE_TABLE):
        delta_table = DeltaTable.forName(spark, BRONZE_TABLE)
        (
            delta_table.alias("existing")
            .merge(
                encrypted_df.alias("new"),
                "existing.transaction_id = new.transaction_id"
            )
            .whenNotMatchedInsertAll()
            .execute()
        )
    else:
        (
            encrypted_df.write
            .format("delta")
            .mode("overwrite")
            .partitionBy("year", "month", "source_country")
            .option("mergeSchema", "true")
            .saveAsTable(BRONZE_TABLE)
        )

    # Log batch metrics to MLflow
    with mlflow.start_run(run_name=f"ingestion_batch_{batch_id}"):
        mlflow.log_metric("records_ingested", clean_df.count())
        mlflow.log_metric("batch_id", batch_id)

# COMMAND ----------
# Start streaming ingestion
query = (
    raw_stream
    .writeStream
    .foreachBatch(process_batch)
    .trigger(processingTime="30 seconds")
    .option("checkpointLocation", f"{BLOB_PATH}/checkpoints/bronze")
    .option("failOnDataLoss", "false")
    .start()
)

print(f"Streaming ingestion started. Status: {query.status}")
# query.awaitTermination()  # Uncomment for blocking mode

# COMMAND ----------
# Data Quality Dashboard Query (run separately)
spark.sql(f"""
    SELECT
        DATE(timestamp) AS txn_date,
        source_country,
        currency,
        COUNT(*) AS txn_count,
        SUM(amount) AS total_volume,
        AVG(amount) AS avg_amount,
        COUNT(CASE WHEN data_quality_flags IS NOT NULL THEN 1 END) AS dq_issues
    FROM {BRONZE_TABLE}
    WHERE year = YEAR(CURRENT_DATE())
    GROUP BY DATE(timestamp), source_country, currency
    ORDER BY txn_date DESC, total_volume DESC
""").display()

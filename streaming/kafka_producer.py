"""
AML Monitoring System — Kafka Producer
Async Kafka producer with message serialization, retry logic, and dead-letter queue.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaConnectionError


class AMLKafkaProducer:
    """
    Async Kafka producer for AML transaction events.

    Features:
    - JSON serialization with metadata envelope
    - Idempotent producer (exactly-once semantics)
    - Automatic retry with backoff
    - Dead-letter queue for failed messages
    - Message key = account_id (ensures ordered processing per account)
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "aml.transactions.raw",
        dlq_topic: str = "aml.transactions.dlq",
        max_batch_size: int = 16384,
        compression: str = "gzip",
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.dlq_topic = dlq_topic
        self.max_batch_size = max_batch_size
        self.compression = compression
        self._producer: AIOKafkaProducer = None

    async def start(self) -> None:
        """Initialize Kafka producer connection."""
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            compression_type=self.compression,
            max_batch_size=self.max_batch_size,
            # Idempotent producer settings
            enable_idempotence=True,
            acks="all",
            retries=5,
            retry_backoff_ms=200,
        )
        await self._producer.start()

    async def stop(self) -> None:
        """Flush and close Kafka producer."""
        if self._producer:
            await self._producer.flush()
            await self._producer.stop()

    async def send(self, transaction: Dict[str, Any]) -> None:
        """
        Send a transaction message to Kafka.

        Message envelope:
        {
            "metadata": {
                "event_id": "<uuid>",
                "sent_at": "<ISO timestamp>",
                "schema_version": "1.0",
                "source": "aml-simulator"
            },
            "payload": { ... transaction fields ... }
        }
        """
        message = {
            "metadata": {
                "event_id": str(uuid.uuid4()),
                "sent_at": datetime.now(timezone.utc).isoformat(),
                "schema_version": "1.0",
                "source": "aml-simulator",
                "topic": self.topic,
            },
            "payload": transaction,
        }

        # Use source_account_id as partition key (ensures ordered per account)
        message_key = transaction.get("source_account_id", "unknown")

        try:
            await self._producer.send_and_wait(
                self.topic,
                value=message,
                key=message_key,
                headers=[
                    ("content-type", b"application/json"),
                    ("schema-version", b"1.0"),
                    ("is-aml", b"true" if transaction.get("_is_aml") else b"false"),
                ],
            )
        except KafkaConnectionError as e:
            # Send to DLQ
            await self._send_to_dlq(message, str(e))
        except Exception as e:
            await self._send_to_dlq(message, str(e))

    async def _send_to_dlq(self, message: Dict, error: str) -> None:
        """Send failed messages to the dead-letter queue."""
        dlq_message = {
            "original_message": message,
            "error": error,
            "dlq_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await self._producer.send_and_wait(
                self.dlq_topic,
                value=dlq_message,
            )
        except Exception:
            # Log to stderr as last resort
            import sys
            print(f"DLQ send failed: {error}", file=sys.stderr)

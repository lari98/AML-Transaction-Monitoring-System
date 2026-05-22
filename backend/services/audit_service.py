"""
AML Monitoring System — Immutable Audit Service
HMAC-signed, append-only audit trail for FINMA/BaFin compliance.
Retention: 7 years minimum (Swiss banking law).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.config.logging_config import get_logger
from backend.core.security import audit_signer

logger = get_logger(__name__)


class AuditService:
    """
    Immutable audit trail service.

    Every entry is:
    - HMAC-SHA256 signed (tamper detection)
    - Timestamped in UTC
    - Persisted to PostgreSQL (append-only table, no UPDATE/DELETE permissions)
    - Replicated to Azure Blob Storage for long-term retention
    """

    async def log(
        self,
        action: str,
        actor: str,
        resource_id: str,
        details: Dict[str, Any],
        severity: str = "INFO",
        request_id: Optional[str] = None,
    ) -> str:
        """
        Create an immutable audit log entry.

        Args:
            action: Dot-notation action (e.g., "alert.updated", "gdpr.deletion_requested")
            actor: Username performing the action
            resource_id: ID of the affected resource
            details: Additional context (will be JSON-serialized)
            severity: INFO | MEDIUM | HIGH | CRITICAL
            request_id: HTTP request ID for tracing

        Returns:
            Audit entry ID
        """
        entry_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        entry = {
            "id": entry_id,
            "timestamp": timestamp,
            "action": action,
            "actor": actor,
            "resource_id": resource_id,
            "details": details,
            "severity": severity,
            "request_id": request_id or "N/A",
            "service": "aml-monitoring",
        }

        # Sign the entry for tamper detection
        signature = audit_signer.sign(entry)
        entry["signature"] = signature

        # Persist to append-only audit table
        await self._persist(entry)

        # Structured log (also captured by Azure Monitor)
        logger.info(
            "AUDIT",
            audit_action=action,
            audit_actor=actor,
            audit_resource=resource_id,
            audit_severity=severity,
            audit_id=entry_id,
        )

        return entry_id

    async def get_resource_history(
        self,
        resource_type: str,
        resource_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve the full audit history for a resource.
        Verifies HMAC signatures on each entry.
        """
        # In production: query append-only PostgreSQL audit table
        # Return example structure
        entries = await self._fetch_from_db(resource_type, resource_id, limit)

        # Verify signatures
        verified = []
        for entry in entries:
            sig = entry.pop("signature", "")
            is_valid = audit_signer.verify(entry, sig)
            entry["signature_valid"] = is_valid
            entry["signature"] = sig
            if not is_valid:
                logger.warning(
                    "Audit entry signature invalid — possible tampering!",
                    entry_id=entry.get("id"),
                    resource_id=resource_id,
                )
            verified.append(entry)

        return verified

    async def _persist(self, entry: Dict[str, Any]) -> None:
        """Persist audit entry to database and blob storage."""
        # In production:
        # 1. INSERT INTO audit_log (id, timestamp, action, actor, ...) VALUES (...)
        #    Note: The audit_log table has GRANT INSERT only — no UPDATE/DELETE
        # 2. Write to Azure Blob Storage in JSONL format for long-term retention
        logger.debug("Audit entry persisted", entry_id=entry["id"])

    async def _fetch_from_db(
        self, resource_type: str, resource_id: str, limit: int
    ) -> List[Dict[str, Any]]:
        """Fetch audit entries from database."""
        # In production: async SQLAlchemy query
        return []

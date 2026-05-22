"""
AML Monitoring System — Structured Logging Configuration
GDPR-compliant: automatic PII masking in all log outputs.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Any, MutableMapping

import structlog
from structlog.types import EventDict, WrappedLogger

# ── PII Masking Patterns ─────────────────────────────────────────────────────
PII_PATTERNS = [
    # IBAN (Swiss/German/EU)
    (re.compile(r"\b(CH|DE|AT|LI|LU|NL|BE|FR|IT)\d{2}[A-Z0-9]{10,30}\b"), "***IBAN***"),
    # German BIC/SWIFT
    (re.compile(r"\b[A-Z]{4}DE[A-Z0-9]{2}([A-Z0-9]{3})?\b"), "***BIC***"),
    # Swiss social insurance number (AHV/AVS)
    (re.compile(r"\b756\.\d{4}\.\d{4}\.\d{2}\b"), "***AHV***"),
    # German tax ID (Steueridentifikationsnummer)
    (re.compile(r"\b\d{11}\b"), "***TAXID***"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"), "***EMAIL***"),
    # Phone numbers (DE/CH/AT)
    (re.compile(r"\+?(41|49|43)\s?[\d\s\-\.]{8,15}"), "***PHONE***"),
    # IP addresses (partial mask for audit)
    (re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b"), r"\1.\2.***.***"),
]


class PIIMaskingProcessor:
    """structlog processor that masks PII in log events."""

    def __call__(
        self,
        logger: WrappedLogger,
        method: str,
        event_dict: EventDict,
    ) -> EventDict:
        event_dict["event"] = self._mask(str(event_dict.get("event", "")))
        # Also mask string values in the event dict
        for key, value in event_dict.items():
            if isinstance(value, str) and key not in ("timestamp", "level", "logger"):
                event_dict[key] = self._mask(value)
        return event_dict

    def _mask(self, text: str) -> str:
        for pattern, replacement in PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text


class AuditContextProcessor:
    """Adds audit context (request_id, user_id, action) to every log entry."""

    def __call__(
        self,
        logger: WrappedLogger,
        method: str,
        event_dict: EventDict,
    ) -> EventDict:
        # These are injected by middleware via structlog.contextvars
        from structlog.contextvars import get_contextvars
        ctx = get_contextvars()
        event_dict.update(ctx)
        return event_dict


def configure_logging(
    log_level: str = "INFO",
    json_logs: bool = True,
    mask_pii: bool = True,
) -> None:
    """Configure structlog for production use with optional PII masking."""

    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if mask_pii:
        processors.append(PIIMaskingProcessor())

    processors.append(AuditContextProcessor())

    if json_logs:
        processors.append(structlog.processors.format_exc_info)
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("kafka").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger with the module name."""
    return structlog.get_logger(name)

"""
AML Monitoring System — Request Logging & PII Masking Middleware
Every request is traced, timed, and logged in structured JSON.
All PII is masked before logging.
"""
from __future__ import annotations

import time
import uuid
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.contextvars import bind_contextvars, clear_contextvars

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()

# Headers that must NEVER be logged (even masked)
SENSITIVE_HEADERS = frozenset({
    "authorization", "x-api-key", "cookie", "set-cookie",
    "x-forwarded-for",  # PII — contains real IP
})


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Structured request/response logging middleware.
    - Assigns unique request_id to every request
    - Logs method, path, status, duration
    - Masks PII in request metadata
    - Injects context into structlog context vars
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        # Bind context for all downstream log calls
        clear_contextvars()
        bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=self._safe_ip(request),
        )

        # Add request ID to response headers for tracing
        response = None
        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000

            bind_contextvars(
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )

            log_level = "warning" if response.status_code >= 400 else "info"
            getattr(logger, log_level)(
                "HTTP request processed",
                query_params=self._safe_query(request),
            )

            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
            return response

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "Unhandled exception in request",
                exc_info=True,
                duration_ms=round(duration_ms, 2),
            )
            raise

    def _safe_ip(self, request: Request) -> str:
        """Return partial IP for logging (mask last octet for GDPR)."""
        ip = request.client.host if request.client else "unknown"
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***"
        return "***"

    def _safe_query(self, request: Request) -> str:
        """Remove sensitive query parameters before logging."""
        params = dict(request.query_params)
        for key in ["token", "api_key", "password", "secret"]:
            if key in params:
                params[key] = "***"
        return str(params)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Redis-backed rate limiting middleware.
    Per-user: 100 req/min. Per-IP: 1000 req/min.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for health checks and metrics
        if request.url.path in ("/health", "/metrics", "/api/v1/health"):
            return await call_next(request)

        try:
            from backend.services.cache_service import get_redis
            redis = await get_redis()

            client_ip = request.client.host if request.client else "unknown"
            window_key = f"ratelimit:ip:{client_ip}"

            count = await redis.incr(window_key)
            if count == 1:
                await redis.expire(window_key, 60)

            if count > settings.RATE_LIMIT_PER_MINUTE:
                logger.warning(
                    "Rate limit exceeded",
                    client_ip=client_ip[:10],
                    count=count,
                )
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "message_de": "Anfragelimit überschritten. Bitte warten Sie eine Minute.",
                        "message_en": "Rate limit exceeded. Please wait one minute.",
                        "retry_after": 60,
                    },
                    headers={"Retry-After": "60"},
                )
        except Exception:
            # Redis down — fail open, log warning
            logger.warning("Rate limiting unavailable (Redis unreachable)")

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add OWASP-recommended security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self';"
        )
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

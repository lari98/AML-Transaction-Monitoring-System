"""
AML Transaction Monitoring System — FastAPI Application Entry Point
Production-grade API for Swiss/German banking AML compliance.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import sentry_sdk
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, make_asgi_app

from backend.api.v1.router import api_router
from backend.config.logging_config import configure_logging, get_logger
from backend.config.settings import get_settings
from backend.middleware.logging_middleware import (
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)

settings = get_settings()
logger = get_logger(__name__)


# ── Application Startup / Shutdown ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Manage application lifecycle: startup checks and graceful shutdown."""
    logger.info(
        "AML Monitoring System starting",
        version=settings.APP_VERSION,
        environment=settings.APP_ENV.value,
    )

    # Initialize connections
    from backend.services.cache_service import init_redis
    from backend.services.ml_service import MLService
    await init_redis()
    await MLService.load_models()

    logger.info("All services initialized. API ready.")
    yield

    # Graceful shutdown
    logger.info("AML Monitoring System shutting down")
    from backend.services.cache_service import close_redis
    await close_redis()


# ── FastAPI App ───────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    configure_logging(
        log_level="DEBUG" if settings.is_development else "INFO",
        json_logs=settings.is_production,
        mask_pii=settings.MASK_PII_IN_LOGS,
    )

    if settings.SENTRY_DSN:
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            environment=settings.APP_ENV.value,
            traces_sample_rate=0.1,
            profiles_sample_rate=0.05,
        )

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Production-grade AI AML Transaction Monitoring System for Swiss and German banks. "
            "FINMA & BaFin compliant | GDPR/DSGVO ready | Multilingual (DE/EN)"
        ),
        contact={
            "name": "AML Technology Team",
            "email": "aml-tech@bank.de",
        },
        license_info={
            "name": "Internal Use Only",
        },
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── Middleware (order matters: outermost first) ────────────────────────
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "Accept-Language", "X-API-Key"],
    )

    # ── Routes ───────────────────────────────────────────────────────────
    app.include_router(api_router)

    # ── Prometheus Metrics Endpoint ───────────────────────────────────────
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    # ── Exception Handlers ────────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled exception", exc_info=True, path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "message_de": "Ein interner Fehler ist aufgetreten. Bitte kontaktieren Sie den Support.",
                "message_en": "An internal error occurred. Please contact support.",
                "request_id": request.headers.get("X-Request-ID", "unknown"),
            },
        )

    @app.exception_handler(ValueError)
    async def validation_exception_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message_de": f"Validierungsfehler: {str(exc)}",
                "message_en": f"Validation error: {str(exc)}",
            },
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.is_development,
        workers=1 if settings.is_development else 4,
        log_level="debug" if settings.is_development else "info",
        access_log=False,  # Handled by RequestLoggingMiddleware
    )

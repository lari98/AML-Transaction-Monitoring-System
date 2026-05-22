"""
AML Monitoring System — API v1 Router
Assembles all sub-routers with versioning and common dependencies.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.api.v1 import alerts, compliance, gdpr, transactions
from backend.config.settings import get_settings

settings = get_settings()

# -- Main v1 Router -----------------------------------------------------------
api_router = APIRouter(prefix="/api/v1")

# Include all sub-routers
api_router.include_router(transactions.router)
api_router.include_router(alerts.router)
api_router.include_router(gdpr.router)
api_router.include_router(compliance.router)


# -- Auth Router (prefix="/auth" — nested under api_router "/api/v1") ---------
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.post("/token")
async def login(request: Request) -> JSONResponse:
    """OAuth2-compatible token endpoint. Final path: POST /api/v1/auth/token"""
    from backend.core.security import create_access_token, create_refresh_token

    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    # Demo users — in production: validate against Azure AD / DB
    DEMO_USERS = {
        "analyst@bank.de":    {"roles": ["aml_analyst"]},
        "compliance@bank.de": {"roles": ["compliance_officer"]},
        "admin@bank.de":      {"roles": ["data_admin"]},
        "auditor@bank.de":    {"roles": ["auditor"]},
    }

    user = DEMO_USERS.get(username)
    # Accept any password in demo mode (real auth uses bcrypt/Azure AD)
    if not user:
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_credentials",
                "message_de": "Ungueltige Anmeldedaten.",
                "message_en": "Invalid credentials.",
            },
        )

    access_token = create_access_token(subject=username, roles=user["roles"])
    refresh_token = create_refresh_token(subject=username)

    return JSONResponse(content={
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "roles": user["roles"],
        "username": username,
    })


@auth_router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    """Revoke the current access token."""
    from backend.core.auth import revoke_token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        from backend.core.security import decode_token
        try:
            token = auth_header[7:]
            payload = decode_token(token)
            jti = payload.get("jti", "")
            await revoke_token(jti)
        except Exception:
            pass
    return JSONResponse(content={
        "message_de": "Erfolgreich abgemeldet.",
        "message_en": "Logged out successfully.",
    })


api_router.include_router(auth_router)


# -- Health Check -------------------------------------------------------------
@api_router.get("/health", tags=["System"])
async def health_check() -> JSONResponse:
    return JSONResponse(content={
        "status": "healthy",
        "version": settings.APP_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "service": settings.APP_NAME,
        "environment": settings.APP_ENV,
    })

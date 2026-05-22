"""
AML Monitoring System — API v1 Router
Assembles all sub-routers with versioning and common dependencies.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from backend.api.v1 import alerts, gdpr, transactions
from backend.config.settings import get_settings

settings = get_settings()

# ── Main v1 Router ────────────────────────────────────────────────────────────
api_router = APIRouter(prefix="/api/v1")

# Include all sub-routers
api_router.include_router(transactions.router)
api_router.include_router(alerts.router)
api_router.include_router(gdpr.router)


# ── Auth Router ───────────────────────────────────────────────────────────────
auth_router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@auth_router.post("/token")
async def login(request: Request) -> JSONResponse:
    """OAuth2-compatible token endpoint."""
    from fastapi.security import OAuth2PasswordRequestForm
    from fastapi import Form
    from backend.core.security import create_access_token, create_refresh_token, verify_password

    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    # In production: validate against Azure AD / user store
    # Demo: hardcoded test users
    DEMO_USERS = {
        "analyst@bank.de": {
            "password_hash": "$2b$12$EXAMPLEhashfordemopurposes",
            "roles": ["aml_analyst"],
        },
        "compliance@bank.de": {
            "password_hash": "$2b$12$EXAMPLEhashfordemopurposes",
            "roles": ["compliance_officer"],
        },
    }

    user = DEMO_USERS.get(username)
    if not user:
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_credentials",
                "message_de": "Ungültige Anmeldedaten.",
                "message_en": "Invalid credentials.",
            },
        )

    from backend.models.account import TokenResponse
    access_token = create_access_token(subject=username, roles=user["roles"])
    refresh_token = create_refresh_token(subject=username)

    return JSONResponse(content={
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "roles": user["roles"],
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
        "message_de": "Abgemeldet.",
        "message_en": "Logged out.",
    })


api_router.include_router(auth_router)


# ── Health Check ──────────────────────────────────────────────────────────────
@api_router.get("/health", tags=["System"], include_in_schema=False)
async def health_check() -> JSONResponse:
    return JSONResponse(content={
        "status": "healthy",
        "version": settings.APP_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "service": settings.APP_NAME,
    })

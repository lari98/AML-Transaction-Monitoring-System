"""
AML Monitoring System — Authentication
JWT-based authentication with token blacklisting via Redis.
"""
from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings
from backend.core.security import decode_token
from backend.models.account import UserInDB

logger = get_logger(__name__)
settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
) -> UserInDB:
    """
    Decode JWT and return authenticated user.
    Checks Redis token blacklist for revoked tokens.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "not_authenticated",
            "message_de": "Authentifizierung erforderlich.",
            "message_en": "Authentication required.",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub")
        roles: list = payload.get("roles", [])
        jti: str = payload.get("jti", "")

        if not user_id:
            raise credentials_exception

        # Check token blacklist (Redis)
        await _check_token_blacklist(jti)

        return UserInDB(
            id=user_id,
            username=user_id,
            roles=roles,
            is_active=True,
            jti=jti,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Authentication failed", error=str(e))
        raise credentials_exception


async def _check_token_blacklist(jti: str) -> None:
    """Check if a token JTI has been revoked (logout/rotation)."""
    try:
        from backend.services.cache_service import get_redis
        redis = await get_redis()
        if await redis.exists(f"token:blacklist:{jti}"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "token_revoked",
                    "message_de": "Token wurde widerrufen. Bitte erneut anmelden.",
                    "message_en": "Token has been revoked. Please log in again.",
                },
            )
    except HTTPException:
        raise
    except Exception:
        # Redis unavailable — fail open for now (log and alert)
        logger.warning("Redis unavailable for token blacklist check")


async def revoke_token(jti: str, expiry_seconds: int = 7200) -> None:
    """Add a token JTI to the Redis blacklist."""
    try:
        from backend.services.cache_service import get_redis
        redis = await get_redis()
        await redis.setex(f"token:blacklist:{jti}", expiry_seconds, "1")
    except Exception as e:
        logger.error("Failed to revoke token", jti=jti, error=str(e))


async def get_optional_user(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
) -> Optional[UserInDB]:
    """Like get_current_user but returns None if unauthenticated (for public endpoints)."""
    if not token:
        return None
    try:
        return await get_current_user(token)
    except HTTPException:
        return None

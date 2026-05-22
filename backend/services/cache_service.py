"""
AML Monitoring System — Redis Cache Service
Session management, rate limiting, model cache, token blacklist.
"""
from __future__ import annotations

from typing import Optional

import redis.asyncio as aioredis

from backend.config.logging_config import get_logger
from backend.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()

_redis_client: Optional[aioredis.Redis] = None


async def init_redis() -> None:
    """Initialize Redis connection pool at app startup."""
    global _redis_client
    try:
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            password=settings.REDIS_PASSWORD,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50,
        )
        await _redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning("Redis unavailable — caching disabled", error=str(e))
        _redis_client = None


async def close_redis() -> None:
    """Close Redis connection at app shutdown."""
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None


async def get_redis() -> aioredis.Redis:
    """Return the Redis client. Raises if not initialized."""
    if _redis_client is None:
        raise RuntimeError("Redis not initialized")
    return _redis_client

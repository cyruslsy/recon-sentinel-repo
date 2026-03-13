"""
Recon Sentinel — Redis Client
Shared async Redis connection for:
  - JWT token blacklist (Amendment #19)
  - API key rate limiting (Amendment #22)
  - WebSocket pub/sub
  - Scan state caching
"""

import json
import time

import redis.asyncio as aioredis

from app.core.config import get_settings

settings = get_settings()

# Main Redis connection (db 0)
redis_client = aioredis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    max_connections=20,
)


# ─── Token Blacklist (Amendment #19) ─────────────────────────

async def blacklist_token(jti: str, ttl_seconds: int) -> None:
    """Add a JWT token ID to the blacklist with auto-expiry."""
    await redis_client.setex(f"blacklist:{jti}", ttl_seconds, "1")


async def is_token_blacklisted(jti: str) -> bool:
    """Check if a token has been revoked."""
    return await redis_client.exists(f"blacklist:{jti}") > 0


async def blacklist_all_user_tokens(user_id: str) -> None:
    """Revoke all tokens for a user (password change, account disable).
    Sets a 'user_revoked_at' timestamp; tokens issued before this are invalid."""
    await redis_client.set(f"user_revoked:{user_id}", str(int(time.time())))


async def get_user_revoked_at(user_id: str) -> int | None:
    """Get the timestamp after which all tokens for this user are invalid."""
    val = await redis_client.get(f"user_revoked:{user_id}")
    return int(val) if val else None


# ─── API Key Rate Limiting (Amendment #22) ────────────────────

async def check_api_key_rate_limit(ip: str) -> bool:
    """
    Check if an IP is rate-limited for API key attempts.
    10 failures in 60s → 15-minute lockout.
    Returns True if allowed, False if blocked.
    """
    lockout_key = f"api_key_lockout:{ip}"
    if await redis_client.exists(lockout_key):
        return False

    fail_key = f"api_key_fail:{ip}"
    count = await redis_client.incr(fail_key)
    if count == 1:
        await redis_client.expire(fail_key, 60)

    if count > 10:
        await redis_client.setex(lockout_key, 900, "1")  # 15-min lockout
        return False

    return True


async def reset_api_key_rate_limit(ip: str) -> None:
    """Reset rate limit counter on successful auth."""
    await redis_client.delete(f"api_key_fail:{ip}")


# ─── WebSocket Pub/Sub ────────────────────────────────────────

async def publish_scan_event(scan_id: str, event: dict) -> None:
    """Publish a scan event for WebSocket broadcast."""
    await redis_client.publish(f"scan:{scan_id}", json.dumps(event))


async def publish_chat_event(session_id: str, event: dict) -> None:
    """Publish a chat event for streaming."""
    await redis_client.publish(f"chat:{session_id}", json.dumps(event))

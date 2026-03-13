"""
Recon Sentinel — JWT Authentication
Amendments #19 (blacklist), #20 (Docker secrets), #22 (rate limiting)

Auth flow:
  1. Register: bcrypt hash → store in DB
  2. Login: verify password → issue access (15min) + refresh (7d) tokens
  3. Every request: validate JWT → check blacklist → extract user
  4. Logout: blacklist refresh token in Redis (TTL = remaining lifetime)
  5. Password change: blacklist ALL user tokens
"""

import uuid
import hashlib
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redis import (
    blacklist_token, is_token_blacklisted,
    get_user_revoked_at,
    check_api_key_rate_limit, reset_api_key_rate_limit,
)
from app.models.models import User

settings = get_settings()

# ─── Password Hashing ────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─── Token Creation ──────────────────────────────────────────

def create_access_token(user_id: str, role: str) -> str:
    """Short-lived access token (15 min default)."""
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iat": datetime.utcnow(),
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> tuple[str, str, datetime]:
    """Long-lived refresh token (7 day default). Returns (token, jti, expires_at)."""
    expire = datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "type": "refresh",
        "jti": jti,
        "iat": datetime.utcnow(),
        "exp": expire,
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti, expire


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─── Token Revocation (Amendment #19) ────────────────────────

async def revoke_token(jti: str, expires_at: datetime) -> None:
    """Blacklist a specific token by its JTI."""
    ttl = max(int((expires_at - datetime.utcnow()).total_seconds()), 1)
    await blacklist_token(jti, ttl)


# ─── FastAPI Dependencies ────────────────────────────────────

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Authenticate via JWT bearer token or X-API-Key header.
    Checks:
      1. Token blacklist (per-token JTI)
      2. User-level revocation (password change invalidates all tokens)
      3. User exists and is active
    """
    # Try API key first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return await _authenticate_api_key(api_key, request, db)

    # JWT bearer token
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(token)

    # Check token type
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type — use access token")

    # Check per-token blacklist
    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    # Check user-level revocation (password change)
    user_id = payload.get("sub")
    revoked_at = await get_user_revoked_at(user_id)
    if revoked_at:
        token_iat = payload.get("iat", 0)
        if isinstance(token_iat, datetime):
            token_iat = int(token_iat.timestamp())
        if token_iat < revoked_at:
            raise HTTPException(status_code=401, detail="Token invalidated by password change")

    # Load user from DB
    user = await db.get(User, uuid.UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Set on request state for audit middleware (Fix #3)
    request.state.user_id = str(user.id)

    return user


async def _authenticate_api_key(api_key: str, request: Request, db: AsyncSession) -> User:
    """Authenticate via X-API-Key header with rate limiting."""
    client_ip = request.client.host if request.client else "unknown"

    # Rate limit check (Amendment #22)
    if not await check_api_key_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed API key attempts. Locked out for 15 minutes.",
        )

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    result = await db.execute(select(User).where(User.api_key_hash == key_hash))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        # Don't reset rate limit on failure — let it accumulate
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Success — reset rate limit counter
    await reset_api_key_rate_limit(client_ip)
    request.state.user_id = str(user.id)
    return user


# ─── Role-Based Access ───────────────────────────────────────

def require_role(*roles: str):
    """Dependency that checks if the current user has one of the required roles."""
    async def check_role(user: User = Depends(get_current_user)) -> User:
        if user.role.value not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' not authorized. Required: {roles}",
            )
        return user
    return check_role

"""
Recon Sentinel — Database Configuration & Base Model
SQLAlchemy 2.0 async engine with PostgreSQL + asyncpg
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import MetaData, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from starlette.requests import Request

from app.core.config import get_settings
from app.core.tz import utc_now

# Naming convention for consistent constraint names
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=convention)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    metadata = metadata

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    created_at: Mapped[datetime] = mapped_column(default=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class TimestampMixin:
    """Mixin for models that need updated_at tracking."""
    updated_at: Mapped[datetime] = mapped_column(
        default=utc_now, onupdate=utc_now
    )


# ─── Engine & Session ─────────────────────────────────────────

_settings = get_settings()

engine = create_async_engine(
    _settings.DATABASE_URL,
    echo=False,
    pool_size=40,          # Support 10+ concurrent scans
    max_overflow=20,       # Burst capacity
    pool_pre_ping=True,
    pool_timeout=30,       # Seconds to wait for a connection before error
    pool_recycle=1800,     # Recycle connections every 30 min (prevent stale)
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db(request: Request = None) -> AsyncSession:
    """
    FastAPI dependency for database sessions.
    Automatically sets RLS context (app.current_user_id) if the request
    has been authenticated by RLSMiddleware.
    Uses begin() to ensure SET LOCAL persists within the transaction.
    """
    async with AsyncSessionLocal() as session:
        async with session.begin():
            try:
                # Set RLS context if user is authenticated
                if request and hasattr(request, "state") and hasattr(request.state, "rls_user_id"):
                    await session.execute(
                        text("SET LOCAL app.current_user_id = :uid"),
                        {"uid": request.state.rls_user_id},
                    )
                yield session
            except Exception:
                await session.rollback()
                raise


async def get_db_with_rls(user_id: str) -> AsyncSession:
    """Database session with RLS context set inside a transaction."""
    async with AsyncSessionLocal() as session:
        async with session.begin():
            try:
                await session.execute(
                    text("SET LOCAL app.current_user_id = :uid"),
                    {"uid": user_id},
                )
                yield session
            except Exception:
                await session.rollback()
                raise


async def init_db():
    """Create extensions. Tables managed by Alembic."""
    async with engine.begin() as conn:
        await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
        await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "pgcrypto"'))
        await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "pg_trgm"'))

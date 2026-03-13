"""
Recon Sentinel — Secrets & Configuration Loader
Reads from Docker secrets (file-based) with env var fallback.
Amendment #20: Secrets are NEVER stored as plain environment variables.
"""

import os
from pathlib import Path
from functools import lru_cache


def load_secret(name: str, env_fallback: str | None = None, default: str = "") -> str:
    """
    Load a secret value. Priority order:
    1. Docker secret file: /run/secrets/{name}
    2. File pointed to by env var: {NAME}_FILE env var
    3. Direct env var (development only, warns)
    4. Default value
    """
    # 1. Docker secret path
    secret_path = Path(f"/run/secrets/{name}")
    if secret_path.exists():
        return secret_path.read_text().strip()

    # 2. _FILE env var pointing to a secret file
    file_env = f"{name.upper()}_FILE"
    file_path = os.environ.get(file_env)
    if file_path:
        p = Path(file_path)
        if p.exists():
            return p.read_text().strip()

    # 3. Direct env var (development fallback)
    if env_fallback:
        val = os.environ.get(env_fallback)
        if val:
            return val

    return default


from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    DATABASE_URL: str
    REDIS_URL: str
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int
    ANTHROPIC_API_KEY: str
    APP_ENV: str
    LLM_MONTHLY_BUDGET_USD: float
    LLM_MAX_REPLAN_COST_USD: float
    LLM_MAX_REPLAN_ITERATIONS: int


@lru_cache()
def get_settings() -> Settings:
    """Load all application settings. Cached and immutable after first call."""
    db_password = load_secret("db_password", "POSTGRES_PASSWORD", "sentinel")
    db_url_base = os.environ.get("DATABASE_URL", "postgresql+asyncpg://sentinel:@localhost:5432/recon_sentinel")

    # Inject password into URL if placeholder
    if "@" in db_url_base and ":@" in db_url_base:
        db_url = db_url_base.replace(":@", f":{db_password}@")
    else:
        db_url = db_url_base

    return Settings(
        DATABASE_URL=db_url,
        REDIS_URL=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        CELERY_BROKER_URL=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/1"),
        CELERY_RESULT_BACKEND=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/2"),
        JWT_SECRET_KEY=load_secret("jwt_secret", "JWT_SECRET_KEY", "CHANGE-ME-IN-PRODUCTION"),
        JWT_ALGORITHM=os.environ.get("JWT_ALGORITHM", "HS256"),
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15")),
        JWT_REFRESH_TOKEN_EXPIRE_DAYS=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7")),
        ANTHROPIC_API_KEY=load_secret("anthropic_api_key", "ANTHROPIC_API_KEY", ""),
        APP_ENV=os.environ.get("APP_ENV", "development"),
        LLM_MONTHLY_BUDGET_USD=float(os.environ.get("LLM_MONTHLY_BUDGET_USD", "50.00")),
        LLM_MAX_REPLAN_COST_USD=float(os.environ.get("LLM_MAX_REPLAN_COST_USD", "0.50")),
        LLM_MAX_REPLAN_ITERATIONS=int(os.environ.get("LLM_MAX_REPLAN_ITERATIONS", "3")),
    )

    # Reject known weak JWT secrets in non-development environments
    WEAK_SECRETS = {"CHANGE-ME-IN-PRODUCTION", "secret", "changeme", "test", ""}
    if settings.JWT_SECRET_KEY in WEAK_SECRETS and settings.APP_ENV != "development":
        raise RuntimeError(
            f"FATAL: JWT_SECRET_KEY is set to a known weak value ('{settings.JWT_SECRET_KEY[:10]}...'). "
            "Set a strong secret via Docker secret (secrets/jwt_secret) or JWT_SECRET_KEY env var."
        )

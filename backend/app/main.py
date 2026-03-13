"""
Recon Sentinel — FastAPI Application Entry Point
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.database import init_db
from app.core.middleware import AuditMiddleware, RLSMiddleware
from app.api.auth import router as auth_router
from app.api.organizations import router as orgs_router
from app.api.projects import router as projects_router
from app.api.targets import router as targets_router
from app.api.scope import router as scope_router
from app.api.scans import router as scans_router
from app.api.agents import router as agents_router
from app.api.findings import router as findings_router
from app.api.mitre import router as mitre_router
from app.api.credentials import router as credentials_router
from app.api.reports import router as reports_router
from app.api.history import router as history_router
from app.api.chat import router as chat_router
from app.api.notifications import router as notifications_router
from app.api.settings import router as settings_router
from app.api.websocket import router as ws_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create extensions. Shutdown: cleanup."""
    await init_db()
    yield


app = FastAPI(
    title="Recon Sentinel",
    description="AI-Powered External Reconnaissance Platform",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)


# ─── Global Exception Handler ─────────────────────────────────
# Prevents raw Python tracebacks from leaking to clients.
# Without this, unhandled exceptions return stack traces with file paths,
# module names, and internal architecture details.

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions — return generic 500, log the real error."""
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again or contact support."},
    )


# ─── Middleware ────────────────────────────────────────────────
# RLS middleware: sets PostgreSQL session variable from JWT for row-level security
app.add_middleware(RLSMiddleware)

# Audit middleware (Amendment #21): logs all mutations + security events
app.add_middleware(AuditMiddleware)

# CORS: configurable via env var for production deployments
# Default allows localhost dev servers; production should set CORS_ORIGINS
_cors_origins = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173"
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Route Registration ──────────────────────────────────────
PREFIX = "/api/v1"

app.include_router(auth_router,          prefix=f"{PREFIX}/auth",          tags=["Authentication"])
app.include_router(orgs_router,          prefix=f"{PREFIX}/organizations", tags=["Organizations"])
app.include_router(projects_router,      prefix=f"{PREFIX}/projects",      tags=["Projects"])
app.include_router(targets_router,       prefix=f"{PREFIX}/targets",       tags=["Targets"])
app.include_router(scope_router,         prefix=f"{PREFIX}/scope",         tags=["Scope Control"])
app.include_router(scans_router,         prefix=f"{PREFIX}/scans",         tags=["Scans"])
app.include_router(agents_router,        prefix=f"{PREFIX}/agents",        tags=["Agent Runs"])
app.include_router(findings_router,      prefix=f"{PREFIX}/findings",      tags=["Findings"])
app.include_router(mitre_router,         prefix=f"{PREFIX}/mitre",         tags=["MITRE ATT&CK"])
app.include_router(credentials_router,   prefix=f"{PREFIX}/credentials",   tags=["Credentials"])
app.include_router(reports_router,       prefix=f"{PREFIX}/reports",       tags=["Reports"])
app.include_router(history_router,       prefix=f"{PREFIX}/history",       tags=["Scan History"])
app.include_router(chat_router,          prefix=f"{PREFIX}/chat",          tags=["AI Copilot"])
app.include_router(notifications_router, prefix=f"{PREFIX}/notifications", tags=["Notifications"])
app.include_router(settings_router,      prefix=f"{PREFIX}/settings",      tags=["Settings"])
app.include_router(ws_router,            prefix="/ws",                     tags=["WebSocket"])


@app.get("/api/health")
async def health_check():
    """Health check: verifies DB and Redis connectivity for Docker/K8s probes."""
    health = {"status": "ok", "version": "0.1.0", "services": {}}

    # Check PostgreSQL
    try:
        from app.core.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        health["services"]["postgresql"] = "ok"
    except Exception as e:
        health["services"]["postgresql"] = f"error: {str(e)[:100]}"
        health["status"] = "degraded"

    # Check Redis
    try:
        from app.core.redis import redis_client
        await redis_client.ping()
        health["services"]["redis"] = "ok"
    except Exception as e:
        health["services"]["redis"] = f"error: {str(e)[:100]}"
        health["status"] = "degraded"

    status_code = 200 if health["status"] == "ok" else 503
    return JSONResponse(content=health, status_code=status_code)


# ─── Login Rate Limiting ──────────────────────────────────────
# Protect auth endpoints against brute force without adding slowapi dependency.
# Uses Redis counter with sliding window per IP.

@app.middleware("http")
async def login_rate_limit_middleware(request: Request, call_next):
    """Rate limit: 10 login attempts per minute per IP on auth endpoints."""
    if request.url.path in ("/api/v1/auth/login", "/api/v1/auth/register"):
        try:
            from app.core.redis import redis_client
            client_ip = request.client.host if request.client else "unknown"
            key = f"ratelimit:auth:{client_ip}"
            count = await redis_client.incr(key)
            if count == 1:
                await redis_client.expire(key, 60)  # 60-second window
            if count > 10:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many login attempts. Please wait 60 seconds."},
                )
        except Exception:
            pass  # If Redis is down, don't block logins — fail open on rate limiting

    return await call_next(request)

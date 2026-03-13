"""
Recon Sentinel — FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import init_db
from app.core.middleware import AuditMiddleware
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

# ─── Middleware ────────────────────────────────────────────────
# Audit middleware (Amendment #21): logs all mutations + security events
app.add_middleware(AuditMiddleware)

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
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
    return {"status": "ok", "version": "0.1.0"}

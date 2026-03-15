# Recon Sentinel

AI-powered external reconnaissance platform for pentesters.
Author: Cyrus Li · Repo: github.com/cyruslsy/recon-sentinel-repo

## Stack

FastAPI · Next.js 14 · PostgreSQL 16 · Redis 7 · Celery · LiteLLM · Docker Compose (7 prod services)

## Architecture

LangGraph orchestrator with 7 phases: passive → gate_1 → active → gate_2 → replan → vuln → report.
17 scanning agents, 3 phases, per-subdomain fan-out. 11 self-correction patterns.
13 authorize_* helpers (every endpoint). RLS on 5 tables. JWT auth (admin/tester/auditor).

Scan profiles: full (2 gates), passive_only, quick (1 gate), stealth, bounty (auto-approve).
LLM: configurable via `LLM_PRESET` env var (claude/free/gemini/openai). See `.env.llm.example`.

## Build & Run

```bash
# Production
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml logs -f api worker

# Restart (Python changes only — no rebuild)
docker compose -f docker-compose.prod.yml restart api worker

# Rebuild (Dockerfile/requirements changes)
docker compose -f docker-compose.prod.yml up -d --build api worker

# Database
docker compose -f docker-compose.prod.yml exec api alembic upgrade head
docker compose -f docker-compose.prod.yml exec postgres psql -U sentinel -d recon_sentinel

# Tests
docker compose -f docker-compose.prod.yml exec api python -m pytest tests/ -v

# Switch LLM
LLM_PRESET=free docker compose -f docker-compose.prod.yml restart api worker
```

## Key Files

- `docs/MASTER-PLAN.md` — Implementation plan (37 items, 7 phases). Read before any feature work.
- `docs/TECHNICAL-DEBT.md` — Known issues and stats.
- `CHANGELOG.md` — What changed recently.
- `.claude/rules/` — Coding rules by domain (backend, frontend, agents, database, docker).

## Known Broken Pipes

These exist in the DB but are NOT exposed via API:
1. `Finding.raw_data` (JSONB with curl commands, Shodan data) — missing from FindingResponse schema
2. `Screenshot` table (11 columns) — no API endpoint, no frontend display
3. `Report` branding fields (company_name, logo) — backend ignores during PDF generation

## Compact Instructions

When compacting, always preserve: the current task being worked on, list of all modified files, and any pending three-layer consistency checks.

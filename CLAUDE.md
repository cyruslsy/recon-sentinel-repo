# Recon Sentinel

AI-powered external reconnaissance platform for pentesters.
Author: Cyrus Li · Repo: github.com/cyruslsy/recon-sentinel-repo

## Stack

FastAPI · Next.js 14 · PostgreSQL 16 · Redis 7 · Celery · LiteLLM · Docker Compose (8 prod services)

## Architecture

LangGraph orchestrator with 7 phases: passive → gate_1 → active → gate_2 → replan → vuln → report.
18 scanning agents (17 original + web_spider), 3 phases, per-subdomain fan-out. 11 self-correction patterns.
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

- `docs/MASTER-PLAN.md` — Implementation plan (55 items, Phase 0 + A-I). Read before any feature work.
- `docs/design/data-flow.md` — What each agent produces and who consumes it.
- `docs/design/three-layer-contract.md` — Every field across DB → Schema → Types → Frontend.
- `docs/design/ux-wireframes.md` — 16 pages with purpose, data source, states, design tokens.
- `docs/design/review-checklist.md` — 30 questions. Run before starting any phase.
- `docs/TECHNICAL-DEBT.md` — Known issues and stats.
- `CHANGELOG.md` — What changed recently.

## Current Progress

Phases A-C complete. Immediate fixes mostly done. Currently testing with bounty scan.
Next: Phase D (Finding Quality) → Phase E (Intelligence Layer — THE DIFFERENTIATOR).

## Known Broken Pipes

1. `Report` branding fields: primary_color, logo_path, included_sections, ai_executive_summary — in DB, NOT in ReportResponse schema (F6)
2. `Screenshot` table — API endpoint exists now but frontend doesn't display images yet
3. Report section toggles — all set to disabled: false (F4 incomplete)

## Compact Instructions

When compacting, always preserve: the current task being worked on, list of all modified files, and any pending three-layer consistency checks.

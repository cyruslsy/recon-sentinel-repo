# Recon Sentinel — Claude Code Context

## What This Is

AI-powered external reconnaissance platform for pentesters. Automated scanning with LangGraph orchestration, AI approval gates, 17 scanning agents, self-correction, and MITRE ATT&CK mapping.

**Author:** Cyrus Li · **Repo:** https://github.com/cyruslsy/recon-sentinel-repo

## Stack

FastAPI + Next.js 14 + PostgreSQL 16 + Redis 7 + Celery + LiteLLM + Docker Compose

## Critical Rules — READ BEFORE EDITING

### Rule 1: Three-Layer Consistency

Every change must be consistent across all three layers. This is the #1 source of bugs.

| Layer | Files | Check |
|-------|-------|-------|
| Database | `enums.py` → `models.py` → Alembic migration | New enum? Add `ALTER TYPE ADD VALUE IF NOT EXISTS` in migration. |
| Backend | `schemas.py` → `api/*.py` endpoint | New field? Add to Pydantic schema AND route's `response_model`. |
| Frontend | `types.ts` → `api.ts` → page component | New field? Add to TypeScript interface, API client, and component. |

After every change, list which files across all three layers were affected.

### Rule 2: SQLAlchemy ORM Objects Are Immutable for Extra Attributes

```python
# NEVER — crashes at runtime:
scan.target_value = "example.com"

# ALWAYS — convert to dict:
d = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
d["extra_field"] = computed_value
```

### Rule 3: Enum Values Require Migrations

Python enum changes auto-propagate. PostgreSQL enum types do NOT.
```sql
ALTER TYPE enum_name ADD VALUE IF NOT EXISTS 'new_value';
```

### Rule 4: Verify Before and After Every Edit

- `view` the file before editing (context may be stale)
- `view` again after editing to confirm
- Check for dead code after `return` statements
- Verify imports for new functions/classes

### Rule 5: Post-Change Summary

After changes, output:
```
## Changes Made
- Files modified: [list]
- Three-layer impact: [enums? schemas? types? migrations?]
- Tests to run: [which test files]
```

## Architecture

```
LangGraph Orchestrator: passive → gate_1 → active → gate_2 → replan → vuln → report
17 Agents across 3 phases with per-subdomain fan-out in active phase
11 Self-correction patterns in corrections.py
13 authorize_* helpers — every endpoint must use one
Row-level security on 5 tables via PostgreSQL RLS policies
```

**Scan profiles:** full (2 gates), passive_only (0 gates), quick (1 gate), stealth (1 gate, no vuln), bounty (0 gates, auto-approve)

**LLM routing:** Haiku for routing/replan/diff (~$0.015), Sonnet for gates/reports/chat (~$0.19)

## Project Layout

```
backend/
├── app/
│   ├── agents/          # 17 scanning agents + base.py + corrections.py + tech_context.py
│   ├── api/             # 17 route files, 93 REST + 2 WebSocket endpoints
│   ├── core/            # celery_app.py, config.py, llm.py, security.py, database.py
│   ├── models/          # enums.py + models.py (32 tables)
│   ├── schemas/         # schemas.py (Pydantic request/response)
│   └── tasks/           # orchestrator.py, reports.py, diff.py, notifications.py
├── alembic/versions/    # 7 migrations (0002-0007)
├── tests/               # 91 tests across 12 suites
frontend/
├── src/app/             # 14 Next.js pages
├── src/components/      # Sidebar, AppLayout, SafeHtml, ScanSelector, ErrorBoundary
├── src/lib/             # api.ts, types.ts, auth.tsx, scan-context.tsx
├── src/hooks/           # useWebSocket.ts
```

## Docker Services (Production)

| Service | Container | Port | Purpose |
|---------|-----------|------|---------|
| PostgreSQL 16 | sentinel-postgres | 5432 (internal) | Primary database |
| Redis 7 | sentinel-redis | 6379 (internal) | Celery broker + WebSocket pub/sub |
| FastAPI | sentinel-api | 8000 (internal) | REST API + WebSocket |
| Celery Worker | sentinel-worker | — | Agent execution |
| Celery Beat | sentinel-beat | — | Scheduled monitoring |
| Nginx | sentinel-nginx | 80/443 | Reverse proxy + TLS |
| DB Init | sentinel-db-init | — | Migrations on startup |

## Common Commands

```bash
# Logs
docker compose -f docker-compose.prod.yml logs -f api
docker compose -f docker-compose.prod.yml logs -f worker
docker compose -f docker-compose.prod.yml logs --tail=50 api worker

# Restart single service
docker compose -f docker-compose.prod.yml restart api
docker compose -f docker-compose.prod.yml restart worker

# Rebuild after Dockerfile/requirements change
docker compose -f docker-compose.prod.yml up -d --build api worker

# Database
docker compose -f docker-compose.prod.yml exec postgres psql -U sentinel -d recon_sentinel

# Run migrations
docker compose -f docker-compose.prod.yml exec api alembic upgrade head

# Celery inspection
docker compose -f docker-compose.prod.yml exec worker celery -A app.core.celery_app inspect active
docker compose -f docker-compose.prod.yml exec worker celery -A app.core.celery_app inspect reserved

# Tests (if test DB configured)
docker compose -f docker-compose.prod.yml exec api python -m pytest tests/ -v

# Full rebuild (nuclear option — use only when Dockerfile changes)
docker compose -f docker-compose.prod.yml down
docker compose -f docker-compose.prod.yml up -d --build
```

## Key Models

**Finding** (the central model — all agents write here):
- id, scan_id, agent_run_id, finding_type (enum), severity (enum)
- confidence (Integer 0-100, nullable — NOT YET POPULATED by agents)
- value (String 2000), detail (Text), raw_data (JSONB)
- mitre_technique_ids (ARRAY), tags (ARRAY)
- is_false_positive, verification_status, severity_override
- fingerprint (dedup key)

**Known broken pipe:** raw_data and remediation exist in DB but are NOT in FindingResponse schema → frontend can't see them. Fix: add to schemas.py FindingResponse.

**Scan** (32 fields): target_id, profile, status, phase, langgraph_checkpoint, finding counts, rate_limit, stealth_level

**AgentRun**: scan_id, agent_type, status, phase, progress_pct, findings_count, duration_seconds, target_host

## Known Issues (Current)

1. **raw_data not in FindingResponse schema** — Nuclei curl commands, Shodan data invisible to frontend
2. **remediation field only on Vulnerability table**, not on Finding model
3. **Screenshot table exists** but no API endpoint or frontend display
4. **confidence field never populated** — exists in DB, types.ts shows "—"
5. **Report "Attack Chain" and "Methodology" toggles** — frontend has them, backend doesn't generate them

## Master Plan (37 items, 7 phases)

**Phase A: Foundation (2d)** — DB retry, tool pre-flight, LLM degradation
**Phase B: Tool Upgrades (5d)** — puredns+massdns+n0kovo, katana, gau, subdomain permutation
**Phase C: Cross-Phase Intel (3.5d)** — wayback→dir/file, WAF proactive, tech ports, baseline, vuln tech_context
**Phase D: Finding Quality (5.5d)** — confidence scoring, evidence enrichment, source maps, CORS, DNS zone transfer
**Phase E: Intelligence Layer (8d)** — AttackScenario model, cross-correlation, 6 scenario templates, AI narrative, posture scoring
**Phase F: Report + Frontend (5d)** — report redesign, /scenarios page, scan time estimation
**Phase G: Optimization (10d)** — progressive depth, root domain discovery, testssl.sh, Dalfox

**Immediate fixes (before Phase A):** Add raw_data + remediation to FindingResponse. Add page subtitles. Screenshot API. Disable non-functional report toggles.

**Phase E requires migration 0008:** AttackScenario table + attack_scenario_findings junction table + Finding.remediation column + Finding.linked_scenario_count column + ScenarioType enum.

## Agent Pattern (How to Add a New Agent)

```python
# 1. Create backend/app/agents/my_agent.py
class MyAgent(BaseAgent):
    agent_type = "my_agent"
    agent_name = "My Agent"
    phase = ScanPhase.ACTIVE  # or PASSIVE or VULN
    mitre_tags = ["T1190"]

    async def execute(self) -> list[dict]:
        # Your scanning logic here
        findings = []
        findings.append({
            "finding_type": FindingType.VULNERABILITY,
            "severity": FindingSeverity.HIGH,
            "value": "what was found",
            "detail": "description with evidence",
            "mitre_technique_ids": ["T1190"],
            "fingerprint": hashlib.sha256(f"unique:{key}".encode()).hexdigest()[:32],
            "raw_data": {"key": "value"},
            "tags": ["tag1"],
        })
        return findings

# 2. Add Celery task at bottom of file
@celery_app.task(name="app.agents.my_agent.run_my_agent")
def run_my_agent(scan_id, target_value, project_id, config=None):
    return asyncio.run(MyAgent(scan_id, target_value, project_id, config).run())

# 3. Register in orchestrator.py _get_passive_agents() or _get_active_agents()
# 4. If new FindingType enum value: add to enums.py + migration
# 5. If new tool binary: add to Dockerfile Stage 2 (Go) or Stage 3 (Runtime)
```

## Debugging Checklist

When something breaks, check in this order:

1. **Docker logs:** `docker compose -f docker-compose.prod.yml logs --tail=100 api worker`
2. **Is the service running?** `docker compose -f docker-compose.prod.yml ps`
3. **Database connection?** `docker compose -f docker-compose.prod.yml exec api python -c "from app.core.database import engine; print('OK')"`
4. **Redis connection?** `docker compose -f docker-compose.prod.yml exec api python -c "import redis; r=redis.Redis(); r.ping(); print('OK')"`
5. **Migrations current?** `docker compose -f docker-compose.prod.yml exec api alembic current`
6. **Celery workers alive?** `docker compose -f docker-compose.prod.yml exec worker celery -A app.core.celery_app inspect ping`
7. **Secrets mounted?** `docker compose -f docker-compose.prod.yml exec api ls /run/secrets/`

## Files to Read First

When starting any task, read these in order:
1. `CHANGELOG.md` — what changed recently
2. `docs/TECHNICAL-DEBT.md` — known issues and stats
3. The specific files you'll be editing (always `view` before editing)

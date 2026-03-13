# Development Setup

## Prerequisites

- Docker Desktop (4.0+) with 8GB+ RAM allocated
- Node.js 18+ (for frontend)
- Python 3.11+ (for running tests locally)
- Git

## Quick Start

```bash
# Clone
git clone https://github.com/cyruslsy/recon-sentinel-repo.git
cd recon-sentinel-repo

# Generate secrets
cd secrets && bash generate.sh && cd ..
echo "your-anthropic-api-key" > secrets/anthropic_api_key

# Start all services
docker compose up -d --build

# Run migrations
docker compose exec api alembic upgrade head

# Start frontend dev server
cd frontend && npm install && npm run dev
```

Open http://localhost:3000

## Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | Register on first use |
| API (Swagger) | http://localhost/api/docs | JWT token |
| API (ReDoc) | http://localhost/api/redoc | — |
| Flower (Celery monitor) | http://localhost:5555 | admin / sentinel |
| PostgreSQL | localhost:5432 | sentinel / (from secrets/db_password) |
| Redis | localhost:6379 | — |

## Running Tests

```bash
# Install test dependencies
cd backend && pip install -r requirements.txt

# Run all tests
cd .. && python -m pytest tests/ -v

# Run specific suite
python -m pytest tests/test_auth.py -v

# Run with coverage
python -m pytest tests/ --cov=backend/app --cov-report=html
```

## Project Layout

```
backend/app/
├── core/          # Infrastructure: auth, database, celery, LLM, middleware
├── models/        # SQLAlchemy ORM models + enums
├── schemas/       # Pydantic request/response schemas
├── api/           # FastAPI route handlers (15 modules)
├── agents/        # 13 scanning agents + base class + evasion + corrections
└── tasks/         # Celery tasks: orchestrator, reports, diff, notifications
```

## Adding a New Agent

1. Create `backend/app/agents/your_agent.py`
2. Inherit from `BaseAgent`, implement `execute()` → return `list[dict]` of findings
3. Register Celery task: `@celery_app.task(name="app.agents.your_agent.run_your_agent")`
4. Add to orchestrator phase in `tasks/orchestrator.py`
5. Add queue name to `celery_app.py` task routes
6. Add queue to docker-compose.yml worker `--queues` list
7. Write tests in `tests/test_your_agent.py`

## Common Commands

```bash
# View logs
docker compose logs -f api
docker compose logs -f celery-worker

# Rebuild after code changes
docker compose up -d --build api celery-worker

# Access database
docker compose exec postgres psql -U sentinel -d recon_sentinel

# Check Celery tasks
docker compose exec celery-worker celery -A app.core.celery_app inspect active

# Create new Alembic migration
docker compose exec api alembic revision --autogenerate -m "description"
docker compose exec api alembic upgrade head
```

## Environment Variables

See `.env.example` for all configuration options. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MONTHLY_BUDGET_USD` | 50.00 | Monthly LLM spend cap |
| `LLM_MAX_REPLAN_ITERATIONS` | 3 | Max re-plan cycles per scan |
| `CELERY_WORKER_CONCURRENCY` | 4 | Parallel agent tasks |
| `DATA_RETENTION_DAYS` | 90 | Auto-archive scans after N days |

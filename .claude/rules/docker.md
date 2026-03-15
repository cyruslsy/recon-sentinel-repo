---
paths:
  - "**/Dockerfile"
  - "**/docker-compose*"
  - "**/.env*"
---
# Docker Rules

## Multi-Stage Dockerfile

- Stage 1 (py-builder): Python deps only
- Stage 2 (go-builder): Go tool binaries (subfinder, naabu, httpx, nuclei, ffuf, gowitness)
- Stage 3 (runtime): Slim image, copies from both builders

New Go tools: add to Stage 2 `go install`, copy in Stage 3 `COPY --from=go-builder`.
New Python packages: add to `requirements.txt` (installed in Stage 1).
New system packages: add to Stage 3 `apt-get install`.

## Services

| Service | Container | Restarts on code change? |
|---------|-----------|------------------------|
| sentinel-api | FastAPI | Yes, if volume-mounted with --reload |
| sentinel-worker | Celery | Needs restart: `docker compose restart worker` |
| sentinel-postgres | PostgreSQL | Never restart unless migration needed |
| sentinel-redis | Redis | Never restart |
| sentinel-nginx | Nginx | Only restart if nginx.conf changes |

## When to Rebuild vs Restart

- Python code change → `restart api worker`
- requirements.txt change → `up -d --build api worker`
- Dockerfile change (new tool) → `up -d --build api worker`
- docker-compose.yml change → `up -d`
- Alembic migration → `exec api alembic upgrade head`

Rebuild and redeploy the specified services (or all if none specified).

Steps:
1. Check what changed: git diff --stat HEAD
2. Determine if Dockerfile rebuild is needed (new packages, new Go tools) or just restart (Python code changes)
3. If Dockerfile changed: docker compose -f docker-compose.prod.yml up -d --build $ARGUMENTS
4. If only Python/config: docker compose -f docker-compose.prod.yml restart $ARGUMENTS
5. Run migrations if model changes detected: docker compose -f docker-compose.prod.yml exec api alembic upgrade head
6. Verify all services healthy: docker compose -f docker-compose.prod.yml ps
7. Check logs for startup errors: docker compose -f docker-compose.prod.yml logs --tail=20 api worker

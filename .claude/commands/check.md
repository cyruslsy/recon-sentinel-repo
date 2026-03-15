Run a comprehensive health check on all services.

Check each of these and report status:

1. Docker services: docker compose -f docker-compose.prod.yml ps
2. API health: curl -s http://localhost/api/health | jq
3. Database: docker compose -f docker-compose.prod.yml exec postgres pg_isready -U sentinel
4. Redis: docker compose -f docker-compose.prod.yml exec redis redis-cli ping
5. Celery workers: docker compose -f docker-compose.prod.yml exec worker celery -A app.core.celery_app inspect ping 2>&1
6. Migrations: docker compose -f docker-compose.prod.yml exec api alembic current 2>&1
7. Disk space: df -h /
8. Memory: free -h
9. Docker disk: docker system df

Report as a table: Service | Status | Details
Flag any issues that need attention.

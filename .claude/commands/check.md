Health check all services. Report as table.

1. `docker compose -f docker-compose.prod.yml ps`
2. `curl -s http://localhost/api/health | jq` (or python json)
3. `docker compose -f docker-compose.prod.yml exec redis redis-cli ping`
4. `docker compose -f docker-compose.prod.yml exec api alembic current 2>&1`
5. `df -h /` and `free -h`

Report: Service | Status | Details
Flag anything unhealthy.

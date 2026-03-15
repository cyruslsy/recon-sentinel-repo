Smart rebuild. Detects what changed and does minimum work.

1. `git diff --stat HEAD` to see what changed
2. If Dockerfile/requirements changed → `docker compose -f docker-compose.prod.yml up -d --build $ARGUMENTS`
3. If only Python/config → `docker compose -f docker-compose.prod.yml restart $ARGUMENTS`
4. If models changed → also run `exec api alembic upgrade head`
5. Verify: `docker compose -f docker-compose.prod.yml ps` + check logs

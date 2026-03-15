Run tests. If $ARGUMENTS specified, run that test file. Otherwise run all.

1. `docker compose -f docker-compose.prod.yml exec api python -m pytest tests/$ARGUMENTS -v --tb=short 2>&1`
2. Report: total, passed, failed
3. For failures: read test + source, identify bug, fix, re-run

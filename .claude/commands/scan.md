Launch a test scan and monitor. Default: scanme.nmap.org passive_only.

1. Get auth token from API
2. Create org/project/target if needed
3. Launch scan: POST /api/scans/ with target=$ARGUMENTS and profile=passive_only
4. Monitor: `docker compose -f docker-compose.prod.yml logs -f worker --since=1m`
5. Report findings count by type and severity

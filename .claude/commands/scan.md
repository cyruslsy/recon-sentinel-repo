Launch a test scan and monitor it. Default target: scanme.nmap.org with passive_only profile.

Steps:
1. Get auth token: curl -s -X POST http://localhost/api/auth/login -H "Content-Type: application/json" -d '{"email":"admin@sentinel.local","password":"<check secrets>"}' | jq -r '.access_token'
2. If no user exists, check: docker compose -f docker-compose.prod.yml exec postgres psql -U sentinel -d recon_sentinel -c "SELECT email FROM users LIMIT 5;"
3. Launch scan:
   - Create org if needed: POST /api/organizations/
   - Create project: POST /api/projects/
   - Create target: POST /api/targets/ with target_value=$ARGUMENTS or "scanme.nmap.org"
   - Launch scan: POST /api/scans/ with profile="passive_only"
4. Monitor: watch the worker logs for agent progress
   docker compose -f docker-compose.prod.yml logs -f worker --since=1m
5. Check results:
   GET /api/scans/{scan_id}
   GET /api/findings/?scan_id={scan_id}
6. Report: number of findings by type and severity

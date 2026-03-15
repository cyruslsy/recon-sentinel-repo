Read docker logs, find the error, fix it, verify.

1. `docker compose -f docker-compose.prod.yml logs --tail=50 api worker 2>&1`
2. If error found: read the failing file, propose fix, apply it
3. Restart: `docker compose -f docker-compose.prod.yml restart <service>`
4. Verify: check logs again to confirm fix
5. Check three-layer consistency if the fix changes any model/schema/type

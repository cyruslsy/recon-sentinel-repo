Read the docker compose production logs for the failing service and diagnose the issue. Check logs for api and worker first. If the error is clear, propose a fix with the exact file and line to change. Always verify three-layer consistency (DB model → Pydantic schema → types.ts → frontend) for any fix.

Steps:
1. Run: docker compose -f docker-compose.prod.yml logs --tail=50 api worker 2>&1
2. If error is in a specific service, get more logs: docker compose -f docker-compose.prod.yml logs --tail=100 <service>
3. Read the file where the error occurs
4. Propose and apply the fix
5. Restart the affected service: docker compose -f docker-compose.prod.yml restart <service>
6. Verify the fix by checking logs again

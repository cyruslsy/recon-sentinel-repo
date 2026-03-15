# Security Rules (ALWAYS ENFORCE)

- Every API endpoint MUST use an `authorize_*` helper from `authorization.py`
- Never trust client-side input. Validate server-side with Pydantic schemas.
- Never store secrets as plain environment variables. Use Docker secrets (`/run/secrets/`).
- RLS policies exist on 5 tables. Never bypass with direct SQL unless you re-verify authorization.
- Scan scope is enforced. Never allow an agent to scan targets outside `scope_definitions`.
- JWT tokens expire. Always handle 401 gracefully in frontend.
- CSV exports must sanitize against formula injection (prefix `=`, `+`, `-`, `@` with `'`).

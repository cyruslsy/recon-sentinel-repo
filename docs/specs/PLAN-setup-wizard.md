# Plan: Setup Wizard

## Task 1: Add `setup_completed` to User model + migration + DB
- Files:
  - `backend/app/models/models.py`
  - `backend/app/api/auth.py`
- Changes:
  - Add `setup_completed: Mapped[bool] = mapped_column(Boolean, default=False)` to `User` class in models.py
  - Add `setup_completed: bool` field to `UserProfileResponse` in auth.py
  - Update `get_profile` endpoint to include `setup_completed=user.setup_completed`
  - Add new endpoint `POST /api/v1/auth/complete-setup` that sets `user.setup_completed = True` and flushes
  - Run raw SQL to add the column: `ALTER TABLE users ADD COLUMN setup_completed BOOLEAN NOT NULL DEFAULT false;`
- Verify:
  ```bash
  docker compose -f docker-compose.prod.yml up -d --build api
  sleep 20
  # Register a user and check /me includes setup_completed
  curl -s http://localhost:8000/api/v1/auth/setup-status
  ```
- Depends: none

## Task 2: Add nginx route for complete-setup endpoint
- Files:
  - `nginx/nginx.prod.conf`
- Changes:
  - Add `location = /api/v1/auth/complete-setup` block without rate limiting (same pattern as `/me` and `/setup-status`)
- Verify:
  ```bash
  docker compose -f docker-compose.prod.yml restart nginx
  curl -sk https://localhost/api/v1/auth/setup-status
  ```
- Depends: Task 1

## Task 3: Update frontend types and API client
- Files:
  - `frontend/src/lib/types.ts`
  - `frontend/src/lib/api.ts`
- Changes:
  - Add `setup_completed: boolean` to `User` interface in types.ts
  - Add `completeSetup` method to api object in api.ts:
    ```typescript
    completeSetup: () => request<{ status: string }>("/auth/complete-setup", { method: "POST" }),
    ```
- Verify: TypeScript compile check during build (Task 5)
- Depends: Task 1

## Task 4: Add setup guard to AppLayout + update login/register redirects
- Files:
  - `frontend/src/components/AppLayout.tsx`
  - `frontend/src/app/login/page.tsx`
  - `frontend/src/app/register/page.tsx`
- Changes:
  - **AppLayout.tsx**: After the `if (!loading && !user)` check, add: `if (!loading && user && !user.setup_completed) { router.push("/setup"); return null; }`
  - **login/page.tsx**: In `handleLogin` and `handleSetup`, after auth succeeds, check the returned user profile. If `!setup_completed`, `router.push("/setup")` instead of `/dashboard`
  - **register/page.tsx**: Same — after `register()`, route to `/setup` instead of `/dashboard`
- Verify: Build check (Task 5)
- Depends: Task 3

## Task 5: Create setup wizard page
- Files:
  - `frontend/src/app/setup/page.tsx` (NEW)
- Changes:
  - Create multi-step wizard with 4 steps using React state
  - **Step 1 — Create Organization**: Form with name + description fields. Calls `api.createOrg()`. Stores returned org ID in state.
  - **Step 2 — Create Project**: Form with name field. Calls `api.createProject(orgId, { name })`. Stores returned project ID in state.
  - **Step 3 — Configure API Key**: Form with service name dropdown (anthropic, shodan, virustotal, hibp) + API key input. Calls `api.addApiKey()`. Show success confirmation.
  - **Step 4 — Add Target (Optional)**: Form with target_value + input_type dropdown (domain, ip, cidr, url). Has "Add Target" and "Skip & Finish" buttons. Calls `api.createTarget(projectId, data)` if not skipped.
  - **Completion**: Calls `api.completeSetup()` then `router.push("/dashboard")`
  - **UI Pattern**: Follow sentinel design tokens (dark theme, sentinel-* colors). Step indicator at top showing progress. Each step in a card. Back button on steps 2-4 (but not to go before step 1). No skip on steps 1-3.
  - **Auth guard**: Check `useAuth()` — if no user, redirect to login. If `user.setup_completed`, redirect to dashboard (already done, don't show wizard again).
- Verify:
  ```bash
  docker compose -f docker-compose.prod.yml up -d --build frontend
  # Test in browser: clear users, register, verify redirect to /setup
  ```
- Depends: Task 3, Task 4

## Task 6: Rebuild and end-to-end test
- Files: none (verification only)
- Changes: none
- Verify:
  ```bash
  # Reset state
  docker compose -f docker-compose.prod.yml exec postgres psql -U sentinel -d recon_sentinel -c "DELETE FROM users;"
  # Rebuild all
  docker compose -f docker-compose.prod.yml up -d --build api frontend
  docker compose -f docker-compose.prod.yml restart nginx
  # Verify setup-status
  curl -sk https://localhost/api/v1/auth/setup-status  # needs_setup: true
  # Register via API
  curl -s -X POST http://localhost:8000/api/v1/auth/register -H "Content-Type: application/json" -d '{"email":"test@example.com","password":"TestPass123","display_name":"Test"}'
  # Check /me includes setup_completed=false
  TOKEN=<from above>
  curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer $TOKEN"
  # Complete setup via API
  curl -s -X POST http://localhost:8000/api/v1/auth/complete-setup -H "Authorization: Bearer $TOKEN"
  # Verify setup_completed=true
  curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer $TOKEN"
  ```
- Depends: Task 1-5

## Execution Order

```
Task 1 (DB + backend) → Task 2 (nginx) → Task 3 (frontend types) → Task 4 (guards) → Task 5 (wizard page) → Task 6 (E2E test)
```

Total: 6 tasks, ~9 files modified/created.

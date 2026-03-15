# SPEC: Post-Login Setup Wizard

## Current State

- After login/register, users are sent directly to `/dashboard`
- No guidance on what to configure first
- Fresh install has no orgs, projects, targets, or API keys
- Dashboard shows empty state with no actionable next steps
- `AppLayout` guards routes (redirects to `/login` if not authenticated) but has no setup awareness

## Target State

After the first admin logs in (or any user who hasn't completed setup), they are redirected to a multi-step setup wizard at `/setup` before reaching the dashboard. The wizard is **non-skippable** and shows every time until all required steps are completed.

### Wizard Steps

| Step | Required | What | API Call |
|------|----------|------|----------|
| 1. Create Organization | Yes | Name + optional description | `POST /api/v1/organizations/` |
| 2. Create Project | Yes | Name under the new org | `POST /api/v1/projects/?org_id={id}` |
| 3. Configure LLM API Key | Yes | Add Anthropic/other API key | `POST /api/v1/settings/api-keys` |
| 4. Add First Target | No (optional) | Domain/IP to scan | `POST /api/v1/targets/?project_id={id}` |

After completing required steps (1-3), user can finish and go to dashboard. Step 4 is shown but has a "Skip & Finish" option.

### Behavior Rules

- **Non-skippable**: No way to bypass required steps 1-3
- **Persistent**: Shows on every login until completed (tracked via backend)
- **Resumable**: If user completes step 1 but leaves, next login resumes at step 2
- **Admin-only initially**: First user is admin (already implemented), wizard runs for them
- **Other users**: Non-admin users also see wizard if they have no org/project access

## Three-Layer Changes

### Database Layer

**New column on `users` table:**
```sql
ALTER TABLE users ADD COLUMN setup_completed BOOLEAN NOT NULL DEFAULT false;
```

No new migration file needed — use Alembic.

**Model change:**
```python
# models.py - User class
setup_completed: Mapped[bool] = mapped_column(Boolean, default=False)
```

### Backend Layer

**1. Update User model** (`backend/app/models/models.py`)
- Add `setup_completed` field

**2. Update UserProfileResponse schema** (`backend/app/schemas/schemas.py` or `backend/app/api/auth.py`)
- Add `setup_completed: bool` to the response so frontend knows

**3. New endpoint: `POST /api/v1/auth/complete-setup`** (`backend/app/api/auth.py`)
- Marks `user.setup_completed = True`
- Requires auth (JWT)
- Returns `{"status": "ok"}`

**4. Update `GET /api/v1/auth/me`** response
- Already returns `UserProfileResponse` — just add the field

### Frontend Layer

**1. Update types** (`frontend/src/lib/types.ts`)
- Add `setup_completed: boolean` to `User` interface

**2. Update API client** (`frontend/src/lib/api.ts`)
- Add `completeSetup: () => request<{status: string}>("/auth/complete-setup", { method: "POST" })`

**3. Update AppLayout** (`frontend/src/components/AppLayout.tsx`)
- After auth check, if `!user.setup_completed`, redirect to `/setup`

**4. Update login/register pages**
- After successful login: check `user.setup_completed`, route to `/setup` or `/dashboard`

**5. New page: `/setup`** (`frontend/src/app/setup/page.tsx`)
- Multi-step wizard component
- Steps: CreateOrg → CreateProject → AddApiKey → (Optional) AddTarget
- Each step calls the existing API endpoints
- On final completion, calls `POST /auth/complete-setup` then `router.push("/dashboard")`

## Files to Modify

| File | Change |
|------|--------|
| `backend/app/models/models.py` | Add `setup_completed` to User |
| `backend/app/api/auth.py` | Add `complete-setup` endpoint, update `UserProfileResponse` |
| `backend/alembic/versions/xxxx_add_setup_completed.py` | New migration |
| `frontend/src/lib/types.ts` | Add `setup_completed` to User |
| `frontend/src/lib/api.ts` | Add `completeSetup()` method |
| `frontend/src/components/AppLayout.tsx` | Redirect to `/setup` if not completed |
| `frontend/src/app/login/page.tsx` | Route to `/setup` instead of `/dashboard` if needed |
| `frontend/src/app/register/page.tsx` | Same as login |
| `frontend/src/app/setup/page.tsx` | **NEW** — wizard page |

## Dependencies

- Existing org/project/target/settings API endpoints (all working)
- Auth system (JWT, `/auth/me` — working)
- Fernet encryption for API keys (working)

## Risks & Edge Cases

1. **Race condition**: Two users registering simultaneously — both could be "first user". Mitigated by DB-level uniqueness and the fact that `setup_completed` is per-user.
2. **API key encryption**: Requires `JWT_SECRET_KEY` to be set. If not set, Fernet will fail. Already handled in existing code.
3. **User deletes org after setup**: `setup_completed` stays true. This is acceptable — the wizard is for initial onboarding, not ongoing validation.
4. **Browser back button**: User could navigate away from wizard. AppLayout guard catches this and redirects back.

## Test Plan

1. **Fresh install flow**: Delete all users → register → verify redirect to `/setup` → complete all steps → verify redirect to `/dashboard` → refresh → verify stays on dashboard
2. **Resume flow**: Complete step 1 → close browser → login again → verify wizard resumes (shows step 2, not step 1 again... actually, since we only track `setup_completed` boolean, it restarts from step 1 but org already exists so it can skip/show existing)
3. **API tests**: `POST /auth/complete-setup` returns 200, `GET /auth/me` includes `setup_completed`
4. **Guard test**: Navigate directly to `/dashboard` with `setup_completed=false` → verify redirect to `/setup`

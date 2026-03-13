# Recon Sentinel — Outstanding Technical Debt

**Last Updated:** March 13, 2026 (after Round 5 adversarial review)

**Current State:** 140 files, 15,680 lines, 91 tests, 0 TODOs

**Review Rounds:** 5 adversarial reviews (internal, Grok, ChatGPT, Gemini, Claude ×2), 69+ issues fixed

---

## ~~P0: Systemic IDOR — 21 Endpoints~~ ✅ FIXED

**All 21 IDOR endpoints patched.** 9 new `authorize_*` helpers added to `authorization.py`. 91 routes, 87 authorization checks (4 without are public auth endpoints).

### Root Cause

Endpoints that take a resource UUID (`report_id`, `cred_id`, `agent_run_id`, etc.) do `db.get(Model, uuid)` without verifying the requesting user has access through the org→project→target→scan chain. Any authenticated user can read/modify/delete any resource by guessing UUIDs.

### Fix Strategy

Add 7 new authorization helpers to `backend/app/core/authorization.py`:

```python
async def authorize_report(report_id, user, db) -> Report:
    report = await db.get(Report, report_id)
    if not report: raise 404
    await authorize_scan(report.scan_id, user, db)  # chain to scan
    return report

async def authorize_credential(cred_id, user, db) -> CredentialLeak:
    cred = await db.get(CredentialLeak, cred_id)
    if not cred: raise 404
    await authorize_scan(cred.scan_id, user, db)
    return cred

async def authorize_agent_run(agent_run_id, user, db) -> AgentRun:
    agent = await db.get(AgentRun, agent_run_id)
    if not agent: raise 404
    await authorize_scan(agent.scan_id, user, db)
    return agent

async def authorize_health_event(event_id, user, db) -> HealthEvent:
    event = await db.get(HealthEvent, event_id)
    if not event: raise 404
    await authorize_scan(event.scan_id, user, db)
    return event

async def authorize_target(target_id, user, db) -> Target:
    target = await db.get(Target, target_id)
    if not target: raise 404
    await authorize_project(target.project_id, user, db)
    return target

async def authorize_notification_channel(channel_id, user, db) -> NotificationChannel:
    channel = await db.get(NotificationChannelModel, channel_id)
    if not channel: raise 404
    await authorize_project(channel.project_id, user, db)
    return channel

async def authorize_gate(gate_id, user, db) -> ApprovalGate:
    gate = await db.get(ApprovalGate, gate_id)
    if not gate: raise 404
    await authorize_scan(gate.scan_id, user, db)
    return gate
```

### Affected Endpoints (21)

| File | Endpoint | Line | Fix |
|------|----------|------|-----|
| reports.py | get_report | ~L53 | `authorize_report(report_id, user, db)` |
| reports.py | download_report | ~L62 | `authorize_report(report_id, user, db)` |
| reports.py | delete_report | ~L72 | `authorize_report(report_id, user, db)` |
| credentials.py | get_credential | ~L54 | `authorize_credential(cred_id, user, db)` |
| agents.py | get_agent_run | ~L36 | `authorize_agent_run(agent_run_id, user, db)` |
| agents.py | pause_agent | ~L45 | `authorize_agent_run(agent_run_id, user, db)` |
| agents.py | resume_agent | ~L56 | `authorize_agent_run(agent_run_id, user, db)` |
| agents.py | rerun_agent | ~L77 | `authorize_agent_run(agent_run_id, user, db)` |
| agents.py | get_health_event | ~L126 | `authorize_health_event(event_id, user, db)` |
| agents.py | decide_health_escalation | ~L135 | `authorize_health_event(event_id, user, db)` |
| targets.py | get_target | ~L42 | `authorize_target(target_id, user, db)` |
| targets.py | get_target_context | ~L51 | `authorize_target(target_id, user, db)` |
| targets.py | refresh_target_context | ~L73 | `authorize_target(target_id, user, db)` |
| targets.py | delete_target | ~L88 | `authorize_target(target_id, user, db)` |
| notifications.py | update_channel | ~L59 | `authorize_notification_channel(channel_id, user, db)` |
| notifications.py | delete_channel | ~L71 | `authorize_notification_channel(channel_id, user, db)` |
| notifications.py | test_notification | ~L81 | `authorize_notification_channel(channel_id, user, db)` |
| findings.py | finding_stats | ~L61 | `await authorize_scan(scan_id, user, db)` (already has scan_id param) |
| scans.py | list_gates | ~L163 | `await authorize_scan(scan_id, user, db)` |
| scans.py | get_gate | ~L171 | `authorize_gate(gate_id, user, db)` |
| scans.py | decide_gate | ~L183 | `authorize_gate(gate_id, user, db)` |

### Additional Unscoped List Endpoints

| File | Endpoint | Fix |
|------|----------|-----|
| reports.py | list_reports | Add subquery: `WHERE scan_id IN (SELECT id FROM scans WHERE created_by = user.id)` |
| settings.py | engines CRUD | Add `created_by` column to ScanEngine model + filter |
| history.py | list_diff_items | Chain through diff → scan ownership |
| chat.py | send_message | Add session ownership check |
| scope.py | update/delete_scope_item | Chain through item → project ownership |

---

## P1: High Priority

### 1. Redis Password Mismatch (docker-compose.prod.yml)

`requirepass` uses `${REDIS_PASSWORD:-changeme}` but all service URLs hardcode `sentinel-redis-secret`. Standardize on one approach.

**Fix:** Either remove the env var and hardcode everywhere, or use `${REDIS_PASSWORD}` in all URLs.

### 2. Chat WebSocket Auth Incomplete (websocket.py L151-161)

Current auth inlines `jwt.decode()` but skips: token type check, blacklist check, user exists/is_active check. Should mirror `get_current_user`'s full validation.

**Fix:** Extract a shared `_authenticate_ws_full(token)` that does decode → type=access → JTI blacklist → user lookup → is_active.

### 3. Scan WebSocket Bare Exception (websocket.py L81)

`except Exception` catches DB connection failures as "Access denied". Should catch `HTTPException` specifically.

### 4. SSRF DNS Rebinding TOCTOU (notifications.py)

`_resolve_and_check` resolves hostname, checks IP, but httpx re-resolves during the actual request.

**Fix:** Pin resolved IP into httpx transport (custom `AsyncHTTPTransport` with `local_address` or connect to IP with `Host` header).

---

## P2: Medium Priority

| Issue | File | Description |
|-------|------|-------------|
| ALLOWED_AGENT_TYPES location | orchestrator.py L287 | Move from `_run_vuln()` to module-level constant |
| SMTP Fernet key coupling | notifications.py | JWT secret rotation breaks SMTP decryption. Use dedicated key. |
| Global timeout reset on resume | orchestrator.py L99 | Uses local `scan_start`, not `state.started_at` |
| Redundant session.close() | database.py L105 | Context manager already handles close |

---

## Frontend / UI Debt

### P1

| Issue | File | Description |
|-------|------|-------------|
| MITRE tags hardcoded | agents/page.tsx L67-73 | Use `agent.mitre_tags?.[0]` from backend |
| Raw fetch() calls | history/page.tsx L66,75,92 | Bypass token refresh. Use `api.*` methods |
| No skip-to-content link | AppLayout.tsx | Screen readers must tab through 12 sidebar items |
| Color-only status encoding | agents, findings, history | Add text labels/icons for colorblind users |

### P2

| Issue | File | Description |
|-------|------|-------------|
| Gate "Customize" button | agents/page.tsx L189 | No follow-up UI for specifying modifications |
| Report generation feedback | reports/page.tsx L59 | Single 3s setTimeout, LLM takes 15-30s |
| Sidebar badge no-op | Sidebar.tsx L36-51 | Polling callback empty, badges never update |
| Sidebar cognitive load | Sidebar.tsx | 12 items, consider grouping into sections |
| AI diff summary plain text | history/page.tsx L161 | Should support markdown/bold |
| Timeline emoji a11y | health/page.tsx | Dots use emoji as sole content, add sr-only spans |
| No focus-visible styles | globals.css | Browser defaults clash with dark theme |

---

## Test Coverage Gaps

| Missing Test | Priority | Description |
|-------------|----------|-------------|
| Cross-tenant isolation | P0 | User B cannot access User A's scans/findings/reports/credentials |
| WebSocket auth | P1 | Scan WS rejects wrong user, chat WS rejects revoked tokens |
| IDOR enumeration | P1 | Sequential UUID guessing returns 403 not 404 |
| RLS enforcement | P1 | Tests against PostgreSQL (not SQLite) |
| Negative authorization | P1 | Operator can't do admin actions, viewer can't mutate |

---

## Summary: Path to Production

| Stage | Status | Effort | Blockers |
|-------|--------|--------|----------|
| Internal Testing | **Almost** | ~1 week | Fix 21 IDORs + Redis password |
| Real Pentest | No | ~4 weeks | + TLS tested, RLS verified on PG, 80%+ auth test coverage |
| SaaS Launch | No | ~12 weeks | + Report export, team features, SOC2, monitoring |

**Architecture score: 8/10 (unchanged). Implementation completeness: ~85%. Security hardening: ~70%.**

The codebase is architecturally sound and well-designed. The remaining work is systematic application of the authorization pattern that already exists — not new design.

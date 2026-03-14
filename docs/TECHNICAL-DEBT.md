# Recon Sentinel — Outstanding Technical Debt

**Last Updated:** March 14, 2026 (after R14 ship-ready hardening)

**Current State:** 92 files (66 Python + 26 TypeScript), ~18,500 lines, 115 tests, 17 agents, 93 endpoints, 14 frontend views, 7 Alembic migrations, 32 database tables

**Review Rounds:** 14 rounds, 120+ issues identified and fixed

---

## Resolved (All Previous Rounds)

All P0, P1, and P2 issues from Rounds 1-14 are resolved:

- **R5:** 21 IDOR endpoints → 13 authorize_* helpers, 93/93 endpoints covered
- **R6:** 6 SyntaxErrors, 5 frontend crashes, SSRF TOCTOU → all fixed
- **R7:** 8 P1 list-endpoint scoping gaps → all scoped
- **R8:** Last 2 IDORs (launch_scan, list_scans) → closed
- **R10:** Command injection in retest, CSV injection, input validation → fixed
- **R11:** WebSocket multi-worker delivery, SYS_ADMIN removal, Celery timeouts → fixed
- **Cross-review:** Telegram DNS pinning, bounty profile, DB pool sizing → fixed
- **Schema sync v1.2:** 13 enum/model/schema bugs fixed, migration 0006 + 0007
- **UI redesign:** 48 of 51 items implemented (scan context selector, command diff, accent color added in R13)
- **R12 consistency audit:** 14 issues (5 P0 runtime crashes), all fixed
- **R13 post-review:** Sidebar duplicate bug, accent color, health feed diff, FindingBrief→FindingResponse
- **R14 ship-ready:** Cross-tenant isolation tests (18 tests), WebSocket auth tests (6 tests), PostgreSQL test fixture support, ScanContext provider + sidebar selector, DOMPurify/SafeHtml, TLS enabled in prod compose

---

## Remaining: Pre-Production Items

### P0 — None

All P0 items resolved.

### P1 — Must Fix Before Multi-Tenant / SaaS

| Item | Description | Effort |
|------|-------------|--------|
| SOCKS5/HTTP proxy routing | OPSEC gap for red team engagements | 3 days |
| Scope attestation | No RoE document upload linked to project | 2 days |

### P2 — Should Fix Before v1.1

| Item | Description | Effort |
|------|-------------|--------|
| Subscan endpoint | Can't target individual subdomains | 2 days |
| Data retention policy | Scan data accumulates indefinitely | 1 day |
| Monitoring (Prometheus/Grafana) | No alerts on failures/pool exhaustion | 2 days |
| Negative authorization tests | No test operator can't do admin actions | 1 day |

---

## Architecture Score History

| Round | Score | Key Change |
|-------|-------|------------|
| R4 | 7.3 | 4 P0 blockers |
| R5 | 6.8 | 21 IDOR discovered |
| R6 | 7.3 | All IDORs fixed |
| R7 | 7.7 | List-endpoint scoping |
| R8 | 8.2 | Last IDORs closed |
| R9 | 8.6 | Zero P1 findings |
| R10 | 8.5 | New features introduced new issues |
| R11 | 8.5 | Cross-reviewer consensus fixes applied |
| R12 | 8.8 | Consistency audit — 5 P0 crashes fixed |
| R13 | 9.0 | Post-review polish — 51/51 design items |
| R14 | 9.2 | Ship-ready — cross-tenant tests, TLS, DOMPurify |

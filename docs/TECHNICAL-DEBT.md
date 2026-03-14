# Recon Sentinel — Outstanding Technical Debt

**Last Updated:** March 14, 2026 (after Round 11 — cross-reviewer consensus fixes applied)

**Current State:** 68 Python files, ~13,200 lines backend, 91 tests, 17 agents, 93 endpoints

**Review Rounds:** 11 adversarial reviews, 100+ issues identified and fixed

---

## Resolved (All Previous Rounds)

All P0, P1, and P2 issues from Rounds 1-11 are resolved:

- **R5:** 21 IDOR endpoints → 13 authorize_* helpers, 93/93 endpoints covered
- **R6:** 6 SyntaxErrors, 5 frontend crashes, SSRF TOCTOU → all fixed
- **R7:** 8 P1 list-endpoint scoping gaps → all scoped
- **R8:** Last 2 IDORs (launch_scan, list_scans) → closed
- **R10:** Command injection in retest, CSV injection, input validation → fixed
- **R11:** WebSocket multi-worker delivery, SYS_ADMIN removal, Celery timeouts → fixed
- **Cross-review:** Telegram DNS pinning, bounty profile, DB pool sizing → fixed

---

## Remaining: Pre-Production Items

### P0 — Must Fix Before Any Real Deployment

| Item | Description | Effort |
|------|-------------|--------|
| Cross-tenant isolation tests | Zero tests verify User B can't access User A's data | 2 days |
| PostgreSQL test fixtures | All 91 tests run against SQLite — RLS untested in CI | 1 day |

### P1 — Must Fix Before Multi-Tenant / SaaS

| Item | Description | Effort |
|------|-------------|--------|
| Frontend DOMPurify | Tool output needs client-side sanitization | 2 hours |
| WebSocket auth tests | No test for WS rejecting unauthorized users | 1 day |
| SOCKS5/HTTP proxy routing | OPSEC gap for red team engagements | 3 days |
| Scope attestation | No RoE document upload linked to project | 2 days |
| TLS end-to-end | Nginx TLS commented out, no cert provisioning | 1 day |

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

# Changelog

All notable changes to Recon Sentinel are documented in this file.

## [0.9.0] — 2026-03-13

### Added
- **13 scanning agents** with per-subdomain fan-out across 3 phases
- **LangGraph orchestrator** with checkpoint persistence and resume API
- **Human-in-the-loop approval gates** with AI-generated summaries
- **Self-correcting anomaly detection** (5 patterns: custom 404, WAF, rate limit, redirect, info flood)
- **Multi-tenant authorization** with org → project → target → scan chain
- **Row-level security (RLS)** on 5 tables with middleware auto-context
- **SSRF protection** with DNS rebinding prevention, IPv6 private ranges
- **Scan diff engine** with fingerprint comparison and AI change summaries
- **Continuous monitoring** via Celery Beat (daily re-scans, 24h dedup)
- **Real-time notifications** (Slack, Discord, Telegram, email, webhook)
- **AI Copilot chat** with real LLM streaming via WebSocket
- **HackerOne + Bugcrowd scope import** via GraphQL and REST APIs
- **API key encryption** at rest (Fernet derived from JWT secret)
- **SMTP password encryption** in notification config
- **WAF evasion utilities** (UA rotation, jitter, stealth headers)
- **Process group management** for subprocess cleanup on cancel/timeout
- **Global scan safety limits** (6h timeout, 10K findings cap)
- **Celery Flower** monitoring dashboard
- **React error boundaries** on all pages
- **78 tests** across 11 suites (auth, lifecycle, scope, findings, corrections, vuln, health, fan-out, agent integration, E2E)

### Security
- JWT auth on all 88+ endpoints + WebSocket
- `authorize_scan`, `authorize_project`, `authorize_org` on every data-access route
- API key ownership checks (created_by == user.id)
- LIKE wildcard escaping in search queries
- GraphQL parameterized queries (no string interpolation)
- URL path sanitization on external API calls
- Celery broker retry with visibility timeout
- SIGTERM checkpoint save on worker shutdown
- Stuck scan recovery (15-min Celery Beat)
- 90-day scan archival

### Infrastructure
- 3-stage Dockerfile (Python deps → Go scanning tools → slim runtime)
- Docker Compose: 9 services (PostgreSQL, Redis, FastAPI, Celery worker, Celery Beat, Flower, Nginx, Ollama, DB-init)
- Production compose: no exposed DB/Redis ports, resource limits, TLS-ready Nginx
- Non-root container user (UID 1000), cap_drop ALL, SYS_ADMIN for Chromium
- 4 Alembic migrations (initial, scope function, RLS, findings dedup)

## [0.1.0] — 2026-02-15

### Added
- Initial project structure
- Architecture design v2.0
- Competitive analysis document

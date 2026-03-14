# Changelog

All notable changes to Recon Sentinel are documented in this file.

## [1.0.0-rc1] — 2026-03-14

### Added (R9-R11)
- **17 scanning agents** (added: BadSecrets, WAF Detection, GitHub Dork, Wayback)
- **Nuclei DAST fuzzing** for unknown XSS/SQLi/SSRF/SSTI on parameterized endpoints
- **KEV priority scanning** — CISA Known Exploited Vulnerabilities templates run first
- **WAF-aware rate adaptation** — 15/30/50 req/s based on WAF Detection Agent results
- **Per-subdomain vuln scanning** — all discovered hosts scanned, not just root domain
- **BadSecrets agent** — detects known MachineKeys, Telerik, Flask, Rails, JWT, Symfony secrets
- **Tiered wordlist system** — profile-sized base + tech-adaptive + sensitive file checks
- **PDF/HTML report rendering** via reportlab with styled severity tables
- **CSV export** with formula injection protection and row limits
- **Single-finding retest** — targeted Nuclei run for post-remediation verification
- **Finding triage** — verification_status, severity_override, severity_override_reason
- **Scan profiles** — passive_only, quick, stealth, bounty (fire-and-forget), full (with gates)
- **Login rate limiting** — 10 attempts/min per IP via Redis sliding window
- **Global exception handler** — no more stack trace leaks
- **Health check endpoint** — /api/health verifies DB + Redis, returns 503 when degraded
- **CORS env var** — CORS_ORIGINS configurable for production
- **Alembic migration** for triage columns (0005)

### Fixed (R9-R11)
- **WebSocket event delivery** — Redis subscriber per connection for multi-worker mode
- **SYS_ADMIN removed** from Docker — Chromium uses --no-sandbox instead
- **Celery timeouts** — 45min default, 90min for vuln agent (was 30min, killed legit scans)
- **Worker memory protection** — restart after 50 tasks or 512MB RSS
- **DB pool sizing** — 10+5 per process (was 40+20, caused pool exhaustion)
- **Progress updates** — Redis pub/sub only, no DB writes (eliminated ~420 writes/scan)
- **Telegram SSRF** — routed through _pinned_request for DNS pinning consistency
- **Command injection** — template_id validated with regex in retest endpoint
- **CSV injection** — cell sanitization for formula triggers
- **Input validation** — Literal types on verification_status and severity_override

### Security
- 93 endpoints with authorization (13 authorize_* helpers)
- 5 Alembic migrations including RLS policies
- 11 adversarial review rounds, 100+ issues fixed
- Cross-reviewed by 4 independent AI reviewers (Claude, Gemini, Grok, ChatGPT)

### Infrastructure
- Docker: SecLists, GoWitness, badsecrets now installed in image
- 13 Docker services with resource limits and health checks
- Container hardening: cap_drop ALL, cap_add NET_RAW only, no SYS_ADMIN
- 91 tests across 12 suites

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

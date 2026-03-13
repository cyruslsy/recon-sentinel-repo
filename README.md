# Recon Sentinel

**AI-Powered External Reconnaissance Platform**

An intelligent recon platform for penetration testers, red teams, and security consultants. Combines multi-agent scanning with human-in-the-loop approval gates, self-correcting anomaly detection, and MITRE ATT&CK-native finding classification.

> **Status:** MVP implemented — 9,047 lines of code across 91 files. All 88 API endpoints authenticated. 6 weekly code reviews with 28 bugs fixed.

## Quick Start

```bash
# 1. Generate secrets
cd secrets && bash generate.sh && cd ..
# Edit secrets/anthropic_api_key with your real key

# 2. Start all services
docker compose up -d

# 3. Run database migrations
docker compose exec api alembic revision --autogenerate -m "initial"
docker compose exec api alembic upgrade head

# 4. Start frontend
cd frontend && npm install && npm run dev

# 5. Open http://localhost:3000 → Register → Launch a scan
```

## What's Implemented

### Backend (7,075 Python lines, 49 files)

**Infrastructure (Week 1)**
- Docker Compose: 8 services (PostgreSQL 16, Redis 7, FastAPI, Celery worker, Celery beat, Nginx, Ollama, DB-init)
- JWT auth: bcrypt (12 rounds), access tokens (15min) + HttpOnly refresh cookies (7d), token blacklist via Redis
- API key auth with rate limiting (10 failures/60s → 15min IP lockout)
- Audit middleware: logs all mutations + all 401/403/429 responses
- Docker secrets for all sensitive values (DB password, JWT key, API keys)
- Container hardening: cap_drop ALL, NET_RAW only, read_only, no-new-privileges

**9 Scanning Agents (Weeks 2 + 5)**

| Agent | Phase | Tool | MITRE |
|-------|-------|------|-------|
| Subdomain Discovery | Passive | Subfinder + crt.sh | T1593, T1596 |
| OSINT | Passive | theHarvester | T1589, T1593 |
| Email Security | Passive | DNS (SPF/DKIM/DMARC) | T1566 |
| Threat Intelligence | Passive | Shodan + VirusTotal | T1590 |
| Credential Leak | Passive | HIBP API | T1078 |
| Port & Service Scan | Active | Naabu + Nmap | T1595 |
| Web Reconnaissance | Active | httpx + GoWitness | T1592 |
| SSL/TLS Analysis | Active | OpenSSL | T1190 |
| Dir/File Discovery | Active | ffuf | T1190, T1078 |

All agents inherit from `BaseAgent` which enforces: async subprocess execution, scope checking, progress reporting via WebSocket, finding creation with MITRE tags, and self-correction retry loops.

**Self-Correction Engine (Week 5)**

5 anomaly detection patterns with automatic correction:

| Pattern | Detection | Auto-Fix |
|---------|-----------|----------|
| Custom 404 | >80% same content-length | Re-run with `-fs {size}` |
| Custom 404 (words) | >80% same word count | Re-run with `-fw {count}` |
| WAF Blocking | >95% responses are 403 | Reduce rate, rotate UA, add delay |
| Rate Limiting | >20% responses are 429 | Single thread + 5s backoff |
| Redirect Loop | >90% redirect to same URL | Filter redirect-to-error responses |

**LangGraph-Style Orchestrator (Week 3)**
- State machine: passive → gate_1 → [PAUSE] → active → gate_2 → [PAUSE] → replan → vuln → report → done
- Checkpoint persistence to JSONB — resumes from any phase after restart
- Approval gates: Claude Sonnet summarizes findings, user approves/customizes/skips
- Re-plan node: analyzes findings, decides ADD/SKIP/MODIFY agents (max 3 iterations, $0.50 cost cap, dedup)
- Monthly LLM budget cap ($50 default, 80% warning, 100% auto-pause)

**LLM Integration (Week 3)**
- LiteLLM wrapper: Haiku (routing), Sonnet (analysis/reports), Opus (rare), Ollama (fallback)
- Fallback task allowlist: replan/MITRE/scope/gate blocked from local models
- Per-call cost tracking to `llm_usage_log` table
- Report generation: Sonnet writes executive summaries from finding data

### Frontend (1,931 TypeScript lines, 19 files)

10 implemented views:

| View | Key Features |
|------|-------------|
| Dashboard | Stat cards, recent scans table |
| Scans | Target input (auto-detects domain/IP/CIDR/URL), profile selection, launch |
| Agents | Live progress bars via WebSocket, approval gate banner (approve/customize/skip) |
| Findings | Severity filter, text search (debounced), bulk actions, MITRE badges |
| MITRE Heatmap | Color-coded technique grid, severity breakdown per cell |
| Credentials | Breach summary cards, email/password table |
| Scope Control | Add/toggle scope items, violation log |
| Reports | Generate (LLM-powered), list, download |
| AI Copilot | Chat with scan context, slash commands (/findings, /summarize, /mitre) |
| Settings | API key CRUD, LLM usage/cost dashboard |

Frontend architecture: JWT in memory (XSS-safe), refresh via HttpOnly cookie, WebSocket with exponential backoff reconnect, SWR for caching.

### Database (29 tables)

PostgreSQL 16 with asyncpg. Schema includes: users, organizations, projects, targets, scope definitions, scans, approval gates, agent runs, health events, findings, MITRE techniques, subdomains, open ports, vulnerabilities, credential leaks, screenshots, scan diffs, reports, chat sessions, notifications, API keys, LLM usage logs, plugins, audit log.

57 indexes, 4 functions (including `is_in_scope()`), trigger-maintained MITRE finding counts.

## Architecture

```
React (Next.js 14)  →  Nginx  →  FastAPI (88 endpoints)
     ↕ WebSocket              ↕
                         PostgreSQL 16 + Redis 7
                              ↕
                    Celery Workers (9 agents)
                              ↕
                    LiteLLM (Claude / Ollama)
```

## Scan Flow

```
POST /scans → Celery: start_scan()
  → Phase 1: PASSIVE (5 agents in parallel)
    → Subdomain + OSINT + Email Sec + Threat Intel + Cred Leak
    → AI summarizes findings → Approval Gate #1 → PAUSE

User approves → POST /scans/{id}/gates/1/decide
  → Phase 2: ACTIVE (4 agents in parallel)
    → Port Scan + Web Recon + SSL/TLS + Dir/File
    → AI summarizes → Approval Gate #2 → PAUSE

User approves → Re-plan (Haiku analyzes, adjusts agent plan)
  → Phase 3: VULN → Report Generation (Sonnet) → DONE
```

## Security

- JWT auth on all 88 endpoints + WebSocket
- Token blacklist (Redis) with per-user revocation on password change
- API key rate limiting with IP lockout
- Audit middleware on all mutations and security events
- Scope enforcement: `is_in_scope()` checked before every agent runs
- Docker secrets (never environment variables)
- Container: cap_drop ALL, read_only filesystem, no-new-privileges

## Project Structure

```
recon-sentinel-repo/
├── backend/
│   ├── app/
│   │   ├── agents/        # 9 agents + base class + self-correction engine
│   │   ├── api/           # 15 route modules (88 endpoints) + WebSocket
│   │   ├── core/          # config, database, auth, redis, celery, llm, middleware
│   │   ├── models/        # 29 SQLAlchemy models + 18 enums
│   │   ├── schemas/       # 47 Pydantic schemas
│   │   └── tasks/         # orchestrator, reports, maintenance
│   ├── alembic/           # Database migrations
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── app/           # 10 page views + login
│       ├── components/    # Sidebar, AppLayout
│       ├── hooks/         # WebSocket hook
│       └── lib/           # API client, auth context
├── database/              # SQL schema v1.1
├── docs/                  # Architecture, addendum, sprint plan
├── nginx/                 # Reverse proxy config
├── secrets/               # Secret generation script
├── docker-compose.yml     # 8 services
└── tests/                 # Integration tests
```

## LLM Cost

~$0.25-0.30 per full scan:
- Haiku 4.5: routing/planning (~$0.015)
- Sonnet 4.6: gate analysis + reports (~$0.19)
- Ollama: zero-cost fallback for chat/summarization

Monthly budget cap configurable via `LLM_MONTHLY_BUDGET_USD` (default $50).

## Not Yet Implemented

- Nuclei vulnerability agent (Phase 3 placeholder)
- WAF detection agent, cloud asset agent, JS analysis agent, historical data agent
- Row-level security (RLS) policies
- Plugin sandbox system
- iptables-level scope enforcement (host-side network policy)
- Dual container profiles (worker-tools vs worker-browser)
- PDF/DOCX report export (currently JSON only)
- Notification channels (Slack, email, webhook)
- Scan diff comparison

## License

Proprietary. All rights reserved.

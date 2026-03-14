<p align="center">
  <img src="docs/assets/banner.svg" alt="Recon Sentinel" width="720" />
</p>

<p align="center">
  <strong>AI-Powered External Reconnaissance Platform</strong><br/>
  <em>Multi-agent scanning · Human-in-the-loop gates · Self-correcting agents · MITRE ATT&CK native</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/typescript-5.0+-blue?logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/license-proprietary-red" />
  <img src="https://img.shields.io/badge/tests-91-green" />
  <img src="https://img.shields.io/badge/agents-17-orange" />
  <img src="https://img.shields.io/badge/MITRE_ATT&CK-15_techniques-purple" />
  <img src="https://img.shields.io/badge/review_rounds-11_passed-brightgreen" />
</p>

---

## Overview

Recon Sentinel is an intelligent reconnaissance platform for penetration testers, red teams, and security consultants. It orchestrates 17 specialized scanning agents across a 3-phase pipeline with AI-powered approval gates, self-correcting anomaly detection, and automated MITRE ATT&CK mapping.

**Key differentiators over existing tools (reNgine, BBOT, reconFTW):**

- **Human-in-the-loop gates** — AI summarizes findings between phases; operator approves before active probing begins
- **Self-correcting agents** — detect custom 404s, WAF blocks, rate limiting, and redirect loops; auto-fix and retry
- **Per-subdomain fan-out** — active agents scan every discovered subdomain, not just the root domain
- **Scan diff + continuous monitoring** — auto-diff against previous scans, daily re-scans, AI change summaries
- **Real-time notifications** — Slack/Discord/Telegram/webhook alerts on critical findings as they're discovered
- **Multi-tenant authorization** — org → project → target → scan isolation with RBAC
- **Resume from checkpoint** — crashed or paused scans resume from the exact phase they stopped at

---

## UI Preview

<p align="center">
  <img src="docs/assets/screenshot-dashboard.svg" alt="Dashboard — Real-time scan monitoring with agent status, critical findings, and approval gates" width="900" />
</p>

<p align="center"><em>Dashboard — Live scan monitoring with agent status, approval gates, and critical findings</em></p>

<p align="center">
  <img src="docs/assets/screenshot-health-feed.svg" alt="Health Feed — Self-correction timeline showing agents detecting and fixing anomalies in real-time" width="900" />
</p>

<p align="center"><em>Health Feed — Self-correction timeline: agents detect anomalies, auto-fix, and escalate when needed</em></p>

---

## Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="Architecture Diagram" width="800" />
</p>

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (Next.js 14)                         │
│  12 views: Dashboard, Scans, Agents, Findings, MITRE, Credentials,     │
│  Scope, Reports, Scan Diff, AI Copilot, Settings, Login                │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │ HTTPS / WSS
                    ┌────────▼────────┐
                    │   Nginx (TLS)    │  Security headers, rate limiting
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  FastAPI API     │  93 endpoints + WebSocket
                    │  JWT + RBAC +    │  Multi-tenant authorization
                    │  Audit Middleware │  Scope enforcement
                    └──┬──────────┬───┘
                       │          │
              ┌────────▼──┐  ┌───▼──────────┐
              │ PostgreSQL │  │    Redis      │
              │ 32 tables  │  │ Token blacklist│
              │ JSONB state│  │ Rate limiting  │
              │ is_in_scope│  │ Pub/sub events │
              └────────────┘  └───────────────┘
                       │
              ┌────────▼──────────────────────────────────────────┐
              │              CELERY WORKERS                        │
              │                                                    │
              │  ┌─────────┐  ┌──────────┐  ┌─────────────────┐  │
              │  │ Passive  │  │  Active   │  │  Vulnerability  │  │
              │  │ 6 agents │→ │ 8 agents  │→ │  3 agents       │  │
              │  │          │  │  × N subs │  │                 │  │
              │  └─────────┘  └──────────┘  └─────────────────┘  │
              │       │            │               │              │
              │  ┌────▼────────────▼───────────────▼────┐        │
              │  │      LangGraph Orchestrator           │        │
              │  │  Checkpoints · Gates · Re-plan        │        │
              │  │  Self-correction · Fan-out             │        │
              │  └──────────────┬────────────────────────┘        │
              └─────────────────┼──────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   LiteLLM Gateway     │
                    │  Claude Haiku/Sonnet  │
                    │  Ollama (local)       │
                    │  Budget cap: $50/mo   │
                    └───────────────────────┘
```

---

## Scan Pipeline

<p align="center">
  <img src="docs/assets/scan-flow.svg" alt="Scan Flow" width="800" />
</p>

```
POST /scans → Orchestrator creates ReconState → checkpoint saved

Phase 1: PASSIVE (6 agents, no target interaction)
  ├── Subdomain Discovery (Subfinder + crt.sh)
  ├── OSINT (theHarvester)
  ├── Email Security (SPF/DKIM/DMARC)
  ├── Threat Intelligence (Shodan + VirusTotal)
  ├── Credential Leak (HIBP API)
  └── GitHub Dorking (GitHub Search API)
  → _collect_discovered_targets() → extracts N live subdomains
  → Sonnet generates findings summary → Approval Gate #1 → PAUSE
  → Notification: "Gate ready" → Slack/Discord/Telegram

User approves → POST /scans/{id}/gates/1/decide

Phase 2: ACTIVE (8 agent types × N subdomains, fan-out)
  Per-subdomain (chunked, 20 concurrent):
  ├── Port & Service Scan (Naabu + Nmap)
  ├── Web Reconnaissance (httpx + GoWitness)
  ├── SSL/TLS Analysis (OpenSSL)
  ├── Dir/File Discovery (ffuf + self-correction)
  ├── JavaScript Analysis (secret scanning + endpoint extraction)
  ├── WAF Detection (signature analysis)
  └── Wayback URLs (historical endpoint discovery)
  Domain-level (once):
  └── Cloud Asset Discovery (S3/Azure/GCP + CNAME fingerprinting)
  → Sonnet summary → Approval Gate #2 → PAUSE

User approves → Re-plan node (Haiku adjusts agent plan, max 3 iterations, $0.50 cap)

Phase 3: VULNERABILITY (3 agents)
  ├── Nuclei Scanner (KEV priority + auto tech detection + DAST fuzzing)
  ├── Subdomain Takeover (21 service fingerprints)
  └── Bad Secrets (known MachineKeys, Telerik, Flask, Rails, JWT secrets)
  → Report Generation (Sonnet executive summary)
  → Auto-diff against previous scan
  → Notification: "Scan complete — 42 findings, 3 critical"
  → DONE
```

---

## Agents

| # | Agent | Phase | Tools | MITRE | Self-Correction |
|---|-------|-------|-------|-------|-----------------|
| 1 | Subdomain Discovery | Passive | Subfinder, crt.sh | T1593, T1596 | Wildcard detection |
| 2 | OSINT | Passive | theHarvester | T1589, T1593 | — |
| 3 | Email Security | Passive | DNS queries | T1566 | — |
| 4 | Threat Intelligence | Passive | Shodan, VirusTotal | T1590 | Rate limiting (1 req/s) |
| 5 | Credential Leak | Passive | HIBP API | T1078 | Rate limiting (1.6s/req) |
| 6 | GitHub Dorking | Passive | GitHub API | T1552 | — |
| 7 | Port & Service Scan | Active | Naabu, Nmap | T1595 | Firewall → Connect scan fallback |
| 8 | Web Reconnaissance | Active | httpx, GoWitness | T1592 | — |
| 9 | SSL/TLS Analysis | Active | OpenSSL | T1190 | — |
| 10 | Dir/File Discovery | Active | ffuf | T1190, T1078 | Custom 404, WAF, rate limit, redirect loop |
| 11 | Cloud Asset Discovery | Active | DNS CNAME, HTTP | T1580, T1530 | — |
| 12 | JavaScript Analysis | Active | httpx, regex | T1552, T1190 | — |
| 13 | WAF Detection | Active | httpx | T1595 | — |
| 14 | Wayback URLs | Active | Wayback Machine API | T1593 | — |
| 15 | Vulnerability Scanner | Vuln | Nuclei | T1190 | Info flood → severity filter; WAF-aware rate adaptation; KEV priority scan |
| 16 | Subdomain Takeover | Vuln | DNS, HTTP | T1584 | Truncation warning at 100+ hosts |
| 17 | Bad Secrets | Vuln | badsecrets, httpx | T1078, T1190 | Known MachineKeys, Telerik keys, Flask/Rails/JWT weak secrets |

---

## Self-Correction Engine

<p align="center">
  <img src="docs/assets/self-correction.svg" alt="Self-Correction Engine" width="720" />
</p>

Agents automatically detect and fix common failure scenarios during execution. When an anomaly is detected, the agent adjusts parameters and re-executes — no human intervention required. All corrections are logged as health events for audit.

---

<p align="center">
  <img src="docs/assets/auth-flow.svg" alt="Authorization Flow" width="700" />
</p>

| Layer | Protection |
|-------|-----------|
| **Authentication** | JWT (bcrypt 12 rounds, 15min access + 7d HttpOnly refresh), token blacklist via Redis, API key auth with rate limiting |
| **Authorization** | Multi-tenant RBAC: User → ProjectMember → Project → Org chain. Admin bypass. `authorize_scan()` on all data-access routes |
| **Scope enforcement** | `is_in_scope()` SQL function checked before every agent runs. Wildcard domain, IP, CIDR, regex matching. Violations logged |
| **Audit** | Middleware logs all POST/PUT/DELETE + all 401/403/429 responses |
| **Secrets** | Docker secrets (never env vars). JWT key, DB password, API keys read from mounted files |
| **Containers** | `cap_drop: ALL`, `cap_add: NET_RAW`, `read_only: true`, `no-new-privileges`, non-root user (UID 1000) |
| **Network** | Production Nginx: X-Frame-Options DENY, HSTS, CSP, nosniff, rate limiting (auth: 5/min, API: 30/s) |
| **SSRF** | Notification webhooks validated — blocks private IPs, localhost, link-local, cloud metadata, .internal/.local. DNS rebinding protection (resolve→check). IPv6 private ranges. |
| **Encryption** | API keys encrypted at rest (Fernet). SMTP passwords encrypted in notification config. JWT secret-derived key. |
| **WebSocket** | Token validated via `?token=` query param, 4001 close on invalid |
| **Database** | Row-level security on scans, findings, agent_runs, reports, credential_leaks. RLS context auto-set via middleware. |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose v2
- Node.js 18+ (for frontend dev server)
- Anthropic API key (for AI features)

### Setup

```bash
# Clone
git clone https://github.com/cyruslsy/recon-sentinel-repo.git
cd recon-sentinel-repo

# Generate secrets
cd secrets && bash generate.sh && cd ..
echo "YOUR_ANTHROPIC_KEY" > secrets/anthropic_api_key

# Start services
docker compose up -d --build

# Run migrations
docker compose exec api alembic upgrade head

# Start frontend (dev mode)
cd frontend && npm install && npm run dev
```

Open `http://localhost:3000` → Register → Create Organization → Create Project → Add Target → Launch Scan.

### Production Deployment

```bash
# Uses docker-compose.prod.yml: no exposed DB/Redis ports, 4 uvicorn workers,
# resource limits, TLS-ready Nginx config
docker compose -f docker-compose.prod.yml up -d --build
```

---

## Continuous Monitoring

Recon Sentinel supports automated re-scanning with diff detection:

1. **Auto-diff on completion** — every scan automatically diffs against the previous scan of the same target
2. **Scheduled re-scans** — Celery Beat runs daily at 6 AM, re-scans targets with no scan in the last 24 hours
3. **AI diff summary** — LLM generates "3 new subdomains, 1 S3 bucket now public, 2 CVEs resolved"
4. **Real-time alerts** — Slack/Discord/Telegram/webhook notifications fire instantly for critical findings

### Notification Setup

```bash
# POST /notifications/{project_id}/channels
curl -X POST http://localhost/api/v1/notifications/{project_id}/channels \
  -H "Authorization: Bearer {token}" \
  -d '{
    "channel_type": "slack",
    "config": {"webhook_url": "https://hooks.slack.com/services/..."},
    "subscribed_events": ["critical_finding", "subdomain_takeover", "scan_complete"]
  }'
```

---

## Testing

```bash
cd backend
pip install -r requirements.txt
cd ..
python -m pytest tests/ -v

# 91 tests across 12 suites:
#   test_auth.py           — register, login, JWT, protected routes
#   test_scan_lifecycle.py — org → project → target → scan launch
#   test_scope.py          — scope CRUD, auth enforcement
#   test_findings.py       — listing, auth enforcement
#   test_corrections.py    — all 5 self-correction patterns
#   test_vuln_agent.py     — template selection, severity mapping, MITRE tags
#   test_health.py         — health check, 404, invalid UUID, malformed JSON
#   test_fanout.py         — target cleaning, edge cases
#   test_agent_integration.py — mocked agent lifecycle + scope enforcement
```

---

## LLM Cost

| Model | Usage | Cost per Scan |
|-------|-------|--------------|
| Claude Haiku 4.5 | Routing, re-plan, diff summaries | ~$0.015 |
| Claude Sonnet 4.6 | Gate analysis, reports, chat | ~$0.19 |
| Ollama (local) | Fallback for chat/summarization | $0.00 |
| **Total** | | **~$0.25-0.30** |

Monthly budget cap: `LLM_MONTHLY_BUDGET_USD` (default $50). At 80% usage a warning logs; at 100% all AI features pause with a notification to configured channels.

---

## Project Structure

```
recon-sentinel-repo/
├── backend/                          Python 3.11 + FastAPI
│   ├── Dockerfile                    3-stage: py-builder → go-builder → runtime
│   ├── requirements.txt
│   ├── alembic/                      Database migrations
│   │   └── versions/
│   │       └── 0002_scope_function.py   is_in_scope() SQL function
│   └── app/
│       ├── main.py                   FastAPI app, 15 routers, audit middleware
│       ├── core/
│       │   ├── auth.py               JWT + bcrypt + blacklist + RBAC
│       │   ├── authorization.py      Multi-tenant resource access checks
│       │   ├── celery_app.py         Celery + 14 queues + beat schedule
│       │   ├── config.py             Docker secrets loader
│       │   ├── database.py           Async SQLAlchemy engine
│       │   ├── llm.py                LiteLLM wrapper, fallback, budget
│       │   ├── middleware.py          Audit log middleware
│       │   ├── redis.py              Token blacklist, rate limiting
│       │   └── tz.py                 Timezone-safe utc_now()
│       ├── models/
│       │   ├── enums.py              18 Python enums
│       │   └── models.py             29 SQLAlchemy 2.0 models
│       ├── schemas/
│       │   └── schemas.py            47 Pydantic v2 schemas
│       ├── api/                      15 route modules, 93 endpoints
│       ├── agents/                   17 agents + base + corrections + DNS utils
│       └── tasks/
│           ├── orchestrator.py       LangGraph state machine + fan-out
│           ├── reports.py            LLM-powered report generation
│           ├── diff.py               Scan diff computation engine
│           ├── notifications.py      5-channel notification dispatch
│           ├── monitoring.py         Scheduled re-scans
│           └── maintenance.py        Stuck scan recovery + archival
├── frontend/                         TypeScript + Next.js 14 + Tailwind
│   └── src/
│       ├── app/                      12 page views
│       ├── components/               Sidebar, AppLayout, ErrorBoundary
│       ├── hooks/                    WebSocket hook
│       └── lib/                      Typed API client, auth context, types.ts
├── tests/                            91 tests across 12 suites
├── docs/                             Architecture docs, competitive analysis
│   └── assets/                       SVG diagrams
├── nginx/                            Dev + production configs
├── secrets/                          Secret generation script
├── docker-compose.yml                Dev: 8 services
└── docker-compose.prod.yml           Prod: no exposed DB/Redis, resource limits
```

---

## Stats

| Metric | Value |
|--------|-------|
| Total code lines | 16,200+ |
| Python lines | 13,100+ |
| TypeScript lines | 3,000+ |
| Files | 90+ |
| API endpoints | 93 REST + 2 WebSocket |
| Database tables | 32 |
| Frontend views | 12 |
| Scanning agents | 17 |
| MITRE ATT&CK techniques | 15 |
| Self-correction patterns | 11 |
| Notification channels | 5 (Slack, Discord, Telegram, webhook, email) |
| Authorization helpers | 13 (covering 93/93 endpoints) |
| Tests | 91 |
| Adversarial review rounds | 11 (100+ issues fixed) |

---

## Roadmap

**Implemented:**
- [x] 17 scanning agents with per-subdomain fan-out across 3 phases
- [x] LangGraph orchestrator with checkpoint persistence
- [x] Human-in-the-loop approval gates with AI summaries
- [x] Self-correcting anomaly detection (11 patterns)
- [x] Multi-tenant authorization (org → project → target → scan)
- [x] Row-level security (RLS) on 5 tables with middleware auto-context
- [x] Scan diff + continuous monitoring + AI change summaries
- [x] Real-time notifications (Slack/Discord/Telegram/webhook/email)
- [x] WAF detection agent + Wayback URL agent + GitHub dorking agent
- [x] Bad Secrets agent (8 framework known-secret detection)
- [x] PDF/HTML report rendering with AI executive summaries
- [x] CSV export, single-finding retest, finding triage workflow
- [x] Scan profiles (full, passive_only, quick, stealth, bounty)
- [x] KEV priority scanning + DAST fuzzing + WAF-aware rate adaptation
- [x] Tiered wordlist system (profile-sized + tech-adaptive)
- [x] SSRF protection with DNS rebinding prevention
- [x] Login rate limiting, global exception handler, health check
- [x] 91 tests across 12 suites, 11 adversarial review rounds

**Planned (v1.1):**
- [ ] Cross-tenant isolation tests + PostgreSQL test fixtures
- [ ] SOCKS5/HTTP proxy routing for scan traffic (OPSEC)
- [ ] Scope attestation (Rules of Engagement upload)
- [ ] Subscan endpoint (target individual subdomains)
- [ ] Data retention policy + Prometheus/Grafana monitoring
- [ ] CLI mode (`recon-sentinel scan --target example.com`)
- [ ] Frontend DOMPurify for tool output sanitization

---

## License

Proprietary. All rights reserved.

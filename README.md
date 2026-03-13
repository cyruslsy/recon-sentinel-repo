# Recon Sentinel

**AI-Powered External Reconnaissance Platform**

An intelligent recon platform for penetration testers, red teams, and security consultants. Combines multi-agent scanning with human-in-the-loop approval gates, self-correcting anomaly detection, and MITRE ATT&CK-native finding classification.

> **Status:** Design phase complete. MVP build starting Week 1.

---

## What Makes This Different

| Feature | Recon Sentinel | reNgine | BBOT | reconFTW |
|---------|---------------|---------|------|----------|
| AI agent orchestration | LangGraph + 14 agents | Celery tasks | Pub/sub events | Bash pipeline |
| Human-in-the-loop gates | 2 approval gates with AI summary | None | None | None |
| Self-correcting agents | 11 anomaly patterns with auto-fix | None | None | None |
| MITRE ATT&CK native | Every finding auto-tagged | Not supported | Not supported | Not supported |
| AI Copilot Chat | Real-time with scan context | None | None | None |
| Scope enforcement | 3-level (API + orchestrator + network) | Config only | Config only | Config only |

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  React SPA   │────▶│  FastAPI API  │────▶│  LangGraph      │
│  (Next.js)   │◀────│  88 endpoints │◀────│  Orchestrator   │
└─────────────┘     └──────────────┘     └────────┬────────┘
       │ WebSocket          │                      │
       │                    ▼                      ▼
       │            ┌──────────────┐     ┌─────────────────┐
       └───────────▶│  PostgreSQL   │     │  Celery Workers  │
                    │  29 tables    │     │  14 agents       │
                    └──────────────┘     └─────────────────┘
```

**Tech Stack:** FastAPI, PostgreSQL 16, Redis, Celery, LangGraph, LiteLLM, Claude (Haiku/Sonnet), React, Tailwind CSS, Docker Compose

## Repository Structure

```
recon-sentinel/
├── backend/                    # FastAPI application (3,154 lines Python)
│   └── app/
│       ├── main.py             # App entry point, CORS, 15 routers
│       ├── core/
│       │   └── database.py     # Async SQLAlchemy engine + session
│       ├── models/
│       │   ├── enums.py        # 18 Python enums → PostgreSQL types
│       │   └── models.py       # 29 SQLAlchemy ORM models
│       ├── schemas/
│       │   └── schemas.py      # 47 Pydantic request/response schemas
│       └── api/                # 15 route modules + WebSocket
│           ├── auth.py         # Register, login, JWT, API keys
│           ├── scans.py        # Launch/stop/pause/resume + gates
│           ├── agents.py       # Agent runs + health events
│           ├── findings.py     # Filter/search + bulk actions
│           ├── scope.py        # Scope control + violations
│           ├── mitre.py        # MITRE ATT&CK heatmap
│           ├── chat.py         # AI Copilot sessions + messages
│           ├── websocket.py    # Real-time scan + chat streaming
│           └── ...             # 7 more route modules
├── database/
│   └── schema-v1.1.sql        # PostgreSQL schema (29 tables, 57 indexes)
├── design/
│   └── ui-mockup-v5.jsx       # Interactive React mockup (13 views)
├── docs/
│   ├── Recon-Sentinel-Architecture-v2.0.docx
│   ├── Recon-Sentinel-Addendum-v2.1.docx    # 27 design amendments
│   ├── Recon-Sentinel-Sprint-Plan.docx       # 6-week build plan
│   └── competitive-analysis.md
└── frontend/                   # Next.js app (Week 4)
```

## Key Stats

| Metric | Value |
|--------|-------|
| Python lines | 3,154 across 26 files |
| API endpoints | 88 REST + 2 WebSocket |
| Database tables | 29 |
| UI views | 13 + command palette |
| Agent types | 14 specialist agents |
| Self-correction patterns | 11 |
| Design amendments | 27 (from 3 adversarial reviews) |

## Scan Flow

```
Phase 1: PASSIVE (auto-runs)
  → Subdomain, OSINT, Email Security, Threat Intel, Credential Leak, Historical
  → APPROVAL GATE #1 (AI presents findings, user approves/customizes/skips)

Phase 2: ACTIVE (requires approval)
  → Port/Service, WAF, SSL/TLS, Cloud, Web Recon, Dir/File, JS Analysis
  → APPROVAL GATE #2 (AI suggests vuln scan scope)

Phase 3: VULNERABILITY (requires approval)
  → Nuclei templates, Subdomain Takeover, DNS Zone Transfer
  → REPORT GENERATION (Claude Sonnet)
```

## Self-Correcting Agents

Agents automatically detect and fix common failure scenarios:

| Scenario | Detection | Auto-Fix |
|----------|-----------|----------|
| Custom 404 pages | >80% same content-length | Re-run with `-fs {size}` |
| WAF blocking | >95% responses 403 | Reduce rate + rotate user-agent |
| DNS wildcard | Random subdomain resolves | Filter wildcard IP + HTTP diff |
| Rate limiting | 429 response spike | Backoff + reduce threads |
| SPA empty DOM | Root div only | Switch to headless Chrome |
| API rate limit | External API 429 | Failover to alternate API |

## LLM Cost

~$0.25-0.30 per scan using tiered models:
- **Haiku 4.5**: Routing and planning (~$0.015)
- **Sonnet 4.6**: Gate analysis and reports (~$0.19)
- **Ollama (local)**: Zero-cost fallback for non-critical tasks

## MVP Roadmap (6 Weeks)

| Week | Focus | Key Deliverable |
|------|-------|-----------------|
| 1 | Infrastructure | Docker Compose + JWT auth + audit logging |
| 2 | Core Agents | Subdomain, port scan, web recon agents |
| 3 | Orchestration | LangGraph + approval gates + WebSocket |
| 4 | Frontend | React dashboard + live scan monitoring |
| 5 | Intelligence | Self-correction + re-plan + 6 more agents |
| 6 | Hardening | Scope enforcement + container security + deploy |

## Design Documents

The `docs/` directory contains the complete system design:

- **Architecture v2.0** — Full system design: tech stack, 5-layer architecture, agent orchestration, self-correction patterns, MITRE mapping, cost analysis
- **Addendum v2.1** — 27 amendments from 3 rounds of adversarial review covering JWT hardening, audit completeness, re-plan safety, plugin sandboxing, LLM cost controls
- **Sprint Plan** — Day-by-day 6-week build plan with checkpoints, risk register, and amendment traceability matrix
- **Competitive Analysis** — Deep analysis of reNgine, BBOT, reconFTW, SpiderFoot, and enterprise EASM platforms

## License

Proprietary. All rights reserved.

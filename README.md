<p align="center">
  <img src="docs/assets/banner.svg" alt="Recon Sentinel" width="720" />
</p>

<h3 align="center">AI-Powered External Reconnaissance Platform</h3>

<p align="center">
  <em>17 autonomous agents · Self-correcting pipeline · Human-in-the-loop gates · MITRE ATT&CK native</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/v1.0.0-blue" />
  <img src="https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/next.js-14-000?logo=nextdotjs&logoColor=white" />
  <img src="https://img.shields.io/badge/docker-13_svcs-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/115_tests-22c55e" />
  <img src="https://img.shields.io/badge/17_agents-f97316" />
  <img src="https://img.shields.io/badge/14_reviews-a855f7" />
</p>

<br/>

> **Recon Sentinel** orchestrates 17 scanning agents across a 3-phase pipeline with AI approval gates, self-correcting anomaly detection, and MITRE ATT&CK mapping. Built for pentesters who need visibility and control, not fire-and-forget.

---

## What Makes It Different

<table>
<tr>
<td width="50%">

**🛡️ Approval Gates**
AI summarizes findings between phases. You approve before active probing begins — no surprises.

**🔧 Self-Correcting Agents**
11 patterns: WAF blocking, rate limits, custom 404s, DNS wildcards, redirect loops — agents detect and fix automatically.

**🔱 Per-Subdomain Fan-Out**
Every discovered subdomain gets full active + vuln scanning. Not just the root domain.

</td>
<td width="50%">

**📊 MITRE ATT&CK Native**
Every finding maps to techniques. Heatmap view with tactic grouping and click-through to evidence.

**🔄 Scan Diff + Monitoring**
Auto-diff against previous scans. Daily re-scans. AI change summaries. Slack/Discord/Telegram alerts.

**🔒 Multi-Tenant**
Org → Project → Target → Scan isolation. RBAC + row-level security on 5 tables. 93/93 endpoints authorized.

</td>
</tr>
</table>

---

## Screenshots

<p align="center">
  <img src="docs/assets/screenshot-dashboard.svg" alt="Dashboard" width="900" />
</p>
<p align="center"><sub>Dashboard — live agent status, severity donut, approval gates, critical findings</sub></p>

<p align="center">
  <img src="docs/assets/screenshot-health-feed.svg" alt="Health Feed" width="900" />
</p>
<p align="center"><sub>Health Feed — self-correction event chains with before/after command diffs</sub></p>

---

## Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="Architecture" width="800" />
</p>

---

## Scan Pipeline

<p align="center">
  <img src="docs/assets/scan-flow.svg" alt="Scan Pipeline" width="800" />
</p>

| Profile | Phases | Gates | Use Case |
|---------|--------|-------|----------|
| `full` | All 3 | 2 | Client pentests — full audit trail |
| `passive_only` | Passive only | 0 | OSINT engagement |
| `quick` | All 3 | 1 | Faster with one checkpoint |
| `stealth` | Passive + Active | 1 | Minimal footprint |
| `bounty` | All 3 | 0 | Fire-and-forget |

---

## Self-Correction

<p align="center">
  <img src="docs/assets/self-correction.svg" alt="Self-Correction Engine" width="720" />
</p>

11 patterns: custom 404 (size + word), WAF blocking, rate limiting, redirect loops, DNS wildcards, timeout cascades, connection resets, empty responses, cert errors, encoding mismatches. All corrections logged with full event chains.

---

## Quick Start

```bash
git clone https://github.com/cyruslsy/recon-sentinel-repo.git
cd recon-sentinel-repo

# Secrets + certs
cd secrets && bash generate.sh && cd ..
cd nginx/ssl && bash generate.sh && cd ../..
echo "YOUR_ANTHROPIC_KEY" > secrets/anthropic_api_key

# Dev
docker compose up -d --build
docker compose exec api alembic upgrade head
cd frontend && npm install && npm run dev

# Production
docker compose -f docker-compose.prod.yml up -d --build
```

Open `http://localhost:3000` → Register → Create Org → Add Target → Launch Scan.

---

## Tech Stack

<table>
<tr>
<td><strong>Backend</strong></td>
<td>FastAPI · SQLAlchemy 2.0 · Pydantic v2 · Celery · LangGraph · LiteLLM</td>
</tr>
<tr>
<td><strong>Frontend</strong></td>
<td>Next.js 14 · TypeScript · Tailwind CSS · Recharts · WebSocket</td>
</tr>
<tr>
<td><strong>Database</strong></td>
<td>PostgreSQL 16 (32 tables, RLS) · Redis 7 (pub/sub, token blacklist)</td>
</tr>
<tr>
<td><strong>Infra</strong></td>
<td>Docker Compose (13 services) · Nginx (TLS, rate limiting) · Celery Beat</td>
</tr>
<tr>
<td><strong>AI</strong></td>
<td>Claude Haiku/Sonnet/Opus via LiteLLM · Ollama fallback · $0.25/scan</td>
</tr>
<tr>
<td><strong>Security</strong></td>
<td>JWT + RBAC · 13 authorize helpers · SSRF protection · Docker hardening</td>
</tr>
</table>

---

## Stats

`18,500+ lines` · `93 endpoints` · `32 tables` · `17 agents` · `11 self-correction patterns` · `115 tests` · `14 review rounds` · `120+ issues fixed`

---

## Docs

| Doc | Description |
|-----|-------------|
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |
| [`docs/TECHNICAL-DEBT.md`](docs/TECHNICAL-DEBT.md) | Current debt + architecture scores |
| [`docs/API-EXAMPLES.md`](docs/API-EXAMPLES.md) | 40 curl examples |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Local setup + project layout |

---

<p align="center">
  <strong>Cyrus Li</strong> · <a href="mailto:cyruslsyx@gmail.com">cyruslsyx@gmail.com</a>
  <br/><sub>Proprietary. All rights reserved.</sub>
</p>

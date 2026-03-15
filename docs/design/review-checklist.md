# Design Review Checklist

> 30 questions. Run before starting any new phase.

## Data Flow

| # | Question | Answer |
|---|----------|--------|
| DF-1 | For every agent: who consumes its output? | See data-flow.md. No orphan data. |
| DF-2 | For every agent: what inputs from previous phases? | See cross-phase table. |
| DF-3 | Can agents run without input data? | Yes — try/except around cross-phase reads. |
| DF-4 | Any data collected but never used? | V1: Shodan unused. Fixed: consumed by 3 agents. |
| DF-5 | What if agent produces 0 findings? | Health event logged. Not an error. |

## Three-Layer

| # | Question | Answer |
|---|----------|--------|
| TL-1 | Every DB field in API schema? | See three-layer-contract.md. Rules-checker validates. |
| TL-2 | Every schema field in types.ts? | TypeScript compiler catches missing fields. |
| TL-3 | Every types.ts field rendered? | Manual review per field. |
| TL-4 | Python enums match PostgreSQL? | Check enums.py vs ALTER TYPE in migrations. |
| TL-5 | response_model returns FULL schema for details? | All detail endpoints return Full, not Brief. |
| TL-6 | Every migration reversible? | Must have downgrade(). Test: upgrade → downgrade -1 → upgrade. |

## Reliability

| # | Question | Answer |
|---|----------|--------|
| RL-1 | PostgreSQL down during save? | Retry 3x with backoff, buffer to JSON. |
| RL-2 | Redis down? | WebSocket: poll. Revocation: DB fallback. Budget: allow. |
| RL-3 | LLM API down? | Gates: auto-approve. Reports: skip summary. |
| RL-4 | Agent hangs forever? | Per-agent Celery timeout. Default 300s. |
| RL-5 | 10 scans simultaneously? | Concurrent limit (default 3). Queue rest. |
| RL-6 | Disk fills up? | Alert at 90%. Log rotation. |
| RL-7 | LLM returns malformed JSON? | parse_llm_json strips fences. Invalid → auto-approve. |

## Security

| # | Question | Answer |
|---|----------|--------|
| SC-1 | Every endpoint has authorize_*? | 93/93 covered. |
| SC-2 | Cross-tenant isolation? | RLS + authorize_*. Tests verify. |
| SC-3 | Secrets in Docker secrets? | Yes. JWT, DB, API keys via /run/secrets/. |
| SC-4 | Auth rate-limited? | Nginx 5r/m. Backend lockout after 5 failures. |
| SC-5 | Agents stay in scope? | is_in_scope() checked before requests. |
| SC-6 | CSV export safe? | Prefix =, +, -, @ with ' character. |

## UX

| # | Question | Answer |
|---|----------|--------|
| UX-1 | Every page has subtitle? | Yes. |
| UX-2 | 5 states per page? | Loading, empty, error, data, partial. |
| UX-3 | Primary task ≤2 clicks? | Launch scan = 2. Mark FP = 1. |
| UX-4 | Clear hierarchy? | Posture score → critical findings → rest. |
| UX-5 | Severity colors consistent? | critical=red, high=orange, medium=blue, low=green. |
| UX-6 | User notified of events? | WebSocket + Slack/Discord/Telegram. Polling fallback. |

## Performance

| # | Question | Answer |
|---|----------|--------|
| PF-1 | Scan duration (30 subs)? | ~45 min. Target: <30 min. |
| PF-2 | Max concurrent tasks? | CELERY_WORKER_CONCURRENCY=4. Chunked. |
| PF-3 | DB pool sizing? | Pool=5, overflow=10. |
| PF-4 | Frontend bundle? | Next.js standalone. Target <500KB. |

# UX Wireframes & Page Specifications

> 16 pages. Dark theme only (sentinel-* tokens). Every page handles 5 states.

## Page Inventory

| Page | URL | Purpose | Role | Data Source |
|------|-----|---------|------|-------------|
| Login | /login | Auth + first-user bootstrap | All | GET /auth/setup-status |
| Dashboard | /dashboard | At-a-glance posture | All | GET /scans, /posture-score |
| Scans | /scans | List all scans | All | GET /scans |
| Scan Detail | /scans/[id] | Deep-dive + gate approval | All | GET /scans/{id}, /findings, /agents |
| Findings | /findings | Cross-scan browser | All | GET /findings |
| Finding Detail | /findings/[id] | Evidence + raw_data | All | GET /findings/{id} |
| Scenarios | /scenarios | Attack narratives | All | GET /scenarios |
| MITRE Heatmap | /mitre | ATT&CK coverage | All | GET /mitre-heatmap |
| Reports | /reports | PDF reports | All | GET /reports |
| Credentials | /credentials | Leak analysis | All | GET /credentials/summary |
| Health | /health | Agent health feed | All | GET /agents/health |
| Targets | /targets | Target + scope mgmt | All | GET /targets, /scope |
| Chat | /chat | AI security copilot | All | POST /chat, WebSocket |
| Scan Compare | /scans/compare | Side-by-side diff | All | GET /scans/{id}/diff |
| Settings | /settings | Platform config | Admin | GET /settings |
| Users | /admin/users | User management | Admin | GET /users |

## Dashboard Wireframe

### Pre-Phase F (current)

| Section | Content |
|---------|---------|
| Top-left (large) | Finding donut chart by severity |
| Top-right | Last 5 critical/high findings, clickable |
| Middle | Active scans with progress bars + ETA |
| Middle-right | Pending scans + "Launch Scan" button |
| Bottom | Last 5 completed scans: target, counts, duration |

### Post-Phase F (after posture score)

Top-left changes to Posture Score (0-100) with radar chart + trend arrow.

## Gate Approval Wireframe

| Element | Content | Action |
|---------|---------|--------|
| Gate Banner | Yellow, full-width top of scan detail | Visible when gate pending |
| AI Summary | 2-3 sentence recommendation | Read-only |
| Scope Table | Discovered targets with checkboxes | Check/uncheck targets |
| Approve | Green "Approve & Continue" | POST gates/{n}/decide |
| Modify | Blue "Approve with Modifications" | Modified scope |
| Reject | Red "Stop Scan" | Cancel scan |

## Required States (Every Page)

| State | Display |
|-------|---------|
| Loading | Skeleton loaders (shimmer on sentinel-card) |
| Empty | Illustration + message + CTA |
| Error | Red banner + retry button. Never blank. |
| Data | Normal content |
| Partial | Content + warning banner ("3 agents failed") |

## Design Tokens

| Token | Value | Usage |
|-------|-------|-------|
| sentinel-bg | #0B0E14 | Page background |
| sentinel-surface | #111720 | Layout surface |
| sentinel-card | #161D2A | Card backgrounds |
| sentinel-border | #1E2A3A | Borders |
| sentinel-hover | #1A2435 | Hover states |
| sentinel-text | #E2E8F0 | Primary text |
| sentinel-muted | #94A3B8 | Secondary text |
| sentinel-accent | #06B6D4 | Links, active states |
| sentinel-green | #22C55E | Success, low severity |
| sentinel-red | #EF4444 | Error, critical severity |
| sentinel-orange | #F59E0B | Warning, high severity |
| sentinel-purple | #A78BFA | Info accents |
| font-mono | JetBrains Mono | Code, raw data |

Severity: critical=red, high=orange, medium=blue, low=green, info=gray.

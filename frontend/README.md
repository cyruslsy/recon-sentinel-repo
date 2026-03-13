# Recon Sentinel — Frontend

Next.js 14 + React 18 + Tailwind CSS dark-mode application.

**Status:** All 10 core views implemented (Weeks 4 + 6).

## Setup

```bash
npm install
npm run dev   # → http://localhost:3000
```

## Views

1. **Dashboard** — Stat cards, recent scans table
2. **Scans** — Scan list + launch flow (target input, profile selection)
3. **Agents** — Live progress bars via WebSocket, approval gate banners
4. **Findings** — Filterable table with severity, search, bulk actions
5. **MITRE ATT&CK** — Color-coded technique heatmap
6. **Credentials** — Breach data with severity indicators
7. **Scope** — In/out scope management, violation log
8. **Reports** — Generate (LLM-powered), list, download
9. **AI Copilot** — Chat with scan context, slash commands
10. **Settings** — API key management, LLM usage/cost tracking

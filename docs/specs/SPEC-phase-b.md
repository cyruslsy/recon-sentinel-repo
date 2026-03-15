# SPEC: Phase B — Tool Upgrades

## Current State
- Subdomain discovery: subfinder + crt.sh only (passive, ~30 subdomains typical)
- URL collection: Wayback CDX API only (single source, HTTP-based)
- No web crawling/spidering capability
- No subdomain brute-force (no puredns/massdns)

## Target State
- B1: puredns + massdns + n0kovo wordlist for subdomain brute-force (3M entries)
- B2: Subdomain permutation via puredns
- B3: katana web spider agent (new agent, depth=3, runs after web_recon)
- B4: gau replaces Wayback CDX API (multi-source: wayback, commoncrawl, otx, urlscan)

## Files to Modify

| File | Change |
|------|--------|
| `backend/Dockerfile` | Add puredns, katana, gau (Go stage), massdns (C compile), wordlists |
| `backend/app/agents/subdomain.py` | Add puredns brute-force after passive discovery |
| `backend/app/agents/wayback.py` | Replace CDX API with gau subprocess |
| `backend/app/agents/web_spider.py` | **NEW** — katana-based web crawler |
| `backend/app/tasks/orchestrator.py` | Register web_spider in active phase + add to allowlist |

## Three-Layer Impact
Backend only — no DB, schema, types, or frontend changes.

## Risks
- Dockerfile rebuild takes 10-15min (Go compilation)
- massdns C compilation needs build-essential (must purge after)
- puredns brute-force with 3M wordlist is slow on stealth profiles — need profile-aware wordlist selection
- gau may produce 50k+ URLs — need dedup and cap

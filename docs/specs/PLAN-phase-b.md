# Plan: Phase B — Tool Upgrades

## Task 1: Dockerfile — Add new tools and wordlists
- Files: `backend/Dockerfile`
- Changes:
  - **Go builder stage**: Add `puredns v2`, `katana`, `gau v2` to `go install` block
  - **Runtime stage**:
    - Compile massdns from source (clone, make, copy binary, cleanup)
    - Download n0kovo_subdomains_huge.txt → `/usr/share/wordlists/`
    - Download trickest resolvers.txt → `/usr/share/wordlists/`
    - Copy new Go binaries from go-builder stage
- Verify: `docker compose -f docker-compose.prod.yml build api` succeeds
- Depends: none

## Task 2: subdomain.py — Add puredns brute-force
- Files: `backend/app/agents/subdomain.py`
- Changes:
  - After existing passive discovery (subfinder + crt.sh), add `_run_puredns()` method
  - Profile-aware wordlist: passive_only=skip, quick/stealth=SecLists 5K, full/bounty=n0kovo 3M
  - puredns command: `puredns bruteforce {wordlist} {target} --resolvers /usr/share/wordlists/resolvers.txt --rate-limit 500`
  - Parse output (one subdomain per line), merge with passive results
  - Deduplicate by fingerprint before returning
  - Add permutation via `puredns resolve` on discovered subdomains
- Verify: Agent compiles, run_command pre-flight passes for puredns
- Depends: Task 1

## Task 3: wayback.py — Replace CDX API with gau
- Files: `backend/app/agents/wayback.py`
- Changes:
  - Replace `_query_wayback_cdx()` HTTP calls with `self.run_command(["gau", "--subs", target])`
  - Parse one URL per line from stdout
  - Keep existing INTERESTING_EXTENSIONS + INTERESTING_PATHS filters
  - Keep existing tech detection from URL patterns
  - Cap at 10,000 URLs to prevent memory issues
  - Update agent_name to "URL Discovery Agent (gau)"
- Verify: Agent compiles, gau binary exists
- Depends: Task 1

## Task 4: web_spider.py — New katana web crawler agent
- Files: `backend/app/agents/web_spider.py` (NEW)
- Changes:
  - Class: `WebSpiderAgent(BaseAgent)` with agent_type="web_spider", phase=ACTIVE
  - execute(): query DB for live hosts (from web_recon findings), run katana per host
  - katana command: `katana -u {url} -d 3 -jc -kf all -json -silent -timeout 10`
  - Parse JSON output, extract URLs, classify (API endpoint, directory, etc.)
  - Dedup by normalized URL fingerprint
  - Cap at 5,000 URLs per target
  - Celery task at bottom: `run_web_spider_agent`
- Verify: New file compiles, katana binary exists
- Depends: Task 1

## Task 5: Orchestrator — Register web_spider + update allowlist
- Files: `backend/app/tasks/orchestrator.py`
- Changes:
  - Add `"app.agents.web_spider.run_web_spider_agent"` to `per_target_agents` in `_run_active()`, after web_recon
  - Add `"web_spider"` to `ALLOWED_AGENT_TYPES` frozenset
- Verify: `docker compose up -d --build api celery-worker` succeeds, health check passes
- Depends: Task 4

## Task 6: Rebuild and verify
- Files: none
- Changes: none
- Verify:
  ```bash
  docker compose -f docker-compose.prod.yml up -d --build api celery-worker
  # Check tools exist in container
  docker compose exec api which puredns katana gau massdns
  # Health check
  curl -s http://localhost:8000/api/health
  ```
- Depends: Tasks 1-5

# Recon Sentinel — Master Implementation Plan v2.0

> **This is the single source of truth. Replaces all previous improvement documents.**
> 37 items · 7 phases · Full three-layer consistency checks

---

## Immediate Fixes (Before Phase A, ~1 day)

| # | Fix | Time | DB | Schema | Types.ts | Frontend |
|---|-----|------|-----|--------|----------|----------|
| F1 | Add `raw_data` + `remediation` to FindingResponse | 15m | None (exists) | Add 2 fields | Add 2 fields | None yet |
| F2 | Render raw_data in finding detail panel | 2h | None | None | None | Collapsible JSON + curl block |
| F3 | Add page subtitles to all 14 pages | 1h | None | None | None | 1 line per page.tsx |
| F4 | Disable non-functional report section toggles | 30m | None | None | None | Add disabled + tooltip |
| F5 | Screenshot API endpoint + display | 3h | None (exists) | ScreenshotResponse | Screenshot type | API route + img in detail |

### F1 Details
**schemas.py** — add to `FindingResponse`:
```python
raw_data: Optional[dict] = None
remediation: Optional[str] = None
```

**types.ts** — add to `Finding` interface:
```typescript
raw_data: Record<string, unknown> | null;
remediation: string | null;
```

---

## Phase A: Foundation (~2 days)

| # | Item | Days | Depends | Files Changed |
|---|------|------|---------|---------------|
| A1 | DB write retry with backoff | 1d | None | base.py |
| A2 | Tool pre-flight check | 0.5d | None | base.py |
| A3 | LLM graceful degradation | 0.5d | None | orchestrator.py, reports.py |

### A1: DB Write Retry
In `base.py`, wrap all `db.commit()` calls with retry logic (3 attempts, exponential backoff). If all retries fail, buffer findings in memory and write to local JSON file for recovery.

### A2: Tool Pre-flight
Before `run_command()`, verify binary exists: `shutil.which(cmd[0])`. If missing, raise clear error: `"subfinder not found in PATH — check Dockerfile"`.

### A3: LLM Graceful Degradation
In `orchestrator.py`, if LLM call fails due to budget/quota: auto-approve gate with warning. In `reports.py`, generate report without AI executive summary section.

---

## Phase B: Tool Upgrades (~5 days)

| # | Item | Days | Depends | Files Changed |
|---|------|------|---------|---------------|
| B1 | puredns + massdns + n0kovo | 1.5d | A2 | Dockerfile, subdomain.py |
| B2 | Subdomain permutation | 0.5d | B1 | subdomain.py |
| B3 | katana web spider | 2d | A2 | Dockerfile, new web_spider.py, orchestrator.py |
| B4 | gau multi-source URLs | 1d | A2 | Dockerfile, wayback.py |

### B1: Dockerfile Additions
**Stage 2 (go-builder):**
```dockerfile
RUN go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest
```

**Stage 3 (runtime):**
```dockerfile
# massdns (C binary)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && cp bin/massdns /usr/local/bin/ && \
    rm -rf /tmp/massdns && apt-get purge -y build-essential && apt-get autoremove -y

# Wordlists
RUN wget -q https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt \
    -O /usr/share/wordlists/n0kovo_subdomains_huge.txt && \
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -O /usr/share/wordlists/resolvers.txt

# Copy new Go binaries
COPY --from=go-builder /go/bin/puredns /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/gau /usr/local/bin/
```

### B1: subdomain.py Rewrite
Replace `_dns_brute()` dig loop with:
```python
cmd = ["puredns", "bruteforce", wordlist_path, self.target_value,
       "--resolvers", "/usr/share/wordlists/resolvers.txt",
       "--rate-limit", "500", "--wildcard-batch", "1000000"]
```
Wordlist selection: passive_only=none, quick/stealth=SecLists 5K, full/bounty=n0kovo 3M.

### B3: New web_spider.py
New agent following BaseAgent pattern. Runs katana with depth=3 on live hosts discovered by web_recon. Outputs URL findings. Register in orchestrator active phase AFTER web_recon.

### B4: wayback.py Rewrite
Replace `_query_wayback_cdx()` with gau subprocess: `gau --subs {target}`. Parse one URL per line. Apply same INTERESTING_EXTENSIONS + INTERESTING_PATHS filters.

---

## Phase C: Cross-Phase Intelligence (~3.5 days)

| # | Item | Days | Depends | Files Changed |
|---|------|------|---------|---------------|
| C1 | Wayback/gau seeds dir/file wordlists | 0.5d | B4 | dir_file.py |
| C2 | WAF proactive rate adjustment | 1d | None | orchestrator.py, dir_file.py, js_analysis.py |
| C3 | Tech-specific port scanning | 0.5d | None | port_scan.py, tech_context.py |
| C4 | Baseline-before-full probing | 1d | None | dir_file.py, port_scan.py |
| C5 | Vuln agent shared tech_context | 0.5d | None | vuln.py |

Phase C is backend-only. No DB, schema, types, or frontend changes.

### C2: WAF Proactive
Change orchestrator to run WAF agent FIRST in active phase. Other agents check WAF findings and reduce rate before starting.

### C3: Tech Ports
port_scan.py reads Shodan data + tech_context for non-standard ports (MongoDB 27017, Redis 6379, Elasticsearch 9200, Docker API 2375). Adds to naabu target list.

---

## Phase D: Finding Quality (~5.5 days)

| # | Item | Days | Depends | Files Changed |
|---|------|------|---------|---------------|
| D1 | Agent confidence scoring | 1d | None | base.py + all agents |
| D2 | API unavailability finding | 0.5d | None | threat_intel.py, cred_leak.py |
| D3 | Source map detection (.js.map) | 0.5d | None | js_analysis.py |
| D4 | Finding evidence enrichment | 2d | F1 | dir_file.py, github_dork.py, cloud.py, ssl_tls.py |
| D5 | CORS misconfiguration checking | 0.5d | None | web_recon.py |
| D6 | DNS zone transfer | 0.5d | None | subdomain.py or email_sec.py |
| D7 | OSINT emails feed cred_leak | 0.5d | None | cred_leak.py |

### D1: Confidence Scoring Guidelines
Each agent sets `confidence` (0-100) based on evidence quality:
- 90-100: Verified by active probe with matching response content (Nuclei with match)
- 70-89: Strong passive indicator (HIBP breach with passwords, Shodan version match)
- 50-69: Single source, pattern-based (regex match, signature match)
- 30-49: Single source, heuristic (HTTP status code only, directory listing)
- 0-29: Unverified, may be false positive

### D4: Evidence Enrichment
- **dir_file.py**: Add response body preview (first 500 chars) to raw_data
- **github_dork.py**: Add code snippet from GitHub API response to raw_data
- **cloud.py**: Add first 10 objects from public bucket listing to raw_data
- **ssl_tls.py**: Add full cipher negotiation details to raw_data

---

## Phase E: Intelligence Layer (~8 days)

> **THE DIFFERENTIATOR. Major schema changes. Single migration 0008.**

| # | Item | Days | Depends | DB Change | Schema | Types.ts | Frontend |
|---|------|------|---------|-----------|--------|----------|----------|
| E1 | AttackScenario model + migration 0008 | 0.5d | D1 | New table + junction + cols | New schemas | New types | None yet |
| E2 | Finding cross-correlation agent | 2d | D1, E1 | UPDATE confidence | None | None | None |
| E3 | Attack scenario engine (6 templates) | 2d | E1, E2 | INSERT scenarios | None | None | None |
| E4 | AI narrative generation per scenario | 0.5d | E3 | UPDATE narrative | None | None | None |
| E5 | Security posture scoring | 1.5d | D1 | None (computed) | PostureScoreResp | PostureScore | None yet |
| E6 | Threat intel downstream utilization | 1.5d | E3 | None | None | None | None |

### Migration 0008

```sql
-- New enum
CREATE TYPE scenario_type AS ENUM (
  'credential_stuffing', 'exploit_public_app', 'phishing',
  'cloud_compromise', 'subdomain_takeover', 'remote_services'
);

-- Attack scenarios table
CREATE TABLE attack_scenarios (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scenario_type scenario_type NOT NULL,
  risk_level VARCHAR(20) NOT NULL,
  mitre_techniques TEXT[] DEFAULT '{}',
  title VARCHAR(500) NOT NULL,
  narrative TEXT,
  remediation TEXT,
  confidence INTEGER CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
  ai_model_used VARCHAR(100),
  ai_cost_usd NUMERIC(10,6),
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_scenarios_scan ON attack_scenarios(scan_id);

-- Junction table (many-to-many: scenarios ↔ findings)
CREATE TABLE attack_scenario_findings (
  scenario_id UUID NOT NULL REFERENCES attack_scenarios(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  PRIMARY KEY (scenario_id, finding_id)
);
CREATE INDEX idx_asf_finding ON attack_scenario_findings(finding_id);

-- New columns on findings
ALTER TABLE findings ADD COLUMN remediation TEXT;
ALTER TABLE findings ADD COLUMN linked_scenario_count INTEGER DEFAULT 0;
```

### E3: 6 Scenario Templates

| Scenario | MITRE | Trigger |
|----------|-------|---------|
| Credential Stuffing → Account Takeover | T1078 | CREDENTIAL (has_passwords) + DIRECTORY (admin_panel) |
| Exploit Public App → RCE | T1190 | VULNERABILITY (critical) + THREAT_INTEL (version match) |
| Domain Spoofing → Spearphishing | T1566 | EMAIL_SECURITY (no DMARC reject) + OSINT (emails found) |
| Leaked Cloud Keys → Data Exfiltration | T1078+T1530 | GITHUB_LEAK (AWS/GCP/Azure key) + CLOUD_ASSET (bucket exists) |
| Subdomain Takeover → Trusted Phishing | T1199 | VULNERABILITY (subdomain_takeover) |
| Exposed Remote Services | T1133+T1078 | PORT (SSH/RDP exposed) + CREDENTIAL (employee breaches) |

Detection is **rule-based**. Narrative is **AI-generated** per triggered scenario.

### E5: Security Posture Score (0-100)

Weighted factors:
- Critical/High vulnerabilities: 30%
- Credential exposure: 20%
- Attack surface breadth: 15%
- Email security: 10%
- TLS/encryption health: 10%
- Data exposure: 10%
- Misconfiguration: 5%

Computed on-the-fly (no DB table). Returns PostureScoreResponse.

---

## Phase F: Report + Frontend (~5 days)

| # | Item | Days | Depends | Files Changed |
|---|------|------|---------|---------------|
| F1 | Report redesign (posture + scenarios + evidence + methodology) | 3d | E3, E5 | reports.py, PDF template |
| F2 | Frontend: /scenarios page + nav restructure | 1.5d | E3 | new page, Sidebar.tsx, types.ts, api.ts |
| F3 | Scan time estimation at Gate 1 | 0.5d | None | orchestrator.py |

### Report Structure (After F1)
1. Cover page
2. Security Posture Score (0-100 with radar chart)
3. Executive Summary (AI-generated)
4. Attack Scenarios (narratives + evidence + remediation)
5. Findings That Matter (CONFIRMED + HIGH confidence only)
6. All Findings (with evidence)
7. Methodology (tools, phases, profile)
8. Scope (targets, exclusions)
9. Appendix (raw data)

Three audiences: CISO (page 2-3), Red Team (page 4), Blue Team (pages 5-6).

---

## Phase G: Optimization (~10 days, based on real scan results)

| # | Item | Days | Depends | Files Changed |
|---|------|------|---------|---------------|
| G1 | Progressive depth scanning | 2d | C4 | orchestrator.py, dir_file.py |
| G2 | Fan-out as_completed pattern | 0.5d | None | orchestrator.py |
| G3 | Root domain discovery (Phase 0) | 3d | None | new agent, orchestrator, frontend |
| G4 | testssl.sh (TLS depth) | 1d | None | Dockerfile, ssl_tls.py |
| G5 | Cloud tech-specific buckets | 0.5d | None | cloud.py, tech_context.py |
| G6 | Dalfox XSS scanner | 1.5d | B3 | Dockerfile, vuln.py or new agent |
| G7 | Per-finding remediation templates | 1d | E1 | tech_context.py, reports.py |
| G8 | API spec parsing (swagger/openapi) | 1d | None | dir_file.py or new agent |

---

## Summary

| Phase | Items | Days | Key Outcome |
|-------|-------|------|-------------|
| Immediate | 5 | 1d | Unlock data already stored in DB |
| A: Foundation | 3 | 2d | Scans don't lose data on failures |
| B: Tool Upgrades | 4 | 5d | 3M subdomain brute, web crawling, 4x URLs |
| C: Cross-Phase | 5 | 3.5d | Agents inform each other |
| D: Finding Quality | 7 | 5.5d | Confidence scores, evidence depth |
| **E: Intelligence** | **6** | **8d** | **Attack scenarios, posture score — THE DIFFERENTIATOR** |
| F: Report + Frontend | 3 | 5d | Report for 3 audiences, /scenarios page |
| G: Optimization | 8 | 10d* | Progressive depth, testssl, Dalfox |
| **TOTAL** | **41** | **~40d** | **Core A-F: ~30 days** |

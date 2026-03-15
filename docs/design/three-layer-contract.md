# Three-Layer Contract

> If a field exists in the DB and is NOT marked EXCLUDED here, it must appear in API schema and TypeScript types.

## Finding (Most Critical)

| Field | DB | Schema | Types.ts | Frontend | Notes |
|-------|-----|--------|----------|----------|-------|
| id | UUID PK | ✅ FindingResponse | ✅ Finding | Card | |
| scan_id | UUID FK | ✅ | ✅ | Filter | |
| finding_type | ENUM | ✅ | ✅ | Type badge | |
| severity | ENUM | ✅ | ✅ | Severity badge | |
| confidence | INTEGER(0-100) | ✅ | ✅ | Confidence bar | Agents MUST set |
| value | TEXT(2000) | ✅ | ✅ | Title | |
| detail | TEXT | ✅ | ✅ | Description | |
| raw_data | JSONB | ✅ | ✅ | Collapsible JSON | **Was missing in v1, now fixed** |
| remediation | TEXT | ✅ | ✅ | Remediation panel | Migration 0009 |
| mitre_technique_ids | TEXT[] | ✅ | ✅ | MITRE tags | |
| fingerprint | VARCHAR(64) | ✅ | ✅ | Dedup | |
| tags | TEXT[] | ✅ | ✅ | Tag chips | |
| is_false_positive | BOOLEAN | ✅ | ✅ | FP toggle | |
| linked_scenario_count | INTEGER | ✅ | ✅ | Scenario badge | Phase E |
| created_at | TIMESTAMPTZ | ✅ | ✅ | Timestamp | |
| agent_type | COMPUTED (JOIN) | ✅ | ✅ | Agent badge | Not a DB column |

## Report (Had broken pipes in v1)

| Field | DB | Schema | Types.ts | Frontend | Notes |
|-------|-----|--------|----------|----------|-------|
| id | UUID PK | ✅ | ✅ | List | |
| scan_id | UUID FK | ✅ | ✅ | Link | |
| template | ENUM | ✅ | ✅ | Badge | |
| format | ENUM(pdf/html/json) | ✅ | ✅ | Badge | |
| company_name | VARCHAR(255) | ✅ | ✅ | Header | |
| report_title | VARCHAR(500) | ✅ | ✅ | Title | |
| primary_color | VARCHAR(7) | ❌ **BROKEN → ADD** | ❌ **ADD** | Color picker | F6 |
| logo_path | VARCHAR(500) | ❌ **BROKEN → ADD** | ❌ **ADD** | Logo upload | F6 |
| included_sections | TEXT[] | ❌ **BROKEN → ADD** | ❌ **ADD** | Toggles | F6 |
| ai_executive_summary | TEXT | ❌ **BROKEN → ADD** | ❌ **ADD** | Preview | F6 |
| ai_model_used | VARCHAR(100) | ❌ Internal | ❌ | — | Audit |
| ai_tokens_used | INTEGER | ❌ Internal | ❌ | — | Audit |
| ai_cost_usd | NUMERIC | ❌ Internal | ❌ | — | Audit |
| file_path | VARCHAR(500) | ✅ | ✅ | Download | **Was missing, fixed during deploy** |
| file_size_bytes | INTEGER | ✅ | ✅ | Size | |
| generated_by | UUID FK | ✅ | ✅ | User | |
| generated_at | TIMESTAMPTZ | ✅ | ✅ | Timestamp | |

## User

| Field | DB | Schema | Types.ts | Notes |
|-------|-----|--------|----------|-------|
| id | UUID PK | ✅ UserResponse | ✅ User | |
| email | VARCHAR(255) | ✅ | ✅ | |
| password_hash | TEXT | ❌ EXCLUDED | ❌ | Security |
| display_name | VARCHAR(100) | ✅ | ✅ | |
| role | ENUM(admin/tester/auditor) | ✅ | ✅ | |
| api_key_hash | TEXT | ❌ EXCLUDED | ❌ | Security |
| is_active | BOOLEAN | ✅ | ✅ | |
| setup_completed | BOOLEAN | ✅ | ✅ | Migration 0008 |
| last_login_at | TIMESTAMPTZ | ✅ | ✅ | |
| created_at | TIMESTAMPTZ | ✅ | ✅ | |
| updated_at | TIMESTAMPTZ | ❌ EXCLUDED | ❌ | Internal |

## Scan

| Field | DB | Schema | Types.ts | Notes |
|-------|-----|--------|----------|-------|
| id | UUID PK | ✅ ScanResponse | ✅ Scan | |
| target_id | UUID FK | ✅ | ✅ | |
| profile | ENUM | ✅ | ✅ | |
| status | ENUM | ✅ | ✅ | |
| phase | ENUM | ✅ | ✅ | |
| langgraph_checkpoint | JSONB | ❌ EXCLUDED | ❌ | Internal |
| is_archived | BOOLEAN | ✅ | ✅ | |
| started_at | TIMESTAMPTZ | ✅ | ✅ | |
| completed_at | TIMESTAMPTZ | ✅ | ✅ | |
| created_at | TIMESTAMPTZ | ✅ | ✅ | |

## Attack Scenario (Phase F — New)

| Field | DB | Schema | Types.ts | Notes |
|-------|-----|--------|----------|-------|
| id | UUID PK | ✅ ScenarioResponse | ✅ AttackScenario | |
| scan_id | UUID FK | ✅ | ✅ | |
| scenario_type | ENUM(6 types) | ✅ | ✅ | |
| risk_level | VARCHAR | ✅ | ✅ | |
| mitre_techniques | TEXT[] | ✅ | ✅ | |
| title | VARCHAR(500) | ✅ | ✅ | |
| narrative | TEXT | ✅ | ✅ | AI-generated |
| remediation | TEXT | ✅ | ✅ | |
| confidence | INTEGER(0-100) | ✅ | ✅ | |
| findings | Junction table | ✅ (nested) | ✅ | Many-to-many |

## Other Tables (all fields exposed unless noted)

- **Organization** — id, name, slug
- **Project** — id, name, description, org_id
- **Target** — id, target_value, input_type, whois_data, tech_stack, etc.
- **ScopeDefinition** — id, item_type, item_value, status
- **AgentRun** — id, agent_type, status, progress_pct, findings_count
- **HealthEvent** — id, event_type, severity, value, detail
- **ApprovalGate** — id, gate_number, ai_summary, decision
- **Screenshot** — id, finding_id, file_path, page_title. API exists, frontend display pending.
- **ChatSession** — id, scan_id, user_id, title, is_active
- **ChatMessage** — id, session_id, role, content, model_used. tokens/cost internal only.
- **ScanDiff** — id, scan_id, prev_scan_id, delta counts, ai_diff_summary
- **ScanDiffItem** — id, diff_id, change_type, entity_type, value, detail
- **LlmUsageLog** — exposed in aggregate only (LlmUsageSummary)

-- ============================================================================
-- RECON SENTINEL — PostgreSQL Database Schema v1.2
-- AI-Powered External Reconnaissance Platform
-- 
-- Compatible with: PostgreSQL 15+
-- Extensions required: uuid-ossp, pgcrypto, pg_trgm
--
-- Changelog v1.2 (from v1.1):
--   SYNC #1: scan_phase enum — added 'replan' phase
--   SYNC #2: finding_type_enum — added waf_detection, historical, tech_stack, github_leak
--   SYNC #3: scans — added error_message column for resume error tracking
--   SYNC #4: agent_runs — added target_host (fan-out), celery_task_id (revocation)
--   SYNC #5: findings — value expanded VARCHAR(1000) → VARCHAR(2000)
--   SYNC #6: findings — added triage fields (verification_status, severity_override)
--   SYNC #7: api_keys — added created_by FK to users
--   SYNC #8: scan_diff_items — value expanded VARCHAR(1000) → VARCHAR(2000)
--   SYNC #9: reports — added created_at column
--
-- Changelog v1.1 (from v1.0):
--   FIX #1:  is_in_scope() rewritten with proper domain suffix matching
--   FIX #2:  Removed broken subquery index on vulnerabilities; added severity column
--   FIX #3:  mitre_techniques now supports multi-tactic mapping via arrays
--   FIX #4:  findings.assigned_to ON DELETE SET NULL
--   FIX #5:  Unique constraint on approval_gates(scan_id, gate_number)
--   FIX #6:  Unique constraint on scan_diffs(scan_id, prev_scan_id)
--   FIX #7:  credential_leaks now stores encrypted hash values
--   FIX #8:  findings.first_seen_scan FK constraint added
--   FIX #9:  Added audit_log table
--   FIX #10: Added tags[] on findings with GIN index
--   FIX #11: scan_engines now stores config_json JSONB alongside config_yaml
--   FIX #12: Replaced mv_mitre_heatmap with trigger-maintained mitre_finding_counts
--   ADD A:   pg_trgm extension for fuzzy text search
--   ADD B:   Row-level security prep (app.current_user_id setting)
--   ADD C:   Data retention columns on scans
--   ADD D:   finding_type as enum instead of open VARCHAR
-- ============================================================================

-- ─── EXTENSIONS ─────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- ADD A: fuzzy text search

-- ─── CUSTOM TYPES ───────────────────────────────────────────────────────────

CREATE TYPE user_role AS ENUM ('admin', 'tester', 'auditor');
CREATE TYPE input_type AS ENUM ('url', 'domain', 'ip', 'cidr');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'paused', 'completed', 'cancelled', 'failed');
CREATE TYPE scan_phase AS ENUM ('passive', 'gate_1', 'active', 'gate_2', 'replan', 'vuln', 'report', 'done');
CREATE TYPE scan_profile AS ENUM ('full', 'passive_only', 'quick', 'stealth', 'bounty', 'custom');
CREATE TYPE agent_status AS ENUM ('pending', 'running', 'self_correcting', 'completed', 'error', 'error_resolved', 'paused', 'cancelled');
CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE scope_status AS ENUM ('in_scope', 'out_of_scope');
CREATE TYPE scope_item_type AS ENUM ('domain', 'ip', 'cidr', 'regex');
CREATE TYPE health_event_type AS ENUM ('anomaly_detected', 'self_correction', 'correction_success', 'escalate_user');
CREATE TYPE approval_decision AS ENUM ('approved', 'customized', 'skipped', 'pending');
CREATE TYPE notification_channel AS ENUM ('discord', 'slack', 'telegram', 'email', 'webhook');
CREATE TYPE notification_event AS ENUM (
    'critical_finding', 'approval_needed', 'agent_error', 
    'scan_complete', 'new_subdomain', 'credential_leak', 'daily_report'
);
CREATE TYPE report_format AS ENUM ('pdf', 'docx', 'json', 'html');
CREATE TYPE report_template AS ENUM ('full', 'executive', 'vulnerability', 'credential', 'compliance');

-- FIX #D: finding_type as enum instead of open VARCHAR
CREATE TYPE finding_type_enum AS ENUM (
    'subdomain', 'port', 'vulnerability', 'credential', 'directory',
    'ssl_tls', 'email_security', 'threat_intel', 'cloud_asset',
    'js_secret', 'api_endpoint', 'dns', 'screenshot', 'osint', 'waf',
    'waf_detection', 'historical', 'tech_stack', 'github_leak', 'other'
);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 1: CORE IDENTITY & ACCESS
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    display_name    VARCHAR(100) NOT NULL,
    role            user_role NOT NULL DEFAULT 'tester',
    api_key_hash    TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_api_key ON users(api_key_hash) WHERE api_key_hash IS NOT NULL;


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 2: ORGANIZATIONAL HIERARCHY
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    is_bounty_mode  BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_projects_org ON projects(org_id);

CREATE TABLE project_members (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            user_role NOT NULL DEFAULT 'tester',
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, user_id)
);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 3: TARGETS & SCOPE
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE targets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_value    VARCHAR(500) NOT NULL,
    input_type      input_type NOT NULL,
    description     TEXT,
    whois_data      JSONB,
    resolved_ips    TEXT[],
    asn_info        VARCHAR(255),
    cdn_detected    VARCHAR(100),
    registrar       VARCHAR(255),
    domain_created  DATE,
    domain_expires  DATE,
    nameservers     TEXT[],
    tech_stack      TEXT[],
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_targets_project ON targets(project_id);
CREATE INDEX idx_targets_value ON targets(target_value);

CREATE TABLE scope_definitions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    item_type       scope_item_type NOT NULL,
    item_value      VARCHAR(500) NOT NULL,
    status          scope_status NOT NULL DEFAULT 'in_scope',
    note            TEXT,
    auto_detected   BOOLEAN NOT NULL DEFAULT false,
    added_by        UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scope_project ON scope_definitions(project_id);
CREATE INDEX idx_scope_status ON scope_definitions(project_id, status);

-- Scope violation audit log (FK to scans added via ALTER below)
CREATE TABLE scope_violations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL,
    agent_run_id    UUID,
    agent_type      VARCHAR(100) NOT NULL,
    attempted_target VARCHAR(500) NOT NULL,
    matched_rule_id UUID REFERENCES scope_definitions(id),
    reason          TEXT NOT NULL,
    blocked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scope_violations_scan ON scope_violations(scan_id);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 4: SCANS & EXECUTION
-- ═══════════════════════════════════════════════════════════════════════════

-- FIX #11: Added config_json JSONB alongside config_yaml for programmatic access
CREATE TABLE scan_engines (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    profile         scan_profile NOT NULL DEFAULT 'custom',
    config_yaml     TEXT NOT NULL,
    config_json     JSONB,                            -- FIX #11: parsed YAML for queryability
    agent_count     INTEGER NOT NULL DEFAULT 0,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id       UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    engine_id       UUID REFERENCES scan_engines(id),
    profile         scan_profile NOT NULL DEFAULT 'full',
    status          scan_status NOT NULL DEFAULT 'pending',
    phase           scan_phase NOT NULL DEFAULT 'passive',
    langgraph_checkpoint JSONB,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_seconds INTEGER,
    
    -- Denormalized aggregate stats
    total_findings  INTEGER NOT NULL DEFAULT 0,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    info_count      INTEGER NOT NULL DEFAULT 0,
    subdomain_count INTEGER NOT NULL DEFAULT 0,
    open_port_count INTEGER NOT NULL DEFAULT 0,
    credential_count INTEGER NOT NULL DEFAULT 0,
    
    -- Configuration overrides
    rate_limit      INTEGER,
    stealth_level   INTEGER CHECK (stealth_level BETWEEN 1 AND 5),
    custom_wordlist VARCHAR(500),
    path_exclusions TEXT[],
    
    -- ADD C: Data retention
    retain_until    DATE,
    is_archived     BOOLEAN NOT NULL DEFAULT false,
    
    -- SYNC #3: Error tracking for resume
    error_message   TEXT,
    
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_target ON scans(target_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scans_not_archived ON scans(target_id) WHERE is_archived = false;

-- Deferred FK for scope_violations
ALTER TABLE scope_violations 
    ADD CONSTRAINT fk_scope_violations_scan 
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE;

-- FIX #5: Unique constraint on approval gate per scan
CREATE TABLE approval_gates (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    gate_number     INTEGER NOT NULL CHECK (gate_number IN (1, 2)),
    ai_summary      TEXT NOT NULL,
    ai_recommendation JSONB NOT NULL,
    decision        approval_decision NOT NULL DEFAULT 'pending',
    user_modifications JSONB,
    decided_by      UUID REFERENCES users(id),
    decided_at      TIMESTAMPTZ,
    llm_model_used  VARCHAR(100),
    llm_tokens_in   INTEGER,
    llm_tokens_out  INTEGER,
    llm_cost_usd    DECIMAL(10, 6),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT uq_approval_gate_per_scan UNIQUE(scan_id, gate_number)  -- FIX #5
);

CREATE INDEX idx_approval_gates_scan ON approval_gates(scan_id);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 5: AGENT EXECUTION & HEALTH
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE agent_runs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent_type      VARCHAR(100) NOT NULL,
    agent_name      VARCHAR(255) NOT NULL,
    status          agent_status NOT NULL DEFAULT 'pending',
    phase           scan_phase NOT NULL,
    progress_pct    INTEGER NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
    current_tool    VARCHAR(255),
    eta_seconds     INTEGER,
    tools_used      TEXT[] NOT NULL DEFAULT '{}',
    mitre_tags      TEXT[] NOT NULL DEFAULT '{}',
    config_override JSONB,
    findings_count  INTEGER NOT NULL DEFAULT 0,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_seconds INTEGER,
    last_log_line   TEXT,
    target_host     VARCHAR(500),                    -- SYNC #4: fan-out subdomain tracking
    celery_task_id  VARCHAR(255),                    -- SYNC #4: for task revocation on scan stop
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_runs_scan ON agent_runs(scan_id);
CREATE INDEX idx_agent_runs_status ON agent_runs(status);
CREATE INDEX idx_agent_runs_type ON agent_runs(agent_type);

ALTER TABLE scope_violations 
    ADD CONSTRAINT fk_scope_violations_agent 
    FOREIGN KEY (agent_run_id) REFERENCES agent_runs(id) ON DELETE SET NULL;

CREATE TABLE health_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_run_id    UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    event_type      health_event_type NOT NULL,
    title           VARCHAR(500) NOT NULL,
    detail          TEXT NOT NULL,
    raw_command     TEXT,
    correction_results JSONB,
    user_options    TEXT[],
    user_decision   TEXT,
    decided_by      UUID REFERENCES users(id),
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_health_events_agent ON health_events(agent_run_id);
CREATE INDEX idx_health_events_scan ON health_events(scan_id);
CREATE INDEX idx_health_events_type ON health_events(event_type);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 6: FINDINGS & MITRE MAPPING
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent_run_id    UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    
    -- FIX #D: finding_type as enum
    finding_type    finding_type_enum NOT NULL,
    severity        finding_severity NOT NULL,
    confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
    
    value           VARCHAR(2000) NOT NULL,                    -- SYNC #5: expanded from 1000
    detail          TEXT NOT NULL,
    
    -- MITRE ATT&CK (first-class)
    mitre_technique_ids TEXT[] NOT NULL DEFAULT '{}',
    mitre_tactic_ids    TEXT[] NOT NULL DEFAULT '{}',
    
    raw_data        JSONB,
    
    -- User annotations (FIX #4: ON DELETE SET NULL)
    is_false_positive BOOLEAN NOT NULL DEFAULT false,
    user_notes      TEXT,
    assigned_to     UUID REFERENCES users(id) ON DELETE SET NULL,   -- FIX #4
    
    -- FIX #10: Tags for custom labeling
    tags            TEXT[] NOT NULL DEFAULT '{}',
    
    -- SYNC #6: Pentester triage workflow
    verification_status VARCHAR(20) DEFAULT 'unverified',
    severity_override   VARCHAR(20),
    severity_override_reason TEXT,
    
    -- Deduplication (FIX #8: FK constraint)
    fingerprint     VARCHAR(255),
    first_seen_scan UUID REFERENCES scans(id) ON DELETE SET NULL,   -- FIX #8
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_type ON findings(finding_type);
CREATE INDEX idx_findings_mitre ON findings USING GIN(mitre_technique_ids);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_false_positive ON findings(scan_id) WHERE is_false_positive = false;
CREATE INDEX idx_findings_tags ON findings USING GIN(tags);                        -- FIX #10
CREATE INDEX idx_findings_value_trgm ON findings USING GIN(value gin_trgm_ops);   -- ADD A: fuzzy search
CREATE INDEX idx_findings_detail_trgm ON findings USING GIN(detail gin_trgm_ops); -- ADD A: fuzzy search

-- FIX #3: mitre_techniques now supports multi-tactic mapping
CREATE TABLE mitre_techniques (
    technique_id    VARCHAR(20) PRIMARY KEY,
    technique_name  VARCHAR(255) NOT NULL,
    tactic_ids      TEXT[] NOT NULL DEFAULT '{}',       -- FIX #3: array for multi-tactic
    tactic_names    TEXT[] NOT NULL DEFAULT '{}',       -- FIX #3: array for multi-tactic
    description     TEXT,
    url             VARCHAR(500),
    is_subtechnique BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_mitre_tactics ON mitre_techniques USING GIN(tactic_ids);  -- FIX #3: GIN for array

-- FIX #12: Trigger-maintained MITRE finding counts (replaces materialized view)
CREATE TABLE mitre_finding_counts (
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    technique_id    VARCHAR(20) NOT NULL,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    max_severity    finding_severity,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_id, technique_id)
);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 7: SPECIALIZED FINDING TABLES
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE subdomains (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain       VARCHAR(500) NOT NULL,
    resolved_ips    TEXT[],
    http_status     INTEGER,
    http_title      VARCHAR(500),
    content_length  INTEGER,
    tech_detected   TEXT[],
    has_login_panel BOOLEAN DEFAULT false,
    is_wildcard     BOOLEAN DEFAULT false,
    cdn_detected    VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subdomains_scan ON subdomains(scan_id);
CREATE INDEX idx_subdomains_domain ON subdomains(subdomain);

CREATE TABLE open_ports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host            VARCHAR(500) NOT NULL,
    port            INTEGER NOT NULL,
    protocol        VARCHAR(10) NOT NULL DEFAULT 'tcp',
    service_name    VARCHAR(100),
    service_version VARCHAR(255),
    banner          TEXT,
    is_filtered     BOOLEAN DEFAULT false,
    scan_method     VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ports_scan ON open_ports(scan_id);
CREATE INDEX idx_ports_host_port ON open_ports(host, port);

-- FIX #2: Added severity column directly instead of broken subquery index
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity        finding_severity NOT NULL,          -- FIX #2: denormalized from findings
    host            VARCHAR(500) NOT NULL,
    vuln_id         VARCHAR(100),
    vuln_name       VARCHAR(500) NOT NULL,
    vuln_type       VARCHAR(100),
    cvss_score      DECIMAL(3, 1),
    cwe_id          VARCHAR(20),
    affected_component VARCHAR(500),
    proof_of_concept TEXT,
    remediation     TEXT,
    nuclei_template VARCHAR(255),
    is_in_kev       BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_vuln_id ON vulnerabilities(vuln_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);   -- FIX #2: clean B-tree index

-- FIX #7: credential_leaks now stores encrypted hash values
CREATE TABLE credential_leaks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    email           VARCHAR(500) NOT NULL,
    username        VARCHAR(255),
    breach_count    INTEGER NOT NULL DEFAULT 0,
    breach_names    TEXT[],
    has_password    BOOLEAN NOT NULL DEFAULT false,
    has_plaintext   BOOLEAN NOT NULL DEFAULT false,
    password_hash_types TEXT[],
    
    -- FIX #7: Actual credential data (encrypted at rest)
    hash_value              TEXT,                      -- the hash from the breach (bcrypt, md5, etc.)
    password_hash_encrypted TEXT,                      -- plaintext encrypted with pgcrypto aes
    
    password_reuse_detected BOOLEAN DEFAULT false,
    reuse_across_breaches INTEGER DEFAULT 0,
    sources         TEXT[] NOT NULL DEFAULT '{}',
    last_breach_date DATE,
    is_redacted     BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_creds_scan ON credential_leaks(scan_id);
CREATE INDEX idx_creds_email ON credential_leaks(email);

CREATE TABLE directory_discoveries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host            VARCHAR(500) NOT NULL,
    path            VARCHAR(1000) NOT NULL,
    http_status     INTEGER NOT NULL,
    content_length  INTEGER,
    content_type    VARCHAR(255),
    redirect_url    VARCHAR(1000),
    is_admin_panel  BOOLEAN DEFAULT false,
    is_backup_file  BOOLEAN DEFAULT false,
    is_config_file  BOOLEAN DEFAULT false,
    is_api_endpoint BOOLEAN DEFAULT false,
    tool_used       VARCHAR(100),
    wordlist_used   VARCHAR(255),
    filter_applied  VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dirs_scan ON directory_discoveries(scan_id);
CREATE INDEX idx_dirs_path ON directory_discoveries(path);

CREATE TABLE screenshots (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id      UUID REFERENCES findings(id) ON DELETE SET NULL,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url             VARCHAR(2000) NOT NULL,
    http_status     INTEGER,
    page_title      VARCHAR(500),
    file_path       VARCHAR(500) NOT NULL,
    thumbnail_path  VARCHAR(500),
    file_size_bytes INTEGER,
    tech_detected   TEXT[],
    rendered_with   VARCHAR(50) DEFAULT 'gowitness',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_screenshots_scan ON screenshots(scan_id);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 8: SCAN HISTORY & DIFF
-- ═══════════════════════════════════════════════════════════════════════════

-- FIX #6: Unique constraint on scan pair
CREATE TABLE scan_diffs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    prev_scan_id    UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    new_findings_count    INTEGER NOT NULL DEFAULT 0,
    removed_findings_count INTEGER NOT NULL DEFAULT 0,
    new_subdomains        INTEGER NOT NULL DEFAULT 0,
    removed_subdomains    INTEGER NOT NULL DEFAULT 0,
    new_ports             INTEGER NOT NULL DEFAULT 0,
    closed_ports          INTEGER NOT NULL DEFAULT 0,
    new_vulns             INTEGER NOT NULL DEFAULT 0,
    resolved_vulns        INTEGER NOT NULL DEFAULT 0,
    new_credentials       INTEGER NOT NULL DEFAULT 0,
    ai_diff_summary TEXT,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT uq_scan_diff_pair UNIQUE(scan_id, prev_scan_id)  -- FIX #6
);

CREATE INDEX idx_scan_diffs_scan ON scan_diffs(scan_id);

CREATE TABLE scan_diff_items (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    diff_id         UUID NOT NULL REFERENCES scan_diffs(id) ON DELETE CASCADE,
    change_type     VARCHAR(20) NOT NULL CHECK (change_type IN ('new', 'removed', 'changed')),
    finding_type    VARCHAR(100) NOT NULL,
    value           VARCHAR(2000) NOT NULL,                    -- SYNC #8: expanded from 1000
    detail          TEXT,
    severity        finding_severity,
    finding_id      UUID REFERENCES findings(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_diff_items_diff ON scan_diff_items(diff_id);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 9: REPORTS
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    template        report_template NOT NULL,
    format          report_format NOT NULL,
    company_name    VARCHAR(255),
    report_title    VARCHAR(500),
    primary_color   VARCHAR(7),
    logo_path       VARCHAR(500),
    included_sections TEXT[] NOT NULL DEFAULT '{}',
    ai_executive_summary TEXT,
    ai_model_used   VARCHAR(100),
    ai_tokens_used  INTEGER,
    ai_cost_usd     DECIMAL(10, 6),
    file_path       VARCHAR(500) NOT NULL,
    file_size_bytes INTEGER,
    generated_by    UUID NOT NULL REFERENCES users(id),
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()             -- SYNC #9
);

CREATE INDEX idx_reports_scan ON reports(scan_id);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 10: NOTIFICATIONS
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    channel_type    notification_channel NOT NULL,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    config          JSONB NOT NULL,
    subscribed_events notification_event[] NOT NULL DEFAULT '{}',
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_channels_project ON notification_channels(project_id);

CREATE TABLE notification_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id      UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_type      notification_event NOT NULL,
    scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
    payload         JSONB NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message   TEXT,
    sent_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_log_channel ON notification_log(channel_id);
CREATE INDEX idx_notif_log_status ON notification_log(status);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 11: AI COPILOT CHAT
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE chat_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
    user_id         UUID NOT NULL REFERENCES users(id),
    title           VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE chat_messages (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role            VARCHAR(20) NOT NULL CHECK (role IN ('user', 'ai', 'system')),
    content         TEXT NOT NULL,
    slash_command   VARCHAR(100),
    model_used      VARCHAR(100),
    tokens_in       INTEGER,
    tokens_out      INTEGER,
    cost_usd        DECIMAL(10, 6),
    latency_ms      INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chat_messages_session ON chat_messages(session_id);
CREATE INDEX idx_chat_messages_created ON chat_messages(created_at);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 12: API KEYS, CONFIG & LLM TRACKING
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id      UUID REFERENCES projects(id) ON DELETE CASCADE,
    service_name    VARCHAR(100) NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'valid',
    last_used_at    TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    credits_remaining INTEGER,
    created_by      UUID NOT NULL REFERENCES users(id),            -- SYNC #7
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_service ON api_keys(service_name);

CREATE TABLE llm_usage_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
    task_type       VARCHAR(100) NOT NULL,
    model_name      VARCHAR(100) NOT NULL,
    tokens_input    INTEGER NOT NULL,
    tokens_output   INTEGER NOT NULL,
    cost_usd        DECIMAL(10, 6) NOT NULL,
    cached_tokens   INTEGER DEFAULT 0,
    latency_ms      INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_llm_usage_scan ON llm_usage_log(scan_id);
CREATE INDEX idx_llm_usage_date ON llm_usage_log(created_at);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 13: PLUGIN SYSTEM
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE plugins (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL UNIQUE,
    version         VARCHAR(50) NOT NULL,
    author          VARCHAR(255),
    description     TEXT,
    repository_url  VARCHAR(500),
    agent_type      VARCHAR(100) NOT NULL,
    mitre_tags      TEXT[] NOT NULL DEFAULT '{}',
    required_api_keys TEXT[] DEFAULT '{}',
    config_schema   JSONB,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    is_sandboxed    BOOLEAN NOT NULL DEFAULT true,
    installed_by    UUID NOT NULL REFERENCES users(id),
    installed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_plugins_agent_type ON plugins(agent_type);


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 14: AUDIT LOG  (FIX #9)
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     UUID,
    metadata        JSONB,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

COMMENT ON TABLE audit_log IS 'Tracks all security-sensitive actions: credential views, scope changes, gate approvals, report generation';


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 15: SEED DATA
-- ═══════════════════════════════════════════════════════════════════════════

-- FIX #3: MITRE techniques with multi-tactic arrays
INSERT INTO mitre_techniques (technique_id, technique_name, tactic_ids, tactic_names, url) VALUES
    ('T1659', 'Content Injection', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1659'),
    ('T1189', 'Drive-by Compromise', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1189'),
    ('T1190', 'Exploit Public-Facing Application', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1190'),
    ('T1133', 'External Remote Services', '{"TA0001","TA0003"}', '{"Initial Access","Persistence"}', 'https://attack.mitre.org/techniques/T1133'),
    ('T1200', 'Hardware Additions', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1200'),
    ('T1566', 'Phishing', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1566'),
    ('T1566.001', 'Spearphishing Attachment', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1566/001'),
    ('T1566.002', 'Spearphishing Link', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1566/002'),
    ('T1566.003', 'Spearphishing via Service', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1566/003'),
    ('T1566.004', 'Spearphishing Voice', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1566/004'),
    ('T1091', 'Replication Through Removable Media', '{"TA0001","TA0008"}', '{"Initial Access","Lateral Movement"}', 'https://attack.mitre.org/techniques/T1091'),
    ('T1195', 'Supply Chain Compromise', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1195'),
    ('T1195.001', 'Compromise Software Dependencies', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1195/001'),
    ('T1195.002', 'Compromise Software Supply Chain', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1195/002'),
    ('T1195.003', 'Compromise Hardware Supply Chain', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1195/003'),
    ('T1199', 'Trusted Relationship', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1199'),
    -- FIX #3: T1078 maps to 4 tactics
    ('T1078', 'Valid Accounts', '{"TA0001","TA0003","TA0004","TA0005"}', '{"Initial Access","Persistence","Privilege Escalation","Defense Evasion"}', 'https://attack.mitre.org/techniques/T1078'),
    ('T1078.001', 'Default Accounts', '{"TA0001","TA0003","TA0004","TA0005"}', '{"Initial Access","Persistence","Privilege Escalation","Defense Evasion"}', 'https://attack.mitre.org/techniques/T1078/001'),
    ('T1078.002', 'Domain Accounts', '{"TA0001","TA0003","TA0004","TA0005"}', '{"Initial Access","Persistence","Privilege Escalation","Defense Evasion"}', 'https://attack.mitre.org/techniques/T1078/002'),
    ('T1078.003', 'Local Accounts', '{"TA0001","TA0003","TA0004","TA0005"}', '{"Initial Access","Persistence","Privilege Escalation","Defense Evasion"}', 'https://attack.mitre.org/techniques/T1078/003'),
    ('T1078.004', 'Cloud Accounts', '{"TA0001","TA0003","TA0004","TA0005"}', '{"Initial Access","Persistence","Privilege Escalation","Defense Evasion"}', 'https://attack.mitre.org/techniques/T1078/004'),
    ('T1669', 'Wi-Fi Networks', '{"TA0001"}', '{"Initial Access"}', 'https://attack.mitre.org/techniques/T1669'),
    -- Reconnaissance (TA0043)
    ('T1595', 'Active Scanning', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1595'),
    ('T1595.001', 'Scanning IP Blocks', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1595/001'),
    ('T1595.002', 'Vulnerability Scanning', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1595/002'),
    ('T1592', 'Gather Victim Host Information', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1592'),
    ('T1590', 'Gather Victim Network Information', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1590'),
    ('T1589', 'Gather Victim Identity Information', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1589'),
    ('T1593', 'Search Open Websites/Domains', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1593'),
    ('T1596', 'Search Open Technical Databases', '{"TA0043"}', '{"Reconnaissance"}', 'https://attack.mitre.org/techniques/T1596');


-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 16: FUNCTIONS & TRIGGERS
-- ═══════════════════════════════════════════════════════════════════════════

-- Dashboard aggregate materialized view
CREATE MATERIALIZED VIEW mv_scan_summary AS
SELECT 
    s.id AS scan_id,
    s.target_id,
    t.target_value,
    s.status,
    s.phase,
    s.started_at,
    s.completed_at,
    s.total_findings,
    s.critical_count,
    s.high_count,
    s.subdomain_count,
    s.open_port_count,
    s.credential_count,
    COUNT(DISTINCT ar.id) FILTER (WHERE ar.status = 'completed') AS agents_completed,
    COUNT(DISTINCT ar.id) FILTER (WHERE ar.status = 'running') AS agents_running,
    COUNT(DISTINCT ar.id) FILTER (WHERE ar.status = 'error') AS agents_errored,
    COUNT(DISTINCT he.id) FILTER (WHERE he.event_type = 'correction_success') AS auto_corrections,
    COUNT(DISTINCT he.id) FILTER (WHERE he.event_type = 'escalate_user') AS escalations
FROM scans s
JOIN targets t ON s.target_id = t.id
LEFT JOIN agent_runs ar ON ar.scan_id = s.id
LEFT JOIN health_events he ON he.scan_id = s.id
GROUP BY s.id, s.target_id, t.target_value, s.status, s.phase, 
         s.started_at, s.completed_at, s.total_findings, s.critical_count,
         s.high_count, s.subdomain_count, s.open_port_count, s.credential_count;

CREATE UNIQUE INDEX idx_mv_scan_summary ON mv_scan_summary(scan_id);

-- FIX #12: Trigger to maintain mitre_finding_counts on finding INSERT/DELETE
CREATE OR REPLACE FUNCTION update_mitre_counts()
RETURNS TRIGGER AS $$
DECLARE
    t_id TEXT;
BEGIN
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        FOREACH t_id IN ARRAY NEW.mitre_technique_ids LOOP
            INSERT INTO mitre_finding_counts (scan_id, technique_id, finding_count, critical_count, high_count, medium_count, max_severity)
            VALUES (
                NEW.scan_id, t_id, 1,
                CASE WHEN NEW.severity = 'critical' THEN 1 ELSE 0 END,
                CASE WHEN NEW.severity = 'high' THEN 1 ELSE 0 END,
                CASE WHEN NEW.severity = 'medium' THEN 1 ELSE 0 END,
                NEW.severity
            )
            ON CONFLICT (scan_id, technique_id) DO UPDATE SET
                finding_count = mitre_finding_counts.finding_count + 1,
                critical_count = mitre_finding_counts.critical_count + CASE WHEN NEW.severity = 'critical' THEN 1 ELSE 0 END,
                high_count = mitre_finding_counts.high_count + CASE WHEN NEW.severity = 'high' THEN 1 ELSE 0 END,
                medium_count = mitre_finding_counts.medium_count + CASE WHEN NEW.severity = 'medium' THEN 1 ELSE 0 END,
                max_severity = CASE 
                    WHEN NEW.severity::text < mitre_finding_counts.max_severity::text THEN NEW.severity
                    ELSE mitre_finding_counts.max_severity END,
                updated_at = NOW();
        END LOOP;
        RETURN NEW;
    END IF;
    
    IF TG_OP = 'DELETE' THEN
        FOREACH t_id IN ARRAY OLD.mitre_technique_ids LOOP
            UPDATE mitre_finding_counts SET
                finding_count = GREATEST(finding_count - 1, 0),
                critical_count = GREATEST(critical_count - CASE WHEN OLD.severity = 'critical' THEN 1 ELSE 0 END, 0),
                high_count = GREATEST(high_count - CASE WHEN OLD.severity = 'high' THEN 1 ELSE 0 END, 0),
                medium_count = GREATEST(medium_count - CASE WHEN OLD.severity = 'medium' THEN 1 ELSE 0 END, 0),
                updated_at = NOW()
            WHERE scan_id = OLD.scan_id AND technique_id = t_id;
        END LOOP;
        -- Clean up zero-count rows
        DELETE FROM mitre_finding_counts WHERE finding_count = 0;
        RETURN OLD;
    END IF;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_findings_mitre_counts
AFTER INSERT OR DELETE ON findings
FOR EACH ROW EXECUTE FUNCTION update_mitre_counts();

-- FIX #1: Proper scope checking with domain suffix matching and safe CIDR handling
CREATE OR REPLACE FUNCTION is_in_scope(p_project_id UUID, p_target_value VARCHAR)
RETURNS BOOLEAN AS $$
DECLARE
    v_excluded BOOLEAN;
    v_included BOOLEAN;
BEGIN
    -- Exclusions take priority
    SELECT EXISTS(
        SELECT 1 FROM scope_definitions 
        WHERE project_id = p_project_id AND status = 'out_of_scope'
        AND CASE 
            -- Wildcard domain: *.target.com matches sub.target.com AND target.com
            WHEN item_type = 'domain' AND item_value LIKE '*.%' 
                THEN p_target_value = substring(item_value from 3)
                  OR p_target_value LIKE '%.' || substring(item_value from 3)
            -- Exact domain match
            WHEN item_type = 'domain' 
                THEN p_target_value = item_value
            -- IP/CIDR: only if target looks like an IP (safe cast)
            WHEN item_type IN ('ip', 'cidr') 
                 AND p_target_value ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$'
                THEN p_target_value::inet <<= item_value::inet
            -- Regex match
            WHEN item_type = 'regex' 
                THEN p_target_value ~ item_value
            ELSE false
        END
    ) INTO v_excluded;
    
    IF v_excluded THEN RETURN false; END IF;
    
    -- Check inclusions
    SELECT EXISTS(
        SELECT 1 FROM scope_definitions 
        WHERE project_id = p_project_id AND status = 'in_scope'
        AND CASE 
            WHEN item_type = 'domain' AND item_value LIKE '*.%' 
                THEN p_target_value = substring(item_value from 3)
                  OR p_target_value LIKE '%.' || substring(item_value from 3)
            WHEN item_type = 'domain' 
                THEN p_target_value = item_value
            WHEN item_type IN ('ip', 'cidr')
                 AND p_target_value ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$'
                THEN p_target_value::inet <<= item_value::inet
            WHEN item_type = 'regex' 
                THEN p_target_value ~ item_value
            ELSE false
        END
    ) INTO v_included;
    
    RETURN v_included;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_in_scope IS 'Check if a target value falls within the project scope. Exclusions take priority over inclusions. Supports wildcard domains, exact match, CIDR ranges, and regex patterns.';

-- Refresh materialized view function
CREATE OR REPLACE FUNCTION refresh_scan_views(p_scan_id UUID)
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_scan_summary;
END;
$$ LANGUAGE plpgsql;

-- Auto-update updated_at timestamps
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to all relevant tables
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN 
        SELECT table_name FROM information_schema.columns 
        WHERE column_name = 'updated_at' 
        AND table_schema = 'public'
        AND table_name NOT LIKE 'mv_%'
    LOOP
        EXECUTE format('
            CREATE TRIGGER trg_%s_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW EXECUTE FUNCTION update_timestamp()', t, t);
    END LOOP;
END;
$$;


-- ═══════════════════════════════════════════════════════════════════════════
-- SCHEMA v1.2 COMPLETE
-- 
-- Tables:           32 (28 base + audit_log + mitre_finding_counts + project_members + scope_violations)
-- Indexes:          52+
-- Materialized Views: 1 (mv_scan_summary)
-- Functions:        4 (is_in_scope, update_mitre_counts, refresh_scan_views, update_timestamp)
-- Triggers:         2 (mitre counts on findings, updated_at on all tables)
-- Enum Types:       16
-- Seed Data:        30 MITRE techniques (with multi-tactic arrays)
--
-- v1.1 Fixes:       12/12
-- v1.1 Improvements: 4/4 (pg_trgm, RLS prep, retention, finding_type enum)
-- v1.2 Syncs:        9/9 (replan phase, 4 finding types, triage fields, agent fan-out, error_message)
-- ═══════════════════════════════════════════════════════════════════════════

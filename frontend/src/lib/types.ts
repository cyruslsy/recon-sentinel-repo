/**
 * Recon Sentinel — Shared TypeScript Types
 * Synced to backend Pydantic schemas (v1.2) and PostgreSQL enums.
 *
 * IMPORTANT: These must match backend/app/models/enums.py and
 * backend/app/schemas/schemas.py exactly. If you add a value to
 * a backend enum, add it here too.
 */

// ─── Auth ────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  display_name: string;
  role: "admin" | "tester" | "auditor";
  is_active: boolean;
  setup_completed: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// ─── Scans ───────────────────────────────────────────────────

export type ScanStatus = "pending" | "running" | "paused" | "completed" | "cancelled" | "failed";
export type ScanPhase = "passive" | "gate_1" | "active" | "gate_2" | "replan" | "vuln" | "report" | "done";
export type ScanProfile = "full" | "passive_only" | "quick" | "stealth" | "bounty" | "custom";

export interface Scan {
  id: string;
  target_id: string;
  target_value: string | null;
  profile: ScanProfile;
  status: ScanStatus;
  phase: ScanPhase;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  subdomain_count: number;
  open_port_count: number;
  credential_count: number;
  is_archived: boolean;
  created_at: string;
}

export interface ScanBrief {
  id: string;
  target_value: string | null;
  profile: ScanProfile;
  status: ScanStatus;
  phase: ScanPhase;
  total_findings: number;
  critical_count: number;
  high_count: number;
  started_at: string | null;
  duration_seconds: number | null;
}

// ─── Agents ──────────────────────────────────────────────────

export type AgentStatus = "pending" | "running" | "self_correcting" | "completed" | "error" | "error_resolved" | "paused" | "cancelled";

export interface AgentRun {
  id: string;
  scan_id: string;
  agent_type: string;
  agent_name: string;
  status: AgentStatus;
  phase: ScanPhase;
  progress_pct: number;
  current_tool: string | null;
  eta_seconds: number | null;
  tools_used: string[];
  mitre_tags: string[];
  findings_count: number;
  retry_count: number;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  last_log_line: string | null;
  target_host: string | null;
}

// ─── Findings ────────────────────────────────────────────────

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type FindingType =
  | "subdomain" | "port" | "vulnerability" | "credential" | "directory"
  | "ssl_tls" | "email_security" | "threat_intel" | "cloud_asset" | "js_secret"
  | "api_endpoint" | "dns" | "screenshot" | "osint" | "waf" | "waf_detection"
  | "historical" | "tech_stack" | "github_leak" | "other";

export type VerificationStatus = "unverified" | "confirmed" | "false_positive" | "disputed" | "remediated";

export interface Finding {
  id: string;
  scan_id: string;
  agent_run_id: string;
  finding_type: FindingType;
  severity: FindingSeverity;
  confidence: number | null;
  value: string;
  detail: string;
  mitre_technique_ids: string[];
  mitre_tactic_ids: string[];
  is_false_positive: boolean;
  user_notes: string | null;
  assigned_to: string | null;
  tags: string[];
  fingerprint: string | null;
  verification_status: VerificationStatus;
  severity_override: FindingSeverity | null;
  severity_override_reason: string | null;
  raw_data: Record<string, unknown> | null;
  remediation: string | null;
  created_at: string;
}

// ─── Approval Gates ──────────────────────────────────────────

export type GateDecision = "pending" | "approved" | "customized" | "skipped";

export interface ApprovalGate {
  id: string;
  scan_id: string;
  gate_number: number;
  ai_summary: string;
  ai_recommendation: Record<string, unknown>;
  decision: GateDecision;
  decided_at: string | null;
  created_at: string;
}

// ─── Organizations / Projects / Targets ──────────────────────

export interface Organization {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  description: string | null;
  is_bounty_mode: boolean;
  created_at: string;
}

export interface Target {
  id: string;
  project_id: string;
  target_value: string;
  input_type: "domain" | "ip" | "cidr" | "url";
  description: string | null;
  created_at: string;
}

// ─── Scope ───────────────────────────────────────────────────

export interface ScopeItem {
  id: string;
  item_type: "domain" | "ip" | "cidr" | "regex";
  item_value: string;
  status: "in_scope" | "out_of_scope";
  note: string | null;
  auto_detected: boolean;
  created_at: string;
}

export interface ScopeViolation {
  id: string;
  agent_type: string;
  attempted_target: string;
  reason: string;
  blocked_at: string;
}

// ─── Reports ─────────────────────────────────────────────────

export interface Report {
  id: string;
  scan_id: string;
  template: string;
  format: string;
  company_name: string | null;
  report_title: string | null;
  file_path: string;
  file_size_bytes: number | null;
  generated_at: string;
}

// ─── Screenshots ─────────────────────────────────────────────

export interface Screenshot {
  id: string;
  scan_id: string;
  finding_id: string | null;
  url: string;
  http_status: number | null;
  page_title: string | null;
  file_path: string;
  thumbnail_path: string | null;
  file_size_bytes: number | null;
  tech_detected: string[] | null;
  rendered_with: string;
  created_at: string;
}

// ─── Chat ────────────────────────────────────────────────────

export interface ChatSession {
  id: string;
  scan_id: string | null;
  title: string | null;
  is_active: boolean;
  message_count: number;
  created_at: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "ai" | "system";
  content: string;
  slash_command: string | null;
  model_used: string | null;
  cost_usd: number | null;
  latency_ms: number | null;
  created_at: string;
}

// ─── Settings ────────────────────────────────────────────────

export interface ApiKeyConfig {
  id: string;
  service_name: string;
  status: string;
  last_used_at: string | null;
  credits_remaining: number | null;
}

export interface LlmUsageSummary {
  model: string;
  task: string;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  calls: number;
}

// ─── Credentials ─────────────────────────────────────────────

export interface CredentialLeak {
  id: string;
  email: string;
  username: string | null;
  breach_count: number;
  breach_names: string[] | null;
  has_password: boolean;
  has_plaintext: boolean;
  password_reuse_detected: boolean;
  sources: string[];
  last_breach_date: string | null;
  is_redacted: boolean;
}

export interface CredentialSummary {
  total_emails: number;
  with_passwords: number;
  with_plaintext: number;
  password_reuse_count: number;
}

// ─── MITRE ───────────────────────────────────────────────────

export interface MitreHeatmapItem {
  technique_id: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  max_severity: FindingSeverity | null;
}

export interface MitreHeatmapResponse {
  scan_id: string;
  techniques: MitreHeatmapItem[];
}

// ─── Health Events ──────────────────────────────────────────

export type HealthEventType = "anomaly_detected" | "self_correction" | "correction_success" | "escalate_user";

export interface HealthEvent {
  id: string;
  agent_run_id: string;
  scan_id: string;
  agent_type: string | null;
  agent_name: string | null;
  event_type: HealthEventType;
  title: string;
  detail: string;
  raw_command: string | null;
  correction_results: Record<string, unknown> | null;
  user_options: string[] | null;
  user_decision: string | null;
  decided_at: string | null;
  created_at: string;
}

// ─── WebSocket Events ────────────────────────────────────────

export interface ScanEvent {
  event: string;
  data: Record<string, unknown>;
}

// ─── Scan Diff ──────────────────────────────────────────────

export interface ScanDiff {
  id: string;
  scan_id: string;
  prev_scan_id: string;
  new_findings_count: number;
  removed_findings_count: number;
  new_subdomains: number;
  removed_subdomains: number;
  new_ports: number;
  closed_ports: number;
  new_vulns: number;
  resolved_vulns: number;
  new_credentials: number;
  ai_diff_summary: string | null;
}

export interface ScanDiffItem {
  id: string;
  change_type: "new" | "removed" | "changed";
  finding_type: string;
  value: string;
  detail: string | null;
  severity: FindingSeverity | null;
}

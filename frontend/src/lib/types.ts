/**
 * Recon Sentinel — Shared TypeScript Types
 * Mirrors backend Pydantic schemas for type safety.
 */

// ─── Auth ────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  display_name: string;
  role: "admin" | "operator" | "viewer";
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// ─── Scans ───────────────────────────────────────────────────

export type ScanStatus = "queued" | "running" | "paused" | "completed" | "cancelled" | "error";
export type ScanPhase = "passive" | "gate_1" | "active" | "gate_2" | "replan" | "vuln" | "report" | "done";
export type ScanProfile = "full" | "passive_only" | "quick" | "stealth" | "custom";

export interface Scan {
  id: string;
  target_id: string;
  profile: ScanProfile;
  status: ScanStatus;
  phase: ScanPhase;
  total_findings: number;
  critical_count: number;
  high_count: number;
  is_archived: boolean;
  created_at: string;
}

// ─── Agents ──────────────────────────────────────────────────

export type AgentStatus = "queued" | "running" | "completed" | "error" | "cancelled" | "self_correcting" | "waiting_for_api";

export interface AgentRun {
  id: string;
  scan_id: string;
  agent_type: string;
  agent_name: string;
  status: AgentStatus;
  progress_pct: number;
  findings_count: number;
  current_tool: string | null;
  last_log_line: string | null;
  duration_seconds: number | null;
  started_at: string | null;
  completed_at: string | null;
  mitre_tags: string[];
}

// ─── Findings ────────────────────────────────────────────────

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingType = "subdomain" | "port" | "directory" | "vulnerability" | "credential" | "ssl_tls" | "email_security" | "osint" | "threat_intel" | "other";

export interface Finding {
  id: string;
  scan_id: string;
  finding_type: FindingType;
  severity: FindingSeverity;
  value: string;
  detail: string;
  mitre_technique_ids: string[];
  mitre_tactic_ids: string[];
  tags: string[];
  is_false_positive: boolean;
  confidence: number | null;
  fingerprint: string | null;
  created_at: string;
}

// ─── Approval Gates ──────────────────────────────────────────

export type GateDecision = "pending" | "approved" | "customized" | "skipped";

export interface ApprovalGate {
  id: string;
  scan_id: string;
  gate_number: number;
  decision: GateDecision;
  ai_summary: string;
  ai_recommendation: Record<string, unknown> | null;
  user_modifications: Record<string, unknown> | null;
  decided_at: string | null;
}

// ─── Organizations / Projects / Targets ──────────────────────

export interface Organization {
  id: string;
  name: string;
  created_at: string;
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  created_at: string;
}

export interface Target {
  id: string;
  project_id: string;
  target_value: string;
  input_type: "domain" | "ip" | "cidr" | "url";
  created_at: string;
}

// ─── Scope ───────────────────────────────────────────────────

export interface ScopeItem {
  id: string;
  project_id: string;
  item_type: "domain" | "ip" | "cidr" | "regex";
  item_value: string;
  status: "in_scope" | "out_of_scope";
}

export interface ScopeViolation {
  id: string;
  scan_id: string;
  agent_type: string;
  attempted_target: string;
  reason: string;
  created_at: string;
}

// ─── Reports ─────────────────────────────────────────────────

export interface Report {
  id: string;
  scan_id: string;
  report_title: string | null;
  template: string;
  format: string;
  file_path: string;
  ai_executive_summary: string | null;
  generated_at: string | null;
  created_at: string;
}

// ─── Chat ────────────────────────────────────────────────────

export interface ChatSession {
  id: string;
  scan_id: string | null;
  title: string | null;
  created_at: string;
}

export interface ChatMessage {
  id: string;
  session_id: string;
  role: "user" | "ai" | "system";
  content: string;
  slash_command: string | null;
  model_used: string | null;
  tokens_in: number | null;
  tokens_out: number | null;
  cost_usd: number | null;
  created_at: string;
}

// ─── Settings ────────────────────────────────────────────────

export interface ApiKeyConfig {
  id: string;
  service_name: string;
  status: "valid" | "invalid" | "expired";
  created_at: string;
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
  breach_count: number;
  has_password: boolean;
  has_plaintext: boolean;
  sources: string[];
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

// ─── WebSocket Events ────────────────────────────────────────

export interface ScanEvent {
  event: string;
  data: Record<string, unknown>;
}

// ─── Health Events ──────────────────────────────────────────

export interface HealthEvent {
  id: string;
  scan_id: string;
  agent_run_id: string | null;
  agent_type: string | null;
  agent_name: string | null;
  event_type: "anomaly_detected" | "self_correcting" | "correction_success" | "correction_failed" | "escalate_user" | "info";
  detail: string;
  corrected_params: Record<string, unknown> | null;
  raw_data: Record<string, unknown> | null;
  user_decision: string | null;
  decided_at: string | null;
  created_at: string;
}

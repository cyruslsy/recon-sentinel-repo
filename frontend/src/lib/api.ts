/**
 * Recon Sentinel — Typed API Client
 * Every method returns typed data. No `any` allowed.
 */

import type {
  TokenResponse, User, Scan, ScanBrief, AgentRun, Finding, ApprovalGate,
  Organization, Project, Target, ScopeItem, ScopeViolation,
  Report, ChatSession, ChatMessage, ApiKeyConfig, LlmUsageSummary,
  CredentialLeak, CredentialSummary, MitreHeatmapItem, HealthEvent,
} from "./types";

const API_BASE = "/api/v1";

let accessToken: string | null = null;
let isRefreshing = false;
let refreshPromise: Promise<boolean> | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(`API Error ${status}: ${detail}`);
    this.status = status;
    this.detail = detail;
  }
}

export { ApiError };

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: "include" });

  if (res.status === 401) {
    const refreshed = await refreshToken();
    if (refreshed) {
      headers["Authorization"] = `Bearer ${accessToken}`;
      const retry = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: "include" });
      if (retry.ok) return retry.status === 204 ? (undefined as T) : retry.json();
    }
    window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail || res.statusText);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

async function refreshToken(): Promise<boolean> {
  if (isRefreshing && refreshPromise) return refreshPromise;
  isRefreshing = true;
  refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, { method: "POST", credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setAccessToken(data.access_token);
        return true;
      }
    } catch {}
    return false;
  })();
  const result = await refreshPromise;
  isRefreshing = false;
  refreshPromise = null;
  return result;
}

// ─── Typed API Methods ───────────────────────────────────────

export const api = {
  // Auth
  login: (email: string, password: string) =>
    request<TokenResponse>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),

  register: (email: string, password: string, displayName: string) =>
    request<TokenResponse>("/auth/register", {
      method: "POST", body: JSON.stringify({ email, password, display_name: displayName }),
    }),

  logout: () => request<void>("/auth/logout", { method: "POST" }),

  me: () => request<User>("/auth/me"),

  // Scans
  listScans: (params?: string) =>
    request<Scan[]>(`/scans${params ? `?${params}` : ""}`),

  launchScan: (data: { target_id: string; profile?: string }) =>
    request<Scan>("/scans", { method: "POST", body: JSON.stringify(data) }),

  getScan: (id: string) => request<Scan>(`/scans/${id}`),

  stopScan: (id: string) => request<Scan>(`/scans/${id}/stop`, { method: "POST" }),

  // Gates
  listGates: (scanId: string) => request<ApprovalGate[]>(`/scans/${scanId}/gates`),

  decideGate: (scanId: string, gateNumber: number, decision: string, modifications?: Record<string, unknown>) =>
    request<ApprovalGate>(`/scans/${scanId}/gates/${gateNumber}/decide`, {
      method: "POST", body: JSON.stringify({ decision, user_modifications: modifications }),
    }),

  // Agents
  listAgentRuns: (scanId: string) => request<AgentRun[]>(`/agents?scan_id=${scanId}`),

  // Findings
  listFindings: (scanId: string, params?: string) =>
    request<Finding[]>(`/findings?scan_id=${scanId}${params ? `&${params}` : ""}`),

  findingStats: (scanId: string) =>
    request<Record<string, number>>(`/findings/stats?scan_id=${scanId}`),

  updateFinding: (id: string, data: Partial<Finding>) =>
    request<Finding>(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  bulkAction: (data: { finding_ids: string[]; action: string; value?: string }) =>
    request<{ updated: number }>("/findings/bulk", { method: "POST", body: JSON.stringify(data) }),

  retestFinding: (findingId: string) =>
    request<{ status: string }>(`/findings/${findingId}/retest`, { method: "POST" }),

  // Targets
  listTargets: (projectId: string) => request<Target[]>(`/targets?project_id=${projectId}`),

  createTarget: (projectId: string, data: { target_value: string; input_type: string }) =>
    request<Target>(`/targets?project_id=${projectId}`, { method: "POST", body: JSON.stringify(data) }),

  getTargetContext: (targetId: string) =>
    request<{ resolved_ips: string[]; asn_info: string | null; cdn_detected: string | null; registrar: string | null; previous_scan_count: number }>(`/targets/${targetId}/context`),

  // Projects
  listProjects: () => request<Project[]>("/projects"),
  createProject: (orgId: string, data: { name: string }) =>
    request<Project>(`/projects?org_id=${orgId}`, { method: "POST", body: JSON.stringify(data) }),

  // Organizations
  listOrgs: () => request<Organization[]>("/organizations"),
  createOrg: (data: { name: string }) =>
    request<Organization>("/organizations", { method: "POST", body: JSON.stringify(data) }),

  // MITRE
  mitreHeatmap: (scanId: string) =>
    request<{ techniques: MitreHeatmapItem[] }>(`/mitre/heatmap/${scanId}`),

  listMitreTechniques: () =>
    request<{ id: string; technique_id?: string; technique_name: string; tactic_names?: string[] }[]>("/mitre/techniques"),

  // Scope
  listScope: (projectId: string) => request<ScopeItem[]>(`/scope/${projectId}`),

  addScopeItem: (projectId: string, data: { item_type: string; item_value: string; status: string }) =>
    request<ScopeItem>(`/scope/${projectId}`, { method: "POST", body: JSON.stringify(data) }),

  toggleScopeItem: (id: string, status: string) =>
    request<ScopeItem>(`/scope/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),

  listViolations: (projectId: string) =>
    request<ScopeViolation[]>(`/scope/${projectId}/violations?limit=20`),

  // Reports
  listReports: () => request<Report[]>("/reports"),

  generateReport: (data: { scan_id: string; template: string; format: string }) =>
    request<Report>("/reports", { method: "POST", body: JSON.stringify(data) }),

  // Chat
  listChatSessions: (scanId?: string) =>
    request<ChatSession[]>(`/chat/sessions${scanId ? `?scan_id=${scanId}` : ""}`),

  createChatSession: (scanId?: string) =>
    request<ChatSession>(`/chat/sessions${scanId ? `?scan_id=${scanId}` : ""}`, { method: "POST" }),

  listChatMessages: (sessionId: string) =>
    request<ChatMessage[]>(`/chat/sessions/${sessionId}/messages`),

  sendChatMessage: (sessionId: string, content: string) =>
    request<ChatMessage>(`/chat/sessions/${sessionId}/messages`, {
      method: "POST", body: JSON.stringify({ content }),
    }),

  // Credentials
  listCredentials: (scanId: string) => request<CredentialLeak[]>(`/credentials?scan_id=${scanId}`),
  credentialSummary: (scanId: string) => request<CredentialSummary>(`/credentials/summary?scan_id=${scanId}`),

  // Settings
  listApiKeys: () => request<ApiKeyConfig[]>("/settings/api-keys"),

  addApiKey: (data: { service_name: string; api_key: string }) =>
    request<ApiKeyConfig>("/settings/api-keys", { method: "POST", body: JSON.stringify(data) }),

  deleteApiKey: (id: string) => request<void>(`/settings/api-keys/${id}`, { method: "DELETE" }),

  llmUsage: () => request<LlmUsageSummary[]>("/settings/llm-usage"),

  // Health
  healthCheck: () =>
    fetch("/api/health", { credentials: "include" }).then((r) => r.json()) as Promise<{ status: string }>,

  // ─── Health Events ──────────────────────────────────────
  getHealthEvents: (scanId: string) => request<HealthEvent[]>(`/agents/health?scan_id=${scanId}`),

  decideHealthEvent: (eventId: string, decision: string) =>
    request<unknown>(`/agents/health/${eventId}/decide`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision }),
    }),

  // ─── Agent Actions ──────────────────────────────────────
  rerunAgent: (agentRunId: string) =>
    request<unknown>(`/agents/${agentRunId}/rerun`, { method: "POST" }),

  pauseAgent: (agentRunId: string) =>
    request<unknown>(`/agents/${agentRunId}/pause`, { method: "POST" }),

  // ─── Diff / History ─────────────────────────────────────
  getDiff: (scanId: string) => request<unknown>(`/history/diff/${scanId}`),

  getDiffItems: (diffId: string) => request<unknown[]>(`/history/diff/${diffId}/items`),

  computeDiff: (scanId: string, prevScanId: string) =>
    request<unknown>(`/history/diff/${scanId}/compute?prev_scan_id=${prevScanId}`, { method: "POST" }),
};

// SWR fetcher — returns unknown, caller must cast
export const fetcher = <T = unknown>(path: string): Promise<T> => request<T>(path);

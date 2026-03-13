/**
 * Recon Sentinel — API Client
 * Typed fetch wrapper with JWT auth, error handling, and SWR integration.
 */

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

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include", // Send cookies (refresh token)
  });

  if (res.status === 401) {
    // Try token refresh
    const refreshed = await refreshToken();
    if (refreshed) {
      headers["Authorization"] = `Bearer ${accessToken}`;
      const retry = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: "include" });
      if (retry.ok) return retry.json();
    }
    // Refresh failed — redirect to login
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
  // Deduplicate: if a refresh is already in progress, wait for it
  if (isRefreshing && refreshPromise) return refreshPromise;

  isRefreshing = true;
  refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        credentials: "include",
      });
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
    request<{ access_token: string; expires_in: number }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  register: (email: string, password: string, displayName: string) =>
    request<{ access_token: string }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, display_name: displayName }),
    }),

  logout: () => request("/auth/logout", { method: "POST" }),

  me: () => request<any>("/auth/me"),

  // Scans
  listScans: (params?: string) =>
    request<any[]>(`/scans${params ? `?${params}` : ""}`),

  launchScan: (data: { target_id: string; profile?: string }) =>
    request<any>("/scans", { method: "POST", body: JSON.stringify(data) }),

  getScan: (id: string) => request<any>(`/scans/${id}`),

  stopScan: (id: string) =>
    request(`/scans/${id}/stop`, { method: "POST" }),

  // Gates
  listGates: (scanId: string) => request<any[]>(`/scans/${scanId}/gates`),

  decideGate: (scanId: string, gateNumber: number, decision: string, modifications?: any) =>
    request(`/scans/${scanId}/gates/${gateNumber}/decide`, {
      method: "POST",
      body: JSON.stringify({ decision, user_modifications: modifications }),
    }),

  // Agents
  listAgentRuns: (scanId: string) =>
    request<any[]>(`/agents?scan_id=${scanId}`),

  // Findings
  listFindings: (scanId: string, params?: string) =>
    request<any[]>(`/findings?scan_id=${scanId}${params ? `&${params}` : ""}`),

  findingStats: (scanId: string) =>
    request<any>(`/findings/stats?scan_id=${scanId}`),

  updateFinding: (id: string, data: any) =>
    request(`/findings/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  bulkAction: (data: { finding_ids: string[]; action: string; value?: any }) =>
    request("/findings/bulk", { method: "POST", body: JSON.stringify(data) }),

  // Targets
  listTargets: (projectId: string) =>
    request<any[]>(`/targets?project_id=${projectId}`),

  createTarget: (projectId: string, data: { target_value: string; input_type: string }) =>
    request<any>(`/targets?project_id=${projectId}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // Projects
  listProjects: () => request<any[]>("/projects"),
  createProject: (orgId: string, data: { name: string }) =>
    request<any>(`/projects?org_id=${orgId}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // Organizations
  listOrgs: () => request<any[]>("/organizations"),
  createOrg: (data: { name: string }) =>
    request<any>("/organizations", { method: "POST", body: JSON.stringify(data) }),

  // MITRE
  mitreHeatmap: (scanId: string) => request<any>(`/mitre/heatmap/${scanId}`),

  // Health — note: /api/health is NOT under /api/v1
  healthCheck: () =>
    fetch("/api/health", { credentials: "include" }).then((r) => r.json()) as Promise<{ status: string }>,
};

// SWR fetcher
export const fetcher = (path: string) => request(path);

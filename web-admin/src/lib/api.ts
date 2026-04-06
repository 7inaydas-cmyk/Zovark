const BASE_URL = import.meta.env.VITE_API_URL || window.location.origin;

interface LoginResponse {
  token: string;
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

interface ServiceHealth {
  name: string;
  status: "healthy" | "degraded" | "down";
  latency_ms?: number;
  details?: string;
}

interface SystemHealth {
  status: "healthy" | "degraded" | "down";
  services: ServiceHealth[];
  gpu_tier?: string;
  uptime_seconds?: number;
}

interface ConfigEntry {
  key: string;
  value: string;
  is_secret: boolean;
  updated_at: string;
  updated_by: string;
}

interface ConfigAuditEntry {
  id: string;
  key: string;
  old_value: string;
  new_value: string;
  changed_by: string;
  changed_at: string;
}

interface TaskResponse {
  id: string;
  task_type: string;
  status: string;
  output?: {
    verdict?: string;
    risk_score?: number;
    summary?: string;
    findings?: string[];
  };
}

interface DiagHTTPResult {
  url: string;
  status_code: number;
  latency_ms: number;
  tls_version?: string;
  tls_cipher?: string;
  tls_expiry?: string;
  error?: string;
}

interface DiagParseResult {
  parsed: boolean;
  format_detected?: string;
  fields_extracted?: number;
  normalized?: Record<string, unknown>;
  error?: string;
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(
      `API ${res.status}: ${body || res.statusText}`
    );
  }

  return res.json() as Promise<T>;
}

function authHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}

// --- Auth ---

export async function login(
  email: string,
  password: string
): Promise<LoginResponse> {
  return request<LoginResponse>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function breakglassLogin(
  password: string
): Promise<LoginResponse> {
  return request<LoginResponse>("/api/v1/admin/breakglass/login", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

// --- System Health ---

export async function getSystemHealth(
  token: string
): Promise<SystemHealth> {
  return request<SystemHealth>("/api/v1/admin/system/health", {
    headers: authHeaders(token),
  });
}

// --- Config ---

export async function getConfig(
  token: string
): Promise<ConfigEntry[]> {
  return request<ConfigEntry[]>("/api/v1/admin/config", {
    headers: authHeaders(token),
  });
}

export async function upsertConfig(
  token: string,
  key: string,
  value: string,
  isSecret: boolean
): Promise<void> {
  await request<unknown>("/api/v1/admin/config", {
    method: "PUT",
    headers: authHeaders(token),
    body: JSON.stringify({ key, value, is_secret: isSecret }),
  });
}

export async function getConfigAudit(
  token: string
): Promise<ConfigAuditEntry[]> {
  return request<ConfigAuditEntry[]>("/api/v1/admin/config/audit", {
    headers: authHeaders(token),
  });
}

// --- Bootstrap / Synthetic ---

export async function injectSynthetic(
  token: string
): Promise<{ task_ids: string[] }> {
  return request<{ task_ids: string[] }>(
    "/api/v1/admin/bootstrap/inject-synthetic?force=true",
    {
      method: "POST",
      headers: authHeaders(token),
    }
  );
}

// --- Tasks ---

export async function getTask(
  token: string,
  id: string
): Promise<TaskResponse> {
  return request<TaskResponse>(`/api/v1/tasks/${id}`, {
    headers: authHeaders(token),
  });
}

// --- Diagnostics ---

export async function diagHTTPCheck(
  token: string,
  url: string
): Promise<DiagHTTPResult> {
  return request<DiagHTTPResult>(
    "/api/v1/admin/diagnostics/http-check",
    {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ url }),
    }
  );
}

export async function diagParseTest(
  token: string,
  rawJson: string
): Promise<DiagParseResult> {
  return request<DiagParseResult>(
    "/api/v1/admin/diagnostics/parse-test",
    {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ raw: rawJson }),
    }
  );
}

// --- Zvadmin Commands ---

export async function adminDiagnose(token: string) {
  return request<{
    checks: Array<{ name: string; status: string; detail: string }>;
    overall: string;
  }>("/api/v1/admin/diagnose", {
    method: "POST",
    headers: authHeaders(token),
  });
}

export async function adminAlerts(token: string, hours: number) {
  return request<{
    verdicts: Record<string, number>;
    top_types: Array<{ type: string; count: number }>;
    avg_latency_ms: number;
    total: number;
  }>("/api/v1/admin/alerts", {
    method: "POST",
    headers: authHeaders(token),
    body: JSON.stringify({ hours }),
  });
}

export async function adminModelCheck(token: string) {
  return request<{
    types: Array<{
      name: string;
      avg_risk: number;
      attack_count: number;
      benign_count: number;
    }>;
    separation_gap: number;
  }>("/api/v1/admin/model-check", {
    method: "POST",
    headers: authHeaders(token),
  });
}

export async function adminDedupHealth(token: string) {
  return request<{
    decisions: Record<string, number>;
    total: number;
    efficiency: number;
  }>("/api/v1/admin/dedup-health", {
    method: "POST",
    headers: authHeaders(token),
  });
}

export async function adminSystemStats(token: string) {
  return request<{ task_count: number; redis_memory_mb: number }>(
    "/api/v1/admin/system-stats",
    {
      headers: authHeaders(token),
    }
  );
}

// --- Forge ---

export interface ForgeConfig {
  total_alerts: number;
  attack_ratio: number;
  novelty_rate: number;
  campaign_mode: boolean;
  rate_per_second: number;
  include_benign: boolean;
}

export interface ForgeResults {
  total_submitted: number;
  total_completed: number;
  verdicts: Record<string, number>;
  avg_risk_attack: number;
  avg_risk_benign: number;
  separation_gap: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  novel_variants: number;
  dedup_count: number;
  error_count: number;
  errors?: string[];
  duration: string;
}

export interface ForgeJob {
  id: string;
  status: string;
  progress: number;
  results: ForgeResults;
}

export async function forgeStart(token: string, config: ForgeConfig) {
  return request<{ job_id: string; status: string }>(
    "/api/v1/admin/forge/start",
    {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify(config),
    }
  );
}

export async function forgeStatus(token: string, jobId: string) {
  return request<ForgeJob>(`/api/v1/admin/forge/${jobId}`, {
    headers: authHeaders(token),
  });
}

export async function forgeStop(token: string, jobId: string) {
  return request<{ status: string }>(`/api/v1/admin/forge/${jobId}/stop`, {
    method: "POST",
    headers: authHeaders(token),
  });
}

export async function forgeHistory(token: string) {
  return request<ForgeJob[]>("/api/v1/admin/forge/history", {
    headers: authHeaders(token),
  });
}

// --- Analytics ---

export async function analyticsSummary(
  token: string,
  hours: number,
  excludeForge: boolean
) {
  return request<{
    total: number;
    verdicts: Record<string, number>;
    top_types: Array<{ type: string; count: number; avg_risk: number }>;
    separation_gap: number;
    latency_by_path: Record<string, number>;
  }>("/api/v1/admin/analytics/summary", {
    method: "POST",
    headers: authHeaders(token),
    body: JSON.stringify({ hours, exclude_forge: excludeForge }),
  });
}

// --- Investigation Detail ---

export async function getTaskDetail(token: string, id: string) {
  return request<{
    id: string;
    task_type: string;
    status: string;
    created_at: string;
    verdict: string;
    risk_score: number;
    path_taken: string;
    tools_executed: Array<{ name: string; result_summary: string }>;
    findings: string[];
    iocs: Array<{ type: string; value: string }>;
    mitre_attack: Array<{ technique: string; tactic: string; name: string }>;
    summary: string;
    siem_event: Record<string, unknown>;
  }>(`/api/v1/tasks/${id}/detail`, {
    headers: authHeaders(token),
  });
}

// --- Types re-export for consumers ---

export type {
  LoginResponse,
  ServiceHealth,
  SystemHealth,
  ConfigEntry,
  ConfigAuditEntry,
  TaskResponse,
  DiagHTTPResult,
  DiagParseResult,
};

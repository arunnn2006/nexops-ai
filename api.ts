import type {
  AuditEntry, DashboardSummary, Deployment, Diagnosis, IncidentDetail, IncidentPage, Metric, RecoveryAction,
  RecoveryRequest, Service, TokenResponse, User,
} from "./types";

const BASE: string = import.meta.env.VITE_API_BASE ?? "/api/v1";
const TOKEN_KEY = "nexops_token";

export class ApiError extends Error {
  status: number;
  details?: { field: string; message: string }[];
  constructor(status: number, message: string, details?: { field: string; message: string }[]) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

let unauthorizedHandler: (() => void) | null = null;
export const setUnauthorizedHandler = (fn: (() => void) | null) => { unauthorizedHandler = fn; };

// sessionStorage keeps the token for this tab only. See docs/SECURITY.md for the XSS trade-off.
export const getToken = (): string | null => {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
};
export const setToken = (token: string | null) => {
  try { token ? sessionStorage.setItem(TOKEN_KEY, token) : sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ }
};

type Query = Record<string, string | number | undefined | null>;

async function request<T>(path: string, opts: { method?: string; body?: unknown; query?: Query } = {}): Promise<T> {
  const qs = new URLSearchParams();
  Object.entries(opts.query ?? {}).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") qs.set(k, String(v)); });
  const url = `${BASE}${path}${qs.toString() ? `?${qs}` : ""}`;
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(url, { method: opts.method ?? "GET", headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  } catch {
    throw new ApiError(0, "Cannot reach the API. Is the backend running?");
  }
  if (res.ok) return (res.status === 204 ? undefined : await res.json()) as T;
  let message = `Request failed (${res.status})`;
  let details: ApiError["details"];
  try {
    const body = await res.json();
    message = body?.error?.message ?? message;
    details = body?.error?.details;
  } catch { /* non-JSON error body */ }
  if (res.status === 401 && token && !path.startsWith("/auth/login")) unauthorizedHandler?.();
  throw new ApiError(res.status, message, details);
}

const post = <T>(path: string, body?: unknown) => request<T>(path, { method: "POST", body: body ?? {} });

export const api = {
  login: (email: string, password: string) => post<TokenResponse>("/auth/login", { email, password }),
  register: (email: string, password: string) => post<User>("/auth/register", { email, password }),
  me: () => request<User>("/auth/me"),
  dashboard: () => request<DashboardSummary>("/dashboard/summary"),
  services: () => request<Service[]>("/services"),
  metrics: (serviceId: number, limit = 60) => request<Metric[]>(`/services/${serviceId}/metrics`, { query: { limit } }),
  deployments: (serviceId?: number) => request<Deployment[]>("/deployments", { query: { service_id: serviceId, limit: 100 } }),
  incidents: (q: Query) => request<IncidentPage>("/incidents", { query: q }),
  incident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  detect: () => post<{ created: number }>("/incidents/detect"),
  setIncidentStatus: (id: number, status: string) => request<unknown>(`/incidents/${id}/status`, { method: "PATCH", body: { status } }),
  diagnose: (id: number) => post<Diagnosis>(`/incidents/${id}/diagnose`),
  recoveryActions: () => request<RecoveryAction[]>("/recovery/actions"),
  recoveryRequests: (status?: string) => request<RecoveryRequest[]>("/recovery/requests", { query: { status } }),
  createRecovery: (body: { service_id: number; action: string; incident_id?: number; reason?: string }) =>
    post<RecoveryRequest>("/recovery/requests", body),
  decide: (id: number, decision: "approve" | "reject", note: string) =>
    post<RecoveryRequest>(`/recovery/requests/${id}/${decision}`, { note }),
  execute: (id: number, confirmation_phrase: string) =>
    post<RecoveryRequest>(`/recovery/requests/${id}/execute`, { confirm: true, confirmation_phrase }),
  audit: (q: Query) => request<AuditEntry[]>("/audit", { query: q }),
};

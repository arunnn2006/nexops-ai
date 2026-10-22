export type Role = "viewer" | "operator" | "admin";
export type Severity = "low" | "medium" | "high" | "critical";
export type IncidentStatus = "open" | "investigating" | "resolved";
export type ServiceStatus = "healthy" | "degraded" | "down" | "unknown";

export interface User { id: number; email: string; role: Role; is_active: boolean; created_at: string }
export interface TokenResponse { access_token: string; token_type: string; expires_at: string; user: User }
export interface Service {
  id: number; name: string; description: string; environment: string; is_demo: boolean;
  recovery_allowed: boolean; status: ServiceStatus; current_version: string | null;
  last_checked_at: string | null; created_at: string;
}
export interface Metric {
  id: number; service_id: number; observed_at: string; status: ServiceStatus;
  latency_ms: number; error_rate: number; request_count: number; source: string;
}
export interface Deployment {
  id: number; service_id: number; service_name: string; version: string; status: string;
  commit_sha: string | null; deployed_by: string | null; source: string; notes: string; deployed_at: string;
}
export interface Incident {
  id: number; title: string; rule: string; severity: Severity; status: IncidentStatus;
  service_id: number | null; service_name: string | null; subject: string; summary: string;
  detected_at: string; updated_at: string; resolved_at: string | null;
}
export interface Evidence { id: number; kind: string; observed_at: string; summary: string; data: Record<string, unknown> }
export interface Fact { type: "fact"; text: string; evidence_id: number | null; kind: string }
export interface Hypothesis {
  type: "hypothesis"; statement: string; confidence: "low" | "medium";
  supporting_evidence_ids: number[]; missing_evidence: string[];
}
export interface Diagnosis {
  id: number; incident_id: number; generated_at: string; method: string; summary: string;
  facts: Fact[]; hypotheses: Hypothesis[]; next_steps: string[]; limitations: string[];
}
export interface IncidentDetail extends Incident { evidence: Evidence[]; latest_diagnosis: Diagnosis | null }
export interface IncidentPage { items: Incident[]; total: number }
export interface RecoveryAction { name: string; description: string; simulated_effect: string }
export interface RecoveryRequest {
  id: number; incident_id: number | null; service_id: number; service_name: string; action: string;
  reason: string; status: string; mode: string; requested_by_email: string; decided_by_email: string | null;
  decision_note: string; created_at: string; decided_at: string | null; executed_at: string | null;
  result: Record<string, unknown> | null; verification: Record<string, unknown> | null;
}
export interface AuditEntry {
  id: number; observed_at: string; actor_email: string | null; action: string; target_type: string;
  target_id: string | null; outcome: string; detail: Record<string, unknown>;
}
export interface DashboardSummary {
  services_by_status: Record<string, number>; open_incidents_by_severity: Record<string, number>;
  total_open_incidents: number; pending_recovery_requests: number; recent_deployments: Deployment[];
}

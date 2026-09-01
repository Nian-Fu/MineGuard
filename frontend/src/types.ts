export interface User {
  id: number; username: string; full_name: string; role: string; active: boolean; identity_provider: string
  permitted_areas: string[] | null; concurrency_token: string
}
export interface AuthenticationMethods {
  local_enabled: boolean; oidc_enabled: boolean; oidc_provider_label: string | null
}
export interface PageResponse<T> {
  items: T[]; total: number; page: number; page_size: number
}
export interface Camera {
  id: number; code: string; name: string; area: string; playback_path: string; status: string
  enabled_algorithms: string[]; fps: number; latency_ms: number; last_seen_at: string | null
  concurrency_token: string
}
export interface Person {
  id: number; employee_no: string; name: string; department: string; person_type: string
  authorized_areas: string[]; face_enrolled: boolean; active: boolean; created_at: string
  concurrency_token: string
}
export interface FaceTemplate {
  id: number; person_id: number; provider: string; model_version: string; model_sha256: string | null; key_version: string
  quality: number; liveness: number; consent_reference: string; active: boolean; legal_hold: boolean
  created_at: string; concurrency_token: string
  person: { id: number; employee_no: string; name: string } | null
}
export interface EventItem {
  id: number; event_type: string; severity: string; status: string; title: string; description: string
  confidence: number; snapshot_url: string | null; occurred_at: string; legal_hold: boolean; camera: Camera; person: Person | null
  concurrency_token: string
}
export interface Algorithm {
  id: number; name: string; algorithm_type: string; model_version: string; enabled: boolean
  threshold: number; config: Record<string, unknown>; deployment_status: string; updated_at: string
  concurrency_token: string
}
export interface ModelArtifact {
  id: number; name: string; algorithm_type: string; model_version: string; sha256: string
  runtime: string; license_id: string; source_repository: string; source_commit: string
  metrics: Record<string, string | number>; created_by: number; approved: boolean
  approved_by: number | null; approved_at: string | null; created_at: string; updated_at: string
  concurrency_token: string
}
export interface EdgeModelReport {
  algorithm_type: string; model_version: string; sha256: string; runtime: string; ready: boolean
}
export interface EdgeCameraReport {
  camera_id: number; status: string; fps: number; latency_ms: number; errors: string[]
}
export interface AlertRule {
  id: number; name: string; event_types: string[]; minimum_severity: string; areas: string[]
  channels: string[]; channel_targets: Record<string, string>; cooldown_seconds: number; enabled: boolean
  created_at: string; updated_at: string; concurrency_token: string
}
export interface AuditLog {
  id: number; user_id: number | null; action: string; resource_type: string; resource_id: string | null
  detail: Record<string, unknown>; legal_hold: boolean; ip_address: string | null; created_at: string
}
export interface NotificationDelivery {
  id: number; event_id: number; rule_id: number; channel: string; target: string | null
  status: string; idempotency_key: string; payload: Record<string, unknown>; attempts: number
  next_attempt_at: string; last_error: string | null; sent_at: string | null; created_at: string
}
export interface EdgeNode {
  id: number; code: string; name: string; status: string; active: boolean; camera_ids: number[]
  software_version: string | null
  telemetry: {
    gpu_healthy?: boolean; gpu_utilization?: number; gpu_memory_utilization?: number; queue_depth?: number
    dead_letter_depth?: number; outbox_capacity?: number
    stream_reconnects_last_5m?: number; stream_reconnects_total?: number
    central_reconnects_last_5m?: number; central_reconnects_total?: number
    reported_cameras?: number; area_counts?: Record<string, number>; cameras?: EdgeCameraReport[]
    models?: EdgeModelReport[]; unapproved_models?: EdgeModelReport[]; model_policy_enforced?: boolean
  }
  last_seen_at: string | null
  created_at: string; updated_at: string; concurrency_token: string
}
export interface DashboardSummary {
  cameras_total: number; cameras_online: number; open_events: number; critical_events: number
  persons_total: number; today_events: number; event_types: Record<string, number>
  current_person_count: number; area_occupancy: Record<string, number>
  severity_distribution: Record<string, number>; recent_events: EventItem[]
  hourly_trend: Array<{ time: string; count: number }>
  system_health: Record<string, string | number>
  operational_alerts: Array<{ code: string; severity: string; message: string }>
}

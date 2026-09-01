"""Initial MineGuard schema."""

import sqlalchemy as sa
from alembic import op

revision = "20260821_0001"
down_revision = None
branch_labels = None
depends_on = None

def timestamp_columns():
    return (
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("full_name", sa.String(100), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("auth_version", sa.Integer(), nullable=False),
        *timestamp_columns(),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_table(
        "refresh_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("user_agent", sa.String(300)),
    )
    op.create_index("ix_refresh_sessions_user_id", "refresh_sessions", ["user_id"])
    op.create_index("ix_refresh_sessions_token_hash", "refresh_sessions", ["token_hash"], unique=True)
    op.create_index("ix_refresh_sessions_expires_at", "refresh_sessions", ["expires_at"])
    op.create_table(
        "edge_nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("api_key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("camera_ids", sa.JSON(), nullable=False),
        sa.Column("software_version", sa.String(100)),
        sa.Column("telemetry", sa.JSON(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        *timestamp_columns(),
    )
    op.create_index("ix_edge_nodes_code", "edge_nodes", ["code"], unique=True)
    op.create_index("ix_edge_nodes_status", "edge_nodes", ["status"])
    op.create_index("ix_edge_nodes_last_seen_at", "edge_nodes", ["last_seen_at"])
    op.create_table(
        "cameras",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(50), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("area", sa.String(100), nullable=False),
        sa.Column("stream_url", sa.String(500), nullable=False),
        sa.Column("playback_path", sa.String(200), nullable=False, unique=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("enabled_algorithms", sa.JSON(), nullable=False),
        sa.Column("fps", sa.Float(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        *timestamp_columns(),
        sa.UniqueConstraint("code"),
    )
    op.create_index("ix_cameras_code", "cameras", ["code"], unique=True)
    op.create_index("ix_cameras_area", "cameras", ["area"])
    op.create_table(
        "persons",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("employee_no", sa.String(50), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("department", sa.String(100), nullable=False),
        sa.Column("person_type", sa.String(30), nullable=False),
        sa.Column("authorized_areas", sa.JSON(), nullable=False),
        sa.Column("face_enrolled", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        *timestamp_columns(),
        sa.UniqueConstraint("employee_no"),
    )
    op.create_index("ix_persons_employee_no", "persons", ["employee_no"], unique=True)
    op.create_table(
        "face_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("person_id", sa.Integer(), sa.ForeignKey("persons.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model_version", sa.String(100), nullable=False),
        sa.Column("key_version", sa.String(50), nullable=False),
        sa.Column("encrypted_embedding", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(12), nullable=False),
        sa.Column("quality", sa.Float(), nullable=False),
        sa.Column("liveness", sa.Float(), nullable=False),
        sa.Column("consent_reference", sa.String(200), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_face_templates_person_id", "face_templates", ["person_id"])
    op.create_index("ix_face_templates_active", "face_templates", ["active"])
    op.create_table(
        "model_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("algorithm_type", sa.String(50), nullable=False),
        sa.Column("model_version", sa.String(100), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("runtime", sa.String(50), nullable=False),
        sa.Column("license_id", sa.String(100), nullable=False),
        sa.Column("source_repository", sa.String(300), nullable=False),
        sa.Column("source_commit", sa.String(64), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=False),
        sa.Column("approved_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        *timestamp_columns(),
        sa.UniqueConstraint("algorithm_type", "model_version", "sha256", name="uq_model_artifact_identity"),
    )
    op.create_index("ix_model_artifacts_algorithm_type", "model_artifacts", ["algorithm_type"])
    op.create_index("ix_model_artifacts_model_version", "model_artifacts", ["model_version"])
    op.create_index("ix_model_artifacts_sha256", "model_artifacts", ["sha256"])
    op.create_index("ix_model_artifacts_approved", "model_artifacts", ["approved"])
    op.create_table(
        "algorithm_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("algorithm_type", sa.String(50), nullable=False),
        sa.Column("model_version", sa.String(50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("deployment_status", sa.String(30), nullable=False),
        *timestamp_columns(),
    )
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("event_types", sa.JSON(), nullable=False),
        sa.Column("minimum_severity", sa.String(20), nullable=False),
        sa.Column("areas", sa.JSON(), nullable=False),
        sa.Column("channels", sa.JSON(), nullable=False),
        sa.Column("channel_targets", sa.JSON(), nullable=False),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        *timestamp_columns(),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(50)),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("idempotency_key", sa.String(160), unique=True),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("camera_id", sa.Integer(), sa.ForeignKey("cameras.id"), nullable=False),
        sa.Column("person_id", sa.Integer(), sa.ForeignKey("persons.id")),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("snapshot_url", sa.String(500)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        *timestamp_columns(),
    )
    for column in ("event_type", "severity", "status", "camera_id", "occurred_at"):
        op.create_index(f"ix_events_{column}", "events", [column])
    op.create_index("ix_events_idempotency_key", "events", ["idempotency_key"], unique=True)
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("events.id"), nullable=False),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("alert_rules.id"), nullable=False),
        sa.Column("channel", sa.String(30), nullable=False),
        sa.Column("target", sa.String(300)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.String(500)),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_notification_deliveries_event_id", "notification_deliveries", ["event_id"])
    op.create_index("ix_notification_deliveries_rule_id", "notification_deliveries", ["rule_id"])
    op.create_index("ix_notification_deliveries_status", "notification_deliveries", ["status"])
    op.create_index("ix_notification_deliveries_idempotency_key", "notification_deliveries", ["idempotency_key"], unique=True)
    op.create_index("ix_notification_deliveries_next_attempt_at", "notification_deliveries", ["next_attempt_at"])


def downgrade() -> None:
    op.drop_table("notification_deliveries")
    op.drop_table("events")
    op.drop_table("audit_logs")
    op.drop_table("alert_rules")
    op.drop_table("algorithm_configs")
    op.drop_table("model_artifacts")
    op.drop_table("face_templates")
    op.drop_table("persons")
    op.drop_table("cameras")
    op.drop_table("edge_nodes")
    op.drop_table("refresh_sessions")
    op.drop_table("users")

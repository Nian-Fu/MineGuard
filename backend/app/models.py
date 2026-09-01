import hashlib
import hmac
import json
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def configuration_token(*values) -> str:
    from app.core.config import get_settings

    encoded = json.dumps(
        values,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
    return hmac.new(
        get_settings().secret_key.encode("utf-8"),
        encoded.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class CameraStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


class EventType(StrEnum):
    INTRUSION = "intrusion"
    FACE_MATCH = "face_match"
    UNKNOWN_FACE = "unknown_face"
    NO_HELMET = "no_helmet"
    CROWDING = "crowding"
    CAMERA_OFFLINE = "camera_offline"


class EventStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class NotificationChannel(StrEnum):
    CONSOLE = "console"
    SMS = "sms"
    BROADCAST = "broadcast"
    WEBHOOK = "webhook"


class EdgeNodeStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    @property
    def concurrency_token(self) -> str:
        value = self.updated_at
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat(timespec="microseconds")


class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint(
            "identity_provider", "external_subject", name="uq_user_external_identity"
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default=Role.OPERATOR)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_version: Mapped[int] = mapped_column(Integer, default=0)
    identity_provider: Mapped[str] = mapped_column(String(64), default="local", index=True)
    external_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    permitted_areas: Mapped[list[str] | None] = mapped_column(JSON, nullable=True, default=None)


class RefreshSession(Base):
    __tablename__ = "refresh_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    user: Mapped[User] = relationship()


class RealtimeSignal(Base):
    __tablename__ = "realtime_signals"
    id: Mapped[int] = mapped_column(primary_key=True)
    topic: Mapped[str] = mapped_column(String(40), index=True)
    area: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class ServiceHeartbeat(Base):
    __tablename__ = "service_heartbeats"
    instance_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class EdgeNode(TimestampMixin, Base):
    __tablename__ = "edge_nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(100))
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(20), default=EdgeNodeStatus.OFFLINE, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    camera_ids: Mapped[list] = mapped_column(JSON, default=list)
    software_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    telemetry: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    @property
    def concurrency_token(self) -> str:
        return configuration_token(
            self.code,
            self.name,
            self.active,
            sorted(self.camera_ids or []),
            self.api_key_hash,
        )


class Camera(TimestampMixin, Base):
    __tablename__ = "cameras"
    __table_args__ = (
        CheckConstraint(
            "(stream_url IS NOT NULL AND stream_url_ciphertext IS NULL "
            "AND stream_url_nonce IS NULL AND stream_url_key_version IS NULL) OR "
            "(stream_url IS NULL AND stream_url_ciphertext IS NOT NULL "
            "AND stream_url_nonce IS NOT NULL AND stream_url_key_version IS NOT NULL)",
            name="ck_cameras_stream_url_storage",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(100))
    area: Mapped[str] = mapped_column(String(100), index=True)
    _legacy_stream_url: Mapped[str | None] = mapped_column(
        "stream_url", String(500), nullable=True
    )
    stream_url_ciphertext: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    stream_url_nonce: Mapped[bytes | None] = mapped_column(
        LargeBinary(12), nullable=True
    )
    stream_url_key_version: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )
    playback_path: Mapped[str] = mapped_column(String(200), unique=True)
    status: Mapped[str] = mapped_column(String(20), default=CameraStatus.OFFLINE)
    enabled_algorithms: Mapped[list] = mapped_column(JSON, default=list)
    fps: Mapped[float] = mapped_column(Float, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    events: Mapped[list["Event"]] = relationship(back_populates="camera")

    def _stream_url_associated_data(self) -> bytes:
        if not self.code:
            raise ValueError("camera code is required before assigning stream_url")
        return f"mineguard:camera-url:{self.code}".encode("utf-8")

    @property
    def stream_url(self) -> str:
        if self.stream_url_ciphertext is not None:
            from app.services.camera_urls import camera_url_cipher_from_settings

            cipher = camera_url_cipher_from_settings()
            if cipher is None:
                raise RuntimeError("camera URL decryption key is not configured")
            if self.stream_url_nonce is None or self.stream_url_key_version is None:
                raise RuntimeError("encrypted camera URL metadata is incomplete")
            return cipher.decrypt(
                self.stream_url_ciphertext,
                self.stream_url_nonce,
                self.stream_url_key_version,
                self._stream_url_associated_data(),
            )
        if self._legacy_stream_url is None:
            raise RuntimeError("camera stream URL is not configured")
        return self._legacy_stream_url

    @stream_url.setter
    def stream_url(self, value: str) -> None:
        from app.services.camera_urls import camera_url_cipher_from_settings

        cipher = camera_url_cipher_from_settings()
        if cipher is None:
            self._legacy_stream_url = value
            self.stream_url_ciphertext = None
            self.stream_url_nonce = None
            self.stream_url_key_version = None
            return
        encrypted = cipher.encrypt(value, self._stream_url_associated_data())
        self._legacy_stream_url = None
        self.stream_url_ciphertext = encrypted.ciphertext
        self.stream_url_nonce = encrypted.nonce
        self.stream_url_key_version = encrypted.key_version

    @property
    def concurrency_token(self) -> str:
        return configuration_token(
            self.code,
            self.name,
            self.area,
            self.stream_url,
            sorted(self.enabled_algorithms or []),
        )


class Person(TimestampMixin, Base):
    __tablename__ = "persons"
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_no: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(100))
    department: Mapped[str] = mapped_column(String(100))
    person_type: Mapped[str] = mapped_column(String(30), default="employee")
    authorized_areas: Mapped[list] = mapped_column(JSON, default=list)
    face_enrolled: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    area_grants: Mapped[list["PersonAreaGrant"]] = relationship(
        cascade="all, delete-orphan"
    )


class PersonAreaGrant(Base):
    __tablename__ = "person_area_grants"
    person_id: Mapped[int] = mapped_column(
        ForeignKey("persons.id", ondelete="CASCADE"), primary_key=True
    )
    area: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)


class FaceTemplate(Base):
    __tablename__ = "face_templates"
    __table_args__ = (
        Index(
            "ix_face_templates_model_identity",
            "model_version",
            "model_sha256",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    person_id: Mapped[int] = mapped_column(ForeignKey("persons.id"), index=True)
    provider: Mapped[str] = mapped_column(String(50))
    model_version: Mapped[str] = mapped_column(String(100))
    model_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_version: Mapped[str] = mapped_column(String(50))
    encrypted_embedding: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12))
    quality: Mapped[float] = mapped_column(Float)
    liveness: Mapped[float] = mapped_column(Float)
    consent_reference: Mapped[str] = mapped_column(String(200))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    person: Mapped[Person] = relationship()

    @property
    def concurrency_token(self) -> str:
        return configuration_token(
            self.id,
            self.person_id,
            self.provider,
            self.model_version,
            self.model_sha256,
            self.key_version,
            self.active,
            self.legal_hold,
            self.created_at,
        )


class Event(TimestampMixin, Base):
    __tablename__ = "events"
    __table_args__ = (
        Index(
            "ix_events_notification_cooldown_scope",
            "camera_id",
            "event_type",
            "occurred_at",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), unique=True, index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default=EventStatus.OPEN, index=True)
    camera_id: Mapped[int] = mapped_column(ForeignKey("cameras.id"), index=True)
    person_id: Mapped[int | None] = mapped_column(ForeignKey("persons.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float)
    snapshot_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    camera: Mapped[Camera] = relationship(back_populates="events")
    person: Mapped[Person | None] = relationship()


class SnapshotLegalHoldJob(Base):
    __tablename__ = "snapshot_legal_hold_jobs"
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), primary_key=True
    )
    desired_enabled: Mapped[bool] = mapped_column(Boolean)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    reason: Mapped[str] = mapped_column(String(500))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    last_error: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ModelArtifact(TimestampMixin, Base):
    __tablename__ = "model_artifacts"
    __table_args__ = (
        UniqueConstraint("algorithm_type", "model_version", "sha256", name="uq_model_artifact_identity"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    algorithm_type: Mapped[str] = mapped_column(String(50), index=True)
    model_version: Mapped[str] = mapped_column(String(100), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    runtime: Mapped[str] = mapped_column(String(50))
    license_id: Mapped[str] = mapped_column(String(100))
    source_repository: Mapped[str] = mapped_column(String(300))
    source_commit: Mapped[str] = mapped_column(String(64))
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    approved: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AlgorithmConfig(TimestampMixin, Base):
    __tablename__ = "algorithm_configs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    algorithm_type: Mapped[str] = mapped_column(String(50))
    model_version: Mapped[str] = mapped_column(String(50))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    threshold: Mapped[float] = mapped_column(Float, default=0.7)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    deployment_status: Mapped[str] = mapped_column(String(30), default="ready")


class AlertRule(TimestampMixin, Base):
    __tablename__ = "alert_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    event_types: Mapped[list] = mapped_column(JSON, default=list)
    minimum_severity: Mapped[str] = mapped_column(String(20), default=Severity.MEDIUM)
    areas: Mapped[list] = mapped_column(JSON, default=list)
    channels: Mapped[list] = mapped_column(JSON, default=list)
    channel_targets: Mapped[dict] = mapped_column(JSON, default=dict)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        Index(
            "ix_notification_deliveries_cooldown_scope",
            "rule_id",
            "channel",
            "event_id",
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), index=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rules.id"), index=True)
    channel: Mapped[str] = mapped_column(String(30))
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=DeliveryStatus.PENDING, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

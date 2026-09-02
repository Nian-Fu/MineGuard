import json
import re
from datetime import datetime
from math import isfinite
from typing import Any, ClassVar, Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models import CameraStatus, EventStatus, EventType, NotificationChannel, Role, Severity


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PatchModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nullable_patch_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="after")
    def reject_explicit_nulls(self):
        invalid = sorted(
            field
            for field in self.model_fields_set
            if getattr(self, field) is None and field not in self.nullable_patch_fields
        )
        if invalid:
            raise ValueError(
                f"patch fields cannot be null: {', '.join(invalid)}"
            )
        return self


def validate_json_size(value: Any, *, max_bytes: int, field_name: str) -> Any:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{field_name} must be valid JSON") from exc
    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} cannot exceed {max_bytes // 1024} KiB")
    return value


def strict_finite_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("value must be a JSON number")
    try:
        normalized = float(value)
    except OverflowError as exc:
        raise ValueError("value must be finite") from exc
    if not isfinite(normalized):
        raise ValueError("value must be finite")
    return normalized


def normalize_algorithm_names(value: list[str]) -> list[str]:
    normalized = [item.strip() for item in value]
    if (
        len(normalized) > 50
        or len(normalized) != len(set(normalized))
        or any(
            not item
            or len(item) > 50
            or not all(char.isalnum() or char in "_.-" for char in item)
            for item in normalized
        )
    ):
        raise ValueError(
            "enabled_algorithms must contain at most 50 unique algorithm identifiers"
        )
    return normalized


def validate_rtsp_url(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme.lower() not in {"rtsp", "rtsps"}
        or not parts.hostname
        or parts.fragment
        or any(char.isspace() for char in value)
    ):
        raise ValueError(
            "stream_url must be an RTSP/RTSPS URL with a host and without whitespace or fragment"
        )
    return value


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserRead"


class LoginRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class UserRead(ORMModel):
    id: int
    username: str
    full_name: str
    role: str
    active: bool
    identity_provider: str
    permitted_areas: list[str] | None
    concurrency_token: str


class AuthenticationMethods(BaseModel):
    local_enabled: bool
    oidc_enabled: bool
    oidc_provider_label: str | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    full_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=12, max_length=128)
    role: Role = Role.OPERATOR
    permitted_areas: list[str] | None = Field(default_factory=list)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, value: str) -> str:
        if not (any(x.isupper() for x in value) and any(x.islower() for x in value) and any(x.isdigit() for x in value)):
            raise ValueError("password must contain uppercase, lowercase and numeric characters")
        return value

    @field_validator("permitted_areas")
    @classmethod
    def validate_permitted_areas(cls, value: list[str] | None) -> list[str] | None:
        return normalize_areas(value)


class UserUpdate(PatchModel):
    nullable_patch_fields: ClassVar[frozenset[str]] = frozenset(
        {"permitted_areas"}
    )
    full_name: str | None = Field(default=None, min_length=2, max_length=100)
    role: Role | None = None
    active: bool | None = Field(default=None, strict=True)
    permitted_areas: list[str] | None = None

    @field_validator("permitted_areas")
    @classmethod
    def validate_permitted_areas(cls, value: list[str] | None) -> list[str] | None:
        return normalize_areas(value)


def normalize_areas(value: list[str] | None) -> list[str] | None:
    if value is None:
        return None
    normalized = [area.strip() for area in value if area.strip()]
    if len(normalized) > 200 or len(normalized) != len(set(normalized)):
        raise ValueError("areas must contain at most 200 unique values")
    if any(len(area) > 100 for area in normalized):
        raise ValueError("area cannot exceed 100 characters")
    return sorted(normalized)


def validate_new_password(value: str) -> str:
    if not (any(x.isupper() for x in value) and any(x.islower() for x in value) and any(x.isdigit() for x in value)):
        raise ValueError("password must contain uppercase, lowercase and numeric characters")
    return value


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)

    _validate_password = field_validator("new_password")(validate_new_password)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=12, max_length=128)

    _validate_password = field_validator("new_password")(validate_new_password)


class CameraCreate(BaseModel):
    code: str = Field(min_length=2, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    name: str = Field(min_length=2, max_length=100)
    area: str = Field(min_length=2, max_length=100)
    stream_url: str = Field(min_length=4, max_length=500)
    enabled_algorithms: list[str] = Field(default_factory=list)

    _validate_algorithms = field_validator("enabled_algorithms")(
        normalize_algorithm_names
    )

    @field_validator("stream_url")
    @classmethod
    def validate_stream_url(cls, value: str) -> str:
        return validate_rtsp_url(value)


class CameraUpdate(PatchModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    area: str | None = Field(default=None, min_length=2, max_length=100)
    stream_url: str | None = Field(default=None, min_length=4, max_length=500)
    enabled_algorithms: list[str] | None = None

    @field_validator("enabled_algorithms")
    @classmethod
    def validate_algorithms(cls, value: list[str] | None) -> list[str] | None:
        return normalize_algorithm_names(value) if value is not None else None

    @field_validator("stream_url")
    @classmethod
    def validate_stream_url(cls, value: str | None) -> str | None:
        return validate_rtsp_url(value) if value is not None else None


class CameraRead(ORMModel):
    id: int
    code: str
    name: str
    area: str
    playback_path: str
    status: str
    enabled_algorithms: list[str]
    fps: float
    latency_ms: int
    last_seen_at: datetime | None
    concurrency_token: str


class PersonCreate(BaseModel):
    employee_no: str = Field(min_length=2, max_length=50)
    name: str = Field(min_length=2, max_length=100)
    department: str = Field(min_length=2, max_length=100)
    person_type: str = Field(default="employee", min_length=2, max_length=30)
    authorized_areas: list[str] = Field(default_factory=list)

    @field_validator("authorized_areas")
    @classmethod
    def validate_authorized_areas(cls, value: list[str]) -> list[str]:
        normalized = [area.strip() for area in value if area.strip()]
        if len(normalized) > 100 or len(normalized) != len(set(normalized)):
            raise ValueError("authorized_areas must contain at most 100 unique values")
        if any(len(area) > 100 for area in normalized):
            raise ValueError("authorized area cannot exceed 100 characters")
        return normalized


class PersonRead(ORMModel):
    id: int
    employee_no: str
    name: str
    department: str
    person_type: str
    authorized_areas: list[str]
    face_enrolled: bool
    active: bool
    created_at: datetime
    concurrency_token: str


class PersonUpdate(PatchModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    department: str | None = Field(default=None, min_length=2, max_length=100)
    person_type: str | None = Field(default=None, min_length=2, max_length=30)
    authorized_areas: list[str] | None = None
    active: bool | None = Field(default=None, strict=True)

    @field_validator("authorized_areas")
    @classmethod
    def validate_authorized_areas(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        normalized = [area.strip() for area in value if area.strip()]
        if len(normalized) > 100 or len(normalized) != len(set(normalized)):
            raise ValueError("authorized_areas must contain at most 100 unique values")
        if any(len(area) > 100 for area in normalized):
            raise ValueError("authorized area cannot exceed 100 characters")
        return normalized


class FaceTemplatePerson(ORMModel):
    id: int
    employee_no: str
    name: str


class FaceTemplateRead(ORMModel):
    id: int
    person_id: int
    provider: str
    model_version: str
    model_sha256: str | None
    key_version: str
    quality: float
    liveness: float
    consent_reference: str
    active: bool
    legal_hold: bool
    created_at: datetime
    concurrency_token: str
    person: FaceTemplatePerson | None = None


class FaceEnrollmentResponse(BaseModel):
    template: FaceTemplateRead
    message: str


class FaceCandidate(BaseModel):
    person_id: int
    employee_no: str
    name: str
    similarity: float = Field(ge=0, le=1, allow_inf_nan=False)


class FaceIdentificationResponse(BaseModel):
    matched: bool
    unknown: bool
    quality: float
    liveness: float
    model_version: str
    model_sha256: str
    candidates: list[FaceCandidate]


class EdgeFaceCandidate(BaseModel):
    person_id: int
    similarity: float = Field(ge=0, le=1, allow_inf_nan=False)


class EdgeFaceIdentificationResponse(BaseModel):
    matched: bool
    unknown: bool
    quality: float
    liveness: float
    model_version: str
    model_sha256: str
    authorized_for_camera: bool | None
    candidate: EdgeFaceCandidate | None


def canonical_snapshot_reference(value: str | None) -> str | None:
    if value is None:
        return None
    parts = urlsplit(value)
    invalid_common = (
        parts.username is not None
        or parts.password is not None
        or bool(parts.query)
        or bool(parts.fragment)
        or "\\" in value
        or any(char.isspace() for char in value)
    )
    decoded_path = unquote(parts.path)
    reference_match = re.fullmatch(
        r"/snapshots/camera-[1-9][0-9]{0,18}/([0-9]{4})/([0-9]{2})/([0-9]{2})/[a-f0-9]{32}\.jpg",
        decoded_path,
    )
    if (
        invalid_common
        or parts.scheme
        or parts.netloc
        or "\\" in decoded_path
        or not reference_match
    ):
        raise ValueError("snapshot_url must be a canonical internal snapshot reference")
    try:
        datetime(
            int(reference_match.group(1)),
            int(reference_match.group(2)),
            int(reference_match.group(3)),
        )
    except ValueError as exc:
        raise ValueError("snapshot_url must contain a valid calendar date") from exc
    return decoded_path


class EventCreate(BaseModel):
    event_type: EventType
    severity: Severity
    camera_id: int = Field(ge=1, strict=True)
    person_id: int | None = Field(default=None, ge=1, strict=True)
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=2000)
    confidence: float = Field(ge=0, le=1, strict=True, allow_inf_nan=False)
    snapshot_url: str | None = Field(default=None, max_length=500)
    occurred_at: datetime | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)

    _validate_confidence = field_validator("confidence", mode="before")(
        strict_finite_float
    )

    @field_validator("metadata_json")
    @classmethod
    def validate_metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_json_size(
            value, max_bytes=32 * 1024, field_name="metadata_json"
        )

    @field_validator("snapshot_url")
    @classmethod
    def validate_snapshot_reference(cls, value: str | None) -> str | None:
        return canonical_snapshot_reference(value)


class SnapshotUploadRequest(BaseModel):
    camera_id: int = Field(ge=1, strict=True)
    content_type: Literal["image/jpeg"]
    content_length: int = Field(ge=1024, le=20 * 1024 * 1024, strict=True)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    reference: str | None = Field(default=None, max_length=200)

    _validate_reference = field_validator("reference")(
        canonical_snapshot_reference
    )


class SnapshotVerifyRequest(SnapshotUploadRequest):
    reference: str = Field(max_length=200)


class SnapshotUploadGrant(BaseModel):
    reference: str
    upload_url: str
    required_headers: dict[str, str]
    expires_in_seconds: int


class SnapshotAccessGrant(BaseModel):
    download_url: str
    expires_in_seconds: int


class EventRead(ORMModel):
    id: int
    idempotency_key: str | None
    event_type: str
    severity: str
    status: str
    camera_id: int
    person_id: int | None
    title: str
    description: str
    confidence: float
    snapshot_url: str | None
    occurred_at: datetime
    acknowledged_by: int | None
    resolved_at: datetime | None
    metadata_json: dict[str, Any]
    legal_hold: bool
    camera: CameraRead
    person: PersonRead | None
    concurrency_token: str


class EventStatusUpdate(BaseModel):
    status: EventStatus
    note: str = Field(default="", max_length=500)


class LegalHoldUpdate(BaseModel):
    enabled: bool = Field(strict=True)
    reason: str = Field(min_length=3, max_length=500)


class EdgeEventReceipt(BaseModel):
    id: int
    idempotency_key: str
    status: str
    created: bool


class AlgorithmRead(ORMModel):
    id: int
    name: str
    algorithm_type: str
    model_version: str
    enabled: bool
    threshold: float
    config: dict[str, Any]
    deployment_status: str
    updated_at: datetime
    concurrency_token: str


class AlgorithmUpdate(PatchModel):
    enabled: bool | None = Field(default=None, strict=True)
    threshold: float | None = Field(
        default=None, ge=0, le=1, strict=True, allow_inf_nan=False
    )
    config: dict[str, Any] | None = None

    _validate_threshold = field_validator("threshold", mode="before")(
        strict_finite_float
    )

    @field_validator("config")
    @classmethod
    def validate_config(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return validate_json_size(value, max_bytes=32 * 1024, field_name="config")


class ModelArtifactCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    algorithm_type: str = Field(min_length=2, max_length=50, pattern=r"^[a-z0-9_.-]+$")
    model_version: str = Field(min_length=1, max_length=100)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    runtime: str = Field(min_length=2, max_length=50)
    license_id: str = Field(min_length=2, max_length=100)
    source_repository: str = Field(min_length=4, max_length=300)
    source_commit: str = Field(min_length=7, max_length=64, pattern=r"^[a-fA-F0-9]+$")
    metrics: dict[str, float | int | str] = Field(default_factory=dict, max_length=100)

    @field_validator("source_repository")
    @classmethod
    def validate_source_repository(cls, value: str) -> str:
        parts = urlsplit(value)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "source_repository must be an HTTP(S) URL without credentials, query, or fragment"
            )
        return value

    @field_validator("metrics", mode="before")
    @classmethod
    def reject_coerced_metrics(cls, value):
        if not isinstance(value, dict) or any(
            not isinstance(key, str)
            or isinstance(metric, bool)
            or not isinstance(metric, (float, int, str))
            for key, metric in value.items()
        ):
            raise ValueError("metrics contains an invalid key or value")
        return value

    @field_validator("metrics")
    @classmethod
    def validate_metrics(
        cls, value: dict[str, float | int | str]
    ) -> dict[str, float | int | str]:
        if any(
            not key.strip()
            or len(key) > 100
            or isinstance(metric, float)
            and not isfinite(metric)
            or isinstance(metric, str)
            and len(metric) > 500
            for key, metric in value.items()
        ):
            raise ValueError("metrics contains an invalid key or value")
        return validate_json_size(value, max_bytes=16 * 1024, field_name="metrics")


class ModelArtifactRead(ORMModel):
    id: int
    name: str
    algorithm_type: str
    model_version: str
    sha256: str
    runtime: str
    license_id: str
    source_repository: str
    source_commit: str
    metrics: dict[str, Any]
    created_by: int
    approved: bool
    approved_by: int | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    concurrency_token: str


class ModelArtifactApproval(BaseModel):
    approved: bool = Field(strict=True)
    reason: str = Field(min_length=3, max_length=500)


class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    event_types: list[EventType] = Field(min_length=1, max_length=len(EventType))
    minimum_severity: Severity = Severity.MEDIUM
    areas: list[str] = Field(default_factory=list, max_length=200)
    channels: list[NotificationChannel] = Field(
        default_factory=lambda: [NotificationChannel.CONSOLE],
        min_length=1,
        max_length=len(NotificationChannel),
    )
    channel_targets: dict[str, str] = Field(default_factory=dict)
    cooldown_seconds: int = Field(default=60, ge=0, le=86400, strict=True)
    enabled: bool = Field(default=True, strict=True)

    @field_validator("event_types", "channels")
    @classmethod
    def validate_unique_enums(cls, value: list) -> list:
        identities = [item.value for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("event types and channels must not contain duplicates")
        return value

    @field_validator("areas")
    @classmethod
    def validate_areas(cls, value: list[str]) -> list[str]:
        return normalize_areas(value) or []

    @field_validator("channel_targets")
    @classmethod
    def validate_targets(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {channel.value for channel in NotificationChannel}
        for channel, target in value.items():
            if channel not in allowed or not target or len(target) > 100:
                raise ValueError("channel targets must use a known channel and a 1-100 character profile ID")
            if not all(char.isalnum() or char in "_.:-" for char in target):
                raise ValueError("channel target must be a profile ID, not a URL or free-form address")
        return value

    @model_validator(mode="after")
    def validate_target_channels(self):
        selected = {channel.value for channel in self.channels}
        if not set(self.channel_targets).issubset(selected):
            raise ValueError("channel targets must reference an enabled channel")
        return self


class AlertRuleUpdate(PatchModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    event_types: list[EventType] | None = Field(
        default=None, min_length=1, max_length=len(EventType)
    )
    minimum_severity: Severity | None = None
    areas: list[str] | None = Field(default=None, max_length=200)
    channels: list[NotificationChannel] | None = Field(
        default=None, min_length=1, max_length=len(NotificationChannel)
    )
    channel_targets: dict[str, str] | None = None
    cooldown_seconds: int | None = Field(
        default=None, ge=0, le=86400, strict=True
    )
    enabled: bool | None = Field(default=None, strict=True)

    @field_validator("event_types", "channels")
    @classmethod
    def validate_unique_enums(cls, value: list | None) -> list | None:
        if value is not None:
            identities = [item.value for item in value]
            if len(identities) != len(set(identities)):
                raise ValueError("event types and channels must not contain duplicates")
        return value

    @field_validator("areas")
    @classmethod
    def validate_areas(cls, value: list[str] | None) -> list[str] | None:
        return normalize_areas(value)

    @field_validator("channel_targets")
    @classmethod
    def validate_targets(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return value
        allowed = {channel.value for channel in NotificationChannel}
        for channel, target in value.items():
            if channel not in allowed or not target or len(target) > 100:
                raise ValueError("channel targets must use a known channel and a 1-100 character profile ID")
            if not all(char.isalnum() or char in "_.:-" for char in target):
                raise ValueError("channel target must be a profile ID, not a URL or free-form address")
        return value

    @model_validator(mode="after")
    def validate_target_channels(self):
        if self.channels is not None and self.channel_targets is not None:
            selected = {channel.value for channel in self.channels}
            if not set(self.channel_targets).issubset(selected):
                raise ValueError("channel targets must reference an enabled channel")
        return self


class AlertRuleRead(ORMModel):
    id: int
    name: str
    event_types: list[str]
    minimum_severity: str
    areas: list[str]
    channels: list[str]
    channel_targets: dict[str, str]
    cooldown_seconds: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    concurrency_token: str


class NotificationDeliveryRead(ORMModel):
    id: int
    event_id: int
    rule_id: int
    channel: str
    target: str | None
    status: str
    idempotency_key: str
    payload: dict[str, Any]
    attempts: int
    next_attempt_at: datetime
    last_error: str | None
    sent_at: datetime | None
    created_at: datetime


class AuditLogRead(ORMModel):
    id: int
    user_id: int | None
    action: str
    resource_type: str
    resource_id: str | None
    detail: dict[str, Any]
    legal_hold: bool
    ip_address: str | None
    created_at: datetime


class OperationalAlert(BaseModel):
    code: str
    severity: str
    message: str


class DashboardSummary(BaseModel):
    cameras_total: int
    cameras_online: int
    open_events: int
    critical_events: int
    persons_total: int
    today_events: int
    current_person_count: int
    area_occupancy: dict[str, int]
    event_types: dict[str, int]
    severity_distribution: dict[str, int]
    recent_events: list[EventRead]
    hourly_trend: list[dict[str, int | str]]
    system_health: dict[str, float | int | str]
    operational_alerts: list[OperationalAlert]


class Page(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class VideoCaseMetrics(BaseModel):
    decoded_frames: int = Field(ge=0)
    analyzed_frames: int = Field(ge=0)
    frame_sampling_interval: int = Field(ge=1)
    source_fps: float = Field(ge=0, allow_inf_nan=False)
    frames_with_people: int = Field(ge=0)
    detection_coverage: float = Field(ge=0, le=1, allow_inf_nan=False)
    detected_people: int = Field(ge=0)
    rule_events: dict[str, int] = Field(default_factory=dict)
    latency_ms_mean: float = Field(ge=0, allow_inf_nan=False)
    latency_ms_p50: float = Field(ge=0, allow_inf_nan=False)
    latency_ms_p95: float = Field(ge=0, allow_inf_nan=False)
    effective_analysis_fps: float = Field(ge=0, allow_inf_nan=False)


class VideoCaseSample(BaseModel):
    frame: int = Field(ge=0)
    timestamp_seconds: float = Field(ge=0, allow_inf_nan=False)
    people: int = Field(ge=0)
    events: list[str] = Field(default_factory=list)


class VideoCaseRead(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9-]{2,80}$")
    title: str = Field(min_length=2, max_length=200)
    scenario: str = Field(min_length=2, max_length=200)
    video_file: str = Field(pattern=r"^[a-z0-9-]+-480p\.webm$")
    video_path: str = Field(pattern=r"^/cases/[a-z0-9-]+-480p\.webm$")
    source_url: str = Field(min_length=10, max_length=500)
    source_attribution: str = Field(min_length=2, max_length=200)
    license: str = Field(min_length=2, max_length=50)
    metrics: VideoCaseMetrics
    samples: list[VideoCaseSample] = Field(default_factory=list, max_length=20)


class VideoCaseManifest(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    generated_at: datetime
    method: str = Field(min_length=2, max_length=500)
    limitations: str = Field(min_length=2, max_length=1000)
    cases: list[VideoCaseRead] = Field(min_length=1, max_length=20)


class RoleDefinition(BaseModel):
    id: str = Field(pattern=r"^(admin|operator|auditor)$")
    name: str
    description: str
    permissions: list[str]


class LlmConfigurationUpdate(PatchModel):
    enabled: bool | None = Field(default=None, strict=True)
    provider: Literal["openai_compatible", "ollama"] | None = None
    base_url: str | None = Field(default=None, min_length=8, max_length=300)
    model: str | None = Field(default=None, min_length=1, max_length=120)
    api_key_env: str | None = Field(default=None, min_length=3, max_length=100)
    temperature: float | None = Field(default=None, ge=0, le=2, allow_inf_nan=False)
    max_tokens: int | None = Field(default=None, ge=64, le=32768, strict=True)
    system_prompt: str | None = Field(default=None, max_length=4000)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("base_url must be an HTTP(S) URL without credentials, query, or fragment")
        return value.rstrip("/")

    @field_validator("api_key_env")
    @classmethod
    def validate_api_key_env(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"MINEGUARD_[A-Z0-9_]{2,90}", value):
            raise ValueError("api_key_env must be a MINEGUARD_ environment variable name")
        return value


class LlmConfigurationRead(BaseModel):
    enabled: bool
    provider: Literal["openai_compatible", "ollama"]
    base_url: str
    model: str
    api_key_env: str
    temperature: float
    max_tokens: int
    system_prompt: str
    api_key_configured: bool
    updated_at: datetime | None = None
    concurrency_token: str


class SystemCapabilities(BaseModel):
    environment: str
    face_recognition_enabled: bool
    notification_gateway_configured: bool
    authentication_mode: str
    authorization_scope: str
    media_authorization: str
    access_token_minutes: int
    refresh_token_days: int
    live_update_mode: str
    biometric_template_encryption: str
    approved_model_enforcement: bool
    four_eyes_model_approval: bool
    snapshot_storage_enabled: bool


class EdgeNodeCreate(BaseModel):
    code: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    name: str = Field(min_length=2, max_length=100)
    camera_ids: list[int] = Field(default_factory=list, max_length=1000)

    @field_validator("camera_ids", mode="before")
    @classmethod
    def validate_camera_ids(cls, value: list[int]) -> list[int]:
        if not isinstance(value, list) or any(
            isinstance(camera_id, bool)
            or not isinstance(camera_id, int)
            or camera_id < 1
            for camera_id in value
        ) or len(value) != len(set(value)):
            raise ValueError("camera_ids must contain unique positive identifiers")
        return value


class EdgeNodeUpdate(PatchModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    active: bool | None = Field(default=None, strict=True)
    camera_ids: list[int] | None = Field(default=None, max_length=1000)

    @field_validator("camera_ids", mode="before")
    @classmethod
    def validate_camera_ids(cls, value: list[int] | None) -> list[int] | None:
        if value is not None and (
            not isinstance(value, list)
            or any(
                isinstance(camera_id, bool)
                or not isinstance(camera_id, int)
                or camera_id < 1
                for camera_id in value
            )
            or len(value) != len(set(value))
        ):
            raise ValueError("camera_ids must contain unique positive identifiers")
        return value


class EdgeNodeRead(ORMModel):
    id: int
    code: str
    name: str
    status: str
    active: bool
    camera_ids: list[int]
    software_version: str | None
    telemetry: dict[str, Any]
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
    concurrency_token: str

    @field_validator("telemetry")
    @classmethod
    def normalize_legacy_camera_errors(
        cls, value: dict[str, Any]
    ) -> dict[str, Any]:
        cameras = value.get("cameras")
        if not isinstance(cameras, list):
            return value
        return {
            **value,
            "cameras": [
                {**camera, "errors": camera.get("errors", [])}
                if isinstance(camera, dict)
                else camera
                for camera in cameras
            ],
        }


class EdgeNodeCredential(BaseModel):
    node: EdgeNodeRead
    api_key: str
    message: str = "该密钥只显示一次，请立即写入密钥管理系统"


class CameraHeartbeat(BaseModel):
    camera_id: int = Field(ge=1, strict=True)
    status: CameraStatus
    fps: float = Field(ge=0, le=240, strict=True, allow_inf_nan=False)
    latency_ms: int = Field(ge=0, le=60000, strict=True)
    errors: list[str] = Field(default_factory=list, max_length=10)

    _validate_fps = field_validator("fps", mode="before")(strict_finite_float)

    @field_validator("errors")
    @classmethod
    def validate_errors(cls, value: list[str]) -> list[str]:
        if (
            len(value) != len(set(value))
            or any(
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", error)
                for error in value
            )
        ):
            raise ValueError("camera errors must contain unique stable codes")
        return sorted(value)


class EdgeModelReport(BaseModel):
    algorithm_type: str = Field(min_length=2, max_length=50)
    model_version: str = Field(min_length=1, max_length=100)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    runtime: str = Field(min_length=2, max_length=50)
    ready: bool = Field(strict=True)

    @field_validator("sha256")
    @classmethod
    def normalize_sha256(cls, value: str) -> str:
        return value.lower()


class EdgeHeartbeat(BaseModel):
    software_version: str = Field(min_length=1, max_length=100)
    gpu_healthy: bool = Field(default=True, strict=True)
    gpu_utilization: float = Field(
        ge=0, le=1, strict=True, allow_inf_nan=False
    )
    gpu_memory_utilization: float = Field(
        ge=0, le=1, strict=True, allow_inf_nan=False
    )
    queue_depth: int = Field(ge=0, le=10_000_000, strict=True)
    dead_letter_depth: int = Field(default=0, ge=0, le=10_000_000, strict=True)
    outbox_capacity: int = Field(
        default=100_000, ge=1, le=10_000_000, strict=True
    )
    stream_reconnects_last_5m: int = Field(
        default=0, ge=0, le=1_000_000, strict=True
    )
    stream_reconnects_total: int = Field(
        default=0, ge=0, le=2**63 - 1, strict=True
    )
    central_reconnects_last_5m: int = Field(
        default=0, ge=0, le=1_000_000, strict=True
    )
    central_reconnects_total: int = Field(
        default=0, ge=0, le=2**63 - 1, strict=True
    )
    area_counts: dict[str, int] = Field(default_factory=dict)
    models: list["EdgeModelReport"] = Field(default_factory=list, max_length=100)
    cameras: list[CameraHeartbeat] = Field(default_factory=list, max_length=1000)

    _validate_gpu_metrics = field_validator(
        "gpu_utilization", "gpu_memory_utilization", mode="before"
    )(strict_finite_float)

    @model_validator(mode="after")
    def validate_outbox_depth(self):
        if self.queue_depth + self.dead_letter_depth > self.outbox_capacity:
            raise ValueError("combined outbox depth cannot exceed outbox_capacity")
        return self

    @field_validator("area_counts", mode="before")
    @classmethod
    def validate_area_counts(cls, value: dict[str, int]) -> dict[str, int]:
        if not isinstance(value, dict) or any(
            not isinstance(area, str)
            or isinstance(count, bool)
            or not isinstance(count, int)
            for area, count in value.items()
        ):
            raise ValueError("area_counts contains an invalid area or count")
        normalized = {area.strip(): count for area, count in value.items()}
        if len(value) > 200 or len(normalized) != len(value) or any(
            not area or len(area) > 100 or count < 0 or count > 100_000
            for area, count in normalized.items()
        ):
            raise ValueError("area_counts contains an invalid area or count")
        return normalized

    @field_validator("cameras")
    @classmethod
    def validate_unique_cameras(cls, value: list[CameraHeartbeat]) -> list[CameraHeartbeat]:
        camera_ids = [camera.camera_id for camera in value]
        if len(camera_ids) != len(set(camera_ids)):
            raise ValueError("heartbeat cannot contain duplicate cameras")
        return value

    @field_validator("models")
    @classmethod
    def validate_unique_models(cls, value: list[EdgeModelReport]) -> list[EdgeModelReport]:
        identities = [
            (model.algorithm_type, model.model_version, model.sha256.lower())
            for model in value
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("heartbeat cannot contain duplicate model identities")
        return value

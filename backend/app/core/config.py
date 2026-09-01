from functools import lru_cache
import base64
import binascii
import re
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="MINEGUARD_", case_sensitive=False, extra="ignore"
    )

    app_name: str = "MineGuard AI"
    environment: str = "development"
    api_prefix: str = "/api/v1"
    secret_key: str = "development-only-secret-key-change-me"
    access_token_minutes: int = Field(default=30, ge=1, le=1440)
    refresh_token_days: int = Field(default=7, ge=1, le=90)
    token_issuer: str = "mineguard-api"
    docs_enabled: bool = True
    local_login_enabled: bool = True
    oidc_enabled: bool = False
    oidc_provider_id: str = "enterprise-oidc"
    oidc_provider_label: str = "企业统一身份认证"
    oidc_issuer: str | None = None
    oidc_discovery_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_uri: str | None = None
    oidc_post_login_url: str | None = None
    oidc_scopes: str = "openid profile email groups"
    oidc_endpoint_allowed_origins: list[str] = Field(default_factory=list)
    oidc_role_mapping: dict[str, str] = Field(default_factory=dict)
    oidc_area_mapping: dict[str, list[str]] = Field(default_factory=dict)
    oidc_default_areas: list[str] = Field(default_factory=list)
    oidc_default_role: str = "auditor"
    oidc_allowed_groups: list[str] = Field(default_factory=list)
    oidc_auto_provision: bool = False
    database_url: str = "sqlite:///./mineguard.db"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    bootstrap_admin_enabled: bool = True
    bootstrap_admin_username: str = Field(
        default="admin",
        min_length=2,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_.-]+$",
    )
    bootstrap_admin_password: SecretStr = Field(
        default="MineGuard@123", min_length=12, max_length=128
    )
    face_enabled: bool = False
    face_inference_url: str | None = None
    face_template_key: SecretStr | None = None
    face_template_key_version: str = "v1"
    face_template_previous_keys: dict[str, SecretStr] = Field(default_factory=dict)
    face_request_timeout_seconds: float = Field(default=10.0, ge=0.5, le=30)
    face_min_quality: float = Field(default=0.65, ge=0, le=1, allow_inf_nan=False)
    face_min_liveness: float = Field(default=0.80, ge=0, le=1, allow_inf_nan=False)
    face_match_threshold: float = Field(default=0.72, ge=0, le=1, allow_inf_nan=False)
    max_face_image_bytes: int = Field(
        default=8 * 1024 * 1024,
        ge=1024,
        le=20 * 1024 * 1024,
    )
    camera_url_key: SecretStr | None = None
    camera_url_key_version: str = "v1"
    camera_url_previous_keys: dict[str, SecretStr] = Field(default_factory=dict)
    database_connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    database_pool_timeout_seconds: int = Field(default=10, ge=1, le=120)
    database_pool_recycle_seconds: int = Field(default=300, ge=30, le=86400)
    notification_gateway_url: str | None = None
    notification_gateway_token: SecretStr | None = None
    notification_timeout_seconds: float = Field(default=8.0, ge=0.5, le=30)
    media_gateway_api_url: str | None = None
    media_gateway_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30)
    media_reconcile_interval_seconds: int = Field(default=30, ge=5, le=3600)
    edge_heartbeat_timeout_seconds: int = Field(default=45, ge=5, le=300)
    enforce_approved_edge_models: bool = False
    require_four_eyes_model_approval: bool = False
    realtime_stream_poll_seconds: float = Field(default=1.0, ge=0.25, le=10)
    realtime_stream_max_seconds: int = Field(default=600, ge=30, le=3600)
    realtime_signal_retention_hours: int = Field(default=24, ge=1, le=168)
    refresh_session_retention_days: int = Field(default=7, ge=1, le=90)
    notification_delivery_retention_days: int = Field(default=90, ge=7, le=730)
    closed_event_retention_days: int = Field(default=365, ge=30, le=3650)
    event_snapshot_retention_days: int = Field(default=90, ge=7, le=3650)
    snapshot_storage_enabled: bool = False
    snapshot_storage_endpoint_url: str | None = None
    snapshot_storage_bucket: str | None = None
    snapshot_storage_region: str = Field(default="us-east-1", min_length=1, max_length=100)
    snapshot_storage_access_key_id: SecretStr | None = None
    snapshot_storage_secret_access_key: SecretStr | None = None
    snapshot_storage_force_path_style: bool = False
    snapshot_storage_presign_seconds: int = Field(default=300, ge=60, le=900)
    snapshot_storage_maximum_bytes: int = Field(
        default=8 * 1024 * 1024, ge=1024, le=20 * 1024 * 1024
    )
    snapshot_storage_connect_timeout_seconds: float = Field(
        default=3.0, ge=0.5, le=30
    )
    snapshot_storage_read_timeout_seconds: float = Field(
        default=5.0, ge=0.5, le=60
    )
    snapshot_storage_total_attempts: int = Field(default=1, ge=1, le=3)
    audit_log_retention_days: int = Field(default=2555, ge=365, le=3650)
    inactive_face_template_retention_days: int = Field(default=30, ge=0, le=3650)
    service_heartbeat_retention_days: int = Field(default=7, ge=1, le=90)
    lifecycle_cleanup_interval_seconds: int = Field(default=3600, ge=300, le=86400)
    lifecycle_cleanup_batch_size: int = Field(default=5000, ge=100, le=50000)
    worker_heartbeat_timeout_seconds: int = Field(default=60, ge=5, le=300)
    notification_queue_stale_seconds: int = Field(default=300, ge=30, le=86400)
    reconnect_storm_threshold: int = Field(default=10, ge=2, le=10000)

    @field_validator("secret_key")
    @classmethod
    def validate_secret(cls, value: str, info):
        environment = info.data.get("environment", "development")
        if environment == "production" and (
            len(value) < 32
            or value
            in {
                "development-only-secret-key-change-me",
                "replace-with-at-least-32-random-characters",
            }
        ):
            raise ValueError(
                "production secret_key must be a non-example secret of at least 32 characters"
            )
        return value

    @field_validator("bootstrap_admin_password")
    @classmethod
    def validate_bootstrap_password(cls, value: SecretStr) -> SecretStr:
        plaintext = value.get_secret_value()
        if not (
            any(char.isupper() for char in plaintext)
            and any(char.islower() for char in plaintext)
            and any(char.isdigit() for char in plaintext)
        ):
            raise ValueError(
                "bootstrap administrator password must contain uppercase, lowercase and numeric characters"
            )
        return value

    @field_validator(
        "oidc_discovery_url",
        "oidc_issuer",
        "oidc_client_id",
        "oidc_redirect_uri",
        "oidc_post_login_url",
        "oidc_client_secret",
        mode="before",
    )
    @classmethod
    def normalize_optional_oidc_value(cls, value):
        return None if value == "" else value

    @model_validator(mode="after")
    def validate_configuration(self):
        if self.environment == "production" and self.docs_enabled:
            raise ValueError("docs_enabled must be false in production")
        if (
            self.environment == "production"
            and self.bootstrap_admin_enabled
            and self.bootstrap_admin_password.get_secret_value()
            in {
                "MineGuard@123",
                "DevelopmentAdmin123",
            }
        ):
            raise ValueError(
                "production bootstrap administrator password must be overridden"
            )
        if self.environment == "production" and self.database_url.startswith("sqlite"):
            raise ValueError("production database must not use SQLite")
        if self.face_template_previous_keys and not self.face_template_key:
            raise ValueError("face template previous keys require a current key")
        face_keys = {
            **self.face_template_previous_keys,
            **(
                {self.face_template_key_version: self.face_template_key}
                if self.face_template_key
                else {}
            ),
        }
        if len(face_keys) != len(self.face_template_previous_keys) + bool(
            self.face_template_key
        ):
            raise ValueError(
                "current face template key version cannot also be previous"
            )
        for version, secret in face_keys.items():
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,50}", version):
                raise ValueError("face template key version is invalid")
            try:
                decoded_key = base64.b64decode(
                    secret.get_secret_value(), validate=True
                )
            except (ValueError, binascii.Error) as exc:
                raise ValueError("face template key must be valid base64") from exc
            if len(decoded_key) != 32:
                raise ValueError(
                    "face template key must decode to exactly 32 bytes"
                )
        if self.environment == "production" and not self.camera_url_key:
            raise ValueError("production camera_url_key is required")
        if self.camera_url_previous_keys and not self.camera_url_key:
            raise ValueError("camera URL previous keys require a current key")
        camera_keys = {
            **self.camera_url_previous_keys,
            **(
                {self.camera_url_key_version: self.camera_url_key}
                if self.camera_url_key
                else {}
            ),
        }
        if len(camera_keys) != len(self.camera_url_previous_keys) + bool(
            self.camera_url_key
        ):
            raise ValueError("current camera URL key version cannot also be previous")
        for version, secret in camera_keys.items():
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,50}", version):
                raise ValueError("camera URL key version is invalid")
            try:
                decoded_key = base64.b64decode(
                    secret.get_secret_value(), validate=True
                )
            except (ValueError, binascii.Error) as exc:
                raise ValueError("camera URL key must be valid base64") from exc
            if len(decoded_key) != 32:
                raise ValueError("camera URL key must decode to exactly 32 bytes")
        for origin in self.cors_origins:
            parts = urlsplit(origin)
            if (
                origin == "*"
                or parts.scheme not in {"http", "https"}
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.path
                or parts.query
                or parts.fragment
            ):
                raise ValueError("CORS origins must be explicit HTTP(S) origins")
            if self.environment == "production" and parts.scheme != "https":
                raise ValueError("production CORS origins must use HTTPS")
        if len(self.cors_origins) > 50 or len(self.cors_origins) != len(set(self.cors_origins)):
            raise ValueError("CORS origins must contain at most 50 unique values")
        for origin in self.oidc_endpoint_allowed_origins:
            parts = urlsplit(origin)
            try:
                port = parts.port
            except ValueError as exc:
                raise ValueError("OIDC endpoint allowed origins are invalid") from exc
            if (
                parts.scheme not in {"http", "https"}
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.path not in {"", "/"}
                or parts.query
                or parts.fragment
                or port is not None and not 1 <= port <= 65535
            ):
                raise ValueError(
                    "OIDC endpoint allowed origins must be explicit HTTP(S) origins"
                )
            if self.environment == "production" and parts.scheme != "https":
                raise ValueError(
                    "production OIDC endpoint allowed origins must use HTTPS"
                )
        if (
            len(self.oidc_endpoint_allowed_origins) > 20
            or len(self.oidc_endpoint_allowed_origins)
            != len(set(self.oidc_endpoint_allowed_origins))
        ):
            raise ValueError(
                "OIDC endpoint allowed origins must contain at most 20 unique values"
            )
        for name, value in (
            ("face_inference_url", self.face_inference_url),
            ("notification_gateway_url", self.notification_gateway_url),
            ("media_gateway_api_url", self.media_gateway_api_url),
            ("snapshot_storage_endpoint_url", self.snapshot_storage_endpoint_url),
        ):
            if not value:
                continue
            parts = urlsplit(value)
            if (
                parts.scheme not in {"http", "https"}
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.query
                or parts.fragment
                or (
                    name
                    in {"media_gateway_api_url", "snapshot_storage_endpoint_url"}
                    and parts.path not in {"", "/"}
                )
            ):
                raise ValueError(
                    f"{name} must be an HTTP(S) base URL without credentials, query, fragment, or an unsupported path"
                )
            if (
                self.environment == "production"
                and name
                in {
                    "face_inference_url",
                    "notification_gateway_url",
                    "snapshot_storage_endpoint_url",
                }
                and parts.scheme != "https"
            ):
                raise ValueError(
                    f"production {name} must use HTTPS"
                )
        if self.face_enabled and (not self.face_inference_url or not self.face_template_key):
            raise ValueError("face inference URL and template key are required when face recognition is enabled")
        gateway_token = (
            self.notification_gateway_token.get_secret_value()
            if self.notification_gateway_token
            else ""
        )
        if bool(self.notification_gateway_url) != bool(gateway_token):
            raise ValueError("notification gateway URL and token must be configured together")
        snapshot_access_key = (
            self.snapshot_storage_access_key_id.get_secret_value()
            if self.snapshot_storage_access_key_id
            else ""
        )
        snapshot_secret_key = (
            self.snapshot_storage_secret_access_key.get_secret_value()
            if self.snapshot_storage_secret_access_key
            else ""
        )
        if bool(snapshot_access_key) != bool(snapshot_secret_key):
            raise ValueError(
                "snapshot storage access key and secret key must be configured together"
            )
        if self.snapshot_storage_enabled:
            bucket = self.snapshot_storage_bucket or ""
            if (
                not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
                or ".." in bucket
                or ".-" in bucket
                or "-." in bucket
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", bucket)
            ):
                raise ValueError(
                    "enabled snapshot storage requires a valid 3-63 character bucket name"
                )
        media_timeout = (
            self.media_gateway_timeout_seconds
            if self.media_gateway_api_url
            else 0
        )
        snapshot_timeout = (
            2
            * self.snapshot_storage_total_attempts
            * (
                self.snapshot_storage_connect_timeout_seconds
                + self.snapshot_storage_read_timeout_seconds
            )
            if self.snapshot_storage_enabled
            else 0
        )
        if self.worker_heartbeat_timeout_seconds <= (
            self.notification_timeout_seconds
            + media_timeout
            + snapshot_timeout
            + self.database_connect_timeout_seconds
            + 5
        ):
            raise ValueError(
                "worker heartbeat timeout must exceed the combined blocking and recovery connection timeouts by more than 5 seconds"
            )
        if self.closed_event_retention_days < self.notification_delivery_retention_days:
            raise ValueError(
                "closed event retention must be at least notification delivery retention"
            )
        if not self.local_login_enabled and not self.oidc_enabled:
            raise ValueError("at least one authentication method must be enabled")
        if self.oidc_enabled:
            required = {
                "oidc_issuer": self.oidc_issuer,
                "oidc_discovery_url": self.oidc_discovery_url,
                "oidc_client_id": self.oidc_client_id,
                "oidc_redirect_uri": self.oidc_redirect_uri,
                "oidc_post_login_url": self.oidc_post_login_url,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError(f"OIDC configuration missing: {', '.join(missing)}")
            for name in (
                "oidc_issuer",
                "oidc_discovery_url",
                "oidc_redirect_uri",
                "oidc_post_login_url",
            ):
                parts = urlsplit(required[name])
                if (
                    parts.scheme not in {"http", "https"}
                    or not parts.hostname
                    or parts.username is not None
                    or parts.password is not None
                    or parts.fragment
                ):
                    raise ValueError(f"{name} must be an HTTP(S) URL without credentials or fragment")
            if self.environment == "production" and any(
                not value.startswith("https://")
                for value in (
                    self.oidc_discovery_url,
                    self.oidc_issuer,
                    self.oidc_redirect_uri,
                    self.oidc_post_login_url,
                )
            ):
                raise ValueError("production OIDC URLs must use HTTPS")
            if self.environment == "production" and (
                urlsplit(self.oidc_redirect_uri).netloc
                != urlsplit(self.oidc_post_login_url).netloc
            ):
                raise ValueError(
                    "production OIDC API callback and console must use the same origin"
                )
            if self.oidc_auto_provision and not self.oidc_allowed_groups:
                raise ValueError("OIDC auto-provisioning requires at least one allowed group")
            valid_roles = {"admin", "operator", "auditor"}
            if self.oidc_default_role not in valid_roles or any(
                role not in valid_roles for role in self.oidc_role_mapping.values()
            ):
                raise ValueError("OIDC role mapping contains an invalid platform role")
            area_values = [*self.oidc_default_areas]
            for areas in self.oidc_area_mapping.values():
                area_values.extend(areas)
            if (
                len(self.oidc_area_mapping) > 200
                or len(area_values) > 2000
                or any(
                    not group.strip() or len(group) > 256
                    for group in self.oidc_area_mapping
                )
                or any(not area.strip() or len(area) > 100 for area in area_values)
            ):
                raise ValueError("OIDC area mapping exceeds limits or contains an invalid area")
            self.oidc_default_areas = sorted(
                {area.strip() for area in self.oidc_default_areas}
            )
            self.oidc_area_mapping = {
                group: sorted({area.strip() for area in areas})
                for group, areas in self.oidc_area_mapping.items()
            }
            post_login_parts = urlsplit(self.oidc_post_login_url)
            if self.environment != "production" and not any(
                (post_login_parts.scheme, post_login_parts.netloc)
                == (urlsplit(origin).scheme, urlsplit(origin).netloc)
                for origin in self.cors_origins
            ):
                raise ValueError("OIDC post-login URL must use a configured CORS origin")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.database import database_engine_options

PRODUCTION_VALUES = {
    "environment": "production",
    "secret_key": "x" * 32,
    "docs_enabled": False,
    "bootstrap_admin_password": "ProductionAdmin123",
    "database_url": "postgresql+psycopg://mineguard:test@db/mineguard",
    "cors_origins": ["https://console.test"],
    "camera_url_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
}


def test_production_rejects_enabled_api_documentation():
    with pytest.raises(ValidationError, match="docs_enabled must be false"):
        Settings(
            environment="production",
            secret_key="x" * 32,
            docs_enabled=True,
        )


def test_production_accepts_disabled_api_documentation():
    settings = Settings(**PRODUCTION_VALUES)
    assert settings.docs_enabled is False


def test_production_requires_camera_url_encryption_key():
    values = {**PRODUCTION_VALUES, "camera_url_key": None}
    with pytest.raises(ValidationError, match="camera_url_key"):
        Settings(**values)


@pytest.mark.parametrize(
    "key",
    ["not-base64", "YQ=="],
)
def test_camera_url_key_must_be_base64_encoded_aes_256(key):
    with pytest.raises(ValidationError, match="camera URL key"):
        Settings(_env_file=None, camera_url_key=key)


@pytest.mark.parametrize(
    "key",
    ["not-base64", "YQ=="],
)
def test_face_template_key_must_be_base64_encoded_aes_256(key):
    with pytest.raises(ValidationError, match="face template key"):
        Settings(_env_file=None, face_template_key=key)


def test_face_template_current_key_version_cannot_be_previous():
    encoded_key = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
    with pytest.raises(ValidationError, match="cannot also be previous"):
        Settings(
            _env_file=None,
            face_template_key=encoded_key,
            face_template_key_version="v1",
            face_template_previous_keys={"v1": encoded_key},
        )


def test_production_oidc_requires_https_for_every_browser_flow_url():
    with pytest.raises(ValidationError, match="production OIDC URLs must use HTTPS"):
        Settings(
            **PRODUCTION_VALUES,
            oidc_enabled=True,
            oidc_issuer="https://identity.test",
            oidc_discovery_url="https://identity.test/.well-known/openid-configuration",
            oidc_client_id="mineguard",
            oidc_redirect_uri="https://api.test/api/v1/auth/oidc/callback",
            oidc_post_login_url="http://console.test/auth/callback",
        )


def test_production_same_origin_oidc_does_not_require_cors():
    settings = Settings(
        **{**PRODUCTION_VALUES, "cors_origins": []},
        oidc_enabled=True,
        oidc_issuer="https://identity.test",
        oidc_discovery_url="https://identity.test/.well-known/openid-configuration",
        oidc_client_id="mineguard",
        oidc_redirect_uri="https://mineguard.test/api/v1/auth/oidc/callback",
        oidc_post_login_url="https://mineguard.test/auth/callback",
    )
    assert settings.cors_origins == []


@pytest.mark.parametrize(
    "origin",
    [
        "file:///etc/passwd",
        "https://user:secret@identity.test",
        "https://identity.test/oauth",
        "https://identity.test?tenant=mineguard",
    ],
)
def test_oidc_endpoint_allowed_origins_reject_non_origins(origin):
    with pytest.raises(ValidationError, match="OIDC endpoint allowed origins"):
        Settings(_env_file=None, oidc_endpoint_allowed_origins=[origin])


def test_production_oidc_endpoint_allowed_origins_require_https():
    with pytest.raises(ValidationError, match="must use HTTPS"):
        Settings(
            **PRODUCTION_VALUES,
            oidc_endpoint_allowed_origins=["http://identity.test"],
        )


def test_production_rejects_default_bootstrap_password_and_sqlite():
    with pytest.raises(ValidationError, match="bootstrap administrator password"):
        Settings(
            environment="production",
            secret_key="x" * 32,
            docs_enabled=False,
            database_url="postgresql+psycopg://mineguard:test@db/mineguard",
        )
    with pytest.raises(ValidationError, match="must not use SQLite"):
        Settings(
            environment="production",
            secret_key="x" * 32,
            docs_enabled=False,
            bootstrap_admin_password="ProductionAdmin123",
        )


@pytest.mark.parametrize(
    "secret_key",
    [
        "development-only-secret-key-change-me",
        "replace-with-at-least-32-random-characters",
    ],
)
def test_production_rejects_documented_secret_key_placeholders(secret_key):
    with pytest.raises(ValidationError, match="non-example secret"):
        Settings(**{**PRODUCTION_VALUES, "secret_key": secret_key})


def test_production_rejects_documented_bootstrap_password_placeholder():
    with pytest.raises(ValidationError, match="bootstrap administrator password"):
        Settings(
            **{
                **PRODUCTION_VALUES,
                "bootstrap_admin_password": "DevelopmentAdmin123",
            }
        )


def test_production_long_running_service_can_disable_bootstrap_admin():
    settings = Settings(
        **{
            **PRODUCTION_VALUES,
            "bootstrap_admin_enabled": False,
            "bootstrap_admin_password": "DevelopmentAdmin123",
        }
    )
    assert settings.bootstrap_admin_enabled is False


def test_bootstrap_admin_password_is_masked_in_settings_representation():
    password = "RepresentationSecret123"
    settings = Settings(_env_file=None, bootstrap_admin_password=password)
    assert password not in repr(settings)


@pytest.mark.parametrize("username", ["", "a", "admin user", "管理员"])
def test_bootstrap_admin_username_matches_account_identifier_rules(username):
    with pytest.raises(ValidationError, match="bootstrap_admin_username"):
        Settings(_env_file=None, bootstrap_admin_username=username)


def test_worker_heartbeat_timeout_exceeds_blocking_gateway_timeout():
    with pytest.raises(ValidationError, match="worker heartbeat timeout"):
        Settings(
            _env_file=None,
            notification_timeout_seconds=10,
            worker_heartbeat_timeout_seconds=15,
        )


def test_worker_heartbeat_timeout_includes_enabled_media_control_timeout():
    with pytest.raises(ValidationError, match="worker heartbeat timeout"):
        Settings(
            _env_file=None,
            notification_timeout_seconds=8,
            media_gateway_api_url="http://media-gateway:9997",
            media_gateway_timeout_seconds=10,
            worker_heartbeat_timeout_seconds=20,
        )


def test_worker_heartbeat_timeout_includes_snapshot_tagging_budget():
    with pytest.raises(ValidationError, match="worker heartbeat timeout"):
        Settings(
            _env_file=None,
            snapshot_storage_enabled=True,
            snapshot_storage_bucket="mineguard-snapshots",
            worker_heartbeat_timeout_seconds=35,
        )


@pytest.mark.parametrize(
    "origin",
    ["*", "https://user:secret@console.test", "https://console.test/path"],
)
def test_cors_rejects_wildcards_credentials_and_paths(origin):
    with pytest.raises(ValidationError, match="CORS origins"):
        Settings(_env_file=None, cors_origins=[origin])


def test_production_cors_requires_https():
    with pytest.raises(ValidationError, match="production CORS origins must use HTTPS"):
        Settings(**{**PRODUCTION_VALUES, "cors_origins": ["http://console.test"]})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("face_inference_url", "file:///etc/passwd"),
        ("notification_gateway_url", "https://user:secret@gateway.test"),
        ("media_gateway_api_url", "http://user:secret@media-gateway:9997"),
        ("media_gateway_api_url", "http://media-gateway:9997/control"),
    ],
)
def test_internal_service_urls_reject_invalid_protocols_and_credentials(
    field, value
):
    with pytest.raises(ValidationError, match=field):
        Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize(
    "field",
    ["face_inference_url", "notification_gateway_url"],
)
def test_production_sensitive_service_urls_require_https(field):
    values = {**PRODUCTION_VALUES, field: "http://sensitive-service.internal"}
    if field == "notification_gateway_url":
        values["notification_gateway_token"] = "gateway-secret"
    else:
        values["face_enabled"] = True
        values["face_template_key"] = (
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
        )
    with pytest.raises(ValidationError, match="must use HTTPS"):
        Settings(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("face_request_timeout_seconds", 0),
        ("face_request_timeout_seconds", 31),
        ("face_min_quality", -0.1),
        ("face_min_liveness", float("nan")),
        ("face_match_threshold", 1.1),
        ("max_face_image_bytes", 1023),
        ("max_face_image_bytes", 20 * 1024 * 1024 + 1),
    ],
)
def test_face_runtime_settings_have_bounded_contracts(field, value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_event_retention_cannot_expire_before_notification_history():
    with pytest.raises(ValidationError, match="closed event retention"):
        Settings(
            _env_file=None,
            closed_event_retention_days=30,
            notification_delivery_retention_days=90,
        )


def test_enabled_snapshot_storage_requires_valid_bucket_configuration():
    with pytest.raises(ValidationError, match="snapshot storage"):
        Settings(_env_file=None, snapshot_storage_enabled=True)
    with pytest.raises(ValidationError, match="snapshot storage"):
        Settings(
            _env_file=None,
            snapshot_storage_enabled=True,
            snapshot_storage_bucket="192.168.1.10",
        )


def test_snapshot_storage_static_credentials_must_be_complete_and_masked():
    secret = "SnapshotStorageSecret"
    with pytest.raises(ValidationError, match="configured together"):
        Settings(
            _env_file=None,
            snapshot_storage_access_key_id="access-key",
        )
    settings = Settings(
        _env_file=None,
        snapshot_storage_enabled=True,
        snapshot_storage_bucket="mineguard-snapshots",
        snapshot_storage_access_key_id="access-key",
        snapshot_storage_secret_access_key=secret,
    )
    assert secret not in repr(settings)


def test_production_snapshot_storage_endpoint_requires_https():
    with pytest.raises(ValidationError, match="snapshot storage endpoint"):
        Settings(
            **PRODUCTION_VALUES,
            snapshot_storage_enabled=True,
            snapshot_storage_bucket="mineguard-snapshots",
            snapshot_storage_endpoint_url="http://object-storage.test",
        )


def test_postgres_engine_options_bound_disconnect_recovery_waits():
    settings = Settings(
        _env_file=None,
        database_url="postgresql+psycopg://mineguard:test@db/mineguard",
        database_connect_timeout_seconds=7,
        database_pool_timeout_seconds=8,
        database_pool_recycle_seconds=240,
    )
    assert database_engine_options(settings) == {
        "pool_pre_ping": True,
        "pool_timeout": 8,
        "pool_recycle": 240,
        "connect_args": {"connect_timeout": 7},
    }


def test_sqlite_engine_options_do_not_receive_postgres_connect_arguments():
    settings = Settings(_env_file=None, database_url="sqlite:///./test.db")
    assert database_engine_options(settings) == {
        "pool_pre_ping": True,
        "connect_args": {"check_same_thread": False},
    }

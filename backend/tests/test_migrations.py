from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, create_engine, inspect, select, text

from app.core.config import get_settings
from app.services.camera_urls import CameraUrlCipher


def test_person_area_migration_normalizes_and_backfills_legacy_json(
    tmp_path, monkeypatch, request
):
    request.addfinalizer(get_settings.cache_clear)
    backend_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    monkeypatch.setenv("MINEGUARD_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))

    command.upgrade(config, "20260821_0003")
    engine = create_engine(database_url)
    metadata = MetaData()
    persons = Table("persons", metadata, autoload_with=engine)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        result = connection.execute(
            persons.insert().values(
                employee_no="MIGRATION-001",
                name="Migration user",
                department="Safety",
                person_type="employee",
                authorized_areas=[" shaft-b ", "shaft-a", "shaft-a"],
                face_enrolled=False,
                active=True,
                created_at=now,
                updated_at=now,
            )
        )
        person_id = result.inserted_primary_key[0]
    engine.dispose()

    command.upgrade(config, "20260821_0004")
    engine = create_engine(database_url)
    metadata = MetaData()
    persons = Table("persons", metadata, autoload_with=engine)
    grants = Table("person_area_grants", metadata, autoload_with=engine)
    with engine.connect() as connection:
        stored_areas = connection.scalar(
            select(persons.c.authorized_areas).where(persons.c.id == person_id)
        )
        stored_grants = connection.scalars(
            select(grants.c.area)
            .where(grants.c.person_id == person_id)
            .order_by(grants.c.area)
        ).all()
    engine.dispose()
    assert stored_areas == ["shaft-a", "shaft-b"]
    assert stored_grants == ["shaft-a", "shaft-b"]


def test_legal_hold_migration_adds_event_and_face_template_controls(
    tmp_path, monkeypatch, request
):
    request.addfinalizer(get_settings.cache_clear)
    backend_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite:///{(tmp_path / 'legal-hold-migration.db').as_posix()}"
    monkeypatch.setenv("MINEGUARD_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))

    command.upgrade(config, "20260821_0006")
    command.upgrade(config, "20260821_0007")

    engine = create_engine(database_url)
    inspector = inspect(engine)
    event_columns = {column["name"] for column in inspector.get_columns("events")}
    template_columns = {
        column["name"] for column in inspector.get_columns("face_templates")
    }
    audit_columns = {
        column["name"] for column in inspector.get_columns("audit_logs")
    }
    version_table = Table("alembic_version", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        revision = connection.scalar(select(version_table.c.version_num))
    engine.dispose()
    assert "legal_hold" in event_columns
    assert "legal_hold" in template_columns
    assert "legal_hold" in audit_columns
    assert revision == "20260821_0007"


def test_casefold_identifier_migration_adds_unique_indexes(
    tmp_path, monkeypatch, request
):
    request.addfinalizer(get_settings.cache_clear)
    backend_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite:///{(tmp_path / 'casefold-migration.db').as_posix()}"
    monkeypatch.setenv("MINEGUARD_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))

    command.upgrade(config, "20260821_0008")
    engine = create_engine(database_url)
    version_table = Table("alembic_version", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        revision = connection.scalar(select(version_table.c.version_num))
        index_names = set(
            connection.scalars(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'index' AND name LIKE 'uq_%_lower'"
                )
            )
        )
    engine.dispose()
    assert revision == "20260821_0008"
    assert index_names == {
        "uq_users_username_lower",
        "uq_persons_employee_no_lower",
        "uq_edge_nodes_code_lower",
        "uq_alert_rules_name_lower",
    }


def test_camera_url_migration_encrypts_existing_rows_and_can_downgrade(
    tmp_path, monkeypatch, request
):
    request.addfinalizer(get_settings.cache_clear)
    backend_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite:///{(tmp_path / 'camera-url-migration.db').as_posix()}"
    encoded_key = "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M="
    monkeypatch.setenv("MINEGUARD_DATABASE_URL", database_url)
    monkeypatch.setenv("MINEGUARD_CAMERA_URL_KEY", encoded_key)
    monkeypatch.setenv("MINEGUARD_CAMERA_URL_KEY_VERSION", "migration-v1")
    get_settings.cache_clear()
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))

    command.upgrade(config, "20260821_0008")
    engine = create_engine(database_url)
    cameras = Table("cameras", MetaData(), autoload_with=engine)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        result = connection.execute(
            cameras.insert().values(
                code="MIG-CAM-001",
                name="Migration camera",
                area="shaft-a",
                stream_url="rtsps://reader:secret@camera.internal/live",
                playback_path="/media/mig-cam-001/index.m3u8",
                status="offline",
                enabled_algorithms=["intrusion"],
                fps=0,
                latency_ms=0,
                created_at=now,
                updated_at=now,
            )
        )
        camera_id = result.inserted_primary_key[0]
    engine.dispose()

    command.upgrade(config, "20260821_0009")
    engine = create_engine(database_url)
    cameras = Table("cameras", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        row = connection.execute(
            select(cameras).where(cameras.c.id == camera_id)
        ).mappings().one()
    constraint_names = {
        constraint["name"] for constraint in inspect(engine).get_check_constraints("cameras")
    }
    assert row["stream_url"] is None
    assert row["stream_url_nonce"] is not None
    assert row["stream_url_key_version"] == "migration-v1"
    assert CameraUrlCipher("migration-v1", encoded_key).decrypt(
        row["stream_url_ciphertext"],
        row["stream_url_nonce"],
        row["stream_url_key_version"],
        b"mineguard:camera-url:MIG-CAM-001",
    ) == "rtsps://reader:secret@camera.internal/live"
    assert "ck_cameras_stream_url_storage" in constraint_names
    engine.dispose()

    command.downgrade(config, "20260821_0008")
    engine = create_engine(database_url)
    cameras = Table("cameras", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        restored = connection.scalar(
            select(cameras.c.stream_url).where(cameras.c.id == camera_id)
        )
    engine.dispose()
    assert restored == "rtsps://reader:secret@camera.internal/live"


def test_snapshot_legal_hold_job_migration_adds_durable_retry_state(
    tmp_path, monkeypatch, request
):
    request.addfinalizer(get_settings.cache_clear)
    backend_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite:///{(tmp_path / 'snapshot-hold-jobs.db').as_posix()}"
    monkeypatch.setenv("MINEGUARD_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))

    command.upgrade(config, "20260822_0010")
    engine = create_engine(database_url)
    inspector = inspect(engine)
    columns = {
        column["name"]
        for column in inspector.get_columns("snapshot_legal_hold_jobs")
    }
    indexes = {
        index["name"]
        for index in inspector.get_indexes("snapshot_legal_hold_jobs")
    }
    version_table = Table("alembic_version", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        revision = connection.scalar(select(version_table.c.version_num))
    engine.dispose()

    assert columns == {
        "event_id",
        "desired_enabled",
        "requested_by",
        "reason",
        "attempts",
        "next_attempt_at",
        "last_error",
        "created_at",
        "updated_at",
    }
    assert "ix_snapshot_legal_hold_jobs_next_attempt_at" in indexes
    assert revision == "20260822_0010"


def test_face_model_identity_migration_deactivates_legacy_templates_on_upgrade_and_downgrade(
    tmp_path, monkeypatch, request
):
    request.addfinalizer(get_settings.cache_clear)
    backend_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite:///{(tmp_path / 'face-model-identity.db').as_posix()}"
    monkeypatch.setenv("MINEGUARD_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))

    command.upgrade(config, "20260822_0010")
    engine = create_engine(database_url)
    metadata = MetaData()
    users = Table("users", metadata, autoload_with=engine)
    persons = Table("persons", metadata, autoload_with=engine)
    templates = Table("face_templates", metadata, autoload_with=engine)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            users.insert().values(
                username="migration-admin",
                full_name="Migration administrator",
                password_hash="not-used-by-test",
                role="admin",
                active=True,
                auth_version=0,
                identity_provider="local",
                external_subject=None,
                permitted_areas=None,
                created_at=now,
                updated_at=now,
            )
        ).inserted_primary_key[0]
        person_id = connection.execute(
            persons.insert().values(
                employee_no="FACE-MIGRATION-001",
                name="Legacy face subject",
                department="Safety",
                person_type="employee",
                authorized_areas=[],
                face_enrolled=True,
                active=True,
                created_at=now,
                updated_at=now,
            )
        ).inserted_primary_key[0]
        template_id = connection.execute(
            templates.insert().values(
                person_id=person_id,
                provider="legacy-provider",
                model_version="legacy-v1",
                key_version="face-key-v1",
                encrypted_embedding=b"ciphertext-for-audit",
                nonce=b"n" * 12,
                quality=0.99,
                liveness=0.99,
                consent_reference="consent-migration-test",
                active=True,
                legal_hold=False,
                created_by=user_id,
                created_at=now,
            )
        ).inserted_primary_key[0]
    engine.dispose()

    command.upgrade(config, "20260822_0011")
    engine = create_engine(database_url)
    metadata = MetaData()
    persons = Table("persons", metadata, autoload_with=engine)
    templates = Table("face_templates", metadata, autoload_with=engine)
    with engine.connect() as connection:
        template = connection.execute(
            select(templates).where(templates.c.id == template_id)
        ).mappings().one()
        face_enrolled = connection.scalar(
            select(persons.c.face_enrolled).where(persons.c.id == person_id)
        )
    assert template["model_sha256"] is None
    assert template["active"] is False
    assert template["encrypted_embedding"] == b"ciphertext-for-audit"
    assert face_enrolled is False
    assert "ix_face_templates_model_identity" in {
        index["name"] for index in inspect(engine).get_indexes("face_templates")
    }
    with engine.begin() as connection:
        connection.execute(
            persons.update()
            .where(persons.c.id == person_id)
            .values(face_enrolled=True)
        )
        current_template_id = connection.execute(
            templates.insert().values(
                person_id=person_id,
                provider="current-provider",
                model_version="current-v2",
                model_sha256="a" * 64,
                key_version="face-key-v2",
                encrypted_embedding=b"current-ciphertext-for-audit",
                nonce=b"c" * 12,
                quality=0.99,
                liveness=0.99,
                consent_reference="current-consent-migration-test",
                active=True,
                legal_hold=False,
                created_by=user_id,
                created_at=now,
            )
        ).inserted_primary_key[0]
    engine.dispose()

    command.downgrade(config, "20260822_0010")
    engine = create_engine(database_url)
    metadata = MetaData()
    persons = Table("persons", metadata, autoload_with=engine)
    templates = Table("face_templates", metadata, autoload_with=engine)
    assert "model_sha256" not in {
        column["name"] for column in inspect(engine).get_columns("face_templates")
    }
    with engine.connect() as connection:
        template = connection.execute(
            select(templates).where(templates.c.id == template_id)
        ).mappings().one()
        current_template = connection.execute(
            select(templates).where(templates.c.id == current_template_id)
        ).mappings().one()
        face_enrolled = connection.scalar(
            select(persons.c.face_enrolled).where(persons.c.id == person_id)
        )
    engine.dispose()
    assert template["active"] is False
    assert template["encrypted_embedding"] == b"ciphertext-for-audit"
    assert current_template["active"] is False
    assert current_template["encrypted_embedding"] == b"current-ciphertext-for-audit"
    assert face_enrolled is False


def test_notification_cooldown_migration_adds_scope_indexes(
    tmp_path, monkeypatch, request
):
    request.addfinalizer(get_settings.cache_clear)
    backend_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite:///{(tmp_path / 'notification-cooldown.db').as_posix()}"
    monkeypatch.setenv("MINEGUARD_DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))

    command.upgrade(config, "20260824_0012")
    engine = create_engine(database_url)
    inspector = inspect(engine)
    event_indexes = {index["name"] for index in inspector.get_indexes("events")}
    delivery_indexes = {
        index["name"]
        for index in inspector.get_indexes("notification_deliveries")
    }
    version_table = Table("alembic_version", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        revision = connection.scalar(select(version_table.c.version_num))
    engine.dispose()

    assert "ix_events_notification_cooldown_scope" in event_indexes
    assert "ix_notification_deliveries_cooldown_scope" in delivery_indexes
    assert revision == "20260824_0012"

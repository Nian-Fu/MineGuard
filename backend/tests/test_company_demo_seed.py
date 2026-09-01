from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.company_demo_seed import DEMO_PREFIX, seed_company_demo_data
from app.models import (
    AlertRule,
    AlgorithmConfig,
    AuditLog,
    Base,
    Camera,
    EdgeNode,
    Event,
    FaceTemplate,
    ModelArtifact,
    NotificationDelivery,
    Person,
    PersonAreaGrant,
    User,
)


def test_company_demo_seed_is_idempotent_and_relationally_complete(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'company-demo.db'}")
    Base.metadata.create_all(engine)
    anchor = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)

    with Session(engine) as db:
        db.add(
            User(
                username="admin",
                full_name="Administrator",
                password_hash="not-used-by-this-test",
                role="admin",
                active=True,
            )
        )
        db.commit()

        first = seed_company_demo_data(db, now=anchor)
        second = seed_company_demo_data(db, now=anchor + timedelta(hours=1))

        assert first == second
        assert first == {
            "cameras": 24,
            "persons": 48,
            "events": 240,
            "edge_nodes": 6,
            "model_artifacts": 5,
            "algorithms": 6,
            "alert_rules": 7,
            "notification_deliveries": 72,
            "audit_logs": 64,
        }
        assert db.scalar(select(func.count()).select_from(Camera).where(Camera.code.like(f"{DEMO_PREFIX}%"))) == 24
        assert db.scalar(select(func.count()).select_from(Person).where(Person.employee_no.like(f"{DEMO_PREFIX}%"))) == 48
        assert db.scalar(select(func.count()).select_from(Event).where(Event.idempotency_key.like(f"{DEMO_PREFIX}%"))) == 240
        assert db.scalar(select(func.count()).select_from(EdgeNode).where(EdgeNode.code.like(f"{DEMO_PREFIX}%"))) == 6
        assert db.scalar(select(func.count()).select_from(NotificationDelivery).where(NotificationDelivery.idempotency_key.like(f"{DEMO_PREFIX}%"))) == 72
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.resource_id.like(f"{DEMO_PREFIX}%"))) == 64
        assert db.scalar(select(func.count()).select_from(ModelArtifact).where(ModelArtifact.model_version.like("ylzk-demo-%"))) == 5
        assert db.scalar(select(func.count()).select_from(AlgorithmConfig).where(AlgorithmConfig.name.like("%易联业务演示%"))) == 6
        assert db.scalar(select(func.count()).select_from(AlertRule).where(AlertRule.name.like("%业务演示%"))) == 7
        assert db.scalar(select(func.count()).select_from(PersonAreaGrant)) == 96
        assert db.scalar(select(func.count()).select_from(FaceTemplate)) == 0

        node_camera_ids = {
            camera_id
            for node in db.scalars(select(EdgeNode).where(EdgeNode.code.like(f"{DEMO_PREFIX}%")))
            for camera_id in node.camera_ids
        }
        demo_camera_ids = set(
            db.scalars(select(Camera.id).where(Camera.code.like(f"{DEMO_PREFIX}%")))
        )
        assert node_camera_ids == demo_camera_ids


def test_company_demo_seed_requires_active_administrator(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'company-demo-no-admin.db'}")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        try:
            seed_company_demo_data(db)
        except RuntimeError as exc:
            assert str(exc) == "an active administrator is required before importing demo data"
        else:
            raise AssertionError("seed should reject databases without an active administrator")

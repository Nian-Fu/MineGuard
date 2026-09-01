from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import (
    AlertRule,
    AuditLog,
    Camera,
    Event,
    FaceTemplate,
    NotificationDelivery,
    Person,
    RefreshSession,
    SnapshotLegalHoldJob,
    User,
)
from app.services.operations import prune_data_lifecycle


def test_data_lifecycle_preserves_active_retrying_and_held_records():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    old = now - timedelta(days=3000)
    settings = SimpleNamespace(
        lifecycle_cleanup_batch_size=100,
        refresh_session_retention_days=7,
        notification_delivery_retention_days=90,
        inactive_face_template_retention_days=30,
        closed_event_retention_days=365,
        audit_log_retention_days=2555,
    )

    with Session(engine) as db:
        user = User(
            username="lifecycle-admin",
            full_name="Lifecycle Admin",
            password_hash="test",
            role="admin",
        )
        person = Person(
            employee_no="LIFECYCLE-1",
            name="Lifecycle Person",
            department="Safety",
        )
        camera = Camera(
            code="LIFECYCLE-CAM",
            name="Lifecycle camera",
            area="shaft-a",
            stream_url="rtsp://source/lifecycle",
            playback_path="/media/lifecycle/index.m3u8",
        )
        rule = AlertRule(
            name="Lifecycle rule",
            event_types=["intrusion"],
            channels=["console"],
        )
        db.add_all([user, person, camera, rule])
        db.flush()

        deletable_event = Event(
            event_type="intrusion",
            severity="high",
            status="resolved",
            camera_id=camera.id,
            title="Delete after retention",
            confidence=0.9,
            occurred_at=old,
        )
        held_event = Event(
            event_type="intrusion",
            severity="high",
            status="resolved",
            camera_id=camera.id,
            title="Legal hold",
            confidence=0.9,
            occurred_at=old,
            legal_hold=True,
        )
        retrying_event = Event(
            event_type="intrusion",
            severity="high",
            status="false_positive",
            camera_id=camera.id,
            title="Retrying delivery",
            confidence=0.9,
            occurred_at=old,
        )
        recent_event = Event(
            event_type="intrusion",
            severity="high",
            status="resolved",
            camera_id=camera.id,
            title="Recent closed event",
            confidence=0.9,
            occurred_at=now,
        )
        pending_hold_event = Event(
            event_type="intrusion",
            severity="critical",
            status="resolved",
            camera_id=camera.id,
            title="Pending snapshot legal hold",
            confidence=0.99,
            snapshot_url=(
                "/snapshots/camera-1/2026/08/22/"
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.jpg"
            ),
            occurred_at=old,
        )
        recently_sent_event = Event(
            event_type="intrusion",
            severity="high",
            status="resolved",
            camera_id=camera.id,
            title="Recently delivered after outage",
            confidence=0.9,
            occurred_at=old,
        )
        db.add_all(
            [
                deletable_event,
                held_event,
                retrying_event,
                recent_event,
                pending_hold_event,
                recently_sent_event,
            ]
        )
        db.flush()

        db.add_all(
            [
                NotificationDelivery(
                    event_id=deletable_event.id,
                    rule_id=rule.id,
                    channel="console",
                    status="sent",
                    idempotency_key="lifecycle-delete",
                    created_at=old,
                    next_attempt_at=old,
                    sent_at=old,
                ),
                NotificationDelivery(
                    event_id=held_event.id,
                    rule_id=rule.id,
                    channel="console",
                    status="sent",
                    idempotency_key="lifecycle-held",
                    created_at=old,
                    next_attempt_at=old,
                    sent_at=old,
                ),
                NotificationDelivery(
                    event_id=recently_sent_event.id,
                    rule_id=rule.id,
                    channel="console",
                    status="sent",
                    idempotency_key="lifecycle-recently-sent",
                    created_at=old,
                    next_attempt_at=old,
                    sent_at=now,
                ),
                NotificationDelivery(
                    event_id=retrying_event.id,
                    rule_id=rule.id,
                    channel="webhook",
                    status="failed",
                    idempotency_key="lifecycle-retrying",
                    created_at=old,
                    next_attempt_at=now,
                ),
                FaceTemplate(
                    person_id=person.id,
                    provider="test",
                    model_version="1",
                    key_version="v1",
                    encrypted_embedding=b"old",
                    nonce=b"0" * 12,
                    quality=0.9,
                    liveness=0.9,
                    consent_reference="old-consent",
                    active=False,
                    created_by=user.id,
                    created_at=old,
                ),
                FaceTemplate(
                    person_id=person.id,
                    provider="test",
                    model_version="1",
                    key_version="v1",
                    encrypted_embedding=b"held",
                    nonce=b"2" * 12,
                    quality=0.9,
                    liveness=0.9,
                    consent_reference="held-consent",
                    active=False,
                    legal_hold=True,
                    created_by=user.id,
                    created_at=old,
                ),
                FaceTemplate(
                    person_id=person.id,
                    provider="test",
                    model_version="1",
                    key_version="v1",
                    encrypted_embedding=b"active",
                    nonce=b"1" * 12,
                    quality=0.9,
                    liveness=0.9,
                    consent_reference="active-consent",
                    active=True,
                    created_by=user.id,
                    created_at=old,
                ),
                RefreshSession(
                    user_id=user.id,
                    token_hash="a" * 64,
                    expires_at=now - timedelta(days=30),
                    created_at=old,
                ),
                RefreshSession(
                    user_id=user.id,
                    token_hash="b" * 64,
                    expires_at=now + timedelta(days=1),
                    created_at=now,
                ),
                AuditLog(
                    user_id=user.id,
                    action="old.audit",
                    resource_type="system",
                    detail={},
                    created_at=old,
                ),
                AuditLog(
                    user_id=user.id,
                    action="held.audit",
                    resource_type="system",
                    detail={"legal_hold": True},
                    legal_hold=True,
                    created_at=old,
                ),
                AuditLog(
                    user_id=user.id,
                    action="event.audit",
                    resource_type="event",
                    resource_id=str(held_event.id),
                    detail={},
                    legal_hold=True,
                    created_at=old,
                ),
                SnapshotLegalHoldJob(
                    event_id=pending_hold_event.id,
                    desired_enabled=True,
                    requested_by=user.id,
                    reason="Pending provider recovery",
                    next_attempt_at=now,
                ),
            ]
        )
        db.commit()

        counts = prune_data_lifecycle(db, settings, now=now)
        db.commit()

        assert counts == {
            "refresh_sessions": 1,
            "notification_deliveries": 1,
            "face_templates": 1,
            "events": 1,
            "audit_logs": 1,
        }
        remaining_event_titles = set(db.scalars(select(Event.title)))
        assert remaining_event_titles == {
            "Legal hold",
            "Retrying delivery",
            "Recent closed event",
            "Pending snapshot legal hold",
            "Recently delivered after outage",
        }
        assert db.get(SnapshotLegalHoldJob, pending_hold_event.id) is not None
        assert set(db.scalars(select(NotificationDelivery.idempotency_key))) == {
            "lifecycle-held",
            "lifecycle-recently-sent",
            "lifecycle-retrying",
        }
        assert set(db.scalars(select(AuditLog.action))) == {
            "held.audit",
            "event.audit",
        }
        remaining_templates = set(
            db.execute(
                select(FaceTemplate.consent_reference, FaceTemplate.active)
            ).all()
        )
        assert remaining_templates == {
            ("active-consent", True),
            ("held-consent", False),
        }
        assert list(db.scalars(select(RefreshSession.token_hash))) == ["b" * 64]

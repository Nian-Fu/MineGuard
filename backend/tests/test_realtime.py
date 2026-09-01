from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models import User
from app.services import realtime


def test_realtime_signal_sequence_can_resume_across_sessions(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(realtime, "SessionLocal", local_session)

    with Session(engine) as db:
        realtime.publish_realtime_signal(db, "events", 41, "created")
        realtime.publish_realtime_signal(db, "events", 41, "status_changed")
        db.commit()

    first = realtime.load_realtime_signals(0, limit=1)
    resumed = realtime.load_realtime_signals(first[0]["id"])

    assert realtime.latest_realtime_signal_id() == resumed[0]["id"]
    assert first[0]["action"] == "created"
    assert resumed[0]["action"] == "status_changed"
    assert resumed[0]["resource_id"] == "41"


def test_realtime_signals_fail_closed_for_area_scopes():
    scoped = {"shaft-a"}
    assert realtime.signal_visible_to_scope({"area": "shaft-a"}, scoped) is True
    assert realtime.signal_visible_to_scope({"area": "shaft-b"}, scoped) is False
    assert realtime.signal_visible_to_scope({"area": None}, scoped) is False
    assert realtime.signal_visible_to_scope({"area": None}, None) is True


def test_realtime_session_revalidation_detects_revocation(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(realtime, "SessionLocal", local_session)

    with Session(engine) as db:
        user = User(
            username="realtime-user",
            full_name="Realtime user",
            password_hash="not-used",
            role="operator",
            active=True,
            auth_version=4,
            identity_provider="local",
            permitted_areas=["shaft-a"],
        )
        db.add(user)
        db.commit()
        user_id = user.id

    assert realtime.realtime_session_active(user_id, 4) is True
    assert realtime.realtime_session_active(user_id, 3) is False

    with Session(engine) as db:
        user = db.get(User, user_id)
        user.active = False
        db.commit()
    assert realtime.realtime_session_active(user_id, 4) is False

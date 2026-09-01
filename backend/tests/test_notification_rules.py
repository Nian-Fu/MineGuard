from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import (
    AlertRule,
    Camera,
    DeliveryStatus,
    Event,
    NotificationDelivery,
)
from app.services.notifications import (
    NotificationDispatcher,
    create_notification_deliveries,
    delivery_error_code,
    rule_matches,
)


def event(event_type: str = "intrusion", severity: str = "high") -> Event:
    return Event(
        event_type=event_type,
        severity=severity,
        camera_id=1,
        title="test",
        confidence=0.9,
        occurred_at=datetime.now(UTC),
    )


def test_rule_matches_type_severity_and_area():
    rule = AlertRule(
        name="critical area intrusion",
        event_types=["intrusion"],
        minimum_severity="high",
        areas=["explosives"],
        channels=["console"],
        enabled=True,
    )
    assert rule_matches(rule, event(), "explosives")
    assert not rule_matches(rule, event(severity="medium"), "explosives")
    assert not rule_matches(rule, event(event_type="crowding"), "explosives")
    assert not rule_matches(rule, event(), "entrance")


def test_notification_errors_are_redacted_to_stable_codes():
    assert delivery_error_code(RuntimeError("secret internal URL")) == "gateway_not_configured"
    assert delivery_error_code(ValueError("sensitive provider response")) == "delivery_failed"


def test_notification_cooldown_is_a_rolling_window_across_fixed_bucket_boundary():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        camera = Camera(
            code="ROLLING-CAM",
            name="Rolling cooldown camera",
            area="shaft-a",
            stream_url="rtsp://source/rolling",
            playback_path="/media/rolling-cam/index.m3u8",
        )
        rule = AlertRule(
            name="Rolling rule",
            event_types=["intrusion"],
            channels=["console"],
            cooldown_seconds=60,
        )
        db.add_all([camera, rule])
        db.flush()
        first = event()
        first.camera_id = camera.id
        first.occurred_at = datetime(2026, 8, 23, 8, 0, 59, 500000, tzinfo=UTC)
        db.add(first)
        db.flush()
        assert len(create_notification_deliveries(db, first, camera.area)) == 1

        inside_window = event()
        inside_window.camera_id = camera.id
        inside_window.occurred_at = first.occurred_at + timedelta(seconds=1)
        db.add(inside_window)
        db.flush()
        assert create_notification_deliveries(db, inside_window, camera.area) == []

        at_boundary = event()
        at_boundary.camera_id = camera.id
        at_boundary.occurred_at = first.occurred_at + timedelta(seconds=60)
        db.add(at_boundary)
        db.flush()
        assert len(create_notification_deliveries(db, at_boundary, camera.area)) == 1


def test_zero_cooldown_allows_distinct_events_but_keeps_event_idempotency():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        camera = Camera(
            code="ZERO-COOLDOWN-CAM",
            name="Zero cooldown camera",
            area="shaft-a",
            stream_url="rtsp://source/zero-cooldown",
            playback_path="/media/zero-cooldown-cam/index.m3u8",
        )
        rule = AlertRule(
            name="Zero cooldown rule",
            event_types=["intrusion"],
            channels=["console"],
            cooldown_seconds=0,
        )
        db.add_all([camera, rule])
        db.flush()
        occurred_at = datetime(2026, 8, 23, 8, 0, tzinfo=UTC)
        first = event()
        first.camera_id = camera.id
        first.occurred_at = occurred_at
        second = event()
        second.camera_id = camera.id
        second.occurred_at = occurred_at
        db.add_all([first, second])
        db.flush()

        first_deliveries = create_notification_deliveries(db, first, camera.area)
        second_deliveries = create_notification_deliveries(db, second, camera.area)
        duplicate_deliveries = create_notification_deliveries(db, second, camera.area)

        assert len(first_deliveries) == 1
        assert len(second_deliveries) == 1
        assert duplicate_deliveries == []
        assert first_deliveries[0].idempotency_key == (
            f"rule:{rule.id}:event:{first.id}:channel:console"
        )
        assert second_deliveries[0].idempotency_key == (
            f"rule:{rule.id}:event:{second.id}:channel:console"
        )


def test_gateway_request_carries_stable_idempotency_contract(monkeypatch):
    captured = {}

    class Response:
        status_code = 202

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def raise_for_status(self):
            return None

    def stream(method, url, **options):
        captured.update(method=method, url=url, options=options)
        return Response()

    monkeypatch.setattr("app.services.notifications.httpx.stream", stream)
    monkeypatch.setattr(
        "app.services.notifications.get_settings",
        lambda: SimpleNamespace(
            notification_gateway_url="https://notify.internal/",
            notification_gateway_token=SimpleNamespace(
                get_secret_value=lambda: "service-token"
            ),
            notification_timeout_seconds=8,
        ),
    )
    delivery = SimpleNamespace(
        idempotency_key="stable-delivery-key",
        channel="broadcast",
        target="shaft-a-speakers",
        payload={"event_id": 42},
    )

    NotificationDispatcher()._send(delivery)

    assert captured["method"] == "POST"
    assert captured["url"] == "https://notify.internal/v1/deliveries"
    assert captured["options"]["follow_redirects"] is False
    assert captured["options"]["headers"] == {
        "Authorization": "Bearer service-token"
    }
    assert captured["options"]["json"] == {
        "idempotency_key": "stable-delivery-key",
        "channel": "broadcast",
        "target": "shaft-a-speakers",
        "payload": {"event_id": 42},
    }


def test_gateway_circuit_keeps_console_delivery_available(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        camera = Camera(
            code="CIRCUIT-CAM",
            name="Circuit camera",
            area="shaft-a",
            stream_url="rtsp://source/circuit",
            playback_path="/media/circuit-cam/index.m3u8",
        )
        rule = AlertRule(
            name="Circuit rule",
            event_types=["intrusion"],
            channels=["sms"],
        )
        db.add_all([camera, rule])
        db.flush()
        stored_event = event()
        stored_event.camera_id = camera.id
        db.add(stored_event)
        db.flush()
        external = NotificationDelivery(
            event_id=stored_event.id,
            rule_id=rule.id,
            channel="sms",
            idempotency_key="circuit-external",
            next_attempt_at=datetime.now(UTC),
        )
        console = NotificationDelivery(
            event_id=stored_event.id,
            rule_id=rule.id,
            channel="console",
            idempotency_key="circuit-console",
            next_attempt_at=datetime.now(UTC),
        )
        db.add_all([external, console])
        db.commit()

        dispatcher = NotificationDispatcher()

        def fail_external(delivery):
            if delivery.channel != "console":
                raise RuntimeError("gateway unavailable")

        monkeypatch.setattr(dispatcher, "_send", fail_external)
        monkeypatch.setattr("app.services.notifications.random.uniform", lambda *_: 1.0)
        assert dispatcher.dispatch_due(db) == 1
        assert dispatcher.gateway_failures == 1
        db.refresh(external)
        assert external.status == DeliveryStatus.FAILED.value
        assert external.last_error == "gateway_not_configured"

        assert dispatcher.dispatch_due(db) == 1
        db.refresh(console)
        assert console.status == DeliveryStatus.SENT.value


def test_gateway_circuit_half_open_success_resets_failure_state(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        camera = Camera(
            code="RECOVERY-CAM",
            name="Recovery camera",
            area="shaft-a",
            stream_url="rtsp://source/recovery",
            playback_path="/media/recovery-cam/index.m3u8",
        )
        rule = AlertRule(
            name="Recovery rule",
            event_types=["intrusion"],
            channels=["sms"],
        )
        db.add_all([camera, rule])
        db.flush()
        stored_event = event()
        stored_event.camera_id = camera.id
        db.add(stored_event)
        db.flush()
        delivery = NotificationDelivery(
            event_id=stored_event.id,
            rule_id=rule.id,
            channel="sms",
            idempotency_key="circuit-recovery",
            next_attempt_at=datetime.now(UTC),
        )
        db.add(delivery)
        db.commit()

        dispatcher = NotificationDispatcher()

        def fail_delivery(_delivery):
            raise RuntimeError("offline")

        monkeypatch.setattr(dispatcher, "_send", fail_delivery)
        monkeypatch.setattr("app.services.notifications.random.uniform", lambda *_: 1.0)
        assert dispatcher.dispatch_due(db) == 1
        assert dispatcher.gateway_failures == 1

        delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        dispatcher._gateway_retry_at = 0
        monkeypatch.setattr(dispatcher, "_send", lambda _delivery: None)
        assert dispatcher.dispatch_due(db) == 1
        db.refresh(delivery)
        assert delivery.status == DeliveryStatus.SENT.value
        assert dispatcher.gateway_failures == 0
        assert dispatcher._gateway_retry_at == 0


def test_failed_delivery_recovers_after_dispatcher_process_state_is_lost(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        camera = Camera(
            code="RESTART-CAM",
            name="Restart camera",
            area="shaft-a",
            stream_url="rtsp://source/restart",
            playback_path="/media/restart-cam/index.m3u8",
        )
        rule = AlertRule(
            name="Restart rule",
            event_types=["intrusion"],
            channels=["sms"],
        )
        db.add_all([camera, rule])
        db.flush()
        stored_event = event()
        stored_event.camera_id = camera.id
        db.add(stored_event)
        db.flush()
        delivery = NotificationDelivery(
            event_id=stored_event.id,
            rule_id=rule.id,
            channel="sms",
            idempotency_key="restart-recovery",
            next_attempt_at=datetime.now(UTC),
        )
        db.add(delivery)
        db.commit()

        first_dispatcher = NotificationDispatcher()

        def fail_delivery(_delivery):
            raise RuntimeError("offline")

        monkeypatch.setattr(first_dispatcher, "_send", fail_delivery)
        monkeypatch.setattr("app.services.notifications.random.uniform", lambda *_: 1.0)
        assert first_dispatcher.dispatch_due(db) == 1
        db.refresh(delivery)
        assert delivery.status == DeliveryStatus.FAILED.value
        assert delivery.attempts == 1

        delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        restarted_dispatcher = NotificationDispatcher()
        monkeypatch.setattr(restarted_dispatcher, "_send", lambda _delivery: None)
        progress_calls = []
        assert restarted_dispatcher.dispatch_due(
            db, progress=lambda: progress_calls.append(True)
        ) == 1
        db.refresh(delivery)
        assert delivery.status == DeliveryStatus.SENT.value
        assert delivery.attempts == 2
        assert progress_calls == [True]


def test_permanent_gateway_rejection_does_not_block_later_delivery(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        camera = Camera(
            code="PERMANENT-CAM",
            name="Permanent failure camera",
            area="shaft-a",
            stream_url="rtsp://source/permanent",
            playback_path="/media/permanent-cam/index.m3u8",
        )
        rule = AlertRule(
            name="Permanent failure rule",
            event_types=["intrusion"],
            channels=["sms"],
        )
        db.add_all([camera, rule])
        db.flush()
        stored_event = event()
        stored_event.camera_id = camera.id
        db.add(stored_event)
        db.flush()
        rejected = NotificationDelivery(
            event_id=stored_event.id,
            rule_id=rule.id,
            channel="sms",
            idempotency_key="permanent-rejected",
            next_attempt_at=datetime.now(UTC),
        )
        accepted = NotificationDelivery(
            event_id=stored_event.id,
            rule_id=rule.id,
            channel="sms",
            idempotency_key="permanent-accepted",
            next_attempt_at=datetime.now(UTC),
        )
        db.add_all([rejected, accepted])
        db.commit()

        dispatcher = NotificationDispatcher()

        def send(delivery):
            if delivery.id == rejected.id:
                request = httpx.Request("POST", "https://gateway.example/v1/deliveries")
                response = httpx.Response(422, request=request)
                raise httpx.HTTPStatusError(
                    "invalid payload", request=request, response=response
                )

        monkeypatch.setattr(dispatcher, "_send", send)
        assert dispatcher.dispatch_due(db) == 2
        db.refresh(rejected)
        db.refresh(accepted)
        assert rejected.status == DeliveryStatus.FAILED.value
        assert rejected.last_error == "gateway_http_422"
        assert accepted.status == DeliveryStatus.SENT.value
        assert dispatcher.gateway_failures == 0
        assert dispatcher.dispatch_due(db) == 0

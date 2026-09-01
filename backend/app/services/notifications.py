import hashlib
import random
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import (
    AlertRule,
    Camera,
    DeliveryStatus,
    Event,
    NotificationChannel,
    NotificationDelivery,
)
from app.services.realtime import publish_realtime_signal

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PERMANENT_GATEWAY_ERRORS = {
    "gateway_http_400",
    "gateway_http_413",
    "gateway_http_415",
    "gateway_http_422",
}


def delivery_error_code(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"gateway_http_{exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "gateway_timeout"
    if isinstance(exc, httpx.RequestError):
        return "gateway_unreachable"
    if isinstance(exc, RuntimeError):
        return "gateway_not_configured"
    return "delivery_failed"


def rule_matches(rule: AlertRule, event: Event, area: str) -> bool:
    return (
        rule.enabled
        and event.event_type in rule.event_types
        and SEVERITY_RANK.get(event.severity, -1) >= SEVERITY_RANK.get(rule.minimum_severity, 99)
        and (not rule.areas or area in rule.areas)
    )


def _locked_rule(db: Session, rule_id: int) -> AlertRule | None:
    statement = select(AlertRule).where(AlertRule.id == rule_id)
    if db.get_bind().dialect.name == "postgresql":
        # Concurrent event creation may share the configuration lock, while a
        # rule edit waits until those transactions have finished using it.
        statement = statement.with_for_update(read=True)
    else:
        # Non-PostgreSQL production deployments lack the scoped advisory lock
        # below, so serialize on the rule row to preserve correctness.
        statement = statement.with_for_update()
    return db.scalar(statement)


def _lock_cooldown_scope(
    db: Session,
    rule_id: int,
    camera_id: int,
    event_type: str,
    channel: str,
) -> None:
    if db.get_bind().dialect.name != "postgresql":
        return
    scope = f"notification:{rule_id}:{camera_id}:{event_type}:{channel}"
    lock_id = int.from_bytes(
        hashlib.sha256(scope.encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )
    db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": lock_id},
    )


def create_notification_deliveries(db: Session, event: Event, area: str) -> list[NotificationDelivery]:
    candidate_rules = db.scalars(
        select(AlertRule)
        .where(AlertRule.enabled.is_(True))
        .order_by(AlertRule.id)
    ).all()
    deliveries = []
    occurred_at = event.occurred_at
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    for candidate in candidate_rules:
        if not rule_matches(candidate, event, area):
            continue
        rule = _locked_rule(db, candidate.id)
        if rule is None or not rule_matches(rule, event, area):
            continue
        for channel in rule.channels:
            if rule.cooldown_seconds > 0:
                # PostgreSQL serializes only this notification scope. The rule
                # row lock above is exclusive on fallback databases.
                _lock_cooldown_scope(
                    db, rule.id, event.camera_id, event.event_type, channel
                )
                cooldown_started_at = occurred_at - timedelta(
                    seconds=rule.cooldown_seconds
                )
                recent_delivery_id = db.scalar(
                    select(NotificationDelivery.id)
                    .join(Event, NotificationDelivery.event_id == Event.id)
                    .where(
                        NotificationDelivery.rule_id == rule.id,
                        NotificationDelivery.channel == channel,
                        Event.camera_id == event.camera_id,
                        Event.event_type == event.event_type,
                        Event.occurred_at > cooldown_started_at,
                        Event.occurred_at <= occurred_at,
                    )
                    .order_by(Event.occurred_at.desc(), NotificationDelivery.id.desc())
                    .limit(1)
                )
                if recent_delivery_id is not None:
                    continue
            idempotency_key = (
                f"rule:{rule.id}:event:{event.id}:channel:{channel}"
            )
            delivery = NotificationDelivery(
                event_id=event.id,
                rule_id=rule.id,
                channel=channel,
                target=rule.channel_targets.get(channel),
                idempotency_key=idempotency_key,
                payload={
                    "event_id": event.id,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "title": event.title,
                    "camera_id": event.camera_id,
                    "area": area,
                    "occurred_at": occurred_at.isoformat(),
                },
            )
            try:
                with db.begin_nested():
                    db.add(delivery)
                    db.flush()
            except IntegrityError:
                continue
            deliveries.append(delivery)
    return deliveries


class NotificationDispatcher:
    def __init__(self) -> None:
        self.gateway_failures = 0
        self._gateway_retry_at = 0.0

    def dispatch_due(
        self,
        db: Session,
        limit: int = 50,
        progress: Callable[[], None] | None = None,
    ) -> int:
        now = datetime.now(UTC)
        conditions = [
            NotificationDelivery.status.in_(
                [DeliveryStatus.PENDING.value, DeliveryStatus.FAILED.value]
            ),
            NotificationDelivery.next_attempt_at <= now,
            or_(
                NotificationDelivery.last_error.is_(None),
                NotificationDelivery.last_error.not_in(PERMANENT_GATEWAY_ERRORS),
            ),
        ]
        if time.monotonic() < self._gateway_retry_at:
            conditions.append(
                NotificationDelivery.channel == NotificationChannel.CONSOLE.value
            )
        deliveries = db.scalars(
            select(NotificationDelivery)
            .where(*conditions)
            .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).all()
        event_areas = dict(
            db.execute(
                select(Event.id, Camera.area)
                .join(Camera, Event.camera_id == Camera.id)
                .where(Event.id.in_({delivery.event_id for delivery in deliveries}))
            ).all()
        )
        processed = 0
        changed_areas: set[str] = set()
        gateway_failed = False
        for delivery in deliveries:
            try:
                self._send(delivery)
            except Exception as exc:
                error_code = delivery_error_code(exc)
                delivery.status = DeliveryStatus.FAILED.value
                delivery.attempts += 1
                delivery.last_error = error_code
                delay = min(2 ** min(delivery.attempts, 9), 300) * random.uniform(0.8, 1.2)
                delivery.next_attempt_at = now + timedelta(seconds=delay)
                if (
                    delivery.channel != NotificationChannel.CONSOLE.value
                    and error_code not in PERMANENT_GATEWAY_ERRORS
                ):
                    gateway_failed = True
                    self.gateway_failures += 1
                    circuit_exponent = min(max(self.gateway_failures - 1, 0), 9)
                    circuit_delay = min(2**circuit_exponent, 300) * random.uniform(
                        0.8, 1.2
                    )
                    self._gateway_retry_at = time.monotonic() + circuit_delay
            else:
                delivery.status = DeliveryStatus.SENT.value
                delivery.attempts += 1
                delivery.last_error = None
                delivery.sent_at = now
                if delivery.channel != NotificationChannel.CONSOLE.value:
                    self.gateway_failures = 0
                    self._gateway_retry_at = 0.0
            processed += 1
            if progress is not None:
                progress()
            if area := event_areas.get(delivery.event_id):
                changed_areas.add(area)
            if gateway_failed:
                break
        for area in changed_areas:
            publish_realtime_signal(
                db, "deliveries", None, "delivery_status_changed", area=area
            )
        db.commit()
        return processed

    def _send(self, delivery: NotificationDelivery) -> None:
        if delivery.channel == "console":
            return
        settings = get_settings()
        if not settings.notification_gateway_url or not settings.notification_gateway_token:
            raise RuntimeError("notification gateway is not configured")
        with httpx.stream(
            "POST",
            f"{settings.notification_gateway_url.rstrip('/')}/v1/deliveries",
            json={
                "idempotency_key": delivery.idempotency_key,
                "channel": delivery.channel,
                "target": delivery.target,
                "payload": delivery.payload,
            },
            headers={"Authorization": f"Bearer {settings.notification_gateway_token.get_secret_value()}"},
            timeout=settings.notification_timeout_seconds,
            follow_redirects=False,
        ) as response:
            response.raise_for_status()

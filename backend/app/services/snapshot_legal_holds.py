import random
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models import (
    AuditLog,
    Camera,
    Event,
    SnapshotLegalHoldJob,
    User,
)
from app.services.audit import write_audit
from app.services.realtime import publish_realtime_signal
from app.services.snapshots import (
    SnapshotStorage,
    SnapshotStorageError,
    get_snapshot_storage,
)

RETRY_ERROR_CODE = "snapshot_storage_unavailable"


def queue_snapshot_legal_hold(
    db: Session,
    event: Event,
    *,
    desired_enabled: bool,
    requested_by: int,
    reason: str,
) -> SnapshotLegalHoldJob:
    now = datetime.now(UTC)
    job = db.scalar(
        select(SnapshotLegalHoldJob)
        .where(SnapshotLegalHoldJob.event_id == event.id)
        .with_for_update()
    )
    if job is None:
        job = SnapshotLegalHoldJob(
            event_id=event.id,
            desired_enabled=desired_enabled,
            requested_by=requested_by,
            reason=reason,
            next_attempt_at=now,
        )
        db.add(job)
    else:
        job.desired_enabled = desired_enabled
        job.requested_by = requested_by
        job.reason = reason
        job.attempts = 0
        job.next_attempt_at = now
        job.last_error = None
    return job


class SnapshotLegalHoldReconciler:
    def __init__(
        self,
        storage: SnapshotStorage | None = None,
        storage_factory: Callable[[], SnapshotStorage] = get_snapshot_storage,
    ) -> None:
        self.storage = storage
        self.storage_factory = storage_factory
        self.consecutive_failures = 0
        self.pending = 0

    @staticmethod
    def _retry_delay(attempts: int) -> float:
        exponent = min(max(attempts, 1), 8)
        return min(2**exponent, 300) * random.uniform(0.8, 1.2)

    @staticmethod
    def _lock_job(
        db: Session, event_id: int
    ) -> tuple[Event | None, SnapshotLegalHoldJob | None]:
        event = db.scalar(
            select(Event).where(Event.id == event_id).with_for_update()
        )
        if event is None:
            return None, None
        job = db.scalar(
            select(SnapshotLegalHoldJob)
            .where(SnapshotLegalHoldJob.event_id == event_id)
            .with_for_update(skip_locked=True)
        )
        return event, job

    @staticmethod
    def _record_database_state(
        db: Session,
        event: Event,
        job: SnapshotLegalHoldJob,
    ) -> None:
        if event.legal_hold == job.desired_enabled:
            return
        event.legal_hold = job.desired_enabled
        if job.desired_enabled:
            db.execute(
                update(AuditLog)
                .where(
                    AuditLog.resource_type == "event",
                    AuditLog.resource_id == str(event.id),
                )
                .values(legal_hold=True)
            )
        area = db.scalar(select(Camera.area).where(Camera.id == event.camera_id))
        publish_realtime_signal(
            db, "events", event.id, "legal_hold_changed", area=area
        )
        write_audit(
            db,
            db.get(User, job.requested_by),
            "event.legal_hold",
            "event",
            event.id,
            {
                "enabled": job.desired_enabled,
                "reason": job.reason,
                "legal_hold": True,
                "reconciled_from_outbox": True,
            },
        )

    def reconcile_one(
        self,
        db: Session,
        event_id: int,
        *,
        expected_enabled: bool | None = None,
    ) -> str:
        event, job = self._lock_job(db, event_id)
        if event is None or job is None:
            db.rollback()
            return "missing"
        if expected_enabled is not None and job.desired_enabled != expected_enabled:
            db.rollback()
            return "superseded"
        if not event.snapshot_url:
            self._record_database_state(db, event, job)
            db.delete(job)
            db.commit()
            return "completed"

        desired_enabled = job.desired_enabled
        if not desired_enabled and event.legal_hold:
            self._record_database_state(db, event, job)
            db.commit()
            event, job = self._lock_job(db, event_id)
            if event is None or job is None:
                db.rollback()
                return "missing"
            if expected_enabled is not None and job.desired_enabled != expected_enabled:
                db.rollback()
                return "superseded"
            desired_enabled = job.desired_enabled

        reference = event.snapshot_url
        try:
            storage = self.storage or self.storage_factory()
            storage.set_legal_hold(reference, desired_enabled)
        except SnapshotStorageError:
            job.attempts += 1
            job.last_error = RETRY_ERROR_CODE
            job.next_attempt_at = datetime.now(UTC) + timedelta(
                seconds=self._retry_delay(job.attempts)
            )
            db.commit()
            return "retry"

        if desired_enabled:
            self._record_database_state(db, event, job)
        db.delete(job)
        db.commit()
        return "completed"

    def dispatch_due(
        self,
        db: Session,
        limit: int = 20,
        progress: Callable[[], None] | None = None,
    ) -> int:
        now = datetime.now(UTC)
        event_ids = list(
            db.scalars(
                select(SnapshotLegalHoldJob.event_id)
                .where(SnapshotLegalHoldJob.next_attempt_at <= now)
                .order_by(
                    SnapshotLegalHoldJob.next_attempt_at,
                    SnapshotLegalHoldJob.event_id,
                )
                .limit(limit)
            )
        )
        attempted = 0
        failed = False
        for event_id in event_ids:
            result = self.reconcile_one(db, event_id)
            if progress is not None:
                progress()
            if result in {"completed", "retry"}:
                attempted += 1
            failed = failed or result == "retry"
        self.pending = (
            db.scalar(select(func.count()).select_from(SnapshotLegalHoldJob)) or 0
        )
        if failed:
            self.consecutive_failures += 1
        elif self.pending == 0 or attempted:
            self.consecutive_failures = 0
        return attempted

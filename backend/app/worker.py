import json
import logging
import os
import random
import signal
import time
from datetime import UTC, datetime
from threading import Event, Lock, Thread
from uuid import uuid4

from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models import Camera
from app.services.edge_nodes import mark_stale_edge_nodes
from app.services.media_gateway import MediaGatewayReconciler
from app.services.notifications import NotificationDispatcher
from app.services.operations import (
    WORKER_SERVICE,
    prune_data_lifecycle,
    prune_service_heartbeats,
    record_service_heartbeat,
)
from app.services.realtime import prune_realtime_signals
from app.services.snapshot_legal_holds import SnapshotLegalHoldReconciler

logger = logging.getLogger("mineguard.worker")
stop_event = Event()


def request_stop(*_) -> None:
    stop_event.set()


def retry_delay(attempt: int) -> float:
    exponent = min(max(attempt - 1, 0), 5)
    return min(2**exponent, 30) * random.uniform(0.8, 1.2)


def log_event(level: int, event: str, **detail) -> None:
    logger.log(level, json.dumps({"event": event, **detail}, separators=(",", ":")))


class WorkerWatchdog:
    """Exit a genuinely stalled worker so the container policy can restart it."""

    def __init__(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        self._last_progress = time.monotonic()
        self._lock = Lock()
        self._stop = Event()
        self._thread = Thread(
            target=self._monitor,
            name="mineguard-worker-watchdog",
            daemon=True,
        )

    def progress(self) -> None:
        with self._lock:
            self._last_progress = time.monotonic()

    def is_stale(self, now: float | None = None) -> bool:
        checked_at = time.monotonic() if now is None else now
        with self._lock:
            return checked_at - self._last_progress > self.timeout_seconds

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _monitor(self) -> None:
        interval = min(max(self.timeout_seconds / 4, 1), 5)
        while not self._stop.wait(interval):
            if not self.is_stale():
                continue
            log_event(
                logging.CRITICAL,
                "worker_watchdog_stalled",
                timeout_seconds=self.timeout_seconds,
            )
            os._exit(70)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    dispatcher = NotificationDispatcher()
    snapshot_reconciler = SnapshotLegalHoldReconciler()
    settings = get_settings()
    watchdog = WorkerWatchdog(settings.worker_heartbeat_timeout_seconds)
    watchdog.start()
    media_reconciler = (
        MediaGatewayReconciler(
            settings.media_gateway_api_url,
            settings.media_gateway_timeout_seconds,
        )
        if settings.media_gateway_api_url
        else None
    )
    instance_id = uuid4().hex
    started_at = datetime.now(UTC)
    next_signal_prune = 0.0
    next_lifecycle_prune = 0.0
    next_media_reconcile = 0.0
    media_failures = 0
    media_detail: dict[str, int | str | bool] = {
        "configured": media_reconciler is not None,
        "status": "pending" if media_reconciler else "disabled",
    }
    failures = 0
    while not stop_event.is_set():
        watchdog.progress()
        processed = 0
        try:
            with SessionLocal() as db:
                settings = get_settings()
                processed = dispatcher.dispatch_due(db, progress=watchdog.progress)
                snapshot_failures_before = snapshot_reconciler.consecutive_failures
                processed += snapshot_reconciler.dispatch_due(
                    db, progress=watchdog.progress
                )
                if (
                    snapshot_reconciler.consecutive_failures
                    > snapshot_failures_before
                ):
                    log_event(
                        logging.ERROR,
                        "snapshot_legal_hold_reconcile_failed",
                        attempt=snapshot_reconciler.consecutive_failures,
                        pending=snapshot_reconciler.pending,
                    )
                elif (
                    snapshot_failures_before
                    and snapshot_reconciler.consecutive_failures == 0
                ):
                    log_event(
                        logging.INFO,
                        "snapshot_legal_hold_recovered",
                        failed_attempts=snapshot_failures_before,
                    )
                processed += mark_stale_edge_nodes(db)
                if media_reconciler and time.monotonic() >= next_media_reconcile:
                    try:
                        result = media_reconciler.reconcile(
                            db.scalars(select(Camera).order_by(Camera.id)).all(),
                            progress=watchdog.progress,
                        )
                    except Exception as exc:
                        media_failures += 1
                        media_delay = retry_delay(media_failures)
                        next_media_reconcile = time.monotonic() + media_delay
                        media_detail = {
                            "configured": True,
                            "status": "recovering",
                            "consecutive_failures": media_failures,
                        }
                        log_event(
                            logging.ERROR,
                            "media_gateway_reconcile_failed",
                            error_type=type(exc).__name__,
                            attempt=media_failures,
                            retry_seconds=round(media_delay, 2),
                        )
                    else:
                        if media_failures:
                            log_event(
                                logging.INFO,
                                "media_gateway_recovered",
                                failed_attempts=media_failures,
                            )
                        media_failures = 0
                        next_media_reconcile = (
                            time.monotonic()
                            + settings.media_reconcile_interval_seconds
                        )
                        media_detail = {
                            "configured": True,
                            "status": "online",
                            "managed_paths": result.managed,
                            "paths_added": result.added,
                            "paths_updated": result.updated,
                            "paths_removed": result.removed,
                        }
                if time.monotonic() >= next_signal_prune:
                    processed += prune_realtime_signals(
                        db, settings.realtime_signal_retention_hours
                    )
                    next_signal_prune = time.monotonic() + 3600
                if time.monotonic() >= next_lifecycle_prune:
                    lifecycle_counts = prune_data_lifecycle(db, settings)
                    lifecycle_counts["service_heartbeats"] = prune_service_heartbeats(
                        db, settings.service_heartbeat_retention_days
                    )
                    processed += sum(lifecycle_counts.values())
                    if any(lifecycle_counts.values()):
                        log_event(
                            logging.INFO,
                            "data_lifecycle_pruned",
                            counts=lifecycle_counts,
                        )
                    next_lifecycle_prune = (
                        time.monotonic()
                        + settings.lifecycle_cleanup_interval_seconds
                    )
                record_service_heartbeat(
                    db,
                    instance_id=instance_id,
                    service=WORKER_SERVICE,
                    started_at=started_at,
                    consecutive_failures=max(
                        dispatcher.gateway_failures,
                        media_failures,
                        snapshot_reconciler.consecutive_failures,
                    ),
                    detail={
                        "processed_last_cycle": processed,
                        "media_gateway": media_detail,
                        "snapshot_legal_holds": {
                            "pending": snapshot_reconciler.pending,
                            "status": (
                                "recovering"
                                if snapshot_reconciler.consecutive_failures
                                else "online"
                            ),
                        },
                    },
                )
                db.commit()
        except Exception as exc:
            failures += 1
            delay = retry_delay(failures)
            log_event(
                logging.ERROR,
                "worker_cycle_failed",
                error_type=type(exc).__name__,
                attempt=failures,
                retry_seconds=round(delay, 2),
            )
            try:
                with SessionLocal() as heartbeat_db:
                    record_service_heartbeat(
                        heartbeat_db,
                        instance_id=instance_id,
                        service=WORKER_SERVICE,
                        started_at=started_at,
                        consecutive_failures=failures,
                    )
                    heartbeat_db.commit()
            except Exception:
                pass
        else:
            if failures:
                log_event(logging.INFO, "worker_recovered", failed_attempts=failures)
            failures = 0
            delay = 0.2 if processed else 2.0
        stop_event.wait(delay)
    watchdog.close()
    if media_reconciler:
        media_reconciler.close()
    log_event(logging.INFO, "worker_stopped")


if __name__ == "__main__":
    main()

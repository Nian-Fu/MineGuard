import asyncio
import json
import logging
import sqlite3
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("mineguard.edge.outbox")


@dataclass(frozen=True)
class OutboxItem:
    id: int
    idempotency_key: str
    payload: dict[str, Any]
    attempts: int


@dataclass(frozen=True)
class DeadLetterItem:
    id: int
    idempotency_key: str
    payload: dict[str, Any]
    attempts: int
    reason: str
    created_at: float
    quarantined_at: float


class PermanentDeliveryError(RuntimeError):
    """The center rejected a payload that cannot succeed without changing it."""


class PersistentOutbox:
    """SQLite-backed edge queue that survives process and network failures."""

    resolved_dead_letter_prune_batch_size = 1000

    def __init__(
        self,
        path: str | Path,
        maximum_items: int = 100_000,
        maximum_payload_bytes: int = 64 * 1024,
        resolved_dead_letter_retention_days: int = 90,
    ) -> None:
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (
                    maximum_items,
                    maximum_payload_bytes,
                    resolved_dead_letter_retention_days,
                )
            )
            or maximum_items < 1
            or maximum_payload_bytes < 1024
            or not 1 <= resolved_dead_letter_retention_days <= 3650
        ):
            raise ValueError("outbox limits are invalid")
        self.path = str(path)
        self.maximum_items = maximum_items
        self.maximum_payload_bytes = maximum_payload_bytes
        self.resolved_dead_letter_retention_days = (
            resolved_dead_letter_retention_days
        )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS event_outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS event_dead_letters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    quarantined_at REAL NOT NULL,
                    resolved_at REAL,
                    resolution TEXT
                )
                """
            )
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(event_dead_letters)"
                ).fetchall()
            }
            if "resolved_at" not in columns:
                connection.execute(
                    "ALTER TABLE event_dead_letters ADD COLUMN resolved_at REAL"
                )
            if "resolution" not in columns:
                connection.execute(
                    "ALTER TABLE event_dead_letters ADD COLUMN resolution TEXT"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ix_event_dead_letters_resolved_at "
                "ON event_dead_letters (resolved_at)"
            )

    def enqueue(self, idempotency_key: str, payload: dict[str, Any]) -> bool:
        if (
            not isinstance(idempotency_key, str)
            or not 1 <= len(idempotency_key) <= 160
        ):
            raise ValueError("idempotency_key must contain 1-160 characters")
        encoded = self._encode_payload(payload)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO event_outbox
                    (idempotency_key, payload, created_at)
                SELECT ?, ?, ?
                WHERE (
                    (SELECT COUNT(*) FROM event_outbox)
                    + (
                        SELECT COUNT(*) FROM event_dead_letters
                        WHERE resolved_at IS NULL
                    )
                ) < ?
                AND NOT EXISTS (
                    SELECT 1 FROM event_dead_letters
                    WHERE idempotency_key = ? AND resolved_at IS NULL
                )
                """,
                (
                    idempotency_key,
                    encoded,
                    time.time(),
                    self.maximum_items,
                    idempotency_key,
                ),
            )
            if cursor.rowcount == 1:
                return True
            duplicate = connection.execute(
                """
                SELECT 1 FROM event_outbox WHERE idempotency_key = ?
                UNION ALL
                SELECT 1 FROM event_dead_letters
                WHERE idempotency_key = ? AND resolved_at IS NULL
                LIMIT 1
                """,
                (idempotency_key, idempotency_key),
            ).fetchone()
            if duplicate:
                return False
            raise OverflowError(
                "edge outbox capacity reached; operator intervention required"
            )

    def replace_payload(
        self, idempotency_key: str, payload: dict[str, Any]
    ) -> bool:
        if (
            not isinstance(idempotency_key, str)
            or not 1 <= len(idempotency_key) <= 160
        ):
            raise ValueError("idempotency_key must contain 1-160 characters")
        encoded = self._encode_payload(payload)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE event_outbox SET payload = ? WHERE idempotency_key = ?",
                (encoded, idempotency_key),
            )
            return cursor.rowcount == 1

    def referenced_snapshot_files(self) -> set[str]:
        references: set[str] = set()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload FROM event_outbox
                UNION ALL
                SELECT payload FROM event_dead_letters WHERE resolved_at IS NULL
                """
            )
            for row in rows:
                try:
                    snapshot = json.loads(row["payload"]).get("_snapshot")
                except (AttributeError, TypeError, ValueError):
                    continue
                if isinstance(snapshot, dict) and isinstance(
                    snapshot.get("file_name"), str
                ):
                    references.add(snapshot["file_name"])
        return references

    def _encode_payload(self, payload: dict[str, Any]) -> str:
        if not isinstance(payload, dict):
            raise ValueError("edge outbox payload must be a JSON object")
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("edge outbox payload must be valid JSON") from exc
        if len(encoded.encode("utf-8")) > self.maximum_payload_bytes:
            raise ValueError("edge outbox payload exceeds the configured limit")
        return encoded

    def due(self, limit: int = 100, now: float | None = None) -> list[OutboxItem]:
        current_time = time.time() if now is None else now
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, idempotency_key, payload, attempts
                FROM event_outbox
                WHERE next_attempt_at <= ?
                ORDER BY id
                LIMIT ?
                """,
                (current_time, min(max(limit, 1), 1000)),
            ).fetchall()
        return [
            OutboxItem(row["id"], row["idempotency_key"], json.loads(row["payload"]), row["attempts"])
            for row in rows
        ]

    def acknowledge(self, item_id: int) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM event_outbox WHERE id = ?", (item_id,))

    def retry_later(self, item_id: int, attempts: int, now: float | None = None) -> None:
        current_time = time.time() if now is None else now
        delay = min(2 ** min(max(attempts, 0), 9), 300)
        with self._connect() as connection:
            connection.execute(
                "UPDATE event_outbox SET attempts = ?, next_attempt_at = ? WHERE id = ?",
                (attempts + 1, current_time + delay, item_id),
            )

    def quarantine(self, item: OutboxItem, reason: str) -> None:
        normalized_reason = reason.strip()
        if not normalized_reason or len(normalized_reason) > 100:
            raise ValueError("dead-letter reason must contain 1-100 characters")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload, created_at FROM event_outbox WHERE id = ?",
                (item.id,),
            ).fetchone()
            if not row:
                return
            connection.execute(
                """
                INSERT INTO event_dead_letters
                    (idempotency_key, payload, attempts, reason, created_at, quarantined_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(idempotency_key) DO UPDATE SET
                    payload = excluded.payload,
                    attempts = excluded.attempts,
                    reason = excluded.reason,
                    created_at = excluded.created_at,
                    quarantined_at = excluded.quarantined_at,
                    resolved_at = NULL,
                    resolution = NULL
                """,
                (
                    item.idempotency_key,
                    row["payload"],
                    item.attempts + 1,
                    normalized_reason,
                    row["created_at"],
                    time.time(),
                ),
            )
            connection.execute("DELETE FROM event_outbox WHERE id = ?", (item.id,))

    def size(self) -> int:
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM event_outbox").fetchone()[0]

    def dead_letter_size(self) -> int:
        with self._connect() as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM event_dead_letters WHERE resolved_at IS NULL"
            ).fetchone()[0]

    def prune_resolved_dead_letters(
        self,
        now: float | None = None,
        limit: int | None = None,
    ) -> int:
        current_time = time.time() if now is None else now
        cutoff = current_time - self.resolved_dead_letter_retention_days * 86400
        batch_size = self.resolved_dead_letter_prune_batch_size
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
                raise ValueError("dead-letter prune limit must be a positive integer")
            batch_size = min(limit, 10_000)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM event_dead_letters
                WHERE id IN (
                    SELECT id FROM event_dead_letters
                    WHERE resolved_at IS NOT NULL AND resolved_at < ?
                    ORDER BY resolved_at, id
                    LIMIT ?
                )
                """,
                (cutoff, batch_size),
            )
            return cursor.rowcount

    def dead_letters(self, limit: int = 100) -> list[DeadLetterItem]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, idempotency_key, payload, attempts, reason,
                       created_at, quarantined_at
                FROM event_dead_letters
                WHERE resolved_at IS NULL
                ORDER BY quarantined_at, id
                LIMIT ?
                """,
                (min(max(limit, 1), 1000),),
            ).fetchall()
        return [
            self._dead_letter_item(row)
            for row in rows
        ]

    def dead_letter(self, item_id: int) -> DeadLetterItem | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, idempotency_key, payload, attempts, reason,
                       created_at, quarantined_at
                FROM event_dead_letters
                WHERE id = ? AND resolved_at IS NULL
                """,
                (item_id,),
            ).fetchone()
        return self._dead_letter_item(row) if row else None

    def requeue_dead_letter(self, item_id: int, resolution: str) -> bool:
        normalized_reason = resolution.strip()
        if len(normalized_reason) < 3 or len(normalized_reason) > 200:
            raise ValueError("dead-letter resolution must contain 3-200 characters")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT idempotency_key, payload, created_at
                FROM event_dead_letters
                WHERE id = ? AND resolved_at IS NULL
                """,
                (item_id,),
            ).fetchone()
            if not row:
                return False
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO event_outbox
                    (idempotency_key, payload, attempts, next_attempt_at, created_at)
                VALUES (?, ?, 0, 0, ?)
                """,
                (row["idempotency_key"], row["payload"], row["created_at"]),
            )
            if cursor.rowcount != 1:
                return False
            connection.execute(
                """
                UPDATE event_dead_letters
                SET resolved_at = ?, resolution = ?
                WHERE id = ?
                """,
                (time.time(), normalized_reason, item_id),
            )
            return True

    @staticmethod
    def _dead_letter_item(row: sqlite3.Row) -> DeadLetterItem:
        return DeadLetterItem(
            id=row["id"],
            idempotency_key=row["idempotency_key"],
            payload=json.loads(row["payload"]),
            attempts=row["attempts"],
            reason=row["reason"],
            created_at=row["created_at"],
            quarantined_at=row["quarantined_at"],
        )


Sender = Callable[[str, dict[str, Any]], Awaitable[None]]
Acknowledged = Callable[[OutboxItem], None]


class OutboxDispatcher:
    def __init__(
        self,
        outbox: PersistentOutbox,
        sender: Sender,
        poll_seconds: float = 1.0,
        acknowledged: Acknowledged | None = None,
    ) -> None:
        self.outbox = outbox
        self.sender = sender
        self.poll_seconds = poll_seconds
        self.acknowledged = acknowledged
        self._stop = asyncio.Event()

    async def run(self) -> None:
        while not self._stop.is_set():
            for item in self.outbox.due():
                try:
                    await self.sender(item.idempotency_key, item.payload)
                except asyncio.CancelledError:
                    raise
                except PermanentDeliveryError as exc:
                    self.outbox.quarantine(item, str(exc))
                except Exception:
                    self.outbox.retry_later(item.id, item.attempts)
                    break
                else:
                    self.outbox.acknowledge(item.id)
                    if self.acknowledged:
                        try:
                            self.acknowledged(item)
                        except Exception as exc:
                            logger.warning(
                                "edge_outbox_acknowledged_callback_failed error_type=%s",
                                type(exc).__name__,
                            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_seconds)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()

import asyncio
import base64
import hashlib
import sqlite3

import httpx
import pytest

from app.edge.outbox import (
    OutboxDispatcher,
    PermanentDeliveryError,
    PersistentOutbox,
)
from app.edge.runtime import EdgeApiClient


def test_outbox_deduplicates_and_acknowledges(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    assert outbox.enqueue("cam-1:track-8:intrusion:100", {"camera_id": 1}) is True
    assert outbox.enqueue("cam-1:track-8:intrusion:100", {"camera_id": 1}) is False
    assert outbox.size() == 1
    item = outbox.due()[0]
    assert item.payload == {"camera_id": 1}
    outbox.acknowledge(item.id)
    assert outbox.size() == 0


def test_outbox_applies_retry_backoff(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    outbox.enqueue("event-1", {"type": "intrusion"})
    item = outbox.due(now=100)[0]
    outbox.retry_later(item.id, item.attempts, now=100)
    assert outbox.due(now=100) == []
    retried = outbox.due(now=101)[0]
    assert retried.attempts == 1


def test_outbox_replaces_payload_before_retry_and_tracks_snapshot_files(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    outbox.enqueue(
        "event-with-snapshot",
        {
            "camera_id": 1,
            "_snapshot": {
                "file_name": "a" * 64 + ".jpg",
                "sha256": "b" * 64,
            },
        },
    )
    replacement = outbox.due()[0].payload
    replacement["_snapshot"]["reference"] = (
        "/snapshots/camera-1/2026/08/22/"
        "cccccccccccccccccccccccccccccccc.jpg"
    )
    assert outbox.replace_payload("event-with-snapshot", replacement) is True
    assert outbox.due()[0].payload == replacement
    assert outbox.referenced_snapshot_files() == {"a" * 64 + ".jpg"}
    assert outbox.replace_payload("missing-event", replacement) is False


def test_dispatcher_calls_acknowledgement_hook_after_durable_delete(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    outbox.enqueue("event-ack-hook", {"camera_id": 1})
    acknowledged = []

    async def scenario():
        dispatcher = None

        async def sender(_key, _payload):
            return None

        def after_ack(item):
            assert outbox.size() == 0
            acknowledged.append(item.idempotency_key)
            dispatcher.stop()

        dispatcher = OutboxDispatcher(
            outbox, sender, poll_seconds=0.01, acknowledged=after_ack
        )
        await asyncio.wait_for(dispatcher.run(), timeout=1)

    asyncio.run(scenario())
    assert acknowledged == ["event-ack-hook"]


def test_outbox_retry_backoff_stays_bounded_for_long_outages(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    outbox.enqueue("long-outage", {"type": "intrusion"})
    item = outbox.due(now=100)[0]
    outbox.retry_later(item.id, 1_000_000, now=100)
    assert outbox.due(now=399) == []
    assert outbox.due(now=400)[0].attempts == 1_000_001


def test_full_outbox_keeps_duplicate_idempotency_without_exceeding_capacity(
    tmp_path,
):
    outbox = PersistentOutbox(tmp_path / "outbox.db", maximum_items=1)
    assert outbox.enqueue("event-1", {"type": "intrusion"}) is True
    assert outbox.enqueue("event-1", {"type": "intrusion"}) is False
    with pytest.raises(OverflowError, match="capacity reached"):
        outbox.enqueue("event-2", {"type": "intrusion"})
    assert outbox.size() == 1


def test_outbox_rejects_oversized_payload_before_writing(tmp_path):
    outbox = PersistentOutbox(
        tmp_path / "outbox.db", maximum_payload_bytes=1024
    )
    with pytest.raises(ValueError, match="payload exceeds"):
        outbox.enqueue("event-large", {"payload": "x" * 2048})
    assert outbox.size() == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"confidence": float("nan")},
        {"confidence": float("inf")},
        {"unsupported": object()},
    ],
)
def test_outbox_rejects_non_json_payload_values(tmp_path, payload):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    with pytest.raises(ValueError, match="valid JSON"):
        outbox.enqueue("invalid-json", payload)
    assert outbox.size() == 0


@pytest.mark.parametrize(
    "limits",
    [
        {"maximum_items": True},
        {"maximum_payload_bytes": 1024.5},
        {"resolved_dead_letter_retention_days": False},
    ],
)
def test_outbox_constructor_rejects_coerced_limit_types(tmp_path, limits):
    with pytest.raises(ValueError, match="outbox limits"):
        PersistentOutbox(tmp_path / "outbox.db", **limits)


def test_permanently_rejected_event_is_quarantined_without_blocking_queue(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    outbox.enqueue("bad-event", {"type": "invalid"})
    outbox.enqueue("good-event", {"type": "intrusion"})
    sent = []

    async def scenario():
        dispatcher = None

        async def sender(key, _payload):
            sent.append(key)
            if key == "bad-event":
                raise PermanentDeliveryError("central_rejected_422")
            dispatcher.stop()

        dispatcher = OutboxDispatcher(outbox, sender, poll_seconds=0.01)
        await asyncio.wait_for(dispatcher.run(), timeout=1)

    asyncio.run(scenario())
    assert sent == ["bad-event", "good-event"]
    assert outbox.size() == 0
    assert outbox.dead_letter_size() == 1
    assert outbox.enqueue("bad-event", {"type": "invalid"}) is False


def test_dead_letters_still_count_toward_edge_capacity(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db", maximum_items=1)
    outbox.enqueue("bad-event", {"type": "invalid"})
    item = outbox.due()[0]
    outbox.quarantine(item, "central_rejected_422")
    assert outbox.size() == 0
    assert outbox.dead_letter_size() == 1
    with pytest.raises(OverflowError, match="capacity reached"):
        outbox.enqueue("another-event", {"type": "intrusion"})


def test_dead_letter_can_be_inspected_and_requeued_with_resolution(tmp_path):
    path = tmp_path / "outbox.db"
    outbox = PersistentOutbox(path, maximum_items=1)
    outbox.enqueue("bad-event", {"type": "invalid"})
    queued = outbox.due()[0]
    outbox.quarantine(queued, "central_rejected_422")

    dead_letter = outbox.dead_letters()[0]
    assert outbox.dead_letter(dead_letter.id) == dead_letter
    assert dead_letter.idempotency_key == "bad-event"
    assert dead_letter.payload == {"type": "invalid"}
    assert dead_letter.attempts == 1

    assert outbox.requeue_dead_letter(dead_letter.id, " corrected schema ") is True
    assert outbox.dead_letter(dead_letter.id) is None
    assert outbox.dead_letter_size() == 0
    assert outbox.size() == 1
    assert outbox.due()[0].idempotency_key == "bad-event"

    with sqlite3.connect(path) as connection:
        resolved_at, resolution = connection.execute(
            "SELECT resolved_at, resolution FROM event_dead_letters WHERE id = ?",
            (dead_letter.id,),
        ).fetchone()
    assert resolved_at is not None
    assert resolution == "corrected schema"


def test_resolved_dead_letter_releases_capacity_and_reactivates_on_failure(tmp_path):
    path = tmp_path / "outbox.db"
    outbox = PersistentOutbox(path, maximum_items=1)
    outbox.enqueue("same-event", {"version": 1})
    first = outbox.due()[0]
    outbox.quarantine(first, "central_rejected_400")
    dead_letter_id = outbox.dead_letters()[0].id
    assert outbox.requeue_dead_letter(dead_letter_id, "fixed mapping") is True

    retried = outbox.due()[0]
    outbox.quarantine(retried, "central_rejected_422")
    active = outbox.dead_letters()
    assert len(active) == 1
    assert active[0].id == dead_letter_id
    assert active[0].reason == "central_rejected_422"
    assert outbox.enqueue("same-event", {"version": 2}) is False
    with pytest.raises(OverflowError, match="capacity reached"):
        outbox.enqueue("new-event", {"version": 1})


def test_resolved_dead_letter_no_longer_consumes_capacity(tmp_path):
    outbox = PersistentOutbox(tmp_path / "outbox.db", maximum_items=1)
    outbox.enqueue("old-event", {"version": 1})
    item = outbox.due()[0]
    outbox.quarantine(item, "central_rejected_400")
    dead_letter_id = outbox.dead_letters()[0].id
    assert outbox.requeue_dead_letter(dead_letter_id, "fixed mapping") is True
    outbox.acknowledge(outbox.due()[0].id)

    assert outbox.enqueue("new-event", {"version": 1}) is True


def test_only_expired_resolved_dead_letters_are_pruned(tmp_path, monkeypatch):
    path = tmp_path / "outbox.db"
    outbox = PersistentOutbox(
        path,
        resolved_dead_letter_retention_days=30,
    )
    outbox.enqueue("resolved-event", {"version": 1})
    resolved = outbox.due()[0]
    outbox.quarantine(resolved, "central_rejected_422")
    monkeypatch.setattr("app.edge.outbox.time.time", lambda: 1_000_000.0)
    dead_letter_id = outbox.dead_letters()[0].id
    assert outbox.requeue_dead_letter(dead_letter_id, "fixed schema") is True
    outbox.acknowledge(outbox.due()[0].id)

    outbox.enqueue("active-event", {"version": 1})
    active = outbox.due()[0]
    outbox.quarantine(active, "central_rejected_422")
    assert outbox.prune_resolved_dead_letters(
        now=1_000_000.0 + 30 * 86400
    ) == 0
    assert outbox.prune_resolved_dead_letters(
        now=1_000_000.0 + 30 * 86400 + 1
    ) == 1
    assert outbox.dead_letter_size() == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM event_dead_letters WHERE resolved_at IS NOT NULL"
        ).fetchone()[0] == 0


def test_resolved_dead_letter_pruning_is_bounded_and_can_catch_up(
    tmp_path, monkeypatch
):
    outbox = PersistentOutbox(
        tmp_path / "outbox.db",
        resolved_dead_letter_retention_days=1,
    )
    monkeypatch.setattr("app.edge.outbox.time.time", lambda: 100.0)
    for index in range(3):
        key = f"resolved-{index}"
        outbox.enqueue(key, {"version": 1})
        queued = outbox.due(now=100.0)[0]
        outbox.quarantine(queued, "central_rejected_422")
        dead_letter = next(
            item
            for item in outbox.dead_letters(limit=10)
            if item.idempotency_key == key
        )
        assert outbox.requeue_dead_letter(dead_letter.id, "fixed schema") is True
        outbox.acknowledge(outbox.due(now=100.0)[0].id)

    expired_at = 100.0 + 86400 + 1
    assert outbox.prune_resolved_dead_letters(now=expired_at, limit=2) == 2
    assert outbox.prune_resolved_dead_letters(now=expired_at, limit=2) == 1
    assert outbox.prune_resolved_dead_letters(now=expired_at, limit=2) == 0


@pytest.mark.parametrize("resolution", ["", "  ", "no", "x" * 201])
def test_dead_letter_requeue_rejects_invalid_resolution(tmp_path, resolution):
    outbox = PersistentOutbox(tmp_path / "outbox.db")
    with pytest.raises(ValueError, match="resolution"):
        outbox.requeue_dead_letter(1, resolution)


def test_existing_dead_letter_schema_is_upgraded_in_place(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE event_dead_letters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at REAL NOT NULL,
                quarantined_at REAL NOT NULL
            )
            """
        )
    outbox = PersistentOutbox(path)
    assert outbox.dead_letter_size() == 0
    with sqlite3.connect(path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(event_dead_letters)")
        }
    assert {"resolved_at", "resolution"} <= columns


def test_edge_snapshot_grant_validation_binds_reference_headers_and_https():
    digest = "a" * 64
    reference = (
        "/snapshots/camera-7/2026/08/22/"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.jpg"
    )
    grant = {
        "reference": reference,
        "upload_url": "https://objects.example/upload?signature=test",
        "required_headers": {
            "Content-Type": "image/jpeg",
            "Content-Length": "2048",
            "x-amz-checksum-sha256": base64.b64encode(
                bytes.fromhex(digest)
            ).decode("ascii"),
            "If-None-Match": "*",
            "x-amz-server-side-encryption": "AES256",
            "x-amz-tagging": "mineguard-legal-hold=false",
        },
        "expires_in_seconds": 120,
    }
    EdgeApiClient._validate_snapshot_grant(
        grant,
        camera_id=7,
        content_length=2048,
        sha256_hex=digest,
        requested_reference=reference,
    )
    with pytest.raises(ValueError, match="violates"):
        EdgeApiClient._validate_snapshot_grant(
            {**grant, "upload_url": "http://metadata.internal/upload"},
            camera_id=7,
            content_length=2048,
            sha256_hex=digest,
            requested_reference=reference,
        )
    with pytest.raises(ValueError, match="violates"):
        EdgeApiClient._validate_snapshot_grant(
            {
                **grant,
                "required_headers": {
                    **grant["required_headers"],
                    "Content-Length": "2049",
                },
            },
            camera_id=7,
            content_length=2048,
            sha256_hex=digest,
            requested_reference=reference,
        )


def test_edge_snapshot_precondition_failure_requires_center_integrity_check():
    snapshot = b"x" * 2048
    digest = hashlib.sha256(snapshot).hexdigest()
    reference = (
        "/snapshots/camera-7/2026/08/22/"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.jpg"
    )
    verified_requests = []

    def center_handler(request):
        verified_requests.append(request)
        return httpx.Response(204, request=request)

    async def scenario():
        client = EdgeApiClient.__new__(EdgeApiClient)
        client.client = httpx.AsyncClient(
            base_url="https://center.example/api/v1/",
            transport=httpx.MockTransport(center_handler),
        )
        client.upload_client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(412, request=request)
            )
        )
        grant = {
            "reference": reference,
            "upload_url": "https://objects.example/upload?signature=test",
            "required_headers": {},
        }
        try:
            await client.upload_snapshot(grant, snapshot)
        finally:
            await client.close()

    asyncio.run(scenario())
    assert len(verified_requests) == 1
    assert verified_requests[0].url.path.endswith("/edge/snapshots/verify")
    assert f'"sha256":"{digest}"' in verified_requests[0].content.decode()


@pytest.mark.parametrize("status_code", [400, 413, 415, 422])
def test_edge_api_client_quarantines_only_permanent_payload_rejections(status_code):
    async def scenario():
        client = EdgeApiClient.__new__(EdgeApiClient)
        client.client = httpx.AsyncClient(
            base_url="https://center.example/api/v1/",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(status_code, request=request)
            ),
        )
        try:
            with pytest.raises(PermanentDeliveryError, match=str(status_code)):
                await client.send_event("edge:key", {"event_type": "intrusion"})
        finally:
            await client.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("status_code", [401, 403, 409, 429, 500, 503])
def test_edge_api_client_retries_recoverable_http_failures(status_code):
    async def scenario():
        client = EdgeApiClient.__new__(EdgeApiClient)
        client.client = httpx.AsyncClient(
            base_url="https://center.example/api/v1/",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(status_code, request=request)
            ),
        )
        try:
            with pytest.raises(httpx.HTTPStatusError):
                await client.send_event("edge:key", {"event_type": "intrusion"})
        finally:
            await client.close()

    asyncio.run(scenario())

import base64
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import Base
from app.services.snapshot_legal_holds import SnapshotLegalHoldReconciler
from app.services.snapshots import (
    SnapshotStorage,
    SnapshotStorageError,
    snapshot_camera_id,
    snapshot_object_key,
)


class FakeS3Client:
    def __init__(self):
        self.presigned = []
        self.tagged = []
        self.head = {}
        self.object_tags = [
            {"Key": "mineguard-legal-hold", "Value": "false"}
        ]

    def generate_presigned_url(self, operation, **options):
        self.presigned.append((operation, options))
        return f"https://objects.test/{operation}"

    def put_object_tagging(self, **options):
        self.tagged.append(options)

    def head_object(self, **_options):
        return self.head

    def get_object_tagging(self, **_options):
        return {"TagSet": self.object_tags}


def snapshot_settings(**overrides):
    values = {
        "snapshot_storage_enabled": True,
        "snapshot_storage_bucket": "mineguard-snapshots",
        "snapshot_storage_maximum_bytes": 4096,
        "snapshot_storage_presign_seconds": 120,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_snapshot_upload_grant_binds_digest_size_encryption_and_retention_tag():
    client = FakeS3Client()
    storage = SnapshotStorage(snapshot_settings(), client=client)
    grant = storage.create_upload_grant(
        camera_id=7,
        content_type="image/jpeg",
        content_length=2048,
        sha256_hex="a" * 64,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    assert snapshot_camera_id(grant.reference) == 7
    assert grant.reference.startswith("/snapshots/camera-7/2026/08/22/")
    operation, options = client.presigned[0]
    assert operation == "put_object"
    assert options["Params"]["ContentLength"] == 2048
    assert options["Params"]["ChecksumSHA256"] == grant.required_headers[
        "x-amz-checksum-sha256"
    ]
    assert options["Params"]["IfNoneMatch"] == "*"
    assert grant.required_headers["If-None-Match"] == "*"
    assert options["Params"]["ServerSideEncryption"] == "AES256"
    assert options["Params"]["Tagging"] == "mineguard-legal-hold=false"


def test_snapshot_storage_rejects_oversized_or_invalid_references():
    storage = SnapshotStorage(snapshot_settings(), client=FakeS3Client())
    with pytest.raises(ValueError, match="upload limit"):
        storage.create_upload_grant(
            camera_id=1,
            content_type="image/jpeg",
            content_length=4097,
            sha256_hex="b" * 64,
        )
    with pytest.raises(ValueError, match="reference"):
        snapshot_object_key(
            "/snapshots/camera-1/2026/99/22/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg"
        )


def test_snapshot_access_and_legal_hold_use_stable_internal_key():
    client = FakeS3Client()
    storage = SnapshotStorage(snapshot_settings(), client=client)
    reference = (
        "/snapshots/camera-3/2026/08/22/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg"
    )
    access = storage.create_access_grant(reference)
    storage.set_legal_hold(reference, True)

    assert access.download_url.endswith("get_object")
    assert client.presigned[0][1]["Params"]["Key"] == reference.removeprefix("/")
    assert client.tagged[0]["Tagging"]["TagSet"] == [
        {"Key": "mineguard-legal-hold", "Value": "true"}
    ]


def test_snapshot_legal_hold_preserves_unrelated_object_tags():
    client = FakeS3Client()
    client.object_tags.append({"Key": "classification", "Value": "L3"})
    storage = SnapshotStorage(snapshot_settings(), client=client)
    storage.set_legal_hold(
        "/snapshots/camera-3/2026/08/22/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg",
        True,
    )
    assert client.tagged[0]["Tagging"]["TagSet"] == [
        {"Key": "classification", "Value": "L3"},
        {"Key": "mineguard-legal-hold", "Value": "true"},
    ]


def test_snapshot_upload_grant_can_resign_the_same_internal_reference():
    client = FakeS3Client()
    storage = SnapshotStorage(snapshot_settings(), client=client)
    reference = (
        "/snapshots/camera-4/2026/08/22/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.jpg"
    )
    grant = storage.create_upload_grant(
        camera_id=4,
        content_type="image/jpeg",
        content_length=2048,
        sha256_hex="f" * 64,
        reference=reference,
    )
    assert grant.reference == reference
    assert client.presigned[0][1]["Params"]["Key"] == reference.removeprefix("/")
    with pytest.raises(ValueError, match="does not match"):
        storage.create_upload_grant(
            camera_id=3,
            content_type="image/jpeg",
            content_length=2048,
            sha256_hex="f" * 64,
            reference=reference,
        )


def test_snapshot_upload_verification_checks_object_integrity_and_tag():
    client = FakeS3Client()
    digest = "a" * 64
    client.head = {
        "ContentLength": 2048,
        "ContentType": "image/jpeg",
        "ChecksumSHA256": base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
        "ServerSideEncryption": "AES256",
    }
    client.object_tags = [{"Key": "mineguard-legal-hold", "Value": "false"}]
    storage = SnapshotStorage(snapshot_settings(), client=client)
    reference = (
        "/snapshots/camera-4/2026/08/22/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.jpg"
    )
    storage.verify_upload(
        reference=reference,
        content_type="image/jpeg",
        content_length=2048,
        sha256_hex=digest,
    )
    client.head["ContentLength"] = 2049
    with pytest.raises(SnapshotStorageError, match="does not match"):
        storage.verify_upload(
            reference=reference,
            content_type="image/jpeg",
            content_length=2048,
            sha256_hex=digest,
        )


def test_disabled_snapshot_storage_fails_without_contacting_a_provider():
    storage = SnapshotStorage(Settings(_env_file=None))
    with pytest.raises(SnapshotStorageError, match="not configured"):
        storage.create_access_grant(
            "/snapshots/camera-1/2026/08/22/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg"
        )


def test_snapshot_reconciler_does_not_initialize_storage_without_due_jobs():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    def unexpected_storage_initialization():
        raise AssertionError("storage must stay lazy while the queue is empty")

    with Session(engine) as db:
        reconciler = SnapshotLegalHoldReconciler(
            storage_factory=unexpected_storage_initialization
        )
        assert reconciler.dispatch_due(db) == 0
        assert reconciler.pending == 0

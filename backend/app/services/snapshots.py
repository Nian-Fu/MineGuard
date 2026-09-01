import base64
import re
from datetime import UTC, datetime
from functools import lru_cache
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import get_settings
from app.schemas import SnapshotAccessGrant, SnapshotUploadGrant

SNAPSHOT_REFERENCE_PATTERN = re.compile(
    r"^/snapshots/camera-([1-9][0-9]{0,18})/([0-9]{4})/([0-9]{2})/([0-9]{2})/([a-f0-9]{32})\.jpg$"
)
LEGAL_HOLD_TAG_KEY = "mineguard-legal-hold"


class SnapshotStorageError(RuntimeError):
    pass


class SnapshotIntegrityError(SnapshotStorageError):
    pass


def _match_snapshot_reference(reference: str):
    match = SNAPSHOT_REFERENCE_PATTERN.fullmatch(reference)
    if not match:
        raise ValueError("invalid internal snapshot reference")
    try:
        datetime(int(match.group(2)), int(match.group(3)), int(match.group(4)))
    except ValueError as exc:
        raise ValueError("invalid internal snapshot reference date") from exc
    return match


def snapshot_object_key(reference: str) -> str:
    _match_snapshot_reference(reference)
    return reference.removeprefix("/")


def snapshot_camera_id(reference: str) -> int:
    match = _match_snapshot_reference(reference)
    return int(match.group(1))


class SnapshotStorage:
    def __init__(self, settings, client=None) -> None:
        self.settings = settings
        if not settings.snapshot_storage_enabled:
            self.client = None
            return
        access_key = (
            settings.snapshot_storage_access_key_id.get_secret_value()
            if settings.snapshot_storage_access_key_id
            else None
        )
        secret_key = (
            settings.snapshot_storage_secret_access_key.get_secret_value()
            if settings.snapshot_storage_secret_access_key
            else None
        )
        try:
            self.client = client or boto3.client(
                "s3",
                endpoint_url=settings.snapshot_storage_endpoint_url,
                region_name=settings.snapshot_storage_region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                config=Config(
                    signature_version="s3v4",
                    connect_timeout=settings.snapshot_storage_connect_timeout_seconds,
                    read_timeout=settings.snapshot_storage_read_timeout_seconds,
                    retries={
                        "total_max_attempts": settings.snapshot_storage_total_attempts,
                        "mode": "standard",
                    },
                    s3={
                        "addressing_style": "path"
                        if settings.snapshot_storage_force_path_style
                        else "virtual"
                    },
                ),
            )
        except BotoCoreError as exc:
            raise SnapshotStorageError(
                "snapshot storage client initialization failed"
            ) from exc

    def _require_client(self):
        if self.client is None:
            raise SnapshotStorageError("snapshot storage is not configured")
        return self.client

    def create_upload_grant(
        self,
        *,
        camera_id: int,
        content_type: str,
        content_length: int,
        sha256_hex: str,
        reference: str | None = None,
        now: datetime | None = None,
    ) -> SnapshotUploadGrant:
        if content_length > self.settings.snapshot_storage_maximum_bytes:
            raise ValueError("snapshot exceeds the configured upload limit")
        checked_at = now or datetime.now(UTC)
        reference = reference or (
            f"/snapshots/camera-{camera_id}/{checked_at:%Y/%m/%d}/{uuid4().hex}.jpg"
        )
        if snapshot_camera_id(reference) != camera_id:
            raise ValueError("snapshot reference camera does not match upload camera")
        checksum = base64.b64encode(bytes.fromhex(sha256_hex)).decode("ascii")
        tagging = f"{LEGAL_HOLD_TAG_KEY}=false"
        parameters = {
            "Bucket": self.settings.snapshot_storage_bucket,
            "Key": snapshot_object_key(reference),
            "ContentType": content_type,
            "ContentLength": content_length,
            "ChecksumSHA256": checksum,
            "IfNoneMatch": "*",
            "ServerSideEncryption": "AES256",
            "Tagging": tagging,
        }
        try:
            upload_url = self._require_client().generate_presigned_url(
                "put_object",
                Params=parameters,
                ExpiresIn=self.settings.snapshot_storage_presign_seconds,
                HttpMethod="PUT",
            )
        except (BotoCoreError, ClientError, ValueError) as exc:
            raise SnapshotStorageError("snapshot upload grant creation failed") from exc
        return SnapshotUploadGrant(
            reference=reference,
            upload_url=upload_url,
            required_headers={
                "Content-Type": content_type,
                "Content-Length": str(content_length),
                "x-amz-checksum-sha256": checksum,
                "If-None-Match": "*",
                "x-amz-server-side-encryption": "AES256",
                "x-amz-tagging": tagging,
            },
            expires_in_seconds=self.settings.snapshot_storage_presign_seconds,
        )

    def create_access_grant(self, reference: str) -> SnapshotAccessGrant:
        try:
            download_url = self._require_client().generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.settings.snapshot_storage_bucket,
                    "Key": snapshot_object_key(reference),
                    "ResponseContentType": "image/jpeg",
                    "ResponseContentDisposition": "inline",
                },
                ExpiresIn=self.settings.snapshot_storage_presign_seconds,
                HttpMethod="GET",
            )
        except (BotoCoreError, ClientError, ValueError) as exc:
            raise SnapshotStorageError("snapshot access grant creation failed") from exc
        return SnapshotAccessGrant(
            download_url=download_url,
            expires_in_seconds=self.settings.snapshot_storage_presign_seconds,
        )

    def verify_upload(
        self,
        *,
        reference: str,
        content_type: str,
        content_length: int,
        sha256_hex: str,
    ) -> None:
        client = self._require_client()
        try:
            head = client.head_object(
                Bucket=self.settings.snapshot_storage_bucket,
                Key=snapshot_object_key(reference),
                ChecksumMode="ENABLED",
            )
            tagging = client.get_object_tagging(
                Bucket=self.settings.snapshot_storage_bucket,
                Key=snapshot_object_key(reference),
            )
        except (BotoCoreError, ClientError, ValueError) as exc:
            raise SnapshotStorageError("snapshot upload verification failed") from exc
        expected_checksum = base64.b64encode(
            bytes.fromhex(sha256_hex)
        ).decode("ascii")
        tags = {
            item.get("Key"): item.get("Value")
            for item in tagging.get("TagSet", [])
            if isinstance(item, dict)
        }
        if (
            head.get("ContentLength") != content_length
            or head.get("ContentType") != content_type
            or head.get("ChecksumSHA256") != expected_checksum
            or head.get("ServerSideEncryption") != "AES256"
            or tags.get(LEGAL_HOLD_TAG_KEY) != "false"
        ):
            raise SnapshotIntegrityError(
                "existing snapshot object does not match the signed upload"
            )

    def set_legal_hold(self, reference: str, enabled: bool) -> None:
        try:
            client = self._require_client()
            existing = client.get_object_tagging(
                Bucket=self.settings.snapshot_storage_bucket,
                Key=snapshot_object_key(reference),
            )
            tags = {
                item.get("Key"): item.get("Value")
                for item in existing.get("TagSet", [])
                if isinstance(item, dict)
                and isinstance(item.get("Key"), str)
                and isinstance(item.get("Value"), str)
            }
            tags[LEGAL_HOLD_TAG_KEY] = "true" if enabled else "false"
            if len(tags) > 10:
                raise ValueError("snapshot object exceeds the S3 tag limit")
            client.put_object_tagging(
                Bucket=self.settings.snapshot_storage_bucket,
                Key=snapshot_object_key(reference),
                Tagging={
                    "TagSet": [
                        {"Key": key, "Value": value}
                        for key, value in sorted(tags.items())
                    ]
                },
            )
        except (BotoCoreError, ClientError, ValueError) as exc:
            raise SnapshotStorageError("snapshot legal-hold synchronization failed") from exc


@lru_cache
def get_snapshot_storage() -> SnapshotStorage:
    return SnapshotStorage(get_settings())

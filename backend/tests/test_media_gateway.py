import json
from types import SimpleNamespace

import httpx
import pytest

from app.services.media_gateway import (
    MediaGatewayError,
    MediaGatewayReconciler,
    media_path_name,
)


def camera(name: str, source: str):
    return SimpleNamespace(
        playback_path=f"/media/{name}/index.m3u8",
        stream_url=source,
    )


def test_media_reconciler_adds_missing_and_updates_changed_sources():
    writes = []

    def handler(request: httpx.Request):
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"name": "unchanged", "source": "rtsp://source/unchanged"},
                        {"name": "changed", "source": "rtsp://source/old"},
                    ]
                },
            )
        writes.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(200)

    client = httpx.Client(
        base_url="http://media-gateway:9997",
        transport=httpx.MockTransport(handler),
    )
    reconciler = MediaGatewayReconciler("http://unused", client=client)
    try:
        result = reconciler.reconcile(
            [
                camera("unchanged", "rtsp://source/unchanged"),
                camera("changed", "rtsps://source/new?token=secret"),
                camera("new-camera", "rtsp://source/new"),
            ]
        )
    finally:
        reconciler.close()

    assert result.managed == 3
    assert result.added == 1
    assert result.updated == 1
    assert result.removed == 0
    assert [(method, path) for method, path, _ in writes] == [
        ("PATCH", "/v3/config/paths/patch/changed"),
        ("POST", "/v3/config/paths/add/new-camera"),
    ]
    assert writes[0][2]["source"] == "rtsps://source/new?token=secret"
    assert writes[0][2]["sourceOnDemand"] is True


def test_media_reconciler_recovers_on_a_later_periodic_attempt():
    attempts = 0

    def handler(request: httpx.Request):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(200, json={"items": []})

    client = httpx.Client(
        base_url="http://media-gateway:9997",
        transport=httpx.MockTransport(handler),
    )
    reconciler = MediaGatewayReconciler("http://unused", client=client)
    with pytest.raises(MediaGatewayError):
        reconciler.reconcile([])
    assert reconciler.reconcile([]).managed == 0
    reconciler.close()


def test_media_reconciler_removes_stale_paths_but_preserves_reserved_default():
    writes = []

    def handler(request: httpx.Request):
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"name": "all_others", "source": "publisher"},
                        {"name": "~external/.+", "source": "publisher"},
                        {"name": "active", "source": "rtsp://source/active"},
                        {"name": "deleted-camera", "source": "rtsp://source/old"},
                    ]
                },
            )
        writes.append((request.method, request.url.path))
        return httpx.Response(200)

    client = httpx.Client(
        base_url="http://media-gateway:9997",
        transport=httpx.MockTransport(handler),
    )
    reconciler = MediaGatewayReconciler("http://unused", client=client)
    result = reconciler.reconcile(
        [camera("active", "rtsp://source/active")]
    )
    reconciler.close()

    assert result.removed == 1
    assert writes == [
        ("DELETE", "/v3/config/paths/delete/deleted-camera")
    ]


def test_invalid_camera_does_not_block_healthy_path_reconciliation():
    writes = []

    class InvalidCamera:
        playback_path = "/media/invalid/index.m3u8"

        @property
        def stream_url(self):
            raise RuntimeError("ciphertext failed authentication")

    def handler(request: httpx.Request):
        if request.method == "GET":
            return httpx.Response(200, json={"items": []})
        writes.append((request.method, request.url.path))
        return httpx.Response(200)

    client = httpx.Client(
        base_url="http://media-gateway:9997",
        transport=httpx.MockTransport(handler),
    )
    reconciler = MediaGatewayReconciler("http://unused", client=client)
    try:
        with pytest.raises(MediaGatewayError, match="skipped 1 invalid"):
            reconciler.reconcile(
                [
                    InvalidCamera(),
                    camera("healthy", "rtsp://source/healthy"),
                ]
            )
    finally:
        reconciler.close()

    assert writes == [("POST", "/v3/config/paths/add/healthy")]


def test_transient_camera_decryption_failure_does_not_delete_its_path():
    writes = []

    class InvalidCamera:
        playback_path = "/media/protected/index.m3u8"

        @property
        def stream_url(self):
            raise RuntimeError("temporary KMS failure")

    def handler(request: httpx.Request):
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"name": "protected", "source": "rtsp://source/old"}
                    ]
                },
            )
        writes.append((request.method, request.url.path))
        return httpx.Response(200)

    client = httpx.Client(
        base_url="http://media-gateway:9997",
        transport=httpx.MockTransport(handler),
    )
    reconciler = MediaGatewayReconciler("http://unused", client=client)
    with pytest.raises(MediaGatewayError, match="skipped 1 invalid"):
        reconciler.reconcile([InvalidCamera()])
    reconciler.close()

    assert writes == []


def test_media_reconciler_reads_all_pages_without_readding_existing_paths():
    writes = []
    progress_calls = []

    def handler(request: httpx.Request):
        if request.method != "GET":
            writes.append(request.method)
            return httpx.Response(200)
        page = int(request.url.params["page"])
        return httpx.Response(
            200,
            json={
                "pageCount": 2,
                "items": [
                    {
                        "name": f"camera-{page}",
                        "source": f"rtsp://source/{page}",
                    }
                ],
            },
        )

    client = httpx.Client(
        base_url="http://media-gateway:9997",
        transport=httpx.MockTransport(handler),
    )
    reconciler = MediaGatewayReconciler("http://unused", client=client)
    result = reconciler.reconcile(
        [
            camera("camera-0", "rtsp://source/0"),
            camera("camera-1", "rtsp://source/1"),
        ],
        progress=lambda: progress_calls.append(True),
    )
    reconciler.close()
    assert result.managed == 2
    assert writes == []
    assert len(progress_calls) == 2


def test_concurrent_media_path_add_conflict_converges_with_patch():
    methods = []

    def handler(request: httpx.Request):
        methods.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json={"items": []})
        if request.method == "POST":
            return httpx.Response(409)
        return httpx.Response(200)

    client = httpx.Client(
        base_url="http://media-gateway:9997",
        transport=httpx.MockTransport(handler),
    )
    reconciler = MediaGatewayReconciler("http://unused", client=client)
    result = reconciler.reconcile([camera("camera-race", "rtsp://source/race")])
    reconciler.close()
    assert result.added == 1
    assert methods == ["GET", "POST", "PATCH"]


@pytest.mark.parametrize(
    "path",
    ["/media/CAM-01/index.m3u8", "/media/../index.m3u8", "/other/cam/index.m3u8"],
)
def test_media_path_name_rejects_unmanaged_paths(path):
    with pytest.raises(ValueError, match="managed media path"):
        media_path_name(path)

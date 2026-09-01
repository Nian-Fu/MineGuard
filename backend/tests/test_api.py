from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.core.database import SessionLocal, get_db
from app.main import app
from app.models import RealtimeSignal
from app.schemas import FaceCandidate


def auth_headers(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "MineGuard@123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def media_authorization(client, path):
    token = client.cookies.get("mineguard_media")
    return client.get(
        "/api/v1/media/authorize",
        headers={
            "X-Original-URI": path,
            "Cookie": f"mineguard_media={token}",
        },
    )


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert client.get("/ready").json()["status"] == "ready"
    metrics = client.get("/internal/metrics")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert "mineguard_worker_up " in metrics.text
    assert "mineguard_notification_queue_depth " in metrics.text
    assert "mineguard_snapshot_legal_hold_pending " in metrics.text
    assert "mineguard_edge_reconnects_last_5m " in metrics.text
    assert "mineguard_edge_camera_reports_degraded " in metrics.text
    assert "mineguard_edge_camera_error_codes " in metrics.text
    assert "mineguard_edge_dead_letter_depth " in metrics.text
    assert "mineguard_edge_outbox_max_utilization_ratio " in metrics.text
    assert "mineguard_media_gateway_up " in metrics.text
    assert "mineguard_media_gateway_reconcile_failures " in metrics.text


def test_database_outage_is_retryable_without_exposing_driver_details(client):
    class UnavailableDatabase:
        def execute(self, *_args, **_kwargs):
            raise OperationalError(
                "SELECT secret FROM internal",
                {},
                ConnectionError("database-password-leak-sentinel"),
            )

    def unavailable_database():
        yield UnavailableDatabase()

    app.dependency_overrides[get_db] = unavailable_database
    try:
        response = client.get("/ready")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "2"
    assert response.json() == {"detail": "数据库暂时不可用，系统正在自动恢复"}
    assert "secret" not in response.text
    assert "password-leak-sentinel" not in response.text


def test_request_id_is_preserved_only_when_header_safe(client):
    accepted = client.get("/health", headers={"X-Request-ID": "ops-check:123"})
    assert accepted.headers["X-Request-ID"] == "ops-check:123"
    rejected = client.get("/health", headers={"X-Request-ID": "invalid request id"})
    assert rejected.headers["X-Request-ID"] != "invalid request id"
    assert " " not in rejected.headers["X-Request-ID"]


def test_authentication_methods_are_public(client):
    response = client.get("/api/v1/auth/methods")
    assert response.status_code == 200
    assert response.json() == {
        "local_enabled": True,
        "oidc_enabled": False,
        "oidc_provider_label": None,
    }


def test_local_username_login_is_case_insensitive(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "ADMIN", "password": "MineGuard@123"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "admin"


def test_media_requires_a_scoped_http_only_session(client):
    assert client.get(
        "/api/v1/media/authorize",
        headers={
            "X-Original-URI": "/media/cam-001/index.m3u8",
            "Cookie": "mineguard_media=invalid",
        },
    ).status_code == 401
    auth_headers(client)
    assert media_authorization(client, "/media/cam-001/index.m3u8").status_code == 204
    assert media_authorization(client, "/media/cam-001/seg7.ts").status_code == 204
    assert media_authorization(client, "/media/cam-001/part42.mp4").status_code == 204
    assert media_authorization(client, "/media/unknown/index.m3u8").status_code == 403
    for invalid_path in (
        "/media/cam-001/../cam-002/index.m3u8",
        "/media/cam-001/%2e%2e",
        "/media/cam-001\\index.m3u8",
        "/media//index.m3u8",
        "/media/cam-001/subdir/segment.ts",
        "https://media.example/media/cam-001/index.m3u8",
        "//media.example/media/cam-001/index.m3u8",
    ):
        assert media_authorization(client, invalid_path).status_code == 403


def test_local_login_endpoint_can_be_disabled(client, monkeypatch):
    monkeypatch.setattr(
        "app.api.auth.get_settings",
        lambda: SimpleNamespace(local_login_enabled=False),
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "MineGuard@123"},
    )
    assert response.status_code == 403


def test_failed_login_is_audited_without_exposing_password(client):
    failed = client.post(
        "/api/v1/auth/login",
        json={"username": "missing-account", "password": "DefinitelyWrong123"},
    )
    assert failed.status_code == 401
    audit = client.get("/api/v1/audit-logs", headers=auth_headers(client))
    matching = [item for item in audit.json()["items"] if item["action"] == "auth.login_failed"]
    assert matching
    assert "DefinitelyWrong123" not in audit.text


def test_refresh_session_rotates_and_logout_revokes(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "MineGuard@123"},
    )
    assert login.status_code == 200
    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"] != login.json()["access_token"]
    assert client.post("/api/v1/auth/logout").status_code == 204
    assert client.cookies.get("mineguard_media") is None
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_failed_refresh_clears_remaining_media_session(client):
    assert auth_headers(client)
    assert client.cookies.get("mineguard_media") is not None
    client.cookies.delete("mineguard_refresh")
    response = client.post("/api/v1/auth/refresh")
    assert response.status_code == 401
    assert client.cookies.get("mineguard_media") is None


def test_refresh_rejects_untrusted_browser_origin(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "MineGuard@123"},
    )
    response = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "https://untrusted.example"},
    )
    assert response.status_code == 403


def test_refresh_accepts_same_origin_when_cors_allowlist_is_empty(client, monkeypatch):
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "cors_origins", [])
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "MineGuard@123"},
    )
    response = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200


def test_password_change_revokes_existing_access_and_refresh_sessions(client):
    admin_headers = auth_headers(client)
    created = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "password-change-user",
            "full_name": "改密测试用户",
            "password": "OriginalPass123",
            "role": "operator",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "password-change-user", "password": "OriginalPass123"},
    )
    old_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    changed = client.post(
        "/api/v1/auth/change-password",
        headers=old_headers,
        json={"current_password": "OriginalPass123", "new_password": "ReplacementPass456"},
    )
    assert changed.status_code == 204
    assert client.get("/api/v1/auth/me", headers=old_headers).status_code == 401
    assert client.post("/api/v1/auth/refresh").status_code == 401
    relogin = client.post(
        "/api/v1/auth/login",
        json={"username": "password-change-user", "password": "ReplacementPass456"},
    )
    assert relogin.status_code == 200


def test_protected_api_and_dashboard(client):
    assert client.get("/api/v1/cameras").status_code == 401
    headers = auth_headers(client)
    cameras = client.get("/api/v1/cameras", headers=headers)
    assert cameras.status_code == 200
    assert cameras.json()["total"] == 4
    assert cameras.json()["items"][0]["playback_path"].startswith("/media/")
    assert "stream_url" not in cameras.text
    dashboard = client.get("/api/v1/dashboard/summary", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["open_events"] >= 3
    assert dashboard.json()["system_health"]["worker_status"] in {
        "online",
        "degraded",
        "offline",
    }
    assert isinstance(dashboard.json()["operational_alerts"], list)
    capabilities = client.get("/api/v1/system/capabilities", headers=headers)
    assert capabilities.status_code == 200
    assert capabilities.json()["face_recognition_enabled"] is False
    assert "key" not in capabilities.text.lower()
    clamped = client.get("/api/v1/persons?page_size=-10", headers=headers)
    assert clamped.status_code == 200
    assert clamped.json()["page_size"] == 1


def test_operational_lists_support_bounded_search_and_pagination(client):
    headers = auth_headers(client)

    camera_page = client.get(
        "/api/v1/cameras?page=2&page_size=2", headers=headers
    )
    assert camera_page.status_code == 200
    assert camera_page.json()["total"] == 4
    assert len(camera_page.json()["items"]) == 2
    camera_search = client.get(
        "/api/v1/cameras?query=cam-001", headers=headers
    )
    assert camera_search.status_code == 200
    assert [item["code"] for item in camera_search.json()["items"]] == [
        "CAM-001"
    ]
    literal_wildcard = client.get(
        "/api/v1/cameras?query=%25", headers=headers
    )
    assert literal_wildcard.status_code == 200
    assert literal_wildcard.json()["total"] == 0

    event_search = client.get(
        "/api/v1/events?query=cam-003", headers=headers
    )
    assert event_search.status_code == 200
    assert event_search.json()["total"] == 1
    assert event_search.json()["items"][0]["camera"]["code"] == "CAM-003"

    person_search = client.get(
        "/api/v1/persons?query=%E9%87%87%E6%8E%98%E4%B8%80%E9%98%9F",
        headers=headers,
    )
    assert person_search.status_code == 200
    assert person_search.json()["total"] == 1
    assert person_search.json()["items"][0]["employee_no"] == "M20260018"

    templates = client.get(
        "/api/v1/faces/templates?page=1&page_size=25", headers=headers
    )
    assert templates.status_code == 200
    assert templates.json()["page"] == 1
    assert templates.json()["page_size"] == 25
    assert isinstance(templates.json()["items"], list)

    for endpoint in (
        "/api/v1/users/page",
        "/api/v1/alert-rules/page",
        "/api/v1/edge-nodes/page",
        "/api/v1/algorithms/artifacts/page",
    ):
        response = client.get(
            endpoint, params={"page": 1, "page_size": 25}, headers=headers
        )
        assert response.status_code == 200
        assert response.json()["page"] == 1
        assert response.json()["page_size"] == 25
        assert isinstance(response.json()["items"], list)
        assert response.json()["total"] >= len(response.json()["items"])

    too_long = "x" * 101
    assert client.get(
        "/api/v1/events", params={"query": too_long}, headers=headers
    ).status_code == 422


def test_edge_face_identification_is_scoped_minimal_and_indeterminate(
    client, monkeypatch
):
    class Provider:
        def __init__(self):
            self.calls = 0
            self.quality = 0.91
            self.liveness = 0.96

        async def embed(self, _image, _content_type):
            self.calls += 1
            return SimpleNamespace(
                embedding=[0.01] * 128,
                quality=self.quality,
                liveness=self.liveness,
                face_count=1,
                provider="test-provider",
                model_version="face-v1",
                model_sha256="a" * 64,
            )

    provider = Provider()
    settings = SimpleNamespace(
        max_face_image_bytes=1024 * 1024,
        face_min_quality=0.65,
        face_min_liveness=0.8,
        face_match_threshold=0.72,
        enforce_approved_edge_models=False,
    )
    monkeypatch.setattr(
        "app.api.faces.face_components", lambda: (provider, None)
    )
    monkeypatch.setattr("app.api.faces.get_settings", lambda: settings)
    candidates = []
    monkeypatch.setattr(
        "app.api.faces.identify_candidates",
        lambda _db, _result, _scope: list(candidates),
    )

    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={
            "code": "edge-face-contract",
            "name": "实时人脸合约节点",
            "camera_ids": [1],
        },
    )
    assert registered.status_code == 201
    edge_headers = {
        "X-Edge-Node": "edge-face-contract",
        "X-Edge-Key": registered.json()["api_key"],
    }
    files = {"image": ("probe.jpg", b"bounded-image", "image/jpeg")}

    unknown = client.post(
        "/api/v1/faces/edge-identify",
        headers=edge_headers,
        data={"camera_id": "1"},
        files=files,
    )
    assert unknown.status_code == 200
    assert unknown.json() == {
        "matched": False,
        "unknown": True,
        "quality": 0.91,
        "liveness": 0.96,
        "model_version": "face-v1",
        "model_sha256": "a" * 64,
        "authorized_for_camera": None,
        "candidate": None,
    }

    person_id = client.get(
        "/api/v1/persons?query=M20260018", headers=admin_headers
    ).json()["items"][0]["id"]
    candidates.append(
        FaceCandidate(
            person_id=person_id,
            employee_no="must-not-leak",
            name="must-not-leak",
            similarity=0.88,
        )
    )
    matched = client.post(
        "/api/v1/faces/edge-identify",
        headers=edge_headers,
        data={"camera_id": "1"},
        files=files,
    )
    assert matched.status_code == 200
    assert matched.json()["candidate"] == {
        "person_id": person_id,
        "similarity": 0.88,
    }
    assert matched.json()["authorized_for_camera"] is True
    assert "must-not-leak" not in matched.text
    assert "embedding" not in matched.text

    calls_before_forbidden = provider.calls
    forbidden = client.post(
        "/api/v1/faces/edge-identify",
        headers=edge_headers,
        data={"camera_id": "2"},
        files=files,
    )
    assert forbidden.status_code == 403
    assert provider.calls == calls_before_forbidden

    provider.quality = 0.1
    indeterminate = client.post(
        "/api/v1/faces/edge-identify",
        headers=edge_headers,
        data={"camera_id": "1"},
        files=files,
    )
    assert indeterminate.status_code == 422
    assert "unknown" not in indeterminate.text.lower()

    provider.quality = 0.91
    settings.enforce_approved_edge_models = True
    blocked_model = client.post(
        "/api/v1/faces/edge-identify",
        headers=edge_headers,
        data={"camera_id": "1"},
        files=files,
    )
    assert blocked_model.status_code == 503
    artifact = client.post(
        "/api/v1/algorithms/artifacts",
        headers=admin_headers,
        json={
            "name": "实时人脸端点测试模型",
            "algorithm_type": "face_recognition",
            "model_version": "face-v1",
            "sha256": "a" * 64,
            "runtime": "triton-24.08",
            "license_id": "Apache-2.0",
            "source_repository": "https://github.com/example/face-endpoint-model",
            "source_commit": "7" * 40,
            "metrics": {"tar_at_far_1e-5": 0.92},
        },
    )
    assert artifact.status_code == 201
    approved = client.post(
        f"/api/v1/algorithms/artifacts/{artifact.json()['id']}/approval",
        headers=admin_headers,
        json={"approved": True, "reason": "端点生产准入回归测试"},
    )
    assert approved.status_code == 200
    approved_model = client.post(
        "/api/v1/faces/edge-identify",
        headers=edge_headers,
        data={"camera_id": "1"},
        files=files,
    )
    assert approved_model.status_code == 200

    deactivated = client.patch(
        f"/api/v1/edge-nodes/{registered.json()['node']['id']}",
        headers=admin_headers,
        json={"active": False},
    )
    assert deactivated.status_code == 200
    calls_before_inactive = provider.calls
    inactive = client.post(
        "/api/v1/faces/edge-identify",
        headers=edge_headers,
        data={"camera_id": "1"},
        files=files,
    )
    assert inactive.status_code == 401
    assert provider.calls == calls_before_inactive


def test_scheduler_protects_any_critical_workload_and_uses_supported_batches(client):
    headers = auth_headers(client)
    critical = client.post(
        "/api/v1/algorithms/scheduler/decision",
        headers=headers,
        json={
            "gpu_utilization": 0.99,
            "queue_depth": 1000,
            "active_streams": 32,
            "critical_zone_ratio": 0.01,
            "telemetry_age_seconds": 0,
            "healthy_gpu_ratio": 1,
        },
    )
    assert critical.status_code == 200
    assert critical.json()["frame_stride"] <= 2
    assert critical.json()["detector_resolution"] >= 768
    assert critical.json()["face_batch_size"] in {4, 8, 16}

    balanced = client.post(
        "/api/v1/algorithms/scheduler/decision",
        headers=headers,
        json={
            "gpu_utilization": 0.8,
            "queue_depth": 10,
            "active_streams": 16,
            "critical_zone_ratio": 0,
            "telemetry_age_seconds": 0,
            "healthy_gpu_ratio": 1,
        },
    )
    assert balanced.status_code == 200
    assert balanced.json()["face_batch_size"] == 8


def test_camera_code_is_unique_without_case_sensitivity(client):
    headers = auth_headers(client)
    first = client.post(
        "/api/v1/cameras",
        headers=headers,
        json={
            "code": "CASE-CAMERA-01",
            "name": "Case-sensitive collision test",
            "area": "主井口",
            "stream_url": "rtsp://source/case-camera-01",
        },
    )
    assert first.status_code == 201
    collision = client.post(
        "/api/v1/cameras",
        headers=headers,
        json={
            "code": "case-camera-01",
            "name": "Case-insensitive collision test",
            "area": "主井口",
            "stream_url": "rtsp://source/case-camera-02",
        },
    )
    assert collision.status_code == 409


def test_business_identifiers_are_unique_without_case_sensitivity(client):
    headers = auth_headers(client)
    user = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "CaseFoldUser",
            "full_name": "Case fold user",
            "password": "CaseFoldPass123",
            "role": "operator",
            "permitted_areas": ["主井口"],
        },
    )
    assert user.status_code == 201
    duplicate_user = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "casefolduser",
            "full_name": "Duplicate user",
            "password": "CaseFoldPass456",
            "role": "operator",
            "permitted_areas": ["主井口"],
        },
    )
    assert duplicate_user.status_code == 409

    person = client.post(
        "/api/v1/persons",
        headers=headers,
        json={
            "employee_no": "CaseFold-Employee-01",
            "name": "Case fold employee",
            "department": "Safety",
            "authorized_areas": ["主井口"],
        },
    )
    assert person.status_code == 201
    duplicate_person = client.post(
        "/api/v1/persons",
        headers=headers,
        json={
            "employee_no": "casefold-employee-01",
            "name": "Duplicate employee",
            "department": "Safety",
            "authorized_areas": ["主井口"],
        },
    )
    assert duplicate_person.status_code == 409

    node = client.post(
        "/api/v1/edge-nodes",
        headers=headers,
        json={"code": "CaseFold-Edge-01", "name": "Case fold edge", "camera_ids": [1]},
    )
    assert node.status_code == 201
    duplicate_node = client.post(
        "/api/v1/edge-nodes",
        headers=headers,
        json={"code": "casefold-edge-01", "name": "Duplicate edge", "camera_ids": [1]},
    )
    assert duplicate_node.status_code == 409
    disabled = client.patch(
        f"/api/v1/edge-nodes/{node.json()['node']['id']}",
        headers=headers,
        json={"active": False},
    )
    assert disabled.status_code == 200


def test_camera_update_changes_configuration_without_exposing_stream_url(client):
    headers = auth_headers(client)
    created = client.post(
        "/api/v1/cameras",
        headers=headers,
        json={
            "code": "EDIT-CAMERA-01",
            "name": "Camera before edit",
            "area": "主井口",
            "stream_url": "rtsps://camera-gateway/edit-camera-01?token=initial-secret",
            "enabled_algorithms": ["intrusion"],
        },
    )
    assert created.status_code == 201
    camera_id = created.json()["id"]
    concurrency_token = created.json()["concurrency_token"]
    forged_runtime_status = client.patch(
        f"/api/v1/cameras/{camera_id}",
        headers={**headers, "If-Match": f'"{concurrency_token}"'},
        json={"status": "online"},
    )
    assert forged_runtime_status.status_code == 422
    replacement_url = "rtsps://camera-gateway/edit-camera-02?token=replacement-secret"
    stale = client.patch(
        f"/api/v1/cameras/{camera_id}",
        headers={**headers, "If-Match": '"stale-version"'},
        json={"name": "Stale overwrite"},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"] == "资源已被其他操作更新，请刷新后重新提交"
    updated = client.patch(
        f"/api/v1/cameras/{camera_id}",
        headers={**headers, "If-Match": f'"{concurrency_token}"'},
        json={
            "name": "Camera after edit",
            "area": "副井口",
            "stream_url": replacement_url,
            "enabled_algorithms": ["no_helmet", "crowding"],
        },
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Camera after edit"
    assert updated.json()["area"] == "副井口"
    assert updated.json()["enabled_algorithms"] == ["no_helmet", "crowding"]
    assert updated.json()["concurrency_token"] != concurrency_token
    assert "stream_url" not in updated.json()
    assert replacement_url not in updated.text

    audit = client.get(
        "/api/v1/audit-logs?action=camera.update&page_size=100",
        headers=headers,
    )
    assert audit.status_code == 200
    matching = [
        item for item in audit.json()["items"]
        if item["resource_id"] == str(camera_id)
    ]
    assert matching
    assert matching[0]["detail"]["stream_url_changed"] is True
    assert replacement_url not in audit.text


def test_area_scoped_account_cannot_cross_production_boundaries(client):
    admin_headers = auth_headers(client)
    created = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "area-scope-operator",
            "full_name": "区域权限值班员",
            "password": "AreaScopePass123",
            "role": "operator",
            "permitted_areas": ["主井口"],
        },
    )
    assert created.status_code == 201
    assert created.json()["permitted_areas"] == ["主井口"]
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "area-scope-operator", "password": "AreaScopePass123"},
    )
    scoped_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    cameras = client.get("/api/v1/cameras?page_size=100", headers=scoped_headers).json()
    assert cameras["total"] == len(cameras["items"])
    assert {camera["area"] for camera in cameras["items"]} == {"主井口"}
    assert media_authorization(client, cameras["items"][0]["playback_path"]).status_code == 204
    events = client.get("/api/v1/events?page_size=100", headers=scoped_headers).json()
    assert all(event["camera"]["area"] == "主井口" for event in events["items"])
    persons = client.get("/api/v1/persons?page_size=100", headers=scoped_headers).json()
    assert all(
        set(person["authorized_areas"]).issubset({"主井口"})
        for person in persons["items"]
    )
    dashboard = client.get("/api/v1/dashboard/summary", headers=scoped_headers).json()
    assert dashboard["cameras_total"] == cameras["total"]
    assert set(dashboard["area_occupancy"]).issubset({"主井口"})

    all_cameras = client.get("/api/v1/cameras?page_size=100", headers=admin_headers).json()["items"]
    denied_camera = next(camera for camera in all_cameras if camera["area"] != "主井口")
    assert media_authorization(client, denied_camera["playback_path"]).status_code == 403
    denied = client.patch(
        f"/api/v1/cameras/{denied_camera['id']}",
        headers=scoped_headers,
        json={"name": "越权修改"},
    )
    assert denied.status_code == 403
    denied_person = client.post(
        "/api/v1/persons",
        headers=scoped_headers,
        json={
            "employee_no": "AREA-DENIED-01",
            "name": "越权人员",
            "department": "测试部门",
            "authorized_areas": ["运输巷道"],
        },
    )
    assert denied_person.status_code == 403

    changed = client.patch(
        f"/api/v1/users/{created.json()['id']}",
        headers=admin_headers,
        json={"permitted_areas": ["运输巷道"]},
    )
    assert changed.status_code == 200
    assert client.get("/api/v1/cameras", headers=scoped_headers).status_code == 401
    assert media_authorization(client, cameras["items"][0]["playback_path"]).status_code == 401
    relogin = client.post(
        "/api/v1/auth/login",
        json={"username": "area-scope-operator", "password": "AreaScopePass123"},
    )
    moved_headers = {"Authorization": f"Bearer {relogin.json()['access_token']}"}
    moved = client.get("/api/v1/cameras?page_size=100", headers=moved_headers).json()
    assert {camera["area"] for camera in moved["items"]} == {"运输巷道"}
    assert media_authorization(client, moved["items"][0]["playback_path"]).status_code == 204


def test_non_admin_cannot_be_changed_to_an_unrestricted_null_scope(client):
    admin_headers = auth_headers(client)
    created = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "null-scope-operator",
            "full_name": "空范围测试账号",
            "password": "NullScopePass123",
            "role": "operator",
            "permitted_areas": ["主井口"],
        },
    )
    assert created.status_code == 201
    rejected = client.patch(
        f"/api/v1/users/{created.json()['id']}",
        headers=admin_headers,
        json={"permitted_areas": None},
    )
    assert rejected.status_code == 422
    unchanged = client.get("/api/v1/users", headers=admin_headers).json()
    account = next(item for item in unchanged if item["id"] == created.json()["id"])
    assert account["permitted_areas"] == ["主井口"]


def test_event_workflow(client):
    headers = auth_headers(client)
    created = client.post("/api/v1/events", headers=headers, json={"event_type": "intrusion", "severity": "high", "camera_id": 1, "title": "测试入侵事件", "confidence": 0.93})
    assert created.status_code == 201
    event_id = created.json()["id"]
    updated = client.patch(f"/api/v1/events/{event_id}/status", headers=headers, json={"status": "resolved", "note": "现场已确认"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "resolved"
    repeated = client.patch(
        f"/api/v1/events/{event_id}/status",
        headers=headers,
        json={"status": "resolved", "note": "重复请求"},
    )
    assert repeated.status_code == 200
    reopened = client.patch(
        f"/api/v1/events/{event_id}/status",
        headers=headers,
        json={"status": "acknowledged", "note": "不得重新打开"},
    )
    assert reopened.status_code == 409
    with SessionLocal() as db:
        actions = db.scalars(
            select(RealtimeSignal.action).where(
                RealtimeSignal.topic == "events",
                RealtimeSignal.resource_id == str(event_id),
            ).order_by(RealtimeSignal.id)
        ).all()
    assert actions == ["created", "status_changed"]


def test_admin_can_apply_and_release_an_audited_event_legal_hold(client):
    headers = auth_headers(client)
    created = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "event_type": "intrusion",
            "severity": "critical",
            "camera_id": 1,
            "title": "Legal hold event",
            "confidence": 0.99,
        },
    )
    assert created.status_code == 201
    event_id = created.json()["id"]

    held = client.patch(
        f"/api/v1/events/{event_id}/legal-hold",
        headers=headers,
        json={"enabled": True, "reason": "Incident investigation CASE-2026-01"},
    )
    assert held.status_code == 200
    assert held.json()["legal_hold"] is True
    released = client.patch(
        f"/api/v1/events/{event_id}/legal-hold",
        headers=headers,
        json={"enabled": False, "reason": "CASE-2026-01 retention released"},
    )
    assert released.status_code == 200
    assert released.json()["legal_hold"] is False

    audit = client.get(
        "/api/v1/audit-logs?action=event.legal_hold&page_size=100",
        headers=headers,
    )
    assert audit.status_code == 200
    matching = [
        item for item in audit.json()["items"] if item["resource_id"] == str(event_id)
    ]
    assert [item["detail"]["enabled"] for item in matching[:2]] == [False, True]


def test_person_profile_update_and_soft_deactivation(client):
    headers = auth_headers(client)
    created = client.post(
        "/api/v1/persons",
        headers=headers,
        json={
            "employee_no": "M-DEACTIVATE-01",
            "name": "停用测试人员",
            "department": "机电队",
            "authorized_areas": ["主井口"],
        },
    )
    assert created.status_code == 201
    updated = client.patch(
        f"/api/v1/persons/{created.json()['id']}",
        headers=headers,
        json={"department": "运输队", "authorized_areas": ["运输巷道"], "active": False},
    )
    assert updated.status_code == 200
    assert updated.json()["department"] == "运输队"
    assert updated.json()["authorized_areas"] == ["运输巷道"]
    assert updated.json()["active"] is False
    assert updated.json()["face_enrolled"] is False


def test_event_ingest_is_idempotent(client):
    headers = {**auth_headers(client), "Idempotency-Key": "cam-1:track-99:intrusion:123"}
    payload = {"event_type": "intrusion", "severity": "high", "camera_id": 1, "title": "幂等入侵事件", "confidence": 0.93}
    first = client.post("/api/v1/events", headers=headers, json=payload)
    second = client.post("/api/v1/events", headers=headers, json=payload)
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]


def test_event_idempotency_rejects_payload_drift(client):
    headers = {
        **auth_headers(client),
        "Idempotency-Key": "event-payload-drift-key",
    }
    payload = {
        "event_type": "intrusion",
        "severity": "high",
        "camera_id": 1,
        "title": "Original idempotent event",
        "confidence": 0.93,
        "metadata_json": {"track_id": 42},
    }
    assert client.post("/api/v1/events", headers=headers, json=payload).status_code == 201

    collision = client.post(
        "/api/v1/events",
        headers=headers,
        json={**payload, "severity": "critical", "title": "Changed event"},
    )
    assert collision.status_code == 409
    assert collision.json()["detail"] == "幂等键载荷与原始事件不一致"


def test_event_idempotency_key_cannot_cross_camera_or_area(client):
    admin_headers = {
        **auth_headers(client),
        "Idempotency-Key": "cross-area-idempotency-key",
    }
    original = client.post(
        "/api/v1/events",
        headers=admin_headers,
        json={
            "event_type": "intrusion",
            "severity": "high",
            "camera_id": 3,
            "title": "高危区域原始事件",
            "confidence": 0.9,
        },
    )
    assert original.status_code == 201
    created = client.post(
        "/api/v1/users",
        headers=auth_headers(client),
        json={
            "username": "idempotency-scope-user",
            "full_name": "幂等隔离测试账号",
            "password": "IdempotencyScope123",
            "role": "operator",
            "permitted_areas": ["主井口"],
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "idempotency-scope-user",
            "password": "IdempotencyScope123",
        },
    )
    scoped_headers = {
        "Authorization": f"Bearer {login.json()['access_token']}",
        "Idempotency-Key": "cross-area-idempotency-key",
    }
    collision = client.post(
        "/api/v1/events",
        headers=scoped_headers,
        json={
            "event_type": "intrusion",
            "severity": "high",
            "camera_id": 1,
            "title": "不得返回其他区域事件",
            "confidence": 0.9,
        },
    )
    assert collision.status_code == 409
    assert str(original.json()["id"]) not in collision.text


def test_event_ingest_rejects_missing_person_reference(client):
    response = client.post(
        "/api/v1/events",
        headers=auth_headers(client),
        json={
            "event_type": "face_match",
            "severity": "medium",
            "camera_id": 1,
            "person_id": 999999,
            "title": "无效人员引用",
            "confidence": 0.9,
        },
    )
    assert response.status_code == 404


def test_event_ingest_rejects_oversized_metadata(client):
    headers = {**auth_headers(client), "Idempotency-Key": "oversized-event-metadata"}
    response = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "event_type": "intrusion",
            "severity": "high",
            "camera_id": 1,
            "title": "超大元数据事件",
            "confidence": 0.9,
            "metadata_json": {"payload": "x" * (33 * 1024)},
        },
    )
    assert response.status_code == 422


def test_scheduler_safety_constraint(client):
    headers = auth_headers(client)
    response = client.post("/api/v1/algorithms/scheduler/decision", headers=headers, json={"gpu_utilization": 0.99, "queue_depth": 200, "active_streams": 40, "critical_zone_ratio": 0.8})
    assert response.status_code == 200
    assert response.json()["frame_stride"] <= 2


def test_scheduler_rejects_invalid_state_and_falls_back_on_stale_telemetry(client):
    headers = auth_headers(client)
    invalid = client.post(
        "/api/v1/algorithms/scheduler/decision",
        headers=headers,
        json={
            "gpu_utilization": -0.1,
            "queue_depth": -1,
            "active_streams": 0,
            "critical_zone_ratio": 1.2,
        },
    )
    assert invalid.status_code == 422
    fallback = client.post(
        "/api/v1/algorithms/scheduler/decision",
        headers=headers,
        json={
            "gpu_utilization": 0.4,
            "queue_depth": 2,
            "active_streams": 12,
            "critical_zone_ratio": 0.2,
            "telemetry_age_seconds": 31,
            "healthy_gpu_ratio": 1,
        },
    )
    assert fallback.status_code == 200
    assert fallback.json()["reason"] == "stale-telemetry safety fallback"
    assert fallback.json()["frame_stride"] == 1


def test_model_artifact_registration_and_approval(client):
    headers = auth_headers(client)
    payload = {
        "name": "矿井人员安全帽检测",
        "algorithm_type": "object_detection",
        "model_version": "mine-detector-1.0.0",
        "sha256": "a" * 64,
        "runtime": "tensorrt-10",
        "license_id": "Apache-2.0",
        "source_repository": "https://github.com/example/mine-detector",
        "source_commit": "b" * 40,
        "metrics": {"person_recall": 0.96, "helmet_recall": 0.94},
    }
    created = client.post("/api/v1/algorithms/artifacts", headers=headers, json=payload)
    assert created.status_code == 201
    assert created.json()["approved"] is False
    duplicate = client.post("/api/v1/algorithms/artifacts", headers=headers, json=payload)
    assert duplicate.status_code == 409
    approved = client.post(
        f"/api/v1/algorithms/artifacts/{created.json()['id']}/approval",
        headers=headers,
        json={"approved": True, "reason": "离线验收集与许可证审查通过"},
    )
    assert approved.status_code == 200
    assert approved.json()["approved"] is True
    revoked = client.post(
        f"/api/v1/algorithms/artifacts/{created.json()['id']}/approval",
        headers=headers,
        json={"approved": False, "reason": "回归测试撤销生产准入"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["approved"] is False
    assert revoked.json()["approved_by"] is None


def test_model_artifact_four_eyes_approval(client, monkeypatch):
    monkeypatch.setattr(
        "app.api.algorithms.get_settings",
        lambda: SimpleNamespace(require_four_eyes_model_approval=True),
    )
    creator_headers = auth_headers(client)
    payload = {
        "name": "井下人群密度检测",
        "algorithm_type": "crowd_detection",
        "model_version": "crowd-2.0.0",
        "sha256": "c" * 64,
        "runtime": "triton-24.08",
        "license_id": "Apache-2.0",
        "source_repository": "https://github.com/example/crowd-detector",
        "source_commit": "d" * 40,
        "metrics": {"mae": 2.4},
    }
    created = client.post(
        "/api/v1/algorithms/artifacts", headers=creator_headers, json=payload
    )
    assert created.status_code == 201
    artifact_id = created.json()["id"]
    self_approval = client.post(
        f"/api/v1/algorithms/artifacts/{artifact_id}/approval",
        headers=creator_headers,
        json={"approved": True, "reason": "创建者尝试自审"},
    )
    assert self_approval.status_code == 409

    second_admin = client.post(
        "/api/v1/users",
        headers=creator_headers,
        json={
            "username": "model-approver",
            "full_name": "模型审批管理员",
            "password": "ModelApprover123",
            "role": "admin",
        },
    )
    assert second_admin.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "model-approver", "password": "ModelApprover123"},
    )
    approver_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    approved = client.post(
        f"/api/v1/algorithms/artifacts/{artifact_id}/approval",
        headers=approver_headers,
        json={"approved": True, "reason": "独立复核评估集、许可证和摘要通过"},
    )
    assert approved.status_code == 200
    assert approved.json()["approved_by"] == second_admin.json()["id"]
    repeated = client.post(
        f"/api/v1/algorithms/artifacts/{artifact_id}/approval",
        headers=approver_headers,
        json={"approved": True, "reason": "网络恢复后的同状态重试"},
    )
    assert repeated.status_code == 200
    assert repeated.json()["approved_at"] == approved.json()["approved_at"]
    audit = client.get(
        "/api/v1/audit-logs?action=model_artifact.approval&page_size=100",
        headers=creator_headers,
    )
    matching = [
        item for item in audit.json()["items"]
        if item["resource_id"] == str(artifact_id)
    ]
    assert len(matching) == 1


def test_unapproved_edge_model_degrades_node_and_blocks_events(client, monkeypatch):
    monkeypatch.setattr(
        "app.api.edge.get_settings",
        lambda: SimpleNamespace(enforce_approved_edge_models=True),
    )
    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={"code": "edge-unapproved-model", "name": "未准入模型节点", "camera_ids": [2]},
    )
    assert registered.status_code == 201
    edge_headers = {
        "X-Edge-Node": "edge-unapproved-model",
        "X-Edge-Key": registered.json()["api_key"],
    }
    heartbeat_payload = {
        "software_version": "edge-worker-0.2.0",
        "gpu_utilization": 0.2,
        "gpu_memory_utilization": 0.3,
        "queue_depth": 0,
        "models": [
            {
                "algorithm_type": "object_detection",
                "model_version": "unknown-9.9.9",
                "sha256": "e" * 64,
                "runtime": "tensorrt-10",
                "ready": True,
            }
        ],
        "cameras": [{"camera_id": 2, "status": "online", "fps": 20, "latency_ms": 90}],
    }
    heartbeat = client.post(
        "/api/v1/edge/heartbeat",
        headers=edge_headers,
        json=heartbeat_payload,
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "degraded"
    assert len(heartbeat.json()["telemetry"]["unapproved_models"]) == 1
    assert heartbeat.json()["telemetry"]["cameras"][0]["errors"] == []
    cameras = client.get("/api/v1/cameras?page_size=100", headers=admin_headers).json()["items"]
    assert next(camera for camera in cameras if camera["id"] == 2)["status"] == "degraded"
    event = client.post(
        "/api/v1/edge/events",
        headers={**edge_headers, "Idempotency-Key": "edge-unapproved-model:event-1"},
        json={
            "event_type": "intrusion",
            "severity": "high",
            "camera_id": 2,
            "title": "未准入模型事件",
            "confidence": 0.91,
        },
    )
    assert event.status_code == 409

    artifact = client.post(
        "/api/v1/algorithms/artifacts",
        headers=admin_headers,
        json={
            "name": "恢复测试模型",
            "algorithm_type": "object_detection",
            "model_version": "unknown-9.9.9",
            "sha256": "e" * 64,
            "runtime": "tensorrt-10",
            "license_id": "Apache-2.0",
            "source_repository": "https://github.com/example/recovery-model",
            "source_commit": "f" * 40,
            "metrics": {"recall": 0.95},
        },
    )
    assert artifact.status_code == 201
    approval = client.post(
        f"/api/v1/algorithms/artifacts/{artifact.json()['id']}/approval",
        headers=admin_headers,
        json={"approved": True, "reason": "恢复路径测试审批"},
    )
    assert approval.status_code == 200
    recovered = client.post(
        "/api/v1/edge/heartbeat", headers=edge_headers, json=heartbeat_payload
    )
    assert recovered.status_code == 200
    assert recovered.json()["status"] == "online"
    unapproved_face_event = client.post(
        "/api/v1/edge/events",
        headers={
            **edge_headers,
            "Idempotency-Key": "edge-unapproved-model:face-1",
        },
        json={
            "event_type": "unknown_face",
            "severity": "high",
            "camera_id": 2,
            "title": "未准入人脸模型事件",
            "confidence": 0.9,
            "metadata_json": {
                "face_model_version": "face-v1",
                "face_model_sha256": "9" * 64,
            },
        },
    )
    assert unapproved_face_event.status_code == 409
    face_artifact = client.post(
        "/api/v1/algorithms/artifacts",
        headers=admin_headers,
        json={
            "name": "实时人脸识别模型",
            "algorithm_type": "face_recognition",
            "model_version": "face-v1",
            "sha256": "9" * 64,
            "runtime": "triton-24.08",
            "license_id": "Apache-2.0",
            "source_repository": "https://github.com/example/face-model",
            "source_commit": "8" * 40,
            "metrics": {"tar_at_far_1e-5": 0.91},
        },
    )
    assert face_artifact.status_code == 201
    face_approval = client.post(
        f"/api/v1/algorithms/artifacts/{face_artifact.json()['id']}/approval",
        headers=admin_headers,
        json={"approved": True, "reason": "人脸离线评估与许可证复核通过"},
    )
    assert face_approval.status_code == 200
    accepted_face_event = client.post(
        "/api/v1/edge/events",
        headers={
            **edge_headers,
            "Idempotency-Key": "edge-unapproved-model:face-2",
        },
        json={
            "event_type": "unknown_face",
            "severity": "high",
            "camera_id": 2,
            "title": "准入人脸模型事件",
            "confidence": 0.9,
            "metadata_json": {
                "face_model_version": "face-v1",
                "face_model_sha256": "9" * 64,
            },
        },
    )
    assert accepted_face_event.status_code == 201
    revoked_face = client.post(
        f"/api/v1/algorithms/artifacts/{face_artifact.json()['id']}/approval",
        headers=admin_headers,
        json={"approved": False, "reason": "验证离线队列补报时重新检查准入"},
    )
    assert revoked_face.status_code == 200
    delayed_after_revocation = client.post(
        "/api/v1/edge/events",
        headers={
            **edge_headers,
            "Idempotency-Key": "edge-unapproved-model:face-3",
        },
        json={
            "event_type": "unknown_face",
            "severity": "high",
            "camera_id": 2,
            "title": "撤销后补报的人脸模型事件",
            "confidence": 0.9,
            "metadata_json": {
                "face_model_version": "face-v1",
                "face_model_sha256": "9" * 64,
            },
        },
    )
    assert delayed_after_revocation.status_code == 409
    accepted = client.post(
        "/api/v1/edge/events",
        headers={**edge_headers, "Idempotency-Key": "edge-unapproved-model:event-2"},
        json={
            "event_type": "intrusion",
            "severity": "high",
            "camera_id": 2,
            "title": "准入恢复后的模型事件",
            "confidence": 0.92,
        },
    )
    assert accepted.status_code == 201
    gpu_failed_payload = {**heartbeat_payload, "gpu_healthy": False}
    degraded = client.post(
        "/api/v1/edge/heartbeat", headers=edge_headers, json=gpu_failed_payload
    )
    assert degraded.status_code == 200
    assert degraded.json()["status"] == "degraded"
    queued_before_failure = client.post(
        "/api/v1/edge/events",
        headers={**edge_headers, "Idempotency-Key": "edge-unapproved-model:event-3"},
        json={
            "event_type": "intrusion",
            "severity": "high",
            "camera_id": 2,
            "title": "GPU 故障前已持久化事件",
            "confidence": 0.91,
        },
    )
    assert queued_before_failure.status_code == 201
    assert client.post(
        "/api/v1/edge/heartbeat", headers=edge_headers, json=heartbeat_payload
    ).json()["status"] == "online"


def test_unhealthy_gpu_degrades_node_and_emits_operational_alert(client):
    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={"code": "edge-gpu-failed", "name": "GPU failed node", "camera_ids": [2]},
    )
    assert registered.status_code == 201
    heartbeat = client.post(
        "/api/v1/edge/heartbeat",
        headers={
            "X-Edge-Node": "edge-gpu-failed",
            "X-Edge-Key": registered.json()["api_key"],
        },
        json={
            "software_version": "edge-worker-gpu-test",
            "gpu_healthy": False,
            "gpu_utilization": 0,
            "gpu_memory_utilization": 0,
            "queue_depth": 0,
            "dead_letter_depth": 2,
            "cameras": [
                {
                    "camera_id": 2,
                    "status": "degraded",
                    "fps": 20,
                    "latency_ms": 70,
                    "errors": ["face_recognition_unavailable"],
                }
            ],
        },
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "degraded"
    assert heartbeat.json()["telemetry"]["gpu_healthy"] is False
    dashboard = client.get("/api/v1/dashboard/summary", headers=admin_headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["system_health"]["edge_gpu_unhealthy_nodes"] >= 1
    assert dashboard.json()["system_health"]["edge_dead_letter_depth"] >= 2
    assert dashboard.json()["system_health"]["edge_camera_reports_degraded"] >= 1
    assert dashboard.json()["system_health"]["edge_camera_error_codes"] >= 1
    assert any(
        alert["code"] == "edge_gpu_unhealthy"
        for alert in dashboard.json()["operational_alerts"]
    )
    assert any(
        alert["code"] == "edge_events_quarantined"
        for alert in dashboard.json()["operational_alerts"]
    )
    assert any(
        alert["code"] == "edge_camera_degraded"
        for alert in dashboard.json()["operational_alerts"]
    )
    metrics = client.get("/internal/metrics")
    assert "mineguard_edge_dead_letter_depth 2" in metrics.text
    assert "mineguard_edge_camera_reports_degraded 1" in metrics.text
    assert "mineguard_edge_camera_error_codes 1" in metrics.text
    disabled = client.patch(
        f"/api/v1/edge-nodes/{registered.json()['node']['id']}",
        headers=admin_headers,
        json={"active": False},
    )
    assert disabled.status_code == 200


def test_edge_outbox_saturation_degrades_and_recovers_node(
    client, monkeypatch
):
    monkeypatch.setattr(
        "app.api.edge.get_settings",
        lambda: SimpleNamespace(enforce_approved_edge_models=False),
    )
    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={
            "code": "edge-outbox-saturated",
            "name": "Outbox saturation node",
            "camera_ids": [1],
        },
    )
    assert registered.status_code == 201
    edge_headers = {
        "X-Edge-Node": "edge-outbox-saturated",
        "X-Edge-Key": registered.json()["api_key"],
    }
    heartbeat = {
        "software_version": "edge-worker-outbox-test",
        "gpu_healthy": True,
        "gpu_utilization": 0.2,
        "gpu_memory_utilization": 0.2,
        "queue_depth": 9,
        "dead_letter_depth": 1,
        "outbox_capacity": 10,
        "cameras": [],
    }
    saturated = client.post(
        "/api/v1/edge/heartbeat", headers=edge_headers, json=heartbeat
    )
    assert saturated.status_code == 200
    assert saturated.json()["status"] == "degraded"
    dashboard = client.get(
        "/api/v1/dashboard/summary", headers=admin_headers
    ).json()
    assert dashboard["system_health"]["edge_outbox_max_utilization"] >= 1
    assert any(
        alert["code"] == "edge_outbox_capacity"
        and alert["severity"] == "critical"
        for alert in dashboard["operational_alerts"]
    )
    assert "mineguard_edge_outbox_max_utilization_ratio 1" in client.get(
        "/internal/metrics"
    ).text

    recovered = client.post(
        "/api/v1/edge/heartbeat",
        headers=edge_headers,
        json={**heartbeat, "queue_depth": 0, "dead_letter_depth": 0},
    )
    assert recovered.status_code == 200
    assert recovered.json()["status"] == "online"
    disabled = client.patch(
        f"/api/v1/edge-nodes/{registered.json()['node']['id']}",
        headers=admin_headers,
        json={"active": False},
    )
    assert disabled.status_code == 200


def test_admin_rule_and_audit_workflow(client):
    headers = auth_headers(client)
    rules = client.get("/api/v1/alert-rules", headers=headers)
    assert rules.status_code == 200
    assert len(rules.json()) == 3
    created = client.post("/api/v1/users", headers=headers, json={"username": "operator01", "full_name": "测试值班员", "password": "StrongPass123", "role": "operator"})
    assert created.status_code == 201
    assert "password" not in created.json()
    user_id = created.json()["id"]
    reset = client.post(
        f"/api/v1/users/{user_id}/reset-password",
        headers=headers,
        json={"new_password": "AnotherStrong456"},
    )
    assert reset.status_code == 204
    audit = client.get("/api/v1/audit-logs", headers=headers)
    assert audit.status_code == 200
    assert audit.json()["total"] > 0


def test_edge_snapshot_upload_grant_is_limited_to_bound_cameras(
    client, monkeypatch
):
    class Storage:
        calls = []
        verified = []

        def create_upload_grant(self, **values):
            self.calls.append(values)
            return {
                "reference": (
                    f"/snapshots/camera-{values['camera_id']}/2026/08/22/"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg"
                ),
                "upload_url": "https://objects.test/upload",
                "required_headers": {"Content-Type": "image/jpeg"},
                "expires_in_seconds": 120,
            }

        def verify_upload(self, **values):
            self.verified.append(values)

    storage = Storage()
    monkeypatch.setattr(
        "app.api.edge.get_snapshot_storage", lambda: storage
    )
    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={
            "code": "edge-snapshot-scope",
            "name": "Snapshot scope node",
            "camera_ids": [1],
        },
    )
    edge_headers = {
        "X-Edge-Node": "edge-snapshot-scope",
        "X-Edge-Key": registered.json()["api_key"],
    }
    payload = {
        "camera_id": 1,
        "content_type": "image/jpeg",
        "content_length": 2048,
        "sha256": "a" * 64,
    }
    accepted = client.post(
        "/api/v1/edge/snapshots/upload", headers=edge_headers, json=payload
    )
    assert accepted.status_code == 201
    assert accepted.json()["reference"].startswith("/snapshots/camera-1/")
    verified = client.post(
        "/api/v1/edge/snapshots/verify",
        headers=edge_headers,
        json={
            **payload,
            "reference": accepted.json()["reference"],
        },
    )
    assert verified.status_code == 204
    assert storage.verified[0]["reference"] == accepted.json()["reference"]
    rejected = client.post(
        "/api/v1/edge/snapshots/upload",
        headers=edge_headers,
        json={**payload, "camera_id": 2},
    )
    assert rejected.status_code == 403
    assert [call["camera_id"] for call in storage.calls] == [1]


def test_event_ingest_rejects_snapshot_from_another_camera(client):
    response = client.post(
        "/api/v1/events",
        headers=auth_headers(client),
        json={
            "event_type": "intrusion",
            "severity": "high",
            "camera_id": 1,
            "title": "Snapshot camera mismatch",
            "confidence": 0.91,
            "snapshot_url": (
                "/snapshots/camera-2/2026/08/22/"
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.jpg"
            ),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "快照引用与摄像头不匹配"


def test_snapshot_access_enforces_event_area_scope(client, monkeypatch):
    class Storage:
        def create_access_grant(self, reference):
            return {
                "download_url": "https://objects.test/authorized-snapshot",
                "expires_in_seconds": 120,
            }

    monkeypatch.setattr(
        "app.api.events.get_snapshot_storage", lambda: Storage()
    )
    admin_headers = auth_headers(client)
    event = client.post(
        "/api/v1/events",
        headers=admin_headers,
        json={
            "event_type": "intrusion",
            "severity": "critical",
            "camera_id": 3,
            "title": "Restricted snapshot",
            "confidence": 0.98,
            "snapshot_url": (
                "/snapshots/camera-3/2026/08/22/"
                "cccccccccccccccccccccccccccccccc.jpg"
            ),
        },
    )
    assert event.status_code == 201
    account = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "snapshot-area-operator",
            "full_name": "Snapshot area operator",
            "password": "SnapshotArea123",
            "role": "operator",
            "permitted_areas": ["主井口"],
        },
    )
    assert account.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "snapshot-area-operator",
            "password": "SnapshotArea123",
        },
    )
    scoped_headers = {
        "Authorization": f"Bearer {login.json()['access_token']}"
    }
    forbidden = client.get(
        f"/api/v1/events/{event.json()['id']}/snapshot-access",
        headers=scoped_headers,
    )
    assert forbidden.status_code == 403
    allowed = client.get(
        f"/api/v1/events/{event.json()['id']}/snapshot-access",
        headers=admin_headers,
    )
    assert allowed.status_code == 200
    assert allowed.json()["download_url"].endswith("authorized-snapshot")


def test_event_legal_hold_storage_failure_is_fail_protective_and_retryable(
    client, monkeypatch
):
    from app.models import SnapshotLegalHoldJob
    from app.services.snapshot_legal_holds import SnapshotLegalHoldReconciler
    from app.services.snapshots import SnapshotStorageError

    class FlakyStorage:
        def __init__(self):
            self.calls = []
            self.fail_next = True

        def set_legal_hold(self, reference, enabled):
            self.calls.append(enabled)
            if self.fail_next:
                self.fail_next = False
                raise SnapshotStorageError("provider unavailable")

    storage = FlakyStorage()
    monkeypatch.setattr(
        "app.api.events.get_snapshot_storage", lambda: storage
    )
    headers = auth_headers(client)
    created = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "event_type": "intrusion",
            "severity": "critical",
            "camera_id": 1,
            "title": "Legal hold storage recovery",
            "confidence": 0.99,
            "snapshot_url": (
                "/snapshots/camera-1/2026/08/22/"
                "dddddddddddddddddddddddddddddddd.jpg"
            ),
        },
    )
    event_id = created.json()["id"]
    enable_payload = {
        "enabled": True,
        "reason": "Incident recovery contract CASE-2026-02",
    }
    failed_enable = client.patch(
        f"/api/v1/events/{event_id}/legal-hold",
        headers=headers,
        json=enable_payload,
    )
    assert failed_enable.status_code == 503
    current = client.get(
        "/api/v1/events?page_size=100", headers=headers
    ).json()["items"]
    assert next(item for item in current if item["id"] == event_id)["legal_hold"] is False
    recovering_summary = client.get(
        "/api/v1/dashboard/summary", headers=headers
    ).json()
    assert recovering_summary["system_health"]["snapshot_legal_hold_pending"] == 1
    assert "snapshot_legal_hold_recovering" in {
        alert["code"] for alert in recovering_summary["operational_alerts"]
    }
    requested_audit = client.get(
        "/api/v1/audit-logs?action=event.legal_hold_requested&page_size=100",
        headers=headers,
    ).json()["items"]
    assert any(item["resource_id"] == str(event_id) for item in requested_audit)
    with SessionLocal() as db:
        job = db.get(SnapshotLegalHoldJob, event_id)
        assert job.desired_enabled is True
        assert job.last_error == "snapshot_storage_unavailable"
        stale_reconciler = SnapshotLegalHoldReconciler(storage)
        assert stale_reconciler.reconcile_one(
            db, event_id, expected_enabled=False
        ) == "superseded"
        job = db.get(SnapshotLegalHoldJob, event_id)
        assert job is not None
        assert job.desired_enabled is True
        job.next_attempt_at = job.created_at
        db.commit()
        reconciler = SnapshotLegalHoldReconciler(storage)
        assert reconciler.dispatch_due(db) == 1
        assert reconciler.pending == 0
        assert db.get(SnapshotLegalHoldJob, event_id) is None
    current = client.get(
        "/api/v1/events?page_size=100", headers=headers
    ).json()["items"]
    assert next(item for item in current if item["id"] == event_id)["legal_hold"] is True

    storage.fail_next = True
    failed_disable = client.patch(
        f"/api/v1/events/{event_id}/legal-hold",
        headers=headers,
        json={
            "enabled": False,
            "reason": "CASE-2026-02 retention released",
        },
    )
    assert failed_disable.status_code == 503
    current = client.get(
        "/api/v1/events?page_size=100", headers=headers
    ).json()["items"]
    assert next(item for item in current if item["id"] == event_id)["legal_hold"] is False
    with SessionLocal() as db:
        job = db.get(SnapshotLegalHoldJob, event_id)
        assert job.desired_enabled is False
        job.next_attempt_at = job.created_at
        db.commit()
        reconciler = SnapshotLegalHoldReconciler(storage)
        assert reconciler.dispatch_due(db) == 1
        assert reconciler.pending == 0
        assert db.get(SnapshotLegalHoldJob, event_id) is None
    assert storage.calls == [True, True, False, False]


def test_alert_rule_cannot_remove_a_channel_with_a_remaining_target(client):
    headers = auth_headers(client)
    created = client.post(
        "/api/v1/alert-rules",
        headers=headers,
        json={
            "name": "Target consistency rule",
            "event_types": ["intrusion"],
            "channels": ["console", "sms"],
            "channel_targets": {"sms": "shift-supervisor"},
        },
    )
    assert created.status_code == 201
    rejected = client.patch(
        f"/api/v1/alert-rules/{created.json()['id']}",
        headers=headers,
        json={"channels": ["console"]},
    )
    assert rejected.status_code == 422


def test_admin_can_update_all_alert_rule_fields_and_audit_the_change(client):
    headers = auth_headers(client)
    created = client.post(
        "/api/v1/alert-rules",
        headers=headers,
        json={
            "name": "Editable rule",
            "event_types": ["intrusion"],
            "minimum_severity": "high",
            "areas": ["主井口"],
            "channels": ["console"],
            "channel_targets": {},
            "cooldown_seconds": 60,
        },
    )
    assert created.status_code == 201
    rule_id = created.json()["id"]

    updated = client.patch(
        f"/api/v1/alert-rules/{rule_id}",
        headers=headers,
        json={
            "name": "Edited safety rule",
            "event_types": ["no_helmet", "crowding"],
            "minimum_severity": "critical",
            "areas": ["运输巷道", "副井口"],
            "channels": ["console", "webhook"],
            "channel_targets": {"webhook": "incident-primary"},
            "cooldown_seconds": 180,
            "enabled": False,
        },
    )
    assert updated.status_code == 200
    expected = {
        "name": "Edited safety rule",
        "event_types": ["no_helmet", "crowding"],
        "minimum_severity": "critical",
        "areas": ["运输巷道", "副井口"],
        "channels": ["console", "webhook"],
        "channel_targets": {"webhook": "incident-primary"},
        "cooldown_seconds": 180,
        "enabled": False,
    }
    assert {key: updated.json()[key] for key in expected} == expected
    audit = client.get(
        "/api/v1/audit-logs?action=alert_rule.update&page_size=100",
        headers=headers,
    )
    assert audit.status_code == 200
    matching = [
        item for item in audit.json()["items"]
        if item["resource_id"] == str(rule_id)
    ]
    assert matching
    assert matching[0]["detail"]["channel_targets"] == {
        "webhook": "incident-primary"
    }


def test_alert_rule_update_rejects_a_case_insensitive_name_collision(client):
    headers = auth_headers(client)
    first = client.post(
        "/api/v1/alert-rules",
        headers=headers,
        json={
            "name": "Unique Safety Rule",
            "event_types": ["intrusion"],
            "channels": ["console"],
        },
    )
    second = client.post(
        "/api/v1/alert-rules",
        headers=headers,
        json={
            "name": "Another Safety Rule",
            "event_types": ["crowding"],
            "channels": ["console"],
        },
    )
    assert first.status_code == 201
    assert second.status_code == 201
    collision = client.patch(
        f"/api/v1/alert-rules/{second.json()['id']}",
        headers=headers,
        json={"name": "unique safety rule"},
    )
    assert collision.status_code == 409
    unchanged = client.get("/api/v1/alert-rules", headers=headers)
    assert unchanged.status_code == 200
    saved = next(item for item in unchanged.json() if item["id"] == second.json()["id"])
    assert saved["name"] == "Another Safety Rule"


def test_area_scoped_auditor_only_sees_own_audit_activity(client):
    admin_headers = auth_headers(client)
    created = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "scoped-auditor",
            "full_name": "区域审计员",
            "password": "ScopedAuditor123",
            "role": "auditor",
            "permitted_areas": ["主井口"],
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "scoped-auditor", "password": "ScopedAuditor123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    audit = client.get("/api/v1/audit-logs?page_size=100", headers=headers)
    assert audit.status_code == 200
    assert audit.json()["items"]
    assert {item["user_id"] for item in audit.json()["items"]} == {
        created.json()["id"]
    }


def test_alert_rule_creates_deduplicated_delivery_records(client):
    headers = {**auth_headers(client), "Idempotency-Key": "camera-3:intrusion:notification-test"}
    created = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "event_type": "intrusion",
            "severity": "critical",
            "camera_id": 3,
            "title": "通知链路测试事件",
            "confidence": 0.95,
        },
    )
    assert created.status_code == 201
    deliveries = client.get("/api/v1/notification-deliveries", headers=headers)
    assert deliveries.status_code == 200
    matching = [item for item in deliveries.json()["items"] if item["event_id"] == created.json()["id"]]
    assert {item["channel"] for item in matching} == {"console", "broadcast"}


def test_edge_node_heartbeat_and_idempotent_event_ingest(client):
    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={"code": "edge-test-01", "name": "测试边缘节点", "camera_ids": [1]},
    )
    assert registered.status_code == 201
    assert "api_key_hash" not in registered.text
    edge_headers = {
        "X-Edge-Node": "edge-test-01",
        "X-Edge-Key": registered.json()["api_key"],
    }
    heartbeat = client.post(
        "/api/v1/edge/heartbeat",
        headers=edge_headers,
        json={
            "software_version": "edge-worker-0.1.0",
            "gpu_utilization": 0.42,
            "gpu_memory_utilization": 0.38,
            "queue_depth": 2,
            "stream_reconnects_last_5m": 8,
            "stream_reconnects_total": 18,
            "central_reconnects_last_5m": 3,
            "central_reconnects_total": 5,
            "area_counts": {"主井口": 6},
            "cameras": [{"camera_id": 1, "status": "online", "fps": 25, "latency_ms": 81}],
        },
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "online"
    unauthorized_area = client.post(
        "/api/v1/edge/heartbeat",
        headers=edge_headers,
        json={
            "software_version": "edge-worker-0.1.0",
            "gpu_utilization": 0.42,
            "gpu_memory_utilization": 0.38,
            "area_counts": {"未授权区域": 1},
            "cameras": [
                {
                    "camera_id": 1,
                    "status": "online",
                    "fps": 25,
                    "latency_ms": 81,
                }
            ],
        },
    )
    assert unauthorized_area.status_code == 403
    assert unauthorized_area.json()["detail"] == {
        "unauthorized_counting_areas": ["未授权区域"]
    }
    incomplete_heartbeat = client.post(
        "/api/v1/edge/heartbeat",
        headers=edge_headers,
        json={
            "software_version": "edge-worker-0.1.0",
            "gpu_utilization": 0.42,
            "gpu_memory_utilization": 0.38,
            "area_counts": {},
            "cameras": [],
        },
    )
    assert incomplete_heartbeat.status_code == 403
    assert incomplete_heartbeat.json()["detail"] == {
        "unauthorized_camera_ids": [],
        "missing_camera_ids": [1],
    }
    updated_dashboard = client.get("/api/v1/dashboard/summary", headers=admin_headers)
    assert updated_dashboard.json()["area_occupancy"]["主井口"] == 6
    assert updated_dashboard.json()["system_health"]["edge_reconnects_last_5m"] >= 11
    assert any(
        alert["code"] == "edge_reconnect_storm"
        for alert in updated_dashboard.json()["operational_alerts"]
    )
    duplicate_counter = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={
            "code": "edge-test-duplicate-counter",
            "name": "重复区域计数节点",
            "camera_ids": [1],
        },
    )
    duplicate_headers = {
        "X-Edge-Node": "edge-test-duplicate-counter",
        "X-Edge-Key": duplicate_counter.json()["api_key"],
    }
    duplicate_heartbeat = client.post(
        "/api/v1/edge/heartbeat",
        headers=duplicate_headers,
        json={
            "software_version": "edge-worker-0.1.0",
            "gpu_utilization": 0.35,
            "gpu_memory_utilization": 0.30,
            "area_counts": {"主井口": 4},
            "cameras": [
                {
                    "camera_id": 1,
                    "status": "online",
                    "fps": 24,
                    "latency_ms": 90,
                }
            ],
        },
    )
    assert duplicate_heartbeat.status_code == 200
    conflicted_dashboard = client.get(
        "/api/v1/dashboard/summary", headers=admin_headers
    ).json()
    assert conflicted_dashboard["area_occupancy"]["主井口"] == 6
    assert any(
        alert["code"] == "area_counter_conflict"
        for alert in conflicted_dashboard["operational_alerts"]
    )
    event_headers = {**edge_headers, "Idempotency-Key": "edge-test-01:event:track-1"}
    payload = {
        "event_type": "no_helmet",
        "severity": "high",
        "camera_id": 1,
        "title": "边缘节点安全帽事件",
        "confidence": 0.92,
    }
    first = client.post("/api/v1/edge/events", headers=event_headers, json=payload)
    second = client.post("/api/v1/edge/events", headers=event_headers, json=payload)
    assert first.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    drifted = client.post(
        "/api/v1/edge/events",
        headers=event_headers,
        json={**payload, "confidence": 0.51},
    )
    assert drifted.status_code == 422
    persisted = client.get(
        "/api/v1/events?page_size=100", headers=admin_headers
    ).json()["items"]
    stored = next(event for event in persisted if event["id"] == first.json()["id"])
    assert stored["metadata_json"]["edge_node_code"] == "edge-test-01"
    denied = client.post(
        "/api/v1/edge/events",
        headers={**edge_headers, "Idempotency-Key": "edge-test-01:unauthorized-camera"},
        json={**payload, "camera_id": 2},
    )
    assert denied.status_code == 403
    rotated = client.post(
        f"/api/v1/edge-nodes/{registered.json()['node']['id']}/rotate-key",
        headers=admin_headers,
    )
    assert rotated.status_code == 200
    assert rotated.json()["api_key"] != registered.json()["api_key"]
    assert client.post(
        "/api/v1/edge/heartbeat",
        headers=edge_headers,
        json={
            "software_version": "x",
            "gpu_utilization": 0,
            "gpu_memory_utilization": 0,
            "queue_depth": 0,
            "cameras": [],
        },
    ).status_code == 401
    assert client.post(
        "/api/v1/edge/heartbeat",
        headers={"X-Edge-Node": "edge-test-01", "X-Edge-Key": rotated.json()["api_key"]},
        json={
            "software_version": "edge-worker-0.1.1",
            "gpu_utilization": 0.4,
            "gpu_memory_utilization": 0.3,
            "queue_depth": 0,
            "area_counts": {},
            "cameras": [],
        },
    ).status_code == 200


def test_edge_event_idempotency_is_isolated_between_service_nodes(client):
    admin_headers = auth_headers(client)
    first_node = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={"code": "edge-idem-a", "name": "Idempotency A", "camera_ids": [1]},
    ).json()
    second_node = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={"code": "edge-idem-b", "name": "Idempotency B", "camera_ids": [1]},
    ).json()
    payload = {
        "event_type": "intrusion",
        "severity": "high",
        "camera_id": 1,
        "title": "Node-scoped idempotency event",
        "confidence": 0.9,
    }
    shared_key = "shared-node-event-key"

    def ingest(node):
        return client.post(
            "/api/v1/edge/events",
            headers={
                "X-Edge-Node": node["node"]["code"],
                "X-Edge-Key": node["api_key"],
                "Idempotency-Key": shared_key,
            },
            json=payload,
        )

    first = ingest(first_node)
    repeated = ingest(first_node)
    second = ingest(second_node)
    assert first.status_code == repeated.status_code == second.status_code == 201
    assert first.json()["id"] == repeated.json()["id"]
    assert first.json()["id"] != second.json()["id"]
    assert first.json()["created"] is True
    assert repeated.json()["created"] is False
    assert second.json()["created"] is True


def test_edge_node_deactivation_immediately_revokes_service_access(client):
    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={"code": "edge-deactivate", "name": "Deactivate node", "camera_ids": [2]},
    )
    assert registered.status_code == 201
    node = registered.json()
    edge_headers = {
        "X-Edge-Node": node["node"]["code"],
        "X-Edge-Key": node["api_key"],
    }
    heartbeat_payload = {
        "software_version": "1.0.0",
        "gpu_utilization": 0.2,
        "gpu_memory_utilization": 0.3,
        "queue_depth": 0,
        "cameras": [
            {"camera_id": 2, "status": "online", "fps": 20, "latency_ms": 70}
        ],
    }
    assert client.post(
        "/api/v1/edge/heartbeat", headers=edge_headers, json=heartbeat_payload
    ).status_code == 200

    disabled = client.patch(
        f"/api/v1/edge-nodes/{node['node']['id']}",
        headers=admin_headers,
        json={"active": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["active"] is False
    assert disabled.json()["status"] == "offline"
    assert client.post(
        "/api/v1/edge/heartbeat", headers=edge_headers, json=heartbeat_payload
    ).status_code == 401

    enabled = client.patch(
        f"/api/v1/edge-nodes/{node['node']['id']}",
        headers=admin_headers,
        json={"active": True},
    )
    assert enabled.status_code == 200
    assert enabled.json()["active"] is True
    assert enabled.json()["status"] == "offline"
    assert client.post(
        "/api/v1/edge/heartbeat", headers=edge_headers, json=heartbeat_payload
    ).status_code == 200


def test_edge_node_camera_bindings_can_be_replaced_and_cleared(client):
    admin_headers = auth_headers(client)
    registered = client.post(
        "/api/v1/edge-nodes",
        headers=admin_headers,
        json={"code": "edge-bindings", "name": "Bindings node", "camera_ids": [1]},
    )
    assert registered.status_code == 201
    node_id = registered.json()["node"]["id"]

    replaced = client.patch(
        f"/api/v1/edge-nodes/{node_id}",
        headers=admin_headers,
        json={"name": "Bindings node updated", "camera_ids": [2]},
    )
    assert replaced.status_code == 200
    assert replaced.json()["name"] == "Bindings node updated"
    assert replaced.json()["camera_ids"] == [2]

    missing = client.patch(
        f"/api/v1/edge-nodes/{node_id}",
        headers=admin_headers,
        json={"camera_ids": [2, 999999]},
    )
    assert missing.status_code == 422
    assert missing.json()["detail"] == {"missing_camera_ids": [999999]}
    unchanged = client.get("/api/v1/edge-nodes", headers=admin_headers)
    assert unchanged.status_code == 200
    current = next(item for item in unchanged.json() if item["id"] == node_id)
    assert current["camera_ids"] == [2]

    cleared = client.patch(
        f"/api/v1/edge-nodes/{node_id}",
        headers=admin_headers,
        json={"camera_ids": []},
    )
    assert cleared.status_code == 200
    assert cleared.json()["camera_ids"] == []

from datetime import UTC, datetime
from hashlib import sha256
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import create_service_key
from app.dependencies import get_current_user, get_edge_node, require_roles
from app.models import Camera, EdgeNode, EdgeNodeStatus, Event, ModelArtifact, Role, User
from app.schemas import (
    CameraHeartbeat,
    EdgeEventReceipt,
    EdgeHeartbeat,
    EdgeNodeCreate,
    EdgeNodeCredential,
    EdgeNodeRead,
    EdgeNodeUpdate,
    EventCreate,
    Page,
    SnapshotUploadGrant,
    SnapshotUploadRequest,
    SnapshotVerifyRequest,
)
from app.services.audit import write_audit
from app.services.concurrency import enforce_if_match
from app.services.edge_nodes import reconcile_camera_states
from app.services.events import ingest_event_record
from app.services.permissions import area_scope
from app.services.realtime import publish_realtime_signal
from app.services.snapshots import (
    SnapshotIntegrityError,
    SnapshotStorageError,
    get_snapshot_storage,
    snapshot_camera_id,
)

router = APIRouter(tags=["edge-nodes"])
LEGACY_LIST_LIMIT = 1000


def edge_node_for_scope(
    node: EdgeNode,
    scope: set[str] | None,
    allowed_camera_ids: set[int] | None,
) -> EdgeNodeRead | None:
    if scope is None:
        return EdgeNodeRead.model_validate(node)
    visible_ids = [
        camera_id
        for camera_id in node.camera_ids
        if allowed_camera_ids is not None and camera_id in allowed_camera_ids
    ]
    if not visible_ids:
        return None
    item = EdgeNodeRead.model_validate(node)
    item.camera_ids = visible_ids
    item.telemetry = {
        **item.telemetry,
        "area_counts": {
            area: count
            for area, count in item.telemetry.get("area_counts", {}).items()
            if area in scope
        },
        "reported_cameras": len(visible_ids),
    }
    return item


@router.post(
    "/edge/snapshots/upload",
    response_model=SnapshotUploadGrant,
    status_code=status.HTTP_201_CREATED,
)
def create_edge_snapshot_upload(
    payload: SnapshotUploadRequest,
    db: Session = Depends(get_db),
    node: EdgeNode = Depends(get_edge_node),
) -> SnapshotUploadGrant:
    if payload.camera_id not in node.camera_ids:
        raise HTTPException(status_code=403, detail="该节点无权上传此摄像头快照")
    if not db.get(Camera, payload.camera_id):
        raise HTTPException(status_code=404, detail="摄像头不存在")
    if (
        payload.reference
        and snapshot_camera_id(payload.reference) != payload.camera_id
    ):
        raise HTTPException(status_code=422, detail="快照引用与摄像头不匹配")
    try:
        return get_snapshot_storage().create_upload_grant(
            camera_id=payload.camera_id,
            content_type=payload.content_type,
            content_length=payload.content_length,
            sha256_hex=payload.sha256,
            reference=payload.reference,
        )
    except ValueError as exc:
        raise HTTPException(status_code=413, detail="事件快照超过允许大小") from exc
    except SnapshotStorageError as exc:
        raise HTTPException(
            status_code=503,
            detail="快照存储暂时不可用，节点将自动重试",
            headers={"Retry-After": "5"},
        ) from exc


@router.post("/edge/snapshots/verify", status_code=status.HTTP_204_NO_CONTENT)
def verify_edge_snapshot_upload(
    payload: SnapshotVerifyRequest,
    db: Session = Depends(get_db),
    node: EdgeNode = Depends(get_edge_node),
) -> None:
    if payload.camera_id not in node.camera_ids:
        raise HTTPException(status_code=403, detail="该节点无权验证此摄像头快照")
    if not db.get(Camera, payload.camera_id):
        raise HTTPException(status_code=404, detail="摄像头不存在")
    if snapshot_camera_id(payload.reference) != payload.camera_id:
        raise HTTPException(status_code=422, detail="快照引用与摄像头不匹配")
    try:
        get_snapshot_storage().verify_upload(
            reference=payload.reference,
            content_type=payload.content_type,
            content_length=payload.content_length,
            sha256_hex=payload.sha256,
        )
    except SnapshotIntegrityError as exc:
        raise HTTPException(
            status_code=422,
            detail="已有快照对象与待传事件摘要不一致",
        ) from exc
    except SnapshotStorageError as exc:
        raise HTTPException(
            status_code=503,
            detail="快照对象校验暂时不可用，节点将自动重试",
            headers={"Retry-After": "5"},
        ) from exc


@router.get("/edge-nodes", response_model=list[EdgeNodeRead])
def list_edge_nodes(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    nodes = db.scalars(
        select(EdgeNode).order_by(EdgeNode.code).limit(LEGACY_LIST_LIMIT + 1)
    ).all()
    if len(nodes) > LEGACY_LIST_LIMIT:
        raise HTTPException(
            status_code=409,
            detail="边缘节点数量超过旧版数组接口上限，请使用分页端点",
        )
    scope = area_scope(user)
    allowed_camera_ids = (
        set(db.scalars(select(Camera.id).where(Camera.area.in_(scope))).all())
        if scope is not None
        else None
    )
    return [
        item
        for node in nodes
        if (item := edge_node_for_scope(node, scope, allowed_camera_ids)) is not None
    ]


@router.get("/edge-nodes/page", response_model=Page)
def list_edge_nodes_page(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Page:
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    scope = area_scope(user)
    allowed_camera_ids = (
        set(db.scalars(select(Camera.id).where(Camera.area.in_(scope))).all())
        if scope is not None
        else None
    )
    if scope is None:
        nodes = db.scalars(
            select(EdgeNode)
            .order_by(EdgeNode.id)
            .offset((safe_page - 1) * safe_size)
            .limit(safe_size)
        ).all()
        items = [EdgeNodeRead.model_validate(node) for node in nodes]
        total = db.scalar(select(func.count()).select_from(EdgeNode)) or 0
    else:
        offset = (safe_page - 1) * safe_size
        total = 0
        items = []
        cursor = 0
        while True:
            batch = db.scalars(
                select(EdgeNode)
                .where(EdgeNode.id > cursor)
                .order_by(EdgeNode.id)
                .limit(500)
            ).all()
            if not batch:
                break
            cursor = batch[-1].id
            for node in batch:
                item = edge_node_for_scope(node, scope, allowed_camera_ids)
                if item is None:
                    continue
                if offset <= total < offset + safe_size:
                    items.append(item)
                total += 1
    return Page(
        items=items,
        total=total,
        page=safe_page,
        page_size=safe_size,
    )


@router.post("/edge-nodes", response_model=EdgeNodeCredential, status_code=status.HTTP_201_CREATED)
def create_edge_node(
    payload: EdgeNodeCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    if db.scalar(
        select(EdgeNode.id).where(func.lower(EdgeNode.code) == payload.code.lower())
    ):
        raise HTTPException(status_code=409, detail="边缘节点编号已存在")
    missing_cameras = [camera_id for camera_id in payload.camera_ids if not db.get(Camera, camera_id)]
    if missing_cameras:
        raise HTTPException(status_code=422, detail={"missing_camera_ids": missing_cameras})
    api_key, api_key_hash = create_service_key()
    node = EdgeNode(**payload.model_dump(), api_key_hash=api_key_hash)
    db.add(node)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="边缘节点编号已存在") from exc
    write_audit(db, actor, "edge_node.create", "edge_node", node.id, {"code": node.code, "camera_ids": node.camera_ids}, request)
    db.commit()
    db.refresh(node)
    return EdgeNodeCredential(node=EdgeNodeRead.model_validate(node), api_key=api_key)


@router.patch("/edge-nodes/{node_id}", response_model=EdgeNodeRead)
def update_edge_node(
    node_id: int,
    payload: EdgeNodeUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    node = db.scalar(
        select(EdgeNode).where(EdgeNode.id == node_id).with_for_update()
    )
    if not node:
        raise HTTPException(status_code=404, detail="边缘节点不存在")
    changes = payload.model_dump(exclude_unset=True)
    if camera_ids := changes.get("camera_ids"):
        missing_cameras = [
            camera_id for camera_id in camera_ids if not db.get(Camera, camera_id)
        ]
        if missing_cameras:
            raise HTTPException(
                status_code=422,
                detail={"missing_camera_ids": missing_cameras},
            )
    changes = {
        key: value for key, value in changes.items() if getattr(node, key) != value
    }
    if not changes:
        return node
    enforce_if_match(node, if_match)
    previous_camera_ids = set(node.camera_ids)
    for key, value in changes.items():
        setattr(node, key, value)
    if changes.get("active") is False:
        node.status = EdgeNodeStatus.OFFLINE.value

    affected_camera_ids = (
        previous_camera_ids | set(node.camera_ids)
        if {"active", "camera_ids"} & changes.keys()
        else set()
    )
    changed_camera_ids = reconcile_camera_states(db, affected_camera_ids)
    changed_areas = {
        camera.area
        for camera_id in changed_camera_ids
        if (camera := db.get(Camera, camera_id)) is not None
    }
    for area in changed_areas:
        publish_realtime_signal(db, "cameras", node.id, "state_changed", area=area)
    write_audit(db, actor, "edge_node.update", "edge_node", node.id, changes, request)
    db.commit()
    db.refresh(node)
    return node


@router.post("/edge-nodes/{node_id}/rotate-key", response_model=EdgeNodeCredential)
def rotate_edge_key(
    node_id: int,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    node = db.scalar(
        select(EdgeNode).where(EdgeNode.id == node_id).with_for_update()
    )
    if not node:
        raise HTTPException(status_code=404, detail="边缘节点不存在")
    enforce_if_match(node, if_match)
    api_key, node.api_key_hash = create_service_key()
    write_audit(db, actor, "edge_node.rotate_key", "edge_node", node.id, request=request)
    db.commit()
    db.refresh(node)
    return EdgeNodeCredential(node=EdgeNodeRead.model_validate(node), api_key=api_key)


@router.post("/edge/heartbeat", response_model=EdgeNodeRead)
def edge_heartbeat(
    payload: EdgeHeartbeat,
    db: Session = Depends(get_db),
    node: EdgeNode = Depends(get_edge_node),
):
    now = datetime.now(UTC)
    previous_node_status = node.status
    allowed = set(node.camera_ids)
    reported = {item.camera_id for item in payload.cameras}
    if reported != allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "unauthorized_camera_ids": sorted(reported - allowed),
                "missing_camera_ids": sorted(allowed - reported),
            },
        )
    reported_cameras: list[tuple[CameraHeartbeat, Camera]] = []
    for item in payload.cameras:
        camera = db.get(Camera, item.camera_id)
        if not camera:
            raise HTTPException(status_code=404, detail=f"摄像头 {item.camera_id} 不存在")
        reported_cameras.append((item, camera))
    reported_areas = {camera.area for _, camera in reported_cameras}
    unauthorized_areas = sorted(set(payload.area_counts) - reported_areas)
    if unauthorized_areas:
        raise HTTPException(
            status_code=403,
            detail={"unauthorized_counting_areas": unauthorized_areas},
        )
    node.status = EdgeNodeStatus.ONLINE.value
    node.last_seen_at = now
    node.software_version = payload.software_version
    approved_identities = {
        (artifact.algorithm_type, artifact.model_version, artifact.sha256.lower())
        for artifact in db.scalars(
            select(ModelArtifact).where(ModelArtifact.approved.is_(True))
        ).all()
    }
    unapproved_models = [
        model.model_dump()
        for model in payload.models
        if not model.ready
        or (model.algorithm_type, model.model_version, model.sha256.lower())
        not in approved_identities
    ]
    model_policy_failed = get_settings().enforce_approved_edge_models and (
        not payload.models or bool(unapproved_models)
    )
    outbox_saturated = (
        payload.queue_depth + payload.dead_letter_depth
        >= payload.outbox_capacity
    )
    if model_policy_failed or not payload.gpu_healthy or outbox_saturated:
        node.status = EdgeNodeStatus.DEGRADED.value
    node.telemetry = {
        "gpu_healthy": payload.gpu_healthy,
        "gpu_utilization": payload.gpu_utilization,
        "gpu_memory_utilization": payload.gpu_memory_utilization,
        "queue_depth": payload.queue_depth,
        "dead_letter_depth": payload.dead_letter_depth,
        "outbox_capacity": payload.outbox_capacity,
        "stream_reconnects_last_5m": payload.stream_reconnects_last_5m,
        "stream_reconnects_total": payload.stream_reconnects_total,
        "central_reconnects_last_5m": payload.central_reconnects_last_5m,
        "central_reconnects_total": payload.central_reconnects_total,
        "area_counts": payload.area_counts,
        "models": [model.model_dump() for model in payload.models],
        "cameras": [camera.model_dump(mode="json") for camera in payload.cameras],
        "unapproved_models": unapproved_models,
        "model_policy_enforced": get_settings().enforce_approved_edge_models,
        "reported_cameras": len(payload.cameras),
    }
    changed_camera_ids = reconcile_camera_states(db, allowed, now=now)
    changed_areas = {
        camera.area
        for camera_id in changed_camera_ids
        if (camera := db.get(Camera, camera_id)) is not None
    }
    if node.status != previous_node_status and not changed_areas:
        changed_areas = {
            camera.area
            for camera_id in node.camera_ids
            if (camera := db.get(Camera, camera_id)) is not None
        }
    for area in changed_areas:
        publish_realtime_signal(
            db, "cameras", node.id, "state_changed", area=area
        )
    db.commit()
    db.refresh(node)
    return node


@router.post(
    "/edge/events", response_model=EdgeEventReceipt, status_code=status.HTTP_201_CREATED
)
def ingest_edge_event(
    payload: EventCreate,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=160)],
    db: Session = Depends(get_db),
    node: EdgeNode = Depends(get_edge_node),
):
    if payload.camera_id not in node.camera_ids:
        raise HTTPException(status_code=403, detail="该节点无权上报此摄像头事件")
    if (
        payload.snapshot_url
        and snapshot_camera_id(payload.snapshot_url) != payload.camera_id
    ):
        raise HTTPException(status_code=422, detail="快照引用与摄像头不匹配")
    if get_settings().enforce_approved_edge_models and (
        not node.telemetry.get("models")
        or node.telemetry.get("unapproved_models")
    ):
        raise HTTPException(status_code=409, detail="节点未满足生产模型准入策略")
    if (
        get_settings().enforce_approved_edge_models
        and payload.event_type in {"face_match", "unknown_face"}
    ):
        face_model_version = payload.metadata_json.get("face_model_version")
        face_model_sha256 = payload.metadata_json.get("face_model_sha256")
        approved_face_model = (
            db.scalar(
                select(ModelArtifact.id).where(
                    ModelArtifact.algorithm_type == "face_recognition",
                    ModelArtifact.model_version == face_model_version,
                    ModelArtifact.sha256 == face_model_sha256,
                    ModelArtifact.approved.is_(True),
                )
            )
            if isinstance(face_model_version, str)
            and isinstance(face_model_sha256, str)
            else None
        )
        if approved_face_model is None:
            raise HTTPException(
                status_code=409,
                detail="人脸识别事件使用的模型未通过生产准入",
            )
    metadata = {
        **payload.metadata_json,
        "edge_node_id": node.id,
        "edge_node_code": node.code,
        "edge_models": node.telemetry.get("models", []),
    }
    edge_payload = payload.model_copy(update={"metadata_json": metadata})
    internal_idempotency_key = (
        f"edge:{node.id}:{sha256(idempotency_key.encode('utf-8')).hexdigest()}"
    )
    legacy_event = db.scalar(
        select(Event).where(Event.idempotency_key == idempotency_key)
    )
    storage_key = (
        idempotency_key
        if legacy_event
        and legacy_event.metadata_json.get("edge_node_id") == node.id
        else internal_idempotency_key
    )
    event, created = ingest_event_record(
        db,
        edge_payload,
        storage_key,
        idempotency_ignored_metadata_keys={
            "edge_node_id",
            "edge_node_code",
            "edge_models",
        },
        idempotency_conflict_status=422,
    )
    if not created and event.metadata_json.get("edge_node_id") != node.id:
        raise HTTPException(status_code=409, detail="幂等键已用于其他边缘节点")
    db.commit()
    return EdgeEventReceipt(
        id=event.id,
        idempotency_key=idempotency_key,
        status=event.status,
        created=created,
    )

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_current_user, require_roles
from app.models import Camera, Role, User
from app.schemas import CameraCreate, CameraRead, CameraUpdate, Page
from app.services.audit import write_audit
from app.services.concurrency import enforce_if_match
from app.services.permissions import area_scope, require_area_access

router = APIRouter(prefix="/cameras", tags=["cameras"])


@router.get("", response_model=Page)
def list_cameras(
    page: int = 1,
    page_size: int = 50,
    area: str | None = None,
    query: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Page:
    page, page_size = max(page, 1), min(max(page_size, 1), 100)
    stmt = select(Camera)
    count_stmt = select(func.count()).select_from(Camera)
    scope = area_scope(user)
    if scope is not None:
        stmt, count_stmt = stmt.where(Camera.area.in_(scope)), count_stmt.where(
            Camera.area.in_(scope)
        )
    if area:
        stmt, count_stmt = stmt.where(Camera.area == area), count_stmt.where(Camera.area == area)
    if query:
        if len(query) > 100:
            raise HTTPException(status_code=422, detail="搜索条件不能超过 100 个字符")
        normalized_query = query.strip().lower()
        if normalized_query:
            condition = or_(
                func.lower(Camera.name).contains(normalized_query, autoescape=True),
                func.lower(Camera.code).contains(normalized_query, autoescape=True),
                func.lower(Camera.area).contains(normalized_query, autoescape=True),
            )
            stmt, count_stmt = stmt.where(condition), count_stmt.where(condition)
    items = db.scalars(stmt.order_by(Camera.code).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[CameraRead.model_validate(x) for x in items], total=db.scalar(count_stmt) or 0, page=page, page_size=page_size)


@router.post("", response_model=CameraRead, status_code=status.HTTP_201_CREATED)
def create_camera(
    payload: CameraCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
) -> Camera:
    require_area_access(user, payload.area)
    playback_path = f"/media/{payload.code.lower()}/index.m3u8"
    if db.scalar(
        select(Camera).where(
            or_(
                func.lower(Camera.code) == payload.code.lower(),
                Camera.playback_path == playback_path,
            )
        )
    ):
        raise HTTPException(status_code=409, detail="摄像头编号已存在")
    camera = Camera(
        **payload.model_dump(),
        playback_path=playback_path,
    )
    db.add(camera)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="摄像头编号已存在") from exc
    write_audit(
        db,
        user,
        "camera.create",
        "camera",
        camera.id,
        {
            "code": camera.code,
            "name": camera.name,
            "area": camera.area,
            "enabled_algorithms": camera.enabled_algorithms,
            "stream_url_configured": True,
        },
        request,
    )
    db.commit()
    db.refresh(camera)
    return camera


@router.patch("/{camera_id}", response_model=CameraRead)
def update_camera(
    camera_id: int,
    payload: CameraUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
) -> Camera:
    camera = db.scalar(
        select(Camera).where(Camera.id == camera_id).with_for_update()
    )
    if not camera:
        raise HTTPException(status_code=404, detail="摄像头不存在")
    require_area_access(user, camera.area)
    enforce_if_match(camera, if_match)
    changes = payload.model_dump(exclude_unset=True)
    if changes.get("area") is not None:
        require_area_access(user, changes["area"])
    for key, value in changes.items():
        setattr(camera, key, value.value if hasattr(value, "value") else value)
    audit_changes = {key: value for key, value in changes.items() if key != "stream_url"}
    if "stream_url" in changes:
        audit_changes["stream_url_changed"] = True
    write_audit(db, user, "camera.update", "camera", camera.id, audit_changes, request)
    db.commit()
    db.refresh(camera)
    return camera

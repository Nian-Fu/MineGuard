from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.dependencies import get_current_user, require_roles
from app.models import AlgorithmConfig, ModelArtifact, Role, User
from app.schemas import (
    AlgorithmRead,
    AlgorithmUpdate,
    ModelArtifactApproval,
    ModelArtifactCreate,
    ModelArtifactRead,
    Page,
)
from app.services.audit import write_audit
from app.services.concurrency import enforce_if_match
from app.services.rl_scheduler import SafetyConstrainedScheduler, SchedulingState

router = APIRouter(prefix="/algorithms", tags=["algorithms"])
LEGACY_LIST_LIMIT = 1000


@router.get("", response_model=list[AlgorithmRead])
def list_algorithms(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.scalars(select(AlgorithmConfig).order_by(AlgorithmConfig.id)).all()


@router.patch("/{algorithm_id}", response_model=AlgorithmRead)
def update_algorithm(
    algorithm_id: int,
    payload: AlgorithmUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.ADMIN)),
):
    algorithm = db.scalar(
        select(AlgorithmConfig)
        .where(AlgorithmConfig.id == algorithm_id)
        .with_for_update()
    )
    if not algorithm:
        raise HTTPException(status_code=404, detail="算法配置不存在")
    enforce_if_match(algorithm, if_match)
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(algorithm, key, value)
    write_audit(db, user, "algorithm.update", "algorithm", algorithm.id, changes, request)
    db.commit()
    db.refresh(algorithm)
    return algorithm


@router.post("/scheduler/decision")
def scheduler_decision(
    state: SchedulingState,
    _: User = Depends(get_current_user),
):
    return SafetyConstrainedScheduler().choose(state)


@router.get("/artifacts", response_model=list[ModelArtifactRead])
def list_model_artifacts(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    artifacts = db.scalars(
        select(ModelArtifact)
        .order_by(ModelArtifact.created_at.desc())
        .limit(LEGACY_LIST_LIMIT + 1)
    ).all()
    if len(artifacts) > LEGACY_LIST_LIMIT:
        raise HTTPException(
            status_code=409,
            detail="模型制品数量超过旧版数组接口上限，请使用分页端点",
        )
    return artifacts


@router.get("/artifacts/page", response_model=Page)
def list_model_artifacts_page(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Page:
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    items = db.scalars(
        select(ModelArtifact)
        .order_by(ModelArtifact.created_at.desc(), ModelArtifact.id.desc())
        .offset((safe_page - 1) * safe_size)
        .limit(safe_size)
    ).all()
    return Page(
        items=[ModelArtifactRead.model_validate(item) for item in items],
        total=db.scalar(select(func.count()).select_from(ModelArtifact)) or 0,
        page=safe_page,
        page_size=safe_size,
    )


@router.post("/artifacts", response_model=ModelArtifactRead, status_code=201)
def create_model_artifact(
    payload: ModelArtifactCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    identity = (
        ModelArtifact.algorithm_type == payload.algorithm_type,
        ModelArtifact.model_version == payload.model_version,
        ModelArtifact.sha256 == payload.sha256.lower(),
    )
    if db.scalar(select(ModelArtifact).where(*identity)):
        raise HTTPException(status_code=409, detail="相同模型制品已登记")
    values = payload.model_dump()
    values["sha256"] = payload.sha256.lower()
    artifact = ModelArtifact(**values, created_by=actor.id)
    db.add(artifact)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="相同模型制品已登记") from exc
    write_audit(
        db,
        actor,
        "model_artifact.create",
        "model_artifact",
        artifact.id,
        {
            "algorithm_type": artifact.algorithm_type,
            "model_version": artifact.model_version,
            "sha256": artifact.sha256,
            "license_id": artifact.license_id,
        },
        request,
    )
    db.commit()
    db.refresh(artifact)
    return artifact


@router.post("/artifacts/{artifact_id}/approval", response_model=ModelArtifactRead)
def approve_model_artifact(
    artifact_id: int,
    payload: ModelArtifactApproval,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    artifact = db.scalar(
        select(ModelArtifact)
        .where(ModelArtifact.id == artifact_id)
        .with_for_update()
    )
    if not artifact:
        raise HTTPException(status_code=404, detail="模型制品不存在")
    if artifact.approved == payload.approved:
        return artifact
    enforce_if_match(artifact, if_match)
    if (
        payload.approved
        and get_settings().require_four_eyes_model_approval
        and artifact.created_by == actor.id
    ):
        raise HTTPException(status_code=409, detail="生产模型制品必须由另一名管理员审批")
    artifact.approved = payload.approved
    artifact.approved_by = actor.id if payload.approved else None
    artifact.approved_at = datetime.now(UTC) if payload.approved else None
    write_audit(
        db,
        actor,
        "model_artifact.approval",
        "model_artifact",
        artifact.id,
        {"approved": payload.approved, "reason": payload.reason},
        request,
    )
    db.commit()
    db.refresh(artifact)
    return artifact

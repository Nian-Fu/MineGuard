from typing import Annotated

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, joinedload

from app.core.config import get_settings
from app.core.database import get_db
from app.dependencies import get_edge_node, require_roles
from app.models import (
    AuditLog,
    Camera,
    EdgeNode,
    FaceTemplate,
    ModelArtifact,
    Person,
    PersonAreaGrant,
    Role,
    User,
)
from app.schemas import (
    EdgeFaceCandidate,
    EdgeFaceIdentificationResponse,
    FaceCandidate,
    FaceEnrollmentResponse,
    FaceIdentificationResponse,
    FaceTemplateRead,
    LegalHoldUpdate,
    Page,
)
from app.services.audit import write_audit
from app.services.concurrency import enforce_if_match
from app.services.face import (
    FaceServiceError,
    HttpFaceProvider,
    TemplateCipher,
    cosine_similarity,
    face_template_associated_data,
)
from app.services.permissions import area_scope, can_access_person, require_area_access

router = APIRouter(prefix="/faces", tags=["face-recognition"])
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
FACE_TEMPLATE_MATCH_MAXIMUM = 5000


def face_components() -> tuple[HttpFaceProvider, TemplateCipher]:
    settings = get_settings()
    if not settings.face_enabled or not settings.face_inference_url or not settings.face_template_key:
        raise HTTPException(status_code=503, detail="人脸推理服务尚未启用")
    try:
        cipher = TemplateCipher(settings.face_template_key.get_secret_value())
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="人脸模板密钥配置无效") from exc
    return HttpFaceProvider(settings.face_inference_url, settings.face_request_timeout_seconds), cipher


def cipher_for_key_version(version: str) -> TemplateCipher:
    settings = get_settings()
    if version == settings.face_template_key_version and settings.face_template_key:
        return TemplateCipher(settings.face_template_key.get_secret_value())
    previous_key = settings.face_template_previous_keys.get(version)
    if previous_key:
        return TemplateCipher(previous_key.get_secret_value())
    raise HTTPException(status_code=503, detail=f"人脸模板密钥版本 {version} 不可用")


async def read_image(image: UploadFile) -> tuple[bytes, str]:
    settings = get_settings()
    content_type = image.content_type or ""
    if content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=415, detail="仅支持 JPEG、PNG 或 WebP 图像")
    data = await image.read(settings.max_face_image_bytes + 1)
    await image.close()
    if not data or len(data) > settings.max_face_image_bytes:
        raise HTTPException(status_code=413, detail="人脸图像为空或超过大小限制")
    return data, content_type


async def infer_checked(image: UploadFile):
    settings = get_settings()
    provider, cipher = face_components()
    data, content_type = await read_image(image)
    try:
        result = await provider.embed(data, content_type)
    except FaceServiceError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if result.face_count != 1:
        raise HTTPException(status_code=422, detail="登记或识别图像必须且只能包含一张人脸")
    if result.quality < settings.face_min_quality:
        raise HTTPException(status_code=422, detail="人脸图像质量未达到登记阈值")
    if result.liveness < settings.face_min_liveness:
        raise HTTPException(status_code=422, detail="活体检测未通过")
    return result, cipher


def identify_candidates(
    db: Session,
    result,
    permitted_areas: set[str] | None,
) -> list[FaceCandidate]:
    settings = get_settings()
    template_stmt = (
        select(FaceTemplate)
        .join(Person)
        .options(joinedload(FaceTemplate.person))
        .where(
            FaceTemplate.active.is_(True),
            FaceTemplate.model_version == result.model_version,
            FaceTemplate.model_sha256 == result.model_sha256,
            Person.active.is_(True),
        )
    )
    if permitted_areas is not None:
        template_stmt = (
            template_stmt.join(
                PersonAreaGrant, PersonAreaGrant.person_id == Person.id
            )
            .where(PersonAreaGrant.area.in_(permitted_areas))
            .distinct()
        )
    templates = db.scalars(
        template_stmt.order_by(FaceTemplate.id).limit(
            FACE_TEMPLATE_MATCH_MAXIMUM + 1
        )
    ).unique().all()
    if len(templates) > FACE_TEMPLATE_MATCH_MAXIMUM:
        raise HTTPException(
            status_code=503,
            detail="人脸模板检索容量已达到上限",
        )
    candidates = []
    for template in templates:
        cipher = cipher_for_key_version(template.key_version)
        associated_data = face_template_associated_data(
            template.person_id,
            template.model_version,
            template.model_sha256,
        )
        try:
            embedding = cipher.decrypt(
                template.encrypted_embedding,
                template.nonce,
                associated_data,
            )
            similarity = cosine_similarity(result.embedding, embedding)
        except (InvalidTag, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="人脸模板完整性校验失败",
            ) from exc
        if similarity >= settings.face_match_threshold:
            candidates.append(
                FaceCandidate(
                    person_id=template.person_id,
                    employee_no=template.person.employee_no,
                    name=template.person.name,
                    similarity=round(similarity, 5),
                )
            )
    candidates.sort(key=lambda candidate: candidate.similarity, reverse=True)
    return candidates[:3]


def require_approved_face_model(db: Session, result) -> None:
    if not get_settings().enforce_approved_edge_models:
        return
    approved = db.scalar(
        select(ModelArtifact.id).where(
            ModelArtifact.algorithm_type == "face_recognition",
            ModelArtifact.model_version == result.model_version,
            ModelArtifact.sha256 == result.model_sha256,
            ModelArtifact.approved.is_(True),
        )
    )
    if approved is None:
        raise HTTPException(status_code=503, detail="人脸识别模型未通过生产准入")


@router.get("/templates", response_model=Page)
def list_templates(
    page: int = 1,
    page_size: int = 50,
    person_id: int | None = None,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
):
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    stmt = select(FaceTemplate).options(joinedload(FaceTemplate.person))
    count_stmt = select(func.count()).select_from(FaceTemplate)
    scope = area_scope(actor)
    if scope is not None:
        stmt = (
            stmt.join(Person, FaceTemplate.person_id == Person.id)
            .join(PersonAreaGrant, PersonAreaGrant.person_id == Person.id)
            .where(PersonAreaGrant.area.in_(scope))
            .distinct()
        )
        count_stmt = (
            select(func.count(func.distinct(FaceTemplate.id)))
            .select_from(FaceTemplate)
            .join(Person, FaceTemplate.person_id == Person.id)
            .join(PersonAreaGrant, PersonAreaGrant.person_id == Person.id)
            .where(PersonAreaGrant.area.in_(scope))
        )
    if person_id is not None:
        stmt = stmt.where(FaceTemplate.person_id == person_id)
        count_stmt = count_stmt.where(FaceTemplate.person_id == person_id)
    templates = db.scalars(
        stmt.order_by(FaceTemplate.created_at.desc())
        .offset((safe_page - 1) * safe_size)
        .limit(safe_size)
    ).unique().all()
    return Page(
        items=[FaceTemplateRead.model_validate(item) for item in templates],
        total=db.scalar(count_stmt) or 0,
        page=safe_page,
        page_size=safe_size,
    )


@router.post("/enroll/{person_id}", response_model=FaceEnrollmentResponse, status_code=status.HTTP_201_CREATED)
async def enroll_face(
    person_id: int,
    image: Annotated[UploadFile, File()],
    consent_reference: Annotated[str, Form(min_length=3, max_length=200)],
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
):
    person = db.scalar(
        select(Person).where(Person.id == person_id).with_for_update()
    )
    if not person or not person.active:
        raise HTTPException(status_code=404, detail="有效人员档案不存在")
    if not can_access_person(db, actor, person.id):
        raise HTTPException(status_code=404, detail="有效人员档案不存在")
    result, cipher = await infer_checked(image)
    require_approved_face_model(db, result)
    associated_data = face_template_associated_data(
        person.id,
        result.model_version,
        result.model_sha256,
    )
    encrypted, nonce = cipher.encrypt(result.embedding, associated_data)
    db.execute(update(FaceTemplate).where(FaceTemplate.person_id == person.id).values(active=False))
    template = FaceTemplate(
        person_id=person.id,
        provider=result.provider,
        model_version=result.model_version,
        model_sha256=result.model_sha256,
        key_version=get_settings().face_template_key_version,
        encrypted_embedding=encrypted,
        nonce=nonce,
        quality=result.quality,
        liveness=result.liveness,
        consent_reference=consent_reference,
        created_by=actor.id,
        person=person,
    )
    db.add(template)
    person.face_enrolled = True
    db.flush()
    write_audit(
        db,
        actor,
        "face.enroll",
        "face_template",
        template.id,
        {
            "person_id": person.id,
            "model_version": result.model_version,
            "model_sha256": result.model_sha256,
        },
        request,
    )
    db.commit()
    db.refresh(template)
    return FaceEnrollmentResponse(template=FaceTemplateRead.model_validate(template), message="人脸模板已加密登记，原始图像未保存")


@router.post("/identify", response_model=FaceIdentificationResponse)
async def identify_face(
    image: Annotated[UploadFile, File()],
    request: Request,
    camera_id: Annotated[int | None, Form()] = None,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
):
    scope = area_scope(actor)
    if camera_id is not None:
        camera = db.get(Camera, camera_id)
        if not camera:
            raise HTTPException(status_code=404, detail="摄像头不存在")
        require_area_access(actor, camera.area)
    elif scope is not None:
        raise HTTPException(status_code=422, detail="区域账号执行识别时必须提供摄像头 ID")
    result, _ = await infer_checked(image)
    require_approved_face_model(db, result)
    candidates = identify_candidates(db, result, scope)
    response = FaceIdentificationResponse(
        matched=bool(candidates),
        unknown=not candidates,
        quality=result.quality,
        liveness=result.liveness,
        model_version=result.model_version,
        model_sha256=result.model_sha256,
        candidates=candidates,
    )
    write_audit(
        db,
        actor,
        "face.identify",
        "face_search",
        detail={
            "camera_id": camera_id,
            "matched": response.matched,
            "candidate_person_ids": [candidate.person_id for candidate in response.candidates],
            "model_version": response.model_version,
            "model_sha256": response.model_sha256,
        },
        request=request,
    )
    db.commit()
    return response


@router.post(
    "/edge-identify",
    response_model=EdgeFaceIdentificationResponse,
)
async def identify_edge_face(
    image: Annotated[UploadFile, File()],
    camera_id: Annotated[int, Form(ge=1)],
    db: Session = Depends(get_db),
    node: EdgeNode = Depends(get_edge_node),
) -> EdgeFaceIdentificationResponse:
    if camera_id not in node.camera_ids:
        raise HTTPException(status_code=403, detail="该节点无权执行此摄像头的人脸识别")
    camera = db.get(Camera, camera_id)
    if not camera:
        raise HTTPException(status_code=404, detail="摄像头不存在")
    result, _ = await infer_checked(image)
    require_approved_face_model(db, result)
    candidates = identify_candidates(db, result, None)
    candidate = candidates[0] if candidates else None
    authorized_for_camera = None
    if candidate:
        authorized_for_camera = db.scalar(
            select(PersonAreaGrant.id).where(
                PersonAreaGrant.person_id == candidate.person_id,
                PersonAreaGrant.area == camera.area,
            )
        ) is not None
    return EdgeFaceIdentificationResponse(
        matched=candidate is not None,
        unknown=candidate is None,
        quality=result.quality,
        liveness=result.liveness,
        model_version=result.model_version,
        model_sha256=result.model_sha256,
        authorized_for_camera=authorized_for_camera,
        candidate=(
            EdgeFaceCandidate(
                person_id=candidate.person_id,
                similarity=candidate.similarity,
            )
            if candidate
            else None
        ),
    )


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_template(
    template_id: int,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    candidate = db.get(FaceTemplate, template_id)
    if not candidate or not can_access_person(db, actor, candidate.person_id):
        raise HTTPException(status_code=404, detail="人脸模板不存在")
    person = db.scalar(
        select(Person).where(Person.id == candidate.person_id).with_for_update()
    )
    template = db.scalar(
        select(FaceTemplate)
        .options(joinedload(FaceTemplate.person))
        .where(FaceTemplate.id == template_id)
        .with_for_update()
    )
    if not template:
        raise HTTPException(status_code=404, detail="人脸模板不存在")
    if not template.active:
        return
    enforce_if_match(template, if_match)
    template.active = False
    remaining = db.scalar(
        select(FaceTemplate.id).where(
            FaceTemplate.person_id == template.person_id,
            FaceTemplate.active.is_(True),
            FaceTemplate.id != template.id,
        )
    )
    if person and not remaining:
        person.face_enrolled = False
    write_audit(db, actor, "face.revoke", "face_template", template.id, {"person_id": template.person_id}, request)
    db.commit()


@router.patch("/templates/{template_id}/legal-hold", response_model=FaceTemplateRead)
def update_template_legal_hold(
    template_id: int,
    payload: LegalHoldUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    template = db.scalar(
        select(FaceTemplate)
        .options(joinedload(FaceTemplate.person))
        .where(FaceTemplate.id == template_id)
        .with_for_update()
    )
    if not template or not can_access_person(db, actor, template.person_id):
        raise HTTPException(status_code=404, detail="人脸模板不存在")
    if template.legal_hold == payload.enabled:
        return template
    enforce_if_match(template, if_match)
    template.legal_hold = payload.enabled
    if payload.enabled:
        db.execute(
            update(AuditLog)
            .where(
                AuditLog.resource_type == "face_template",
                AuditLog.resource_id == str(template.id),
            )
            .values(legal_hold=True)
        )
    write_audit(
        db,
        actor,
        "face.legal_hold",
        "face_template",
        template.id,
        {
            "person_id": template.person_id,
            "enabled": payload.enabled,
            "reason": payload.reason,
            "legal_hold": True,
        },
        request,
    )
    db.commit()
    db.refresh(template)
    return template

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_current_user, require_roles
from app.models import FaceTemplate, Person, PersonAreaGrant, Role, User
from app.schemas import Page, PersonCreate, PersonRead, PersonUpdate
from app.services.audit import write_audit
from app.services.concurrency import enforce_if_match
from app.services.permissions import (
    area_scope,
    can_access_person,
    person_read_for_user,
    replace_person_area_grants,
    require_areas_access,
)

router = APIRouter(prefix="/persons", tags=["persons"])


@router.get("", response_model=Page)
def list_persons(
    page: int = 1,
    page_size: int = 50,
    query: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Page:
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    stmt, count_stmt = select(Person), select(func.count()).select_from(Person)
    scope = area_scope(user)
    if scope is not None:
        stmt = stmt.join(PersonAreaGrant).where(PersonAreaGrant.area.in_(scope)).distinct()
        count_stmt = (
            select(func.count(func.distinct(Person.id)))
            .select_from(Person)
            .join(PersonAreaGrant)
            .where(PersonAreaGrant.area.in_(scope))
        )
    if query:
        if len(query) > 100:
            raise HTTPException(status_code=422, detail="搜索条件不能超过 100 个字符")
        normalized_query = query.strip().lower()
        if normalized_query:
            condition = or_(
                func.lower(Person.name).contains(normalized_query, autoescape=True),
                func.lower(Person.employee_no).contains(
                    normalized_query, autoescape=True
                ),
                func.lower(Person.department).contains(
                    normalized_query, autoescape=True
                ),
            )
            stmt, count_stmt = stmt.where(condition), count_stmt.where(condition)
    items = db.scalars(
        stmt.order_by(Person.employee_no).offset((safe_page - 1) * safe_size).limit(safe_size)
    ).all()
    return Page(
        items=[person_read_for_user(item, user) for item in items],
        total=db.scalar(count_stmt) or 0,
        page=safe_page,
        page_size=safe_size,
    )


@router.post("", response_model=PersonRead, status_code=status.HTTP_201_CREATED)
def create_person(
    payload: PersonCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
) -> PersonRead:
    require_areas_access(user, payload.authorized_areas)
    if db.scalar(
        select(Person.id).where(
            func.lower(Person.employee_no) == payload.employee_no.lower()
        )
    ):
        raise HTTPException(status_code=409, detail="工号已存在")
    person = Person(**payload.model_dump())
    db.add(person)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="工号已存在") from exc
    replace_person_area_grants(db, person.id, person.authorized_areas)
    write_audit(db, user, "person.create", "person", person.id, {"employee_no": person.employee_no}, request)
    db.commit()
    db.refresh(person)
    return person_read_for_user(person, user)


@router.patch("/{person_id}", response_model=PersonRead)
def update_person(
    person_id: int,
    payload: PersonUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
) -> PersonRead:
    person = db.scalar(
        select(Person).where(Person.id == person_id).with_for_update()
    )
    if not person:
        raise HTTPException(status_code=404, detail="人员档案不存在")
    if not can_access_person(db, user, person.id):
        raise HTTPException(status_code=404, detail="人员档案不存在")
    enforce_if_match(person, if_match)
    changes = payload.model_dump(exclude_unset=True)
    if changes.get("authorized_areas") is not None:
        require_areas_access(user, changes["authorized_areas"])
    changes = {key: value for key, value in changes.items() if getattr(person, key) != value}
    for key, value in changes.items():
        setattr(person, key, value)
    if "authorized_areas" in changes:
        replace_person_area_grants(db, person.id, person.authorized_areas)
    if changes.get("active") is False:
        db.execute(
            update(FaceTemplate)
            .where(FaceTemplate.person_id == person.id, FaceTemplate.active.is_(True))
            .values(active=False)
        )
        person.face_enrolled = False
    write_audit(db, user, "person.update", "person", person.id, changes, request)
    db.commit()
    db.refresh(person)
    return person_read_for_user(person, user)

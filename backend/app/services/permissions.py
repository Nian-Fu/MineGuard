from collections.abc import Iterable

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import PersonAreaGrant, Role, User
from app.schemas import EventRead, PersonRead


def area_scope(user: User) -> set[str] | None:
    if user.role == Role.ADMIN.value or user.permitted_areas is None:
        return None
    return set(user.permitted_areas)


def can_access_area(user: User, area: str) -> bool:
    scope = area_scope(user)
    return scope is None or area in scope


def require_area_access(user: User, area: str) -> None:
    if not can_access_area(user, area):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权访问该生产区域",
        )


def require_areas_access(user: User, areas: Iterable[str]) -> None:
    scope = area_scope(user)
    requested = set(areas)
    if scope is not None and (not requested or not requested.issubset(scope)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="区域授权超出当前账号范围",
        )


def can_access_person(db: Session, user: User, person_id: int) -> bool:
    scope = area_scope(user)
    if scope is None:
        return True
    if not scope:
        return False
    return (
        db.scalar(
            select(PersonAreaGrant.person_id).where(
                PersonAreaGrant.person_id == person_id,
                PersonAreaGrant.area.in_(scope),
            )
        )
        is not None
    )


def replace_person_area_grants(db: Session, person_id: int, areas: Iterable[str]) -> None:
    db.execute(delete(PersonAreaGrant).where(PersonAreaGrant.person_id == person_id))
    db.add_all(
        PersonAreaGrant(person_id=person_id, area=area)
        for area in sorted(set(areas))
    )


def person_read_for_user(person, user: User) -> PersonRead:
    result = PersonRead.model_validate(person)
    scope = area_scope(user)
    if scope is not None:
        result.authorized_areas = [area for area in result.authorized_areas if area in scope]
    return result


def event_read_for_user(event, user: User) -> EventRead:
    result = EventRead.model_validate(event)
    if result.person is not None:
        scope = area_scope(user)
        if scope is not None:
            result.person.authorized_areas = [
                area for area in result.person.authorized_areas if area in scope
            ]
    return result

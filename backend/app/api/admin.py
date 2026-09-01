from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import hash_password
from app.dependencies import require_roles
from app.models import (
    AlertRule,
    AuditLog,
    Camera,
    DeliveryStatus,
    Event,
    NotificationDelivery,
    RefreshSession,
    Role,
    User,
)
from app.schemas import (
    AlertRuleCreate,
    AlertRuleRead,
    AlertRuleUpdate,
    AuditLogRead,
    NotificationDeliveryRead,
    Page,
    PasswordReset,
    UserCreate,
    UserRead,
    UserUpdate,
)
from app.services.audit import write_audit
from app.services.concurrency import enforce_if_match
from app.services.permissions import area_scope

router = APIRouter(tags=["administration"])
LEGACY_LIST_LIMIT = 1000


def reject_oversized_legacy_list(items: list, resource: str) -> list:
    if len(items) > LEGACY_LIST_LIMIT:
        raise HTTPException(
            status_code=409,
            detail=f"{resource}数量超过旧版数组接口上限，请使用分页端点",
        )
    return items


@router.get("/users", response_model=list[UserRead])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.ADMIN)),
):
    return reject_oversized_legacy_list(
        db.scalars(
            select(User).order_by(User.username).limit(LEGACY_LIST_LIMIT + 1)
        ).all(),
        "用户",
    )


@router.get("/users/page", response_model=Page)
def list_users_page(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.ADMIN)),
) -> Page:
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    items = db.scalars(
        select(User)
        .order_by(User.username)
        .offset((safe_page - 1) * safe_size)
        .limit(safe_size)
    ).all()
    return Page(
        items=[UserRead.model_validate(item) for item in items],
        total=db.scalar(select(func.count()).select_from(User)) or 0,
        page=safe_page,
        page_size=safe_size,
    )


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    if db.scalar(
        select(User.id).where(func.lower(User.username) == payload.username.lower())
    ):
        raise HTTPException(status_code=409, detail="用户名已存在")
    user = User(
        username=payload.username,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role.value,
        permitted_areas=None if payload.role == Role.ADMIN else payload.permitted_areas,
    )
    if payload.role != Role.ADMIN and payload.permitted_areas is None:
        raise HTTPException(status_code=422, detail="非管理员账号必须明确配置区域范围")
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="用户名已存在") from exc
    write_audit(
        db,
        actor,
        "user.create",
        "user",
        user.id,
        {
            "username": user.username,
            "role": user.role,
            "permitted_areas": user.permitted_areas,
        },
        request,
    )
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    user = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    enforce_if_match(user, if_match)
    changes = {
        key: value.value if hasattr(value, "value") else value
        for key, value in payload.model_dump(exclude_unset=True).items()
    }
    changes = {key: value for key, value in changes.items() if getattr(user, key) != value}
    if user.identity_provider != "local" and {"role", "permitted_areas"}.intersection(changes):
        raise HTTPException(status_code=409, detail="统一身份账号角色与区域由身份提供方组映射管理")
    if user.id == actor.id and changes.get("active") is False:
        raise HTTPException(status_code=409, detail="不能停用当前登录账号")
    if user.id == actor.id and "role" in changes and changes["role"] != Role.ADMIN.value:
        raise HTTPException(status_code=409, detail="不能降低当前登录管理员的角色")
    resulting_role = changes.get("role", user.role)
    resulting_areas = changes.get("permitted_areas", user.permitted_areas)
    if (
        resulting_role != Role.ADMIN.value
        and resulting_areas is None
        and {"role", "permitted_areas"}.intersection(changes)
    ):
        raise HTTPException(
            status_code=422,
            detail="非管理员账号不能配置为全局区域范围",
        )
    if resulting_role == Role.ADMIN.value:
        changes["permitted_areas"] = None
    if "role" in changes or "active" in changes or "permitted_areas" in changes:
        user.auth_version += 1
        db.execute(
            update(RefreshSession)
            .where(RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
    for key, value in changes.items():
        setattr(user, key, value)
    write_audit(db, actor, "user.update", "user", user.id, changes, request)
    db.commit()
    db.refresh(user)
    return user


@router.post("/users/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_user_password(
    user_id: int,
    payload: PasswordReset,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    user = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    enforce_if_match(user, if_match)
    if user.identity_provider != "local":
        raise HTTPException(status_code=409, detail="统一身份账号必须在身份提供方重置密码")
    user.password_hash = hash_password(payload.new_password)
    user.auth_version += 1
    db.execute(
        update(RefreshSession)
        .where(RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    write_audit(db, actor, "user.password_reset", "user", user.id, request=request)
    db.commit()


@router.get("/audit-logs", response_model=Page)
def list_audit_logs(
    page: int = 1,
    page_size: int = 50,
    action: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
) -> Page:
    stmt, count_stmt = select(AuditLog), select(func.count()).select_from(AuditLog)
    if area_scope(actor) is not None:
        stmt = stmt.where(AuditLog.user_id == actor.id)
        count_stmt = count_stmt.where(AuditLog.user_id == actor.id)
    if action:
        stmt, count_stmt = stmt.where(AuditLog.action == action), count_stmt.where(AuditLog.action == action)
    if resource_type:
        stmt, count_stmt = stmt.where(AuditLog.resource_type == resource_type), count_stmt.where(AuditLog.resource_type == resource_type)
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    items = db.scalars(stmt.order_by(AuditLog.created_at.desc()).offset((safe_page - 1) * safe_size).limit(safe_size)).all()
    return Page(items=[AuditLogRead.model_validate(x) for x in items], total=db.scalar(count_stmt) or 0, page=safe_page, page_size=safe_size)


@router.get("/alert-rules", response_model=list[AlertRuleRead])
def list_alert_rules(
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR, Role.AUDITOR)),
):
    rules = db.scalars(
        select(AlertRule).order_by(AlertRule.id).limit(LEGACY_LIST_LIMIT + 1)
    ).all()
    reject_oversized_legacy_list(rules, "告警规则")
    scope = area_scope(actor)
    if scope is None:
        return rules
    return [rule for rule in rules if not rule.areas or scope.intersection(rule.areas)]


@router.get("/alert-rules/page", response_model=Page)
def list_alert_rules_page(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR, Role.AUDITOR)),
) -> Page:
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    scope = area_scope(actor)
    if scope is None:
        items = db.scalars(
            select(AlertRule)
            .order_by(AlertRule.id)
            .offset((safe_page - 1) * safe_size)
            .limit(safe_size)
        ).all()
        total = db.scalar(select(func.count()).select_from(AlertRule)) or 0
    else:
        offset = (safe_page - 1) * safe_size
        total = 0
        items = []
        cursor = 0
        while True:
            batch = db.scalars(
                select(AlertRule)
                .where(AlertRule.id > cursor)
                .order_by(AlertRule.id)
                .limit(500)
            ).all()
            if not batch:
                break
            cursor = batch[-1].id
            for rule in batch:
                if rule.areas and not scope.intersection(rule.areas):
                    continue
                if offset <= total < offset + safe_size:
                    items.append(rule)
                total += 1
    return Page(
        items=[AlertRuleRead.model_validate(item) for item in items],
        total=total,
        page=safe_page,
        page_size=safe_size,
    )


def normalize_rule(values: dict) -> dict:
    for key in ("event_types", "channels"):
        if key in values and values[key] is not None:
            values[key] = [item.value if hasattr(item, "value") else item for item in values[key]]
    if "minimum_severity" in values and hasattr(values["minimum_severity"], "value"):
        values["minimum_severity"] = values["minimum_severity"].value
    return values


def validate_rule_targets(channels: list[str], targets: dict[str, str]) -> None:
    if not set(targets).issubset(channels):
        raise HTTPException(
            status_code=422,
            detail="通知目标只能引用当前规则已启用的通道",
        )


def ensure_rule_name_available(
    db: Session, name: str, *, exclude_rule_id: int | None = None
) -> None:
    stmt = select(AlertRule.id).where(func.lower(AlertRule.name) == name.lower())
    if exclude_rule_id is not None:
        stmt = stmt.where(AlertRule.id != exclude_rule_id)
    if db.scalar(stmt):
        raise HTTPException(status_code=409, detail="规则名称已存在")


@router.post("/alert-rules", response_model=AlertRuleRead, status_code=status.HTTP_201_CREATED)
def create_alert_rule(
    payload: AlertRuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    ensure_rule_name_available(db, payload.name)
    values = normalize_rule(payload.model_dump())
    validate_rule_targets(values["channels"], values["channel_targets"])
    rule = AlertRule(**values)
    db.add(rule)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="规则名称已存在") from exc
    write_audit(db, actor, "alert_rule.create", "alert_rule", rule.id, {"name": rule.name}, request)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/alert-rules/{rule_id}", response_model=AlertRuleRead)
def update_alert_rule(
    rule_id: int,
    payload: AlertRuleUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    rule = db.scalar(
        select(AlertRule).where(AlertRule.id == rule_id).with_for_update()
    )
    if not rule:
        raise HTTPException(status_code=404, detail="告警规则不存在")
    enforce_if_match(rule, if_match)
    changes = normalize_rule(payload.model_dump(exclude_unset=True))
    if "name" in changes:
        ensure_rule_name_available(db, changes["name"], exclude_rule_id=rule.id)
    validate_rule_targets(
        changes.get("channels", rule.channels),
        changes.get("channel_targets", rule.channel_targets),
    )
    for key, value in changes.items():
        setattr(rule, key, value)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="规则名称已存在") from exc
    write_audit(db, actor, "alert_rule.update", "alert_rule", rule.id, changes, request)
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/notification-deliveries", response_model=Page)
def list_notification_deliveries(
    page: int = 1,
    page_size: int = 50,
    delivery_status: str | None = None,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR, Role.AUDITOR)),
) -> Page:
    stmt = select(NotificationDelivery)
    count_stmt = select(func.count()).select_from(NotificationDelivery)
    scope = area_scope(actor)
    if scope is not None:
        stmt = stmt.join(Event).join(Camera).where(Camera.area.in_(scope))
        count_stmt = count_stmt.join(Event).join(Camera).where(Camera.area.in_(scope))
    if delivery_status:
        stmt = stmt.where(NotificationDelivery.status == delivery_status)
        count_stmt = count_stmt.where(NotificationDelivery.status == delivery_status)
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    items = db.scalars(
        stmt.order_by(NotificationDelivery.created_at.desc())
        .offset((safe_page - 1) * safe_size)
        .limit(safe_size)
    ).all()
    return Page(
        items=[NotificationDeliveryRead.model_validate(item) for item in items],
        total=db.scalar(count_stmt) or 0,
        page=safe_page,
        page_size=safe_size,
    )


@router.post("/notification-deliveries/{delivery_id}/retry", response_model=NotificationDeliveryRead)
def retry_notification_delivery(
    delivery_id: int,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
):
    delivery = db.scalar(
        select(NotificationDelivery)
        .where(NotificationDelivery.id == delivery_id)
        .with_for_update()
    )
    if not delivery:
        raise HTTPException(status_code=404, detail="通知投递记录不存在")
    if delivery.status == DeliveryStatus.SENT.value:
        raise HTTPException(status_code=409, detail="已成功投递的通知不能重复发送")
    previous_status = delivery.status
    previous_error = delivery.last_error
    rule = db.get(AlertRule, delivery.rule_id)
    if rule:
        delivery.target = rule.channel_targets.get(delivery.channel)
    delivery.status = DeliveryStatus.PENDING.value
    delivery.attempts = 0
    delivery.next_attempt_at = datetime.now(UTC)
    delivery.last_error = None
    write_audit(
        db,
        actor,
        "notification.retry",
        "notification_delivery",
        delivery.id,
        {
            "previous_status": previous_status,
            "previous_error": previous_error,
            "target_refreshed_from_rule": rule is not None,
        },
        request=request,
    )
    db.commit()
    db.refresh(delivery)
    return delivery

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog, User


def write_audit(
    db: Session,
    user: User | None,
    action: str,
    resource_type: str,
    resource_id: int | str | None = None,
    detail: dict | None = None,
    request: Request | None = None,
) -> None:
    audit_detail = detail or {}
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            detail=audit_detail,
            legal_hold=audit_detail.get("legal_hold") is True,
            ip_address=request.client.host if request and request.client else None,
        )
    )

import hmac
from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, get_db
from app.core.security import decode_access_token, hash_service_key
from app.models import EdgeNode, Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def authenticate_user(token: str, db: Session) -> tuple[User, dict]:
    payload = decode_access_token(token)
    user = db.scalar(select(User).where(User.username == payload.get("sub")))
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    if payload.get("ver") != user.auth_version:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credentials were revoked")
    return user, payload


def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    user, payload = authenticate_user(token, db)
    request.state.access_token_expires_at = payload["exp"]
    return user


def get_streaming_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
) -> User:
    with SessionLocal() as db:
        user, payload = authenticate_user(token, db)
        db.expunge(user)
    request.state.access_token_expires_at = payload["exp"]
    return user


def require_roles(*roles: Role) -> Callable:
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in {role.value for role in roles}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return dependency


def get_edge_node(
    node_code: str = Header(alias="X-Edge-Node"),
    node_key: str = Header(alias="X-Edge-Key"),
    db: Session = Depends(get_db),
) -> EdgeNode:
    node = db.scalar(
        select(EdgeNode)
        .where(EdgeNode.code == node_code)
        .with_for_update(read=True, key_share=True)
    )
    supplied_hash = hash_service_key(node_key)
    if not node or not node.active or not hmac.compare_digest(node.api_key_hash, supplied_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid edge credentials")
    return node

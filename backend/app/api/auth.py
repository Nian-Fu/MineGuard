import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    create_media_token,
    create_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.dependencies import get_current_user
from app.models import RefreshSession, User
from app.schemas import AuthenticationMethods, LoginRequest, PasswordChange, Token, UserRead
from app.services.audit import write_audit
from app.services.oidc import (
    OIDCError,
    authorization_url,
    create_oidc_transaction,
    decode_oidc_transaction,
    exchange_code,
    fetch_discovery,
    resolve_oidc_user,
    validate_id_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])
OIDC_TRANSACTION_COOKIE = "mineguard_oidc_transaction"


def set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        "mineguard_refresh",
        token,
        max_age=settings.refresh_token_days * 86400,
        httponly=True,
        secure=settings.environment == "production",
        samesite="strict",
        path=f"{settings.api_prefix}/auth",
    )


def set_media_cookie(response: Response, user: User) -> None:
    settings = get_settings()
    response.set_cookie(
        "mineguard_media",
        create_media_token(user.username, user.auth_version),
        max_age=settings.access_token_minutes * 60,
        httponly=True,
        secure=settings.environment == "production",
        samesite="strict",
        path="/media",
    )


def delete_media_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        "mineguard_media",
        path="/media",
        secure=settings.environment == "production",
        httponly=True,
        samesite="strict",
    )


def delete_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        "mineguard_refresh",
        path=f"{settings.api_prefix}/auth",
        secure=settings.environment == "production",
        httponly=True,
        samesite="strict",
    )


def expired_refresh_response() -> JSONResponse:
    response = JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": "Refresh session expired"},
    )
    delete_refresh_cookie(response)
    delete_media_cookie(response)
    return response


def new_refresh_session(db: Session, user: User, request: Request) -> str:
    settings = get_settings()
    token, token_hash = create_refresh_token()
    db.add(
        RefreshSession(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_days),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:300],
        )
    )
    return token


def validate_cookie_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    request_origin = f"{request.url.scheme}://{request.url.netloc}"
    if origin and origin != request_origin and origin not in get_settings().cors_origins:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Untrusted request origin")


def set_oidc_transaction_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        OIDC_TRANSACTION_COOKIE,
        token,
        max_age=300,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        path=f"{settings.api_prefix}/auth/oidc",
    )


def delete_oidc_transaction_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        OIDC_TRANSACTION_COOKIE,
        path=f"{settings.api_prefix}/auth/oidc",
        secure=settings.environment == "production",
        httponly=True,
        samesite="lax",
    )


def post_login_redirect(error: bool = False) -> RedirectResponse:
    settings = get_settings()
    target = settings.oidc_post_login_url
    if not target:
        raise RuntimeError("OIDC post-login URL is not configured")
    if error:
        parts = urlsplit(target)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query["oidc_error"] = "authentication_failed"
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    delete_oidc_transaction_cookie(response)
    return response


def oidc_failure(
    db: Session,
    request: Request,
    reason: str,
) -> RedirectResponse:
    db.rollback()
    write_audit(
        db,
        None,
        "auth.oidc_failed",
        "user",
        detail={"reason": reason},
        request=request,
    )
    db.commit()
    return post_login_redirect(error=True)


@router.get("/methods", response_model=AuthenticationMethods)
def authentication_methods() -> AuthenticationMethods:
    settings = get_settings()
    return AuthenticationMethods(
        local_enabled=settings.local_login_enabled,
        oidc_enabled=settings.oidc_enabled,
        oidc_provider_label=settings.oidc_provider_label if settings.oidc_enabled else None,
    )


@router.get("/oidc/login")
async def oidc_login(
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC is not enabled")
    try:
        metadata = await fetch_discovery(settings)
    except OIDCError:
        return oidc_failure(db, request, "provider_unavailable")
    transaction_token, transaction = create_oidc_transaction(settings)
    response = RedirectResponse(
        authorization_url(metadata, settings, transaction),
        status_code=status.HTTP_302_FOUND,
    )
    set_oidc_transaction_cookie(response, transaction_token)
    return response


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    db: Session = Depends(get_db),
    code: str | None = Query(default=None, max_length=4096),
    state_value: str | None = Query(default=None, alias="state", max_length=512),
    provider_error: str | None = Query(default=None, alias="error", max_length=100),
    transaction_token: Annotated[
        str | None, Cookie(alias=OIDC_TRANSACTION_COOKIE)
    ] = None,
) -> RedirectResponse:
    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC is not enabled")
    if provider_error:
        return oidc_failure(db, request, "provider_rejected")
    if not code or not state_value or not transaction_token:
        return oidc_failure(db, request, "callback_incomplete")
    try:
        transaction = decode_oidc_transaction(transaction_token, settings)
        if not secrets.compare_digest(transaction["state"], state_value):
            raise OIDCError("OIDC state mismatch")
        metadata = await fetch_discovery(settings)
        token_payload = await exchange_code(code, transaction, metadata, settings)
        claims = await validate_id_token(
            token_payload["id_token"], transaction["nonce"], metadata, settings
        )
        user, provisioned = resolve_oidc_user(db, claims, settings)
    except (IntegrityError, OIDCError):
        return oidc_failure(db, request, "validation_failed")

    response = post_login_redirect()
    set_refresh_cookie(response, new_refresh_session(db, user, request))
    set_media_cookie(response, user)
    write_audit(
        db,
        user,
        "auth.oidc_login",
        "user",
        user.id,
        {"provider": settings.oidc_provider_id, "provisioned": provisioned},
        request,
    )
    db.commit()
    return response


@router.post("/login", response_model=Token)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Token:
    settings = get_settings()
    if not settings.local_login_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="本地密码登录已停用")
    user = db.scalar(
        select(User).where(func.lower(User.username) == payload.username.lower())
    )
    password_valid = verify_password(
        payload.password, user.password_hash if user else DUMMY_PASSWORD_HASH
    )
    if (
        not user
        or not user.active
        or user.identity_provider != "local"
        or not password_valid
    ):
        write_audit(
            db,
            user,
            "auth.login_failed",
            "user",
            user.id if user else payload.username[:50],
            {"account_exists": bool(user)},
            request,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    write_audit(db, user, "auth.login", "user", user.id, request=request)
    set_refresh_cookie(response, new_refresh_session(db, user, request))
    set_media_cookie(response, user)
    db.commit()
    return Token(
        access_token=create_access_token(user.username, user.role, user.auth_version),
        user=UserRead.model_validate(user),
    )


@router.post("/refresh", response_model=Token)
def refresh(
    request: Request,
    response: Response,
    refresh_token: Annotated[str | None, Cookie(alias="mineguard_refresh")] = None,
    db: Session = Depends(get_db),
) -> Token | Response:
    validate_cookie_origin(request)
    if not refresh_token:
        return expired_refresh_response()
    now = datetime.now(UTC)
    session = db.scalar(
        select(RefreshSession)
        .where(RefreshSession.token_hash == hash_refresh_token(refresh_token))
        .with_for_update()
    )
    expires_at = session.expires_at if session else now
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if not session or session.revoked_at or expires_at <= now or not session.user.active:
        return expired_refresh_response()
    session.revoked_at = now
    session.last_used_at = now
    user = session.user
    set_refresh_cookie(response, new_refresh_session(db, user, request))
    set_media_cookie(response, user)
    write_audit(db, user, "auth.refresh", "refresh_session", session.id, request=request)
    db.commit()
    return Token(
        access_token=create_access_token(user.username, user.role, user.auth_version),
        user=UserRead.model_validate(user),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    refresh_token: Annotated[str | None, Cookie(alias="mineguard_refresh")] = None,
    db: Session = Depends(get_db),
):
    validate_cookie_origin(request)
    if refresh_token:
        session = db.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(refresh_token))
        )
        if session and not session.revoked_at:
            session.revoked_at = datetime.now(UTC)
            db.commit()
    delete_refresh_cookie(response)
    delete_media_cookie(response)


@router.post("/media-session", status_code=status.HTTP_204_NO_CONTENT)
def renew_media_session(
    response: Response,
    user: User = Depends(get_current_user),
):
    set_media_cookie(response, user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChange,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if user.identity_provider != "local":
        raise HTTPException(status_code=409, detail="统一身份账号必须在身份提供方修改密码")
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="当前密码不正确")
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")
    user.password_hash = hash_password(payload.new_password)
    user.auth_version += 1
    now = datetime.now(UTC)
    db.execute(
        update(RefreshSession)
        .where(RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    write_audit(db, user, "auth.password_change", "user", user.id, request=request)
    db.commit()
    delete_refresh_cookie(response)
    delete_media_cookie(response)


@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)) -> User:
    return user

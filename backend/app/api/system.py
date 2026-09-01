from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.dependencies import get_current_user
from app.models import User
from app.schemas import SystemCapabilities

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/capabilities", response_model=SystemCapabilities)
def capabilities(_: User = Depends(get_current_user)) -> SystemCapabilities:
    settings = get_settings()
    gateway_token = (
        settings.notification_gateway_token.get_secret_value()
        if settings.notification_gateway_token
        else ""
    )
    if settings.local_login_enabled and settings.oidc_enabled:
        authentication_mode = "local-or-oidc-pkce"
    elif settings.oidc_enabled:
        authentication_mode = "oidc-pkce"
    else:
        authentication_mode = "local-jwt-refresh"
    return SystemCapabilities(
        environment=settings.environment,
        face_recognition_enabled=settings.face_enabled,
        notification_gateway_configured=bool(settings.notification_gateway_url and gateway_token),
        authentication_mode=authentication_mode,
        authorization_scope="role-and-production-area",
        media_authorization="http-only-session-with-nginx-auth-request",
        access_token_minutes=settings.access_token_minutes,
        refresh_token_days=settings.refresh_token_days,
        live_update_mode="database-sse-with-polling-fallback",
        biometric_template_encryption="AES-256-GCM",
        approved_model_enforcement=settings.enforce_approved_edge_models,
        four_eyes_model_approval=settings.require_four_eyes_model_approval,
        snapshot_storage_enabled=settings.snapshot_storage_enabled,
    )

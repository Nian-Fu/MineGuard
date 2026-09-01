import base64
import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import jwt
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import hash_password
from app.models import RefreshSession, User
from app.services.http_payloads import async_json_response

OIDC_TRANSACTION_AUDIENCE = "mineguard-oidc-transaction"
SUPPORTED_ID_TOKEN_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
}
USERNAME_PATTERN = re.compile(r"[^a-zA-Z0-9_.@-]+")
OIDC_RESPONSE_MAXIMUM_BYTES = 1024 * 1024


class OIDCError(RuntimeError):
    pass


def validate_provider_url(value: str, https_required: bool) -> None:
    parts = urlsplit(value)
    allowed_schemes = {"https"} if https_required else {"http", "https"}
    if (
        parts.scheme not in allowed_schemes
        or not parts.netloc
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise ValueError("OIDC URL is not allowed")


def provider_origin(value: str) -> tuple[str, str, int]:
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("OIDC URL port is invalid") from exc
    if not parts.scheme or not parts.hostname:
        raise ValueError("OIDC URL origin is invalid")
    if port is None:
        port = 443 if parts.scheme.lower() == "https" else 80
    return parts.scheme.lower(), parts.hostname.rstrip(".").lower(), port


def allowed_provider_origins(settings: Settings) -> set[tuple[str, str, int]]:
    configured = [
        settings.oidc_issuer,
        settings.oidc_discovery_url,
        *settings.oidc_endpoint_allowed_origins,
    ]
    return {provider_origin(value) for value in configured if value}


def validate_provider_endpoint(value: str, settings: Settings) -> None:
    validate_provider_url(value, settings.environment == "production")
    if provider_origin(value) not in allowed_provider_origins(settings):
        raise ValueError("OIDC endpoint origin is not allowed")


def base64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def claim_text(
    claims: dict[str, Any],
    name: str,
    maximum_length: int,
    *,
    required: bool = False,
) -> str | None:
    value = claims.get(name)
    if value is None:
        if required:
            raise ValueError(f"{name} claim is required")
        return None
    if (
        not isinstance(value, str)
        or len(value) > maximum_length
        or required and not value
    ):
        raise ValueError(f"{name} claim is invalid")
    return value


def validate_identity_claim_text(claims: dict[str, Any]) -> None:
    claim_text(claims, "sub", 255, required=True)
    claim_text(claims, "preferred_username", 256)
    claim_text(claims, "email", 320)
    claim_text(claims, "name", 1000)


def create_oidc_transaction(settings: Settings) -> tuple[str, dict[str, str]]:
    now = datetime.now(UTC)
    values = {
        "state": secrets.token_urlsafe(32),
        "nonce": secrets.token_urlsafe(32),
        "code_verifier": secrets.token_urlsafe(64),
    }
    token = jwt.encode(
        {
            **values,
            "iss": settings.token_issuer,
            "aud": OIDC_TRANSACTION_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "oidc_transaction",
        },
        settings.secret_key,
        algorithm="HS256",
    )
    return token, values


def decode_oidc_transaction(token: str, settings: Settings) -> dict[str, str]:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            issuer=settings.token_issuer,
            audience=OIDC_TRANSACTION_AUDIENCE,
            options={"require": ["state", "nonce", "code_verifier", "exp", "iat", "type"]},
        )
        if payload["type"] != "oidc_transaction":
            raise OIDCError("invalid OIDC transaction type")
        return payload
    except jwt.PyJWTError as exc:
        raise OIDCError("OIDC login transaction is invalid or expired") from exc


async def fetch_discovery(settings: Settings) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            metadata = await async_json_response(
                client,
                "GET",
                settings.oidc_discovery_url,
                maximum_bytes=OIDC_RESPONSE_MAXIMUM_BYTES,
            )
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(metadata.get(field), str) or not metadata[field]:
                raise ValueError(f"missing {field}")
        if metadata["issuer"].rstrip("/") != settings.oidc_issuer.rstrip("/"):
            raise ValueError("discovered issuer does not match configured issuer")
        validate_provider_url(metadata["issuer"], settings.environment == "production")
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            validate_provider_endpoint(metadata[field], settings)
        return metadata
    except (AttributeError, httpx.HTTPError, ValueError, TypeError) as exc:
        raise OIDCError("OIDC provider metadata is unavailable or invalid") from exc


def authorization_url(
    metadata: dict[str, Any], settings: Settings, transaction: dict[str, str]
) -> str:
    parameters = {
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "response_type": "code",
        "scope": settings.oidc_scopes,
        "state": transaction["state"],
        "nonce": transaction["nonce"],
        "code_challenge": base64url_sha256(transaction["code_verifier"]),
        "code_challenge_method": "S256",
    }
    parts = urlsplit(metadata["authorization_endpoint"])
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(parameters)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


async def exchange_code(
    code: str,
    transaction: dict[str, str],
    metadata: dict[str, Any],
    settings: Settings,
) -> dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_uri,
        "client_id": settings.oidc_client_id,
        "code_verifier": transaction["code_verifier"],
    }
    auth = None
    if settings.oidc_client_secret:
        secret = settings.oidc_client_secret.get_secret_value()
        supported = metadata.get(
            "token_endpoint_auth_methods_supported", ["client_secret_basic"]
        )
        if "client_secret_basic" in supported:
            auth = (settings.oidc_client_id, secret)
        else:
            data["client_secret"] = secret
    try:
        validate_provider_endpoint(metadata["token_endpoint"], settings)
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            payload = await async_json_response(
                client,
                "POST",
                metadata["token_endpoint"],
                maximum_bytes=OIDC_RESPONSE_MAXIMUM_BYTES,
                data=data,
                auth=auth,
            )
        if not isinstance(payload.get("id_token"), str):
            raise ValueError("id_token missing")
        return payload
    except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
        raise OIDCError("OIDC authorization code exchange failed") from exc


async def validate_id_token(
    id_token: str,
    expected_nonce: str,
    metadata: dict[str, Any],
    settings: Settings,
) -> dict[str, Any]:
    try:
        validate_provider_endpoint(metadata["jwks_uri"], settings)
        header = jwt.get_unverified_header(id_token)
        algorithm = header.get("alg")
        key_id = header.get("kid")
        provider_algorithms = set(
            metadata.get("id_token_signing_alg_values_supported", SUPPORTED_ID_TOKEN_ALGORITHMS)
        )
        if algorithm not in SUPPORTED_ID_TOKEN_ALGORITHMS or algorithm not in provider_algorithms:
            raise ValueError("unsupported signing algorithm")
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            jwks = await async_json_response(
                client,
                "GET",
                metadata["jwks_uri"],
                maximum_bytes=OIDC_RESPONSE_MAXIMUM_BYTES,
            )
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise ValueError("JWKS must contain a keys array")
        if len(jwks["keys"]) > 100 or not all(
            isinstance(item, dict) for item in jwks["keys"]
        ):
            raise ValueError("JWKS keys are invalid")
        matching = next(
            (item for item in jwks.get("keys", []) if item.get("kid") == key_id), None
        )
        if not matching:
            raise ValueError("signing key not found")
        if matching.get("use") not in (None, "sig") or (
            matching.get("key_ops") is not None
            and "verify" not in matching["key_ops"]
        ):
            raise ValueError("key is not authorized for signature verification")
        key = jwt.PyJWK.from_dict(matching, algorithm=algorithm).key
        claims = jwt.decode(
            id_token,
            key,
            algorithms=[algorithm],
            audience=settings.oidc_client_id,
            issuer=metadata["issuer"],
            options={"require": ["sub", "iss", "aud", "exp", "iat", "nonce"]},
        )
        validate_identity_claim_text(claims)
        nonce = claim_text(claims, "nonce", 512, required=True)
        if nonce is None or not secrets.compare_digest(nonce, expected_nonce):
            raise ValueError("nonce mismatch")
        audience = claims["aud"]
        if isinstance(audience, str):
            audiences = [audience]
        elif (
            isinstance(audience, list)
            and 1 <= len(audience) <= 20
            and all(
                isinstance(item, str) and 1 <= len(item) <= 256
                for item in audience
            )
        ):
            audiences = audience
        else:
            raise ValueError("audience claim is invalid")
        authorized_party = claim_text(claims, "azp", 256)
        if (
            len(audiences) > 1
            and authorized_party != settings.oidc_client_id
        ) or (
            authorized_party is not None
            and authorized_party != settings.oidc_client_id
        ):
            raise ValueError("authorized party mismatch")
        return claims
    except (httpx.HTTPError, jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise OIDCError("OIDC identity token validation failed") from exc


def claim_groups(claims: dict[str, Any]) -> set[str]:
    raw = claims.get("groups", [])
    if isinstance(raw, str):
        raw = [raw]
    if isinstance(raw, list) and all(isinstance(group, str) for group in raw):
        if len(raw) > 200 or any(not group or len(group) > 256 for group in raw):
            raise OIDCError("OIDC groups claim exceeds limits")
        return set(raw)
    raise OIDCError("OIDC groups claim is invalid")


def resolve_oidc_role(groups: set[str], settings: Settings) -> str:
    precedence = {"auditor": 0, "operator": 1, "admin": 2}
    mapped = [
        settings.oidc_role_mapping[group]
        for group in groups
        if group in settings.oidc_role_mapping
    ]
    return max(mapped, key=precedence.__getitem__) if mapped else settings.oidc_default_role


def resolve_oidc_areas(groups: set[str], role: str, settings: Settings) -> list[str] | None:
    if role == "admin":
        return None
    areas = set(settings.oidc_default_areas)
    for group in groups:
        areas.update(settings.oidc_area_mapping.get(group, []))
    return sorted(areas)


def oidc_username(claims: dict[str, Any], provider_id: str, subject: str) -> str:
    preferred = claims.get("preferred_username") or claims.get("email") or ""
    sanitized = USERNAME_PATTERN.sub("_", preferred).strip("_.")[:64]
    if len(sanitized) >= 2:
        return sanitized
    digest = hashlib.sha256(f"{provider_id}:{subject}".encode()).hexdigest()[:20]
    return f"oidc_{digest}"


def resolve_oidc_user(
    db: Session, claims: dict[str, Any], settings: Settings
) -> tuple[User, bool]:
    try:
        validate_identity_claim_text(claims)
    except ValueError as exc:
        raise OIDCError("OIDC identity claims are invalid") from exc
    subject = claims["sub"]
    groups = claim_groups(claims)
    if settings.oidc_allowed_groups and not groups.intersection(settings.oidc_allowed_groups):
        raise OIDCError("OIDC account is not in an allowed group")
    user = db.scalar(
        select(User)
        .where(
            User.identity_provider == settings.oidc_provider_id,
            User.external_subject == subject,
        )
        .with_for_update()
    )
    role = resolve_oidc_role(groups, settings)
    permitted_areas = resolve_oidc_areas(groups, role, settings)
    full_name = (
        claims.get("name")
        or claims.get("preferred_username")
        or "OIDC 用户"
    ).strip()[:100] or "OIDC 用户"
    if user:
        if not user.active:
            raise OIDCError("OIDC account is disabled")
        if user.role != role or user.permitted_areas != permitted_areas:
            user.role = role
            user.permitted_areas = permitted_areas
            user.auth_version += 1
            db.execute(
                update(RefreshSession)
                .where(RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None))
                .values(revoked_at=datetime.now(UTC))
            )
        user.full_name = full_name
        return user, False
    if not settings.oidc_auto_provision:
        raise OIDCError("OIDC account is not provisioned")

    preferred_username = oidc_username(claims, settings.oidc_provider_id, subject)
    suffix = hashlib.sha256(
        f"{settings.oidc_provider_id}:{subject}".encode()
    ).hexdigest()[:16]
    fallback_username = f"oidc_{suffix}"
    candidates = list(dict.fromkeys([preferred_username, fallback_username]))
    for username in candidates:
        if db.scalar(
            select(User.id).where(func.lower(User.username) == username.lower())
        ):
            continue
        user = User(
            username=username,
            full_name=full_name,
            password_hash=hash_password(secrets.token_urlsafe(64)),
            role=role,
            permitted_areas=permitted_areas,
            identity_provider=settings.oidc_provider_id,
            external_subject=subject,
        )
        try:
            with db.begin_nested():
                db.add(user)
                db.flush()
        except IntegrityError:
            existing = db.scalar(
                select(User).where(
                    User.identity_provider == settings.oidc_provider_id,
                    User.external_subject == subject,
                )
            )
            if existing:
                if not existing.active:
                    raise OIDCError("OIDC account is disabled")
                return existing, False
            continue
        return user, True
    raise OIDCError("OIDC username allocation conflict")

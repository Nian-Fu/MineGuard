import asyncio
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api import auth
from app.core.config import Settings
from app.core.database import Base
from app.models import RefreshSession, User
from app.services import oidc


class AsyncResponseStream:
    def __init__(self, response: httpx.Response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *_):
        return None


def oidc_settings(**overrides) -> Settings:
    values = {
        "environment": "test",
        "secret_key": "test-oidc-transaction-secret-key",
        "cors_origins": ["http://console.test"],
        "oidc_enabled": True,
        "oidc_issuer": "https://identity.test",
        "oidc_discovery_url": "https://identity.test/.well-known/openid-configuration",
        "oidc_client_id": "mineguard-test",
        "oidc_redirect_uri": "http://api.test/api/v1/auth/oidc/callback",
        "oidc_post_login_url": "http://console.test/auth/callback",
        "oidc_allowed_groups": ["mineguard-users"],
        "oidc_role_mapping": {"mineguard-admin": "admin"},
        "oidc_auto_provision": True,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_oidc_transaction_is_signed_and_contains_pkce_material():
    settings = oidc_settings()
    token, transaction = oidc.create_oidc_transaction(settings)

    decoded = oidc.decode_oidc_transaction(token, settings)

    assert decoded["state"] == transaction["state"]
    assert decoded["nonce"] == transaction["nonce"]
    assert len(decoded["code_verifier"]) >= 43
    challenge = oidc.base64url_sha256("verifier")
    assert len(challenge) == 43
    assert "=" not in challenge
    with pytest.raises(oidc.OIDCError):
        oidc.decode_oidc_transaction(f"{token}corrupt", settings)


def test_discovery_rejects_endpoints_outside_trusted_origins(monkeypatch):
    settings = oidc_settings()

    class DiscoveryClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        def stream(self, method, url, **_):
            return AsyncResponseStream(
                httpx.Response(
                    200,
                    json={
                        "issuer": settings.oidc_issuer,
                        "authorization_endpoint": "https://identity.test/authorize",
                        "token_endpoint": "https://attacker.test/token",
                        "jwks_uri": "https://identity.test/jwks",
                    },
                    request=httpx.Request(method, url),
                )
            )

    monkeypatch.setattr(oidc.httpx, "AsyncClient", lambda **_: DiscoveryClient())

    with pytest.raises(oidc.OIDCError, match="metadata"):
        asyncio.run(oidc.fetch_discovery(settings))


def test_discovery_allows_an_explicit_cross_origin_endpoint(monkeypatch):
    settings = oidc_settings(
        oidc_endpoint_allowed_origins=["https://tokens.identity.test"]
    )

    class DiscoveryClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        def stream(self, method, url, **_):
            return AsyncResponseStream(
                httpx.Response(
                    200,
                    json={
                        "issuer": settings.oidc_issuer,
                        "authorization_endpoint": "https://identity.test/authorize",
                        "token_endpoint": "https://tokens.identity.test/token",
                        "jwks_uri": "https://identity.test/jwks",
                    },
                    request=httpx.Request(method, url),
                )
            )

    monkeypatch.setattr(oidc.httpx, "AsyncClient", lambda **_: DiscoveryClient())

    metadata = asyncio.run(oidc.fetch_discovery(settings))
    assert metadata["token_endpoint"] == "https://tokens.identity.test/token"


def test_code_exchange_revalidates_endpoint_origin_without_network_access():
    settings = oidc_settings()
    with pytest.raises(oidc.OIDCError, match="exchange"):
        asyncio.run(
            oidc.exchange_code(
                "secret-code",
                {"code_verifier": "verifier"},
                {"token_endpoint": "https://attacker.test/token"},
                settings,
            )
        )


def test_id_token_signature_audience_and_nonce_are_enforced(monkeypatch):
    settings = oidc_settings()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "signing-key", "alg": "RS256", "use": "sig"})

    class JWKSClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        def stream(self, method, url, **_):
            return AsyncResponseStream(
                httpx.Response(
                    200,
                    json={"keys": [public_jwk]},
                    request=httpx.Request(method, url),
                )
            )

    monkeypatch.setattr(oidc.httpx, "AsyncClient", lambda **_: JWKSClient())
    metadata = {
        "issuer": "https://identity.test",
        "jwks_uri": "https://identity.test/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    now = datetime.now(UTC)

    def encoded_token(
        audience="mineguard-test", nonce="expected-nonce", **claim_overrides
    ):
        claims = {
            "sub": "employee-42",
            "iss": metadata["issuer"],
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "nonce": nonce,
        }
        claims.update(claim_overrides)
        return jwt.encode(
            claims,
            private_key,
            algorithm="RS256",
            headers={"kid": "signing-key"},
        )

    claims = asyncio.run(
        oidc.validate_id_token(encoded_token(), "expected-nonce", metadata, settings)
    )
    assert claims["sub"] == "employee-42"
    with pytest.raises(oidc.OIDCError):
        asyncio.run(
            oidc.validate_id_token(
                encoded_token(audience="another-client"),
                "expected-nonce",
                metadata,
                settings,
            )
        )
    with pytest.raises(oidc.OIDCError):
        asyncio.run(
            oidc.validate_id_token(
                encoded_token(nonce="wrong-nonce"),
                "expected-nonce",
                metadata,
                settings,
            )
        )
    for invalid_claims, expected_nonce in [
        ({"sub": 42}, "expected-nonce"),
        ({"nonce": 42}, "42"),
        ({"preferred_username": {"value": "employee"}}, "expected-nonce"),
        ({"name": ["Employee"]}, "expected-nonce"),
    ]:
        with pytest.raises(oidc.OIDCError):
            asyncio.run(
                oidc.validate_id_token(
                    encoded_token(**invalid_claims),
                    expected_nonce,
                    metadata,
                    settings,
                )
            )


def test_oidc_provisioning_does_not_link_an_existing_username():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    settings = oidc_settings()
    with Session(engine) as db:
        db.add(
            User(
                username="Alice",
                full_name="Local Alice",
                password_hash="unused-in-this-test",
                role="operator",
            )
        )
        db.commit()
        external, created = oidc.resolve_oidc_user(
            db,
            {
                "sub": "external-alice",
                "name": "External Alice",
                "preferred_username": "alice",
                "groups": ["mineguard-users", "mineguard-admin"],
            },
            settings,
        )

        assert created is True
        assert external.username.lower() != "alice"
        assert external.identity_provider == settings.oidc_provider_id
        assert external.external_subject == "external-alice"
        assert external.role == "admin"


def test_oidc_group_allowlist_and_disabled_auto_provision_are_enforced():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    claims = {"sub": "external-user", "groups": ["untrusted-group"]}
    with Session(engine) as db:
        with pytest.raises(oidc.OIDCError, match="allowed group"):
            oidc.resolve_oidc_user(db, claims, oidc_settings())
        with pytest.raises(oidc.OIDCError, match="not provisioned"):
            oidc.resolve_oidc_user(
                db,
                {"sub": "external-user", "groups": ["mineguard-users"]},
                oidc_settings(oidc_auto_provision=False),
            )


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": 42, "groups": ["mineguard-users"]},
        {
            "sub": "external-user",
            "preferred_username": ["external-user"],
            "groups": ["mineguard-users"],
        },
        {
            "sub": "external-user",
            "name": {"display": "External User"},
            "groups": ["mineguard-users"],
        },
    ],
)
def test_oidc_user_resolution_rejects_non_string_identity_claims(claims):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        with pytest.raises(oidc.OIDCError, match="identity claims"):
            oidc.resolve_oidc_user(db, claims, oidc_settings())


def test_oidc_groups_resolve_role_and_union_area_scope():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    settings = oidc_settings(
        oidc_role_mapping={"operations": "operator"},
        oidc_area_mapping={
            "shaft-a": ["主井口"],
            "operations": ["运输巷道"],
        },
        oidc_default_areas=["调度室"],
    )
    with Session(engine) as db:
        user, created = oidc.resolve_oidc_user(
            db,
            {
                "sub": "scoped-operator",
                "preferred_username": "scoped.operator",
                "groups": ["mineguard-users", "operations", "shaft-a"],
            },
            settings,
        )

        assert created is True
        assert user.role == "operator"
        assert set(user.permitted_areas) == {"主井口", "运输巷道", "调度室"}


def test_oidc_area_remapping_revokes_existing_sessions():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    first_settings = oidc_settings(
        oidc_role_mapping={"operations": "operator"},
        oidc_area_mapping={"shaft-scope": ["主井口"]},
    )
    claims = {
        "sub": "remapped-user",
        "preferred_username": "remapped.user",
        "groups": ["mineguard-users", "operations", "shaft-scope"],
    }
    with Session(engine) as db:
        user, created = oidc.resolve_oidc_user(db, claims, first_settings)
        assert created is True
        db.commit()
        original_version = user.auth_version
        session = RefreshSession(
            user_id=user.id,
            token_hash="a" * 64,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        db.add(session)
        db.commit()

        remapped, created = oidc.resolve_oidc_user(
            db,
            claims,
            oidc_settings(
                oidc_role_mapping={"operations": "operator"},
                oidc_area_mapping={"shaft-scope": ["运输巷道"]},
            ),
        )
        db.commit()
        db.refresh(session)

        assert created is False
        assert remapped.id == user.id
        assert remapped.permitted_areas == ["运输巷道"]
        assert remapped.auth_version == original_version + 1
        assert session.revoked_at is not None


def test_oidc_http_flow_uses_transaction_and_refresh_cookies(client, monkeypatch):
    settings = oidc_settings()
    metadata = {
        "issuer": settings.oidc_issuer,
        "authorization_endpoint": "https://identity.test/authorize",
        "token_endpoint": "https://identity.test/token",
        "jwks_uri": "https://identity.test/jwks",
    }

    async def fake_discovery(_):
        return metadata

    async def fake_exchange(code, transaction, discovered, configured):
        assert code == "authorization-code"
        assert transaction["code_verifier"]
        assert discovered == metadata
        assert configured is settings
        return {"id_token": "validated-by-test-double"}

    async def fake_validate(id_token, nonce, discovered, configured):
        assert id_token == "validated-by-test-double"
        assert nonce
        assert discovered == metadata
        assert configured is settings
        return {"sub": "admin-subject", "groups": ["mineguard-users"]}

    def fake_resolve(db, claims, configured):
        assert claims["sub"] == "admin-subject"
        assert configured is settings
        return db.scalar(select(User).where(User.username == "admin")), False

    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(auth, "fetch_discovery", fake_discovery)
    monkeypatch.setattr(auth, "exchange_code", fake_exchange)
    monkeypatch.setattr(auth, "validate_id_token", fake_validate)
    monkeypatch.setattr(auth, "resolve_oidc_user", fake_resolve)

    start = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 302
    authorization_query = parse_qs(urlsplit(start.headers["location"]).query)
    assert authorization_query["code_challenge_method"] == ["S256"]
    assert authorization_query["nonce"]
    assert "mineguard_oidc_transaction=" in start.headers["set-cookie"]

    callback = client.get(
        "/api/v1/auth/oidc/callback",
        params={
            "code": "authorization-code",
            "state": authorization_query["state"][0],
        },
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == settings.oidc_post_login_url
    assert "authorization-code" not in callback.headers["location"]
    assert "mineguard_refresh=" in callback.headers["set-cookie"]


def test_oidc_callback_rejects_a_mismatched_state(client, monkeypatch):
    settings = oidc_settings()
    metadata = {
        "issuer": settings.oidc_issuer,
        "authorization_endpoint": "https://identity.test/authorize",
        "token_endpoint": "https://identity.test/token",
        "jwks_uri": "https://identity.test/jwks",
    }

    async def fake_discovery(_):
        return metadata

    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(auth, "fetch_discovery", fake_discovery)
    start = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 302

    callback = client.get(
        "/api/v1/auth/oidc/callback",
        params={"code": "authorization-code", "state": "attacker-state"},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert parse_qs(urlsplit(callback.headers["location"]).query)["oidc_error"] == [
        "authentication_failed"
    ]
    assert "mineguard_oidc_transaction=" in callback.headers["set-cookie"]
    assert "Max-Age=0" in callback.headers["set-cookie"]

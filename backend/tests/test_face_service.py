import base64
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidTag
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api.faces import identify_candidates
from app.core.config import Settings
from app.core.database import Base, SessionLocal
from app.models import FaceTemplate, Person, User
from app.rotate_face_templates import rotate_face_templates
from app.services.face import TemplateCipher, cosine_similarity, parse_face_embedding


def test_face_template_encryption_round_trip_and_aad_binding():
    key = base64.b64encode(bytes(range(32))).decode()
    cipher = TemplateCipher(key)
    embedding = [0.25, -0.5, 0.75, 1.0] * 16
    encrypted, nonce = cipher.encrypt(embedding, b"person-1:model-1")
    assert bytes(str(embedding), "utf-8") not in encrypted
    assert cipher.decrypt(encrypted, nonce, b"person-1:model-1") == pytest.approx(embedding)
    with pytest.raises(InvalidTag):
        cipher.decrypt(encrypted, nonce, b"person-2:model-1")
    with pytest.raises(ValueError, match="64-2048"):
        cipher.encrypt([0.1] * 63, b"person-1:model-1")


def test_cosine_similarity():
    assert cosine_similarity([1, 0], [1, 0]) == pytest.approx(1)
    assert cosine_similarity([1, 0], [0, 1]) == pytest.approx(0)
    with pytest.raises(ValueError):
        cosine_similarity([1], [1, 2])


def valid_provider_payload():
    return {
        "embedding": [0.01] * 128,
        "quality": 0.9,
        "liveness": 0.95,
        "face_count": 1,
        "provider": "approved-provider",
        "model_version": "face-v1",
        "model_sha256": "a" * 64,
    }


def test_face_provider_payload_requires_strict_numeric_contract():
    parsed = parse_face_embedding(valid_provider_payload())
    assert len(parsed.embedding) == 128
    assert parsed.face_count == 1

    for field, value in (
        ("quality", "0.9"),
        ("quality", 10**10_000),
        ("liveness", True),
        ("face_count", 1.0),
    ):
        payload = {**valid_provider_payload(), field: value}
        with pytest.raises(ValueError):
            parse_face_embedding(payload)

    for invalid_value in (True, "0.01", float("nan"), float("inf")):
        payload = valid_provider_payload()
        payload["embedding"] = [invalid_value] * 128
        with pytest.raises(ValueError, match="embedding"):
            parse_face_embedding(payload)


def test_face_provider_identity_must_fit_persistence_contract():
    for field, value in (
        ("provider", ""),
        ("provider", "p" * 51),
        ("model_version", " version-with-whitespace "),
        ("model_version", "v" * 101),
        ("model_sha256", "not-a-sha256"),
    ):
        payload = {**valid_provider_payload(), field: value}
        with pytest.raises(ValueError, match="provider identity"):
            parse_face_embedding(payload)


def test_corrupted_face_template_fails_closed_with_stable_service_error(
    monkeypatch,
):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    settings = Settings(
        _env_file=None,
        face_template_key=key,
        face_template_key_version="v1",
        face_match_threshold=0.72,
    )
    monkeypatch.setattr("app.api.faces.get_settings", lambda: settings)
    digest = "a" * 64
    cipher = TemplateCipher(key)
    associated_data = f"1:face-v1:{digest}".encode("utf-8")
    encrypted, nonce = cipher.encrypt([0.01] * 128, associated_data)
    corrupted = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        person = Person(
            id=1,
            employee_no="CORRUPT-001",
            name="Integrity Test",
            department="QA",
        )
        db.add(person)
        db.add(
            FaceTemplate(
                person_id=1,
                provider="test-provider",
                model_version="face-v1",
                model_sha256=digest,
                key_version="v1",
                encrypted_embedding=corrupted,
                nonce=nonce,
                quality=0.9,
                liveness=0.9,
                consent_reference="CONSENT-CORRUPT",
                active=True,
                created_by=1,
            )
        )
        db.commit()

        with pytest.raises(HTTPException) as raised:
            identify_candidates(
                db,
                SimpleNamespace(
                    embedding=[0.01] * 128,
                    model_version="face-v1",
                    model_sha256=digest,
                ),
                None,
            )

    assert raised.value.status_code == 503
    assert raised.value.detail == "人脸模板完整性校验失败"


def test_face_template_brute_force_capacity_fails_closed(monkeypatch):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    settings = Settings(
        _env_file=None,
        face_template_key=key,
        face_template_key_version="v1",
        face_match_threshold=0.72,
    )
    monkeypatch.setattr("app.api.faces.get_settings", lambda: settings)
    monkeypatch.setattr("app.api.faces.FACE_TEMPLATE_MATCH_MAXIMUM", 1)
    digest = "a" * 64
    cipher = TemplateCipher(key)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        for person_id in (1, 2):
            person = Person(
                id=person_id,
                employee_no=f"CAPACITY-{person_id:03d}",
                name=f"Capacity subject {person_id}",
                department="QA",
            )
            associated_data = f"{person_id}:face-v1:{digest}".encode("utf-8")
            encrypted, nonce = cipher.encrypt([0.01] * 128, associated_data)
            db.add(person)
            db.add(
                FaceTemplate(
                    person_id=person_id,
                    provider="test-provider",
                    model_version="face-v1",
                    model_sha256=digest,
                    key_version="v1",
                    encrypted_embedding=encrypted,
                    nonce=nonce,
                    quality=0.9,
                    liveness=0.9,
                    consent_reference=f"CONSENT-CAPACITY-{person_id}",
                    active=True,
                    created_by=1,
                )
            )
        db.commit()

        with pytest.raises(HTTPException) as raised:
            identify_candidates(
                db,
                SimpleNamespace(
                    embedding=[0.01] * 128,
                    model_version="face-v1",
                    model_sha256=digest,
                ),
                None,
            )

    assert raised.value.status_code == 503
    assert raised.value.detail == "人脸模板检索容量已达到上限"


def test_face_template_rotation_reencrypts_old_rows(monkeypatch):
    old_key = base64.b64encode(b"o" * 32).decode("ascii")
    current_key = base64.b64encode(b"n" * 32).decode("ascii")
    settings = Settings(
        _env_file=None,
        face_template_key=current_key,
        face_template_key_version="current",
        face_template_previous_keys={"old": old_key},
    )
    embedding = [0.01] * 128
    associated_data = b"1:face-v1"
    encrypted, nonce = TemplateCipher(old_key).encrypt(
        embedding, associated_data
    )
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        template = FaceTemplate(
            person_id=1,
            provider="test-provider",
            model_version="face-v1",
            key_version="old",
            encrypted_embedding=encrypted,
            nonce=nonce,
            quality=0.9,
            liveness=0.9,
            consent_reference="CONSENT-ROTATE",
            active=True,
            created_by=1,
        )
        db.add(template)
        db.commit()
        template_id = template.id
        monkeypatch.setattr(
            "app.rotate_face_templates.get_settings", lambda: settings
        )

        assert rotate_face_templates(db) == 1
        db.expire_all()
        rotated = db.get(FaceTemplate, template_id)
        assert rotated is not None
        assert rotated.key_version == "current"
        assert TemplateCipher(current_key).decrypt(
            rotated.encrypted_embedding,
            rotated.nonce,
            associated_data,
        ) == pytest.approx(embedding)


def test_face_template_rotation_validates_all_rows_before_writing(monkeypatch):
    old_key = base64.b64encode(b"o" * 32).decode("ascii")
    current_key = base64.b64encode(b"n" * 32).decode("ascii")
    settings = Settings(
        _env_file=None,
        face_template_key=current_key,
        face_template_key_version="current",
        face_template_previous_keys={"old": old_key},
    )
    cipher = TemplateCipher(old_key)
    first_encrypted, first_nonce = cipher.encrypt([0.01] * 128, b"1:face-v1")
    second_encrypted, second_nonce = cipher.encrypt([0.02] * 128, b"2:face-v1")
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = FaceTemplate(
            person_id=1,
            provider="test-provider",
            model_version="face-v1",
            key_version="old",
            encrypted_embedding=first_encrypted,
            nonce=first_nonce,
            quality=0.9,
            liveness=0.9,
            consent_reference="CONSENT-FIRST",
            active=True,
            created_by=1,
        )
        invalid = FaceTemplate(
            person_id=2,
            provider="test-provider",
            model_version="face-v1",
            key_version="old",
            encrypted_embedding=(
                second_encrypted[:-1] + bytes([second_encrypted[-1] ^ 1])
            ),
            nonce=second_nonce,
            quality=0.9,
            liveness=0.9,
            consent_reference="CONSENT-INVALID",
            active=True,
            created_by=1,
        )
        db.add_all([first, invalid])
        db.commit()
        first_id = first.id
        monkeypatch.setattr(
            "app.rotate_face_templates.get_settings", lambda: settings
        )

        with pytest.raises(InvalidTag):
            rotate_face_templates(db)
        db.expire_all()
        unchanged = db.get(FaceTemplate, first_id)
        assert unchanged is not None
        assert unchanged.key_version == "old"


def test_face_endpoint_is_explicitly_unavailable_without_provider(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "MineGuard@123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    response = client.post(
        "/api/v1/faces/identify",
        headers=headers,
        files={"image": ("face.jpg", b"not-retained", "image/jpeg")},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "人脸推理服务尚未启用"


def test_auditor_cannot_initiate_face_identification(client):
    admin_login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "MineGuard@123"},
    )
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
    created = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "face-auditor",
            "full_name": "人脸审计员",
            "password": "FaceAuditor123",
            "role": "auditor",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "face-auditor", "password": "FaceAuditor123"},
    )
    response = client.post(
        "/api/v1/faces/identify",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        files={"image": ("face.jpg", b"not-retained", "image/jpeg")},
    )
    assert response.status_code == 403


def test_admin_can_apply_a_legal_hold_to_an_inactive_face_template(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "MineGuard@123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    person_response = client.post(
        "/api/v1/persons",
        headers=headers,
        json={
            "employee_no": "FACE-HOLD-001",
            "name": "Face Hold Person",
            "department": "Safety",
        },
    )
    assert person_response.status_code == 201

    with SessionLocal() as db:
        person = db.scalar(
            select(Person).where(Person.employee_no == "FACE-HOLD-001")
        )
        admin = db.scalar(select(User).where(User.username == "admin"))
        template = FaceTemplate(
            person_id=person.id,
            provider="test",
            model_version="1",
            key_version="v1",
            encrypted_embedding=b"inactive-template",
            nonce=b"3" * 12,
            quality=0.9,
            liveness=0.9,
            consent_reference="FACE-HOLD-CONSENT",
            active=False,
            created_by=admin.id,
        )
        db.add(template)
        db.commit()
        template_id = template.id

    held = client.patch(
        f"/api/v1/faces/templates/{template_id}/legal-hold",
        headers=headers,
        json={"enabled": True, "reason": "Biometric evidence order CASE-2026-02"},
    )
    assert held.status_code == 200
    assert held.json()["legal_hold"] is True
    assert held.json()["person"] == {
        "id": person_response.json()["id"],
        "employee_no": "FACE-HOLD-001",
        "name": "Face Hold Person",
    }
    listed = client.get(
        "/api/v1/faces/templates?page=1&page_size=1", headers=headers
    )
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["page_size"] == 1
    assert listed.json()["items"][0]["person"]["employee_no"] == "FACE-HOLD-001"

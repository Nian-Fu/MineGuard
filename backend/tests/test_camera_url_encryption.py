import base64

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import Base
from app.models import Camera
from app.rotate_camera_urls import rotate_camera_urls
from app.services.camera_urls import CameraUrlCipher, CameraUrlCipherError


def encoded_key(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def test_camera_url_cipher_round_trip_does_not_store_plaintext():
    cipher = CameraUrlCipher("v2", encoded_key(b"c" * 32))
    url = "rtsps://camera-user:secret@camera.internal/shaft-1"
    encrypted = cipher.encrypt(url, b"mineguard:camera-url:CAM-001")

    assert url.encode("utf-8") not in encrypted.ciphertext
    assert len(encrypted.nonce) == 12
    assert encrypted.key_version == "v2"
    assert cipher.decrypt(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.key_version,
        b"mineguard:camera-url:CAM-001",
    ) == url


def test_camera_url_cipher_binds_ciphertext_to_camera_identity():
    cipher = CameraUrlCipher("v1", encoded_key(b"d" * 32))
    encrypted = cipher.encrypt(
        "rtsp://camera.internal/shaft-1", b"mineguard:camera-url:CAM-001"
    )
    with pytest.raises(CameraUrlCipherError, match="authentication"):
        cipher.decrypt(
            encrypted.ciphertext,
            encrypted.nonce,
            encrypted.key_version,
            b"mineguard:camera-url:CAM-002",
        )


def test_camera_url_cipher_reads_previous_key_during_rotation():
    old = CameraUrlCipher("old", encoded_key(b"o" * 32))
    encrypted = old.encrypt("rtsp://camera.internal/old", b"camera")
    rotated = CameraUrlCipher(
        "current",
        encoded_key(b"n" * 32),
        {"old": encoded_key(b"o" * 32)},
    )
    assert rotated.decrypt(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.key_version,
        b"camera",
    ) == "rtsp://camera.internal/old"


def test_camera_model_encrypts_url_and_authenticates_camera_code(monkeypatch):
    settings = Settings(
        _env_file=None,
        camera_url_key=encoded_key(b"m" * 32),
        camera_url_key_version="model-v1",
    )
    monkeypatch.setattr(
        "app.services.camera_urls.get_settings", lambda: settings
    )
    url = "rtsp://reader:secret@camera.internal/live"
    camera = Camera(
        code="CAM-SECURE",
        name="secure camera",
        area="shaft-a",
        stream_url=url,
        playback_path="/media/cam-secure/index.m3u8",
    )
    assert camera._legacy_stream_url is None
    assert url.encode("utf-8") not in camera.stream_url_ciphertext
    assert camera.stream_url == url

    camera.code = "CAM-SWAPPED"
    with pytest.raises(CameraUrlCipherError, match="authentication"):
        _ = camera.stream_url


def test_camera_url_rotation_reencrypts_old_rows_after_validating_all(monkeypatch):
    old_settings = Settings(
        _env_file=None,
        camera_url_key=encoded_key(b"o" * 32),
        camera_url_key_version="old",
    )
    current_settings = Settings(
        _env_file=None,
        camera_url_key=encoded_key(b"n" * 32),
        camera_url_key_version="current",
        camera_url_previous_keys={"old": encoded_key(b"o" * 32)},
    )
    monkeypatch.setattr(
        "app.services.camera_urls.get_settings", lambda: old_settings
    )
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        camera = Camera(
            code="CAM-ROTATE",
            name="rotation camera",
            area="shaft-a",
            stream_url="rtsps://reader:secret@camera.internal/rotation",
            playback_path="/media/cam-rotate/index.m3u8",
        )
        db.add(camera)
        db.commit()
        camera_id = camera.id

        monkeypatch.setattr(
            "app.rotate_camera_urls.get_settings", lambda: current_settings
        )
        monkeypatch.setattr(
            "app.services.camera_urls.get_settings", lambda: current_settings
        )
        assert rotate_camera_urls(db) == 1
        db.expire_all()
        rotated = db.get(Camera, camera_id)
        assert rotated is not None
        assert rotated.stream_url_key_version == "current"
        assert rotated.stream_url == "rtsps://reader:secret@camera.internal/rotation"


def test_camera_url_rotation_rolls_back_when_any_ciphertext_is_invalid(monkeypatch):
    old_settings = Settings(
        _env_file=None,
        camera_url_key=encoded_key(b"o" * 32),
        camera_url_key_version="old",
    )
    current_settings = Settings(
        _env_file=None,
        camera_url_key=encoded_key(b"n" * 32),
        camera_url_key_version="current",
        camera_url_previous_keys={"old": encoded_key(b"o" * 32)},
    )
    monkeypatch.setattr(
        "app.services.camera_urls.get_settings", lambda: old_settings
    )
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        valid = Camera(
            code="CAM-VALID",
            name="valid camera",
            area="shaft-a",
            stream_url="rtsp://camera.internal/valid",
            playback_path="/media/cam-valid/index.m3u8",
        )
        invalid = Camera(
            code="CAM-INVALID",
            name="invalid camera",
            area="shaft-a",
            stream_url="rtsp://camera.internal/invalid",
            playback_path="/media/cam-invalid/index.m3u8",
        )
        db.add_all([valid, invalid])
        db.commit()
        valid_id = valid.id
        invalid.stream_url_ciphertext = b"corrupt-ciphertext"
        db.commit()

        monkeypatch.setattr(
            "app.rotate_camera_urls.get_settings", lambda: current_settings
        )
        monkeypatch.setattr(
            "app.services.camera_urls.get_settings", lambda: current_settings
        )
        with pytest.raises(CameraUrlCipherError, match="authentication"):
            rotate_camera_urls(db)

        db.expire_all()
        unchanged = db.get(Camera, valid_id)
        assert unchanged is not None
        assert unchanged.stream_url_key_version == "old"

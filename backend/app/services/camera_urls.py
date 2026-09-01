import base64
import binascii
import os
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings, get_settings


class CameraUrlCipherError(RuntimeError):
    pass


@dataclass(frozen=True)
class EncryptedCameraUrl:
    ciphertext: bytes
    nonce: bytes
    key_version: str


class CameraUrlCipher:
    def __init__(
        self,
        key_version: str,
        encoded_key: str,
        previous_keys: dict[str, str] | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,50}", key_version):
            raise ValueError("camera URL key version is invalid")
        encoded_keys = {**(previous_keys or {}), key_version: encoded_key}
        if len(encoded_keys) != len(previous_keys or {}) + 1:
            raise ValueError("current camera URL key version cannot also be previous")
        self.key_version = key_version
        self._keys = {
            version: AESGCM(self._decode_key(version, value))
            for version, value in encoded_keys.items()
        }

    @staticmethod
    def _decode_key(version: str, encoded_key: str) -> bytes:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,50}", version):
            raise ValueError("camera URL key version is invalid")
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("camera URL key must be valid base64") from exc
        if len(key) != 32:
            raise ValueError("camera URL key must decode to exactly 32 bytes")
        return key

    def encrypt(self, value: str, associated_data: bytes) -> EncryptedCameraUrl:
        encoded = value.encode("utf-8")
        if not encoded or len(encoded) > 2048:
            raise ValueError("camera URL plaintext length is invalid")
        nonce = os.urandom(12)
        return EncryptedCameraUrl(
            ciphertext=self._keys[self.key_version].encrypt(
                nonce, encoded, associated_data
            ),
            nonce=nonce,
            key_version=self.key_version,
        )

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        key_version: str,
        associated_data: bytes,
    ) -> str:
        cipher = self._keys.get(key_version)
        if cipher is None:
            raise CameraUrlCipherError(
                f"camera URL key version {key_version!r} is unavailable"
            )
        if len(nonce) != 12 or not ciphertext:
            raise CameraUrlCipherError("encrypted camera URL is malformed")
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise CameraUrlCipherError(
                "encrypted camera URL failed authentication"
            ) from exc


def camera_url_cipher_from_settings(
    settings: Settings | None = None,
) -> CameraUrlCipher | None:
    configured = settings or get_settings()
    if not configured.camera_url_key:
        return None
    return CameraUrlCipher(
        configured.camera_url_key_version,
        configured.camera_url_key.get_secret_value(),
        {
            version: key.get_secret_value()
            for version, key in configured.camera_url_previous_keys.items()
        },
    )

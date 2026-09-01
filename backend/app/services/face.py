import base64
import math
import os
import re
import struct
from dataclasses import dataclass

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.http_payloads import async_json_response


class FaceServiceError(RuntimeError):
    pass


FACE_PROVIDER_RESPONSE_MAXIMUM_BYTES = 256 * 1024
FACE_EMBEDDING_MINIMUM_DIMENSIONS = 64
FACE_EMBEDDING_MAXIMUM_DIMENSIONS = 2048
FLOAT32_MAXIMUM = 3.4028234663852886e38


@dataclass(frozen=True)
class FaceEmbedding:
    embedding: list[float]
    quality: float
    liveness: float
    face_count: int
    provider: str
    model_version: str
    model_sha256: str


def parse_face_embedding(payload: object) -> FaceEmbedding:
    if not isinstance(payload, dict):
        raise ValueError("face provider result must be an object")
    raw_embedding = payload.get("embedding")
    if (
        not isinstance(raw_embedding, list)
        or not FACE_EMBEDDING_MINIMUM_DIMENSIONS
        <= len(raw_embedding)
        <= FACE_EMBEDDING_MAXIMUM_DIMENSIONS
    ):
        raise ValueError("embedding dimension is outside the accepted range")
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        for value in raw_embedding
    ):
        raise ValueError("embedding must contain only numeric values")
    try:
        embedding = [float(value) for value in raw_embedding]
    except OverflowError as exc:
        raise ValueError("embedding contains an unrepresentable value") from exc
    if not all(
        math.isfinite(value) and abs(value) <= FLOAT32_MAXIMUM
        for value in embedding
    ):
        raise ValueError("embedding must contain finite float32 values")

    numeric_scores = (payload.get("quality"), payload.get("liveness"))
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        for value in numeric_scores
    ):
        raise ValueError("quality and liveness must be numeric")
    try:
        quality, liveness = (float(value) for value in numeric_scores)
    except OverflowError as exc:
        raise ValueError("quality or liveness is unrepresentable") from exc
    if not math.isfinite(quality) or not math.isfinite(liveness):
        raise ValueError("quality and liveness must be finite")
    if not 0 <= quality <= 1 or not 0 <= liveness <= 1:
        raise ValueError("quality and liveness scores must be between zero and one")

    face_count = payload.get("face_count")
    if isinstance(face_count, bool) or not isinstance(face_count, int):
        raise ValueError("face_count must be an integer")
    if not 0 <= face_count <= 100:
        raise ValueError("face_count is outside the accepted range")

    provider = payload.get("provider")
    model_version = payload.get("model_version")
    model_sha256 = payload.get("model_sha256")
    if (
        not isinstance(provider, str)
        or not 1 <= len(provider) <= 50
        or provider.strip() != provider
        or not isinstance(model_version, str)
        or not 1 <= len(model_version) <= 100
        or model_version.strip() != model_version
        or not isinstance(model_sha256, str)
        or not re.fullmatch(r"[a-fA-F0-9]{64}", model_sha256)
    ):
        raise ValueError("provider identity is invalid")
    return FaceEmbedding(
        embedding=embedding,
        quality=quality,
        liveness=liveness,
        face_count=face_count,
        provider=provider,
        model_version=model_version,
        model_sha256=model_sha256.lower(),
    )


class TemplateCipher:
    def __init__(self, encoded_key: str) -> None:
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except ValueError as exc:
            raise ValueError("face template key must be valid base64") from exc
        if len(key) != 32:
            raise ValueError("face template key must decode to exactly 32 bytes")
        self._cipher = AESGCM(key)

    def encrypt(self, embedding: list[float], associated_data: bytes) -> tuple[bytes, bytes]:
        if (
            not FACE_EMBEDDING_MINIMUM_DIMENSIONS
            <= len(embedding)
            <= FACE_EMBEDDING_MAXIMUM_DIMENSIONS
            or not all(
                math.isfinite(value) and abs(value) <= FLOAT32_MAXIMUM
                for value in embedding
            )
        ):
            raise ValueError("embedding must contain 64-2048 finite float32 values")
        try:
            plaintext = struct.pack(f"!{len(embedding)}f", *embedding)
        except (OverflowError, struct.error) as exc:
            raise ValueError("embedding cannot be represented as float32") from exc
        nonce = os.urandom(12)
        return self._cipher.encrypt(nonce, plaintext, associated_data), nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes, associated_data: bytes) -> list[float]:
        if (
            not isinstance(ciphertext, bytes)
            or not FACE_EMBEDDING_MINIMUM_DIMENSIONS * 4 + 16
            <= len(ciphertext)
            <= FACE_EMBEDDING_MAXIMUM_DIMENSIONS * 4 + 16
            or not isinstance(nonce, bytes)
            or len(nonce) != 12
        ):
            raise ValueError("encrypted embedding metadata is invalid")
        plaintext = self._cipher.decrypt(nonce, ciphertext, associated_data)
        if (
            len(plaintext) % 4
            or not FACE_EMBEDDING_MINIMUM_DIMENSIONS * 4
            <= len(plaintext)
            <= FACE_EMBEDDING_MAXIMUM_DIMENSIONS * 4
        ):
            raise ValueError("invalid encrypted embedding length")
        embedding = list(struct.unpack(f"!{len(plaintext) // 4}f", plaintext))
        if not all(math.isfinite(value) for value in embedding):
            raise ValueError("encrypted embedding contains non-finite values")
        return embedding


def face_template_associated_data(
    person_id: int,
    model_version: str,
    model_sha256: str | None,
) -> bytes:
    identity = f"{person_id}:{model_version}"
    if model_sha256 is not None:
        identity = f"{identity}:{model_sha256}"
    return identity.encode("utf-8")


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        raise ValueError("embeddings must have the same non-zero dimension")
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        raise ValueError("zero-length embedding vector")
    return max(-1.0, min(1.0, dot / (left_norm * right_norm)))


class HttpFaceProvider:
    def __init__(self, base_url: str, timeout_seconds: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def embed(self, image: bytes, content_type: str) -> FaceEmbedding:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                payload = await async_json_response(
                    client,
                    "POST",
                    f"{self.base_url}/v1/embeddings",
                    maximum_bytes=FACE_PROVIDER_RESPONSE_MAXIMUM_BYTES,
                    files={"image": ("face-image", image, content_type)},
                )
            return parse_face_embedding(payload)
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise FaceServiceError("face inference service unavailable or returned an invalid result") from exc

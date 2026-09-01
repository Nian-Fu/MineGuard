import hashlib
import hmac
from pathlib import Path


MAXIMUM_MODEL_ARTIFACT_BYTES = 512 * 1024 * 1024


def resolve_model_path(path: Path) -> Path:
    candidates = [path]
    if path.suffix.lower() != ".zip":
        candidates.append(Path(f"{path}.zip"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"model artifact does not exist: {path}")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        while chunk := artifact.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha256(path: Path, expected_sha256: str) -> str:
    normalized = normalize_sha256(expected_sha256)
    actual = sha256_file(path)
    if not hmac.compare_digest(actual, normalized):
        raise ValueError("model artifact SHA-256 does not match the approved digest")
    return actual


def normalize_sha256(expected_sha256: str) -> str:
    normalized = expected_sha256.strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(
            "expected model SHA-256 must contain 64 hexadecimal characters"
        )
    return normalized


def read_verified_artifact(
    path: Path,
    expected_sha256: str,
    *,
    maximum_bytes: int = MAXIMUM_MODEL_ARTIFACT_BYTES,
    chunk_size: int = 1024 * 1024,
) -> tuple[bytes, str]:
    """Freeze and authenticate the exact bytes that will be deserialized."""
    normalized = normalize_sha256(expected_sha256)
    if maximum_bytes <= 0 or chunk_size <= 0:
        raise ValueError("artifact read limits must be positive")
    digest = hashlib.sha256()
    artifact_bytes = bytearray()
    with path.open("rb") as artifact:
        while chunk := artifact.read(min(chunk_size, maximum_bytes + 1)):
            artifact_bytes.extend(chunk)
            if len(artifact_bytes) > maximum_bytes:
                raise ValueError(
                    f"model artifact exceeds the {maximum_bytes}-byte safety limit"
                )
            digest.update(chunk)
    actual = digest.hexdigest()
    if not hmac.compare_digest(actual, normalized):
        raise ValueError("model artifact SHA-256 does not match the approved digest")
    return bytes(artifact_bytes), actual

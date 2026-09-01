import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class ModelManifest:
    model_name: str
    algorithm_type: str
    model_version: str
    artifact_path: Path
    sha256: str
    runtime: str
    license_id: str
    input_name: str
    output_name: str
    input_width: int
    input_height: int
    class_names: tuple[str, ...]

    @classmethod
    def load(cls, manifest_path: str | Path, model_root: str | Path) -> "ModelManifest":
        manifest_file = Path(manifest_path).resolve()
        root = Path(model_root).resolve()
        try:
            if manifest_file.stat().st_size > 64 * 1024:
                raise ManifestError("model manifest exceeds 64 KiB")
            payload: dict[str, Any] = json.loads(manifest_file.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ManifestError("model manifest must be a JSON object")
            raw_class_names = payload["class_names"]
            if not isinstance(raw_class_names, list):
                raise ManifestError("class_names must be a JSON array")
            string_fields = (
                "model_name",
                "algorithm_type",
                "model_version",
                "artifact",
                "sha256",
                "runtime",
                "license_id",
            )
            if any(not isinstance(payload.get(name), str) for name in string_fields):
                raise ManifestError("model manifest identity fields must be strings")
            if any(not isinstance(name, str) for name in raw_class_names):
                raise ManifestError("class_names must contain only strings")
            if any(
                isinstance(payload.get(name), bool)
                or not isinstance(payload.get(name), int)
                for name in ("input_width", "input_height")
            ):
                raise ManifestError("model input dimensions must be integers")
            for optional_name in ("input_name", "output_name"):
                if optional_name in payload and not isinstance(
                    payload[optional_name], str
                ):
                    raise ManifestError("model tensor names must be strings")
            artifact = (root / payload["artifact"]).resolve()
            artifact.relative_to(root)
            manifest = cls(
                model_name=payload["model_name"],
                algorithm_type=payload["algorithm_type"],
                model_version=payload["model_version"],
                artifact_path=artifact,
                sha256=payload["sha256"].lower(),
                runtime=payload["runtime"],
                license_id=payload["license_id"],
                input_name=payload.get("input_name", "images"),
                output_name=payload.get("output_name", "output0"),
                input_width=payload["input_width"],
                input_height=payload["input_height"],
                class_names=tuple(name.strip() for name in raw_class_names),
            )
        except ManifestError:
            raise
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ManifestError("model manifest is missing, malformed, or escapes model_root") from exc
        manifest.validate()
        return manifest

    def validate(self) -> None:
        if (
            not re.fullmatch(r"[a-zA-Z0-9_.-]{1,120}", self.model_name)
            or not re.fullmatch(r"[a-z0-9_.-]{2,50}", self.algorithm_type)
            or not self.model_version
            or len(self.model_version) > 100
            or self.model_version.strip() != self.model_version
            or not self.runtime
            or len(self.runtime) > 50
            or self.runtime.strip() != self.runtime
            or not self.license_id
            or len(self.license_id) > 100
            or self.license_id.strip() != self.license_id
        ):
            raise ManifestError("model identity fields cannot be empty")
        if len(self.sha256) != 64 or any(char not in "0123456789abcdef" for char in self.sha256):
            raise ManifestError("sha256 must contain 64 lowercase hexadecimal characters")
        if (
            not 32 <= self.input_width <= 4096
            or not 32 <= self.input_height <= 4096
            or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", self.input_name)
            or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", self.output_name)
            or not self.class_names
            or len(self.class_names) > 1000
            or len(self.class_names) != len(set(self.class_names))
            or any(
                not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", name)
                for name in self.class_names
            )
        ):
            raise ManifestError("model input dimensions and class names are invalid")
        if not self.artifact_path.is_file():
            raise ManifestError("model artifact does not exist")

    def verify_artifact(self, chunk_size: int = 1024 * 1024) -> None:
        if not 4096 <= chunk_size <= 16 * 1024 * 1024:
            raise ValueError("artifact hash chunk size is invalid")
        digest = hashlib.sha256()
        with self.artifact_path.open("rb") as artifact:
            while chunk := artifact.read(chunk_size):
                digest.update(chunk)
        if digest.hexdigest() != self.sha256:
            raise ManifestError("model artifact SHA-256 does not match manifest")

    def edge_report(self, ready: bool = True) -> dict[str, str | bool]:
        return {
            "algorithm_type": self.algorithm_type,
            "model_version": self.model_version,
            "sha256": self.sha256,
            "runtime": self.runtime,
            "ready": ready,
        }

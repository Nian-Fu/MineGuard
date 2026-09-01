import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from mineguard_rl.integrity import MAXIMUM_MODEL_ARTIFACT_BYTES, sha256_file


MAXIMUM_CHECKPOINT_METADATA_BYTES = 1024 * 1024
PPO_ROLLOUT_STEPS = 1024
TRAINING_TRACE_LENGTH = 4000


def reject_json_constant(value: str):
    raise ValueError(f"invalid JSON constant: {value}")


def checkpoint_metadata_path(output: Path) -> Path:
    return output.with_suffix(".checkpoint.json")


def checkpoint_model_paths(output: Path) -> list[Path]:
    prefix = f"{output.name}.checkpoint."
    return [
        path
        for path in output.parent.iterdir()
        if path.is_file()
        and path.name.startswith(prefix)
        and path.name.endswith(".zip")
    ]


def checkpoint_temporary_paths(output: Path) -> list[Path]:
    prefix = f".{output.name}.checkpoint-"
    return [
        path for path in output.parent.iterdir() if path.name.startswith(prefix)
    ]


def training_source_digests(project_root: Path) -> dict[str, str]:
    sources = (
        project_root / "train.py",
        project_root / "mineguard_rl" / "checkpoints.py",
        project_root / "mineguard_rl" / "environment.py",
        project_root / "mineguard_rl" / "traces.py",
    )
    return {
        source.relative_to(project_root).as_posix(): sha256_file(source)
        for source in sources
    }


def read_checkpoint_metadata(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAXIMUM_CHECKPOINT_METADATA_BYTES:
        raise RuntimeError(f"checkpoint metadata is missing or oversized: {path}")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_json_constant,
    )
    if not isinstance(value, dict):
        raise RuntimeError("checkpoint metadata must be a JSON object")
    return value


def _valid_sha256(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_training_checkpoint(
    output: Path,
    *,
    seed: int,
    target_timesteps: int,
    source_sha256: dict[str, str],
    training_trace_sha256: str,
    rollout_steps: int = PPO_ROLLOUT_STEPS,
) -> dict | None:
    metadata_path = checkpoint_metadata_path(output)
    candidate_models = checkpoint_model_paths(output)
    if not candidate_models and not metadata_path.exists():
        return None
    if not metadata_path.is_file():
        raise RuntimeError("checkpoint metadata commit marker is missing")

    metadata = read_checkpoint_metadata(metadata_path)
    model = metadata.get("model")
    completed_timesteps = metadata.get("completed_timesteps")
    if metadata.get("format_version") != 1 or not isinstance(model, dict):
        raise RuntimeError("checkpoint metadata structure is invalid")
    if metadata.get("seed") != seed or metadata.get("target_timesteps") != target_timesteps:
        raise RuntimeError("checkpoint does not match the requested training run")
    if (
        not isinstance(completed_timesteps, int)
        or isinstance(completed_timesteps, bool)
        or not 1 <= completed_timesteps <= target_timesteps + rollout_steps - 1
    ):
        raise RuntimeError("checkpoint contains invalid completed timesteps")
    if metadata.get("rollout_steps") != rollout_steps:
        raise RuntimeError("checkpoint rollout size does not match the current trainer")
    if metadata.get("source_sha256") != source_sha256:
        raise RuntimeError("checkpoint source identity does not match the current trainer")
    if metadata.get("training_trace_sha256") != training_trace_sha256:
        raise RuntimeError("checkpoint training trace identity does not match")

    expected_sha256 = model.get("sha256")
    model_filename = model.get("filename")
    if model.get("algorithm") != "sha256" or not _valid_sha256(expected_sha256):
        raise RuntimeError("checkpoint contains an invalid model digest")
    if (
        not isinstance(model_filename, str)
        or Path(model_filename).name != model_filename
        or not model_filename.startswith(f"{output.name}.checkpoint.")
        or not model_filename.endswith(".zip")
    ):
        raise RuntimeError("checkpoint contains an invalid model filename")
    model_path = output.parent / model_filename
    if not model_path.is_file():
        raise RuntimeError("checkpoint model referenced by metadata is missing")
    model_size = model.get("size_bytes")
    if (
        not isinstance(model_size, int)
        or isinstance(model_size, bool)
        or not 0 < model_size <= MAXIMUM_MODEL_ARTIFACT_BYTES
        or model_size != model_path.stat().st_size
    ):
        raise RuntimeError("checkpoint model size does not match its metadata")
    if sha256_file(model_path) != expected_sha256:
        raise RuntimeError("checkpoint model digest does not match its metadata")
    return {
        "completed_timesteps": completed_timesteps,
        "model_path": model_path,
        "model_sha256": expected_sha256,
        "metadata_path": metadata_path,
    }


def archive_training_checkpoint(output: Path, recovery_root: Path, reason: str) -> Path | None:
    metadata_path = checkpoint_metadata_path(output)
    existing = [
        path
        for path in (
            metadata_path,
            *checkpoint_model_paths(output),
            *checkpoint_temporary_paths(output),
        )
        if path.exists()
    ]
    if not existing:
        return None
    archive = recovery_root / f"{output.name}-{int(time.time())}-{uuid4().hex[:8]}"
    archive.mkdir(parents=True, exist_ok=False)
    for path in existing:
        shutil.move(str(path), archive / path.name)
    atomic_write_json(archive / "recovery.json", {"reason": reason})
    fsync_directory(output.parent)
    fsync_directory(recovery_root)
    return archive


def archive_checkpoint_partials(
    output: Path,
    recovery_root: Path,
    reason: str,
    *,
    keep_model: Path | None = None,
) -> list[Path]:
    archives = []
    paths = checkpoint_temporary_paths(output)
    paths.extend(
        path for path in checkpoint_model_paths(output) if path != keep_model
    )
    for path in paths:
        archive = recovery_root / (
            f"{output.name}-partial-{int(time.time())}-{uuid4().hex[:8]}"
        )
        archive.mkdir(parents=True, exist_ok=False)
        shutil.move(str(path), archive / path.name)
        atomic_write_json(archive / "recovery.json", {"reason": reason})
        fsync_directory(output.parent)
        fsync_directory(recovery_root)
        archives.append(archive)
    return archives


def discard_training_checkpoint(output: Path) -> None:
    metadata_path = checkpoint_metadata_path(output)
    metadata_path.unlink(missing_ok=True)
    for model_path in checkpoint_model_paths(output):
        model_path.unlink(missing_ok=True)
    fsync_directory(output.parent)


def discard_superseded_checkpoint_models(output: Path, keep_model: Path) -> None:
    for model_path in checkpoint_model_paths(output):
        if model_path != keep_model:
            model_path.unlink(missing_ok=True)
    fsync_directory(output.parent)


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".partial",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as artifact:
            json.dump(payload, artifact, indent=2, allow_nan=False)
            artifact.write("\n")
            artifact.flush()
            os.fsync(artifact.fileno())
        os.replace(temporary_path, path)
        fsync_directory(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

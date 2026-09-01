import hashlib
import json
from pathlib import Path

import pytest

from mineguard_rl.checkpoints import (
    archive_checkpoint_partials,
    archive_training_checkpoint,
    checkpoint_metadata_path,
    validate_training_checkpoint,
)


SOURCE_DIGESTS = {"train.py": "a" * 64}
TRACE_DIGEST = "b" * 64


def write_checkpoint(output: Path, model_bytes: bytes = b"checkpoint-model") -> None:
    model_path = output.parent / f"{output.name}.checkpoint.10240.test.zip"
    metadata_path = checkpoint_metadata_path(output)
    model_path.write_bytes(model_bytes)
    model_digest = hashlib.sha256(model_bytes).hexdigest()
    metadata_path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "seed": 42,
                "target_timesteps": 20_000,
                "completed_timesteps": 10_240,
                "rollout_steps": 1024,
                "training_trace_sha256": TRACE_DIGEST,
                "source_sha256": SOURCE_DIGESTS,
                "model": {
                    "algorithm": "sha256",
                    "filename": model_path.name,
                    "sha256": model_digest,
                    "size_bytes": len(model_bytes),
                },
            }
        ),
        encoding="utf-8",
    )


def test_valid_checkpoint_is_discovered_and_bound_to_training_request(tmp_path):
    output = tmp_path / "ppo-42"
    write_checkpoint(output)

    checkpoint = validate_training_checkpoint(
        output,
        seed=42,
        target_timesteps=20_000,
        source_sha256=SOURCE_DIGESTS,
        training_trace_sha256=TRACE_DIGEST,
    )

    assert checkpoint is not None
    assert checkpoint["completed_timesteps"] == 10_240
    assert checkpoint["model_path"].read_bytes() == b"checkpoint-model"


def test_corrupt_checkpoint_is_rejected_and_archived_without_overwrite(tmp_path):
    output = tmp_path / "ppo-42"
    write_checkpoint(output)
    model_path = output.parent / f"{output.name}.checkpoint.10240.test.zip"
    metadata_path = checkpoint_metadata_path(output)
    model_path.write_bytes(b"corrupt")

    with pytest.raises(RuntimeError, match="size|digest"):
        validate_training_checkpoint(
            output,
            seed=42,
            target_timesteps=20_000,
            source_sha256=SOURCE_DIGESTS,
            training_trace_sha256=TRACE_DIGEST,
        )

    archive = archive_training_checkpoint(
        output, tmp_path / "recovery", "invalid checkpoint"
    )
    assert archive is not None
    assert not model_path.exists()
    assert not metadata_path.exists()
    assert (archive / model_path.name).read_bytes() == b"corrupt"
    assert (archive / metadata_path.name).is_file()


def test_uncommitted_new_generation_does_not_replace_last_valid_checkpoint(tmp_path):
    output = tmp_path / "ppo-42"
    write_checkpoint(output)
    orphan = output.parent / f"{output.name}.checkpoint.15000.orphan.zip"
    orphan.write_bytes(b"uncommitted-new-generation")

    checkpoint = validate_training_checkpoint(
        output,
        seed=42,
        target_timesteps=20_000,
        source_sha256=SOURCE_DIGESTS,
        training_trace_sha256=TRACE_DIGEST,
    )
    archives = archive_checkpoint_partials(
        output,
        tmp_path / "recovery",
        "orphaned generation",
        keep_model=checkpoint["model_path"],
    )

    assert checkpoint["model_path"].read_bytes() == b"checkpoint-model"
    assert len(archives) == 1
    assert (archives[0] / orphan.name).read_bytes() == b"uncommitted-new-generation"

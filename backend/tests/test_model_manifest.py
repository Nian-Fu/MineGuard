import hashlib
import json

import pytest

from app.edge.model_manifest import ManifestError, ModelManifest


def write_manifest(tmp_path, artifact_name: str, digest: str, **overrides):
    path = tmp_path / "manifest.json"
    payload = {
        "model_name": "mine_detector",
        "algorithm_type": "object_detection",
        "model_version": "1.0.0",
        "artifact": artifact_name,
        "sha256": digest,
        "runtime": "tensorrt-10",
        "license_id": "Apache-2.0",
        "input_width": 640,
        "input_height": 640,
        "class_names": ["person", "helmet", "no_helmet"],
    }
    payload.update(overrides)
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    return path


def test_manifest_verifies_real_artifact_hash(tmp_path):
    artifact = tmp_path / "model.engine"
    artifact.write_bytes(b"approved-model-artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = ModelManifest.load(write_manifest(tmp_path, artifact.name, digest), tmp_path)
    manifest.verify_artifact()
    assert manifest.edge_report()["sha256"] == digest


def test_manifest_rejects_tampering_and_path_escape(tmp_path):
    artifact = tmp_path / "model.engine"
    artifact.write_bytes(b"tampered")
    manifest = ModelManifest.load(write_manifest(tmp_path, artifact.name, "a" * 64), tmp_path)
    with pytest.raises(ManifestError, match="does not match"):
        manifest.verify_artifact()
    with pytest.raises(ManifestError, match="escapes"):
        ModelManifest.load(write_manifest(tmp_path, "../outside.engine", "a" * 64), tmp_path)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"class_names": "person"}, "JSON array"),
        ({"class_names": [1, "helmet"]}, "only strings"),
        ({"model_version": 1}, "must be strings"),
        ({"artifact": {"path": "model.engine"}}, "must be strings"),
        ({"input_width": "640"}, "must be integers"),
        ({"input_name": 7}, "tensor names must be strings"),
        ({"class_names": ["person", "person"]}, "dimensions and class names"),
        ({"input_width": 100_000}, "dimensions and class names"),
    ],
)
def test_manifest_rejects_unbounded_or_ambiguous_shapes(
    tmp_path, overrides, message
):
    artifact = tmp_path / "model.engine"
    artifact.write_bytes(b"model")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    path = write_manifest(tmp_path, artifact.name, digest, **overrides)
    with pytest.raises(ManifestError, match=message):
        ModelManifest.load(path, tmp_path)


def test_manifest_rejects_files_larger_than_64_kib(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(" " * (64 * 1024 + 1), encoding="utf-8")
    with pytest.raises(ManifestError, match="64 KiB"):
        ModelManifest.load(path, tmp_path)

import hashlib

import pytest

from mineguard_rl.integrity import read_verified_artifact, require_sha256


def test_require_sha256_accepts_the_approved_artifact(tmp_path):
    artifact = tmp_path / "candidate.zip"
    artifact.write_bytes(b"approved model bytes")
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()

    assert require_sha256(artifact, expected.upper()) == expected


def test_require_sha256_rejects_an_artifact_mismatch(tmp_path):
    artifact = tmp_path / "candidate.zip"
    artifact.write_bytes(b"unapproved model bytes")

    with pytest.raises(ValueError, match="does not match"):
        require_sha256(artifact, "0" * 64)


@pytest.mark.parametrize("digest", ["", "a" * 63, "g" * 64])
def test_require_sha256_rejects_an_invalid_expected_digest(tmp_path, digest):
    artifact = tmp_path / "candidate.zip"
    artifact.write_bytes(b"model bytes")

    with pytest.raises(ValueError, match="64 hexadecimal"):
        require_sha256(artifact, digest)


def test_read_verified_artifact_returns_the_authenticated_snapshot(tmp_path):
    artifact = tmp_path / "candidate.zip"
    approved = b"approved immutable model snapshot"
    artifact.write_bytes(approved)
    expected = hashlib.sha256(approved).hexdigest()

    frozen, actual = read_verified_artifact(artifact, expected)
    artifact.write_bytes(b"replacement after verification")

    assert frozen == approved
    assert actual == expected


def test_read_verified_artifact_rejects_oversized_input(tmp_path):
    artifact = tmp_path / "candidate.zip"
    artifact.write_bytes(b"12345")
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="safety limit"):
        read_verified_artifact(artifact, expected, maximum_bytes=4, chunk_size=2)

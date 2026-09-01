import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

import run_training_study as study
from run_training_study import (
    StudyLock,
    archive_incomplete_run,
    atomic_write_json,
    parse_deadline,
    run_training_process,
    validate_completed_run,
    validate_training_seeds,
)


def test_training_study_accepts_five_independent_seeds():
    seeds = [20260827, 20260828, 20260829, 20260830, 20260831]
    assert validate_training_seeds(seeds) == seeds


@pytest.mark.parametrize(
    "seeds",
    [
        [1, 2, 3, 4],
        [1, 2, 3, 4, 4],
        [20260822, 2, 3, 4, 5],
        [20260812, 2, 3, 4, 5],
        [20260807, 2, 3, 4, 5],
    ],
)
def test_training_study_rejects_insufficient_duplicate_or_reserved_seeds(seeds):
    with pytest.raises(ValueError):
        validate_training_seeds(seeds)


def test_training_deadline_requires_an_explicit_offset():
    assert parse_deadline("2026-08-27T23:59:59+08:00").utcoffset().total_seconds() == 28800
    with pytest.raises(ValueError, match="explicit UTC offset"):
        parse_deadline("2026-08-27T23:59:59")


def test_completed_training_run_is_bound_to_model_metrics_and_request(tmp_path):
    output = tmp_path / "ppo-42"
    model_path = tmp_path / "ppo-42.zip"
    model_path.write_bytes(b"authenticated-model")
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    output.with_suffix(".development_metrics.json").write_text(
        json.dumps({"model_sha256": digest}),
        encoding="utf-8",
    )
    output.with_suffix(".training_manifest.json").write_text(
        json.dumps(
            {
                "model": {"sha256": digest, "size_bytes": model_path.stat().st_size},
                "training": {"seed": 42, "timesteps": 1000},
            }
        ),
        encoding="utf-8",
    )

    completed = validate_completed_run(output, 42, 1000)
    assert completed["model_sha256"] == digest
    model_path.write_bytes(b"tampered-model")
    with pytest.raises(RuntimeError, match="digest"):
        validate_completed_run(output, 42, 1000)


def test_incomplete_training_run_is_archived_without_deletion(tmp_path):
    output = tmp_path / "ppo-99"
    partial_model = tmp_path / "ppo-99.zip"
    partial_model.write_bytes(b"partial")

    archive = archive_incomplete_run(
        output,
        tmp_path / "recovery",
        "interrupted",
    )

    assert archive is not None
    assert not partial_model.exists()
    assert (archive / partial_model.name).read_bytes() == b"partial"
    assert json.loads((archive / "recovery.json").read_text(encoding="utf-8")) == {
        "reason": "interrupted"
    }


def write_completed_run(output, seed, timesteps):
    model_path = output.parent / f"{output.name}.zip"
    model_path.write_bytes(f"model-{seed}".encode())
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    output.with_suffix(".development_metrics.json").write_text(
        json.dumps({"model_sha256": digest}), encoding="utf-8"
    )
    output.with_suffix(".training_manifest.json").write_text(
        json.dumps(
            {
                "model": {
                    "sha256": digest,
                    "size_bytes": model_path.stat().st_size,
                },
                "training": {"seed": seed, "timesteps": timesteps},
            }
        ),
        encoding="utf-8",
    )


def configure_lightweight_study(monkeypatch):
    monkeypatch.setattr(study, "training_source_digests", lambda _: {})
    monkeypatch.setattr(study, "generate_trace", lambda *_: [])
    monkeypatch.setattr(study, "trace_sha256", lambda _: "b" * 64)


def test_completed_seeds_are_skipped_and_manifest_never_selects_a_candidate(
    tmp_path, monkeypatch
):
    seeds = [20260827, 20260828, 20260829, 20260830, 20260831]
    for seed in seeds:
        write_completed_run(tmp_path / f"ppo-{seed}", seed, 1000)
    configure_lightweight_study(monkeypatch)
    monkeypatch.setattr(
        study,
        "run_training_process",
        lambda *_: pytest.fail("completed seeds must not launch a subprocess"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_training_study.py",
            "--timesteps",
            "1000",
            "--output-dir",
            str(tmp_path),
        ],
    )

    study.main()

    manifest = json.loads((tmp_path / "study_manifest.json").read_text())
    state = json.loads((tmp_path / "study_state.json").read_text())
    assert manifest["selection_status"] == "not_selected"
    assert state["selection_status"] == "not_selected"
    assert state["status"] == "completed"
    assert len(manifest["runs"]) == 5


def test_failed_child_without_deadline_is_not_retried(tmp_path, monkeypatch):
    configure_lightweight_study(monkeypatch)
    calls = []
    monkeypatch.setattr(
        study,
        "run_training_process",
        lambda *_: calls.append("called") or 9,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_training_study.py", "--output-dir", str(tmp_path)],
    )

    with pytest.raises(RuntimeError, match="failed with exit code 9"):
        study.main()
    assert calls == ["called"]


def test_failed_child_with_deadline_is_retried(tmp_path, monkeypatch):
    configure_lightweight_study(monkeypatch)
    monkeypatch.setattr(study, "wait_for_retry", lambda *_: None)
    calls = 0

    class RetryObserved(Exception):
        pass

    def fail_then_observe_retry(*_):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RetryObserved
        return 9

    monkeypatch.setattr(study, "run_training_process", fail_then_observe_retry)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_training_study.py",
            "--output-dir",
            str(tmp_path),
            "--deadline",
            "2099-08-27T23:59:59+08:00",
        ],
    )

    with pytest.raises(RetryObserved):
        study.main()
    assert calls == 2


def test_elapsed_deadline_writes_recoverable_state_and_exits_75(
    tmp_path, monkeypatch
):
    configure_lightweight_study(monkeypatch)
    monkeypatch.setattr(
        study,
        "run_training_process",
        lambda *_: pytest.fail("an elapsed deadline must not start training"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_training_study.py",
            "--output-dir",
            str(tmp_path),
            "--deadline",
            "2000-01-01T00:00:00+08:00",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        study.main()

    state = json.loads((tmp_path / "study_state.json").read_text())
    assert exit_info.value.code == 75
    assert state["status"] == "deadline_reached"
    assert state["selection_status"] == "not_selected"


def test_existing_state_cannot_be_reused_for_a_different_study(
    tmp_path, monkeypatch
):
    configure_lightweight_study(monkeypatch)
    atomic_write_json(
        tmp_path / "study_state.json",
        {
            "training_seeds": [20260827, 20260828, 20260829, 20260830, 20260831],
            "timesteps_per_run": 123,
            "attempts": {},
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_training_study.py", "--output-dir", str(tmp_path)],
    )

    with pytest.raises(RuntimeError, match="does not match"):
        study.main()


def test_deadline_terminates_training_child(monkeypatch):
    class FakeProcess:
        returncode = None
        terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True
            self.returncode = 124

        def wait(self, timeout=None):
            return 0

    class FakeLock:
        def heartbeat(self):
            pass

    process = FakeProcess()
    monkeypatch.setattr(study.subprocess, "Popen", lambda _: process)
    deadline = datetime.now(timezone.utc) - timedelta(seconds=1)

    assert run_training_process(["trainer"], FakeLock(), deadline) == 124
    assert process.terminated is True


def test_live_lock_is_rejected_even_when_heartbeat_is_old(tmp_path):
    lock_path = tmp_path / ".study.lock"
    lock_path.mkdir()
    atomic_write_json(
        lock_path / "heartbeat.json",
        {
            "owner": "other",
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "updated_at_epoch": 0,
        },
    )

    with pytest.raises(RuntimeError, match="live lock"):
        StudyLock(tmp_path, stale_seconds=1).acquire()


def test_stale_lock_is_archived_and_replaced(tmp_path):
    lock_path = tmp_path / ".study.lock"
    lock_path.mkdir()
    atomic_write_json(
        lock_path / "heartbeat.json",
        {
            "owner": "stale",
            "pid": os.getpid(),
            "host": "different-host",
            "updated_at_epoch": 0,
        },
    )
    old_timestamp = time.time() - 60
    os.utime(lock_path, (old_timestamp, old_timestamp))

    lock = StudyLock(tmp_path, stale_seconds=1)
    lock.acquire()
    assert lock.acquired is True
    lock.close()
    archived = list((tmp_path / "recovery" / "locks").iterdir())
    assert len(archived) == 1
    assert (archived[0] / "heartbeat.json").is_file()

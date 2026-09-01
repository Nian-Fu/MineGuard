import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

import run_training_supervisor as supervisor
from run_training_supervisor import (
    SupervisorLock,
    archive_invalid_state,
    parse_deadline,
    retry_delay,
    run_study_process,
    validate_completed_study,
)


def test_supervisor_deadline_requires_explicit_offset():
    deadline = parse_deadline("2026-08-27T23:59:59+08:00")
    assert deadline.utcoffset().total_seconds() == 28800
    with pytest.raises(ValueError, match="explicit UTC offset"):
        parse_deadline("2026-08-27T23:59:59")


def test_supervisor_retry_delay_is_exponential_and_capped():
    assert retry_delay(1, 30) == 30
    assert retry_delay(2, 30) == 60
    assert retry_delay(20, 30) == 300


def test_supervisor_lock_rejects_a_second_live_owner(tmp_path):
    first = SupervisorLock(tmp_path)
    second = SupervisorLock(tmp_path)
    first.acquire()
    try:
        with pytest.raises(RuntimeError, match="holds the lock"):
            second.acquire()
    finally:
        first.close()

    second.acquire()
    second.close()


def test_supervisor_deadline_terminates_the_study_process_tree(monkeypatch):
    class FakeProcess:
        pid = 1234
        returncode = None

        def poll(self):
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda *_, **__: process)

    def terminate(fake_process):
        fake_process.returncode = 75

    monkeypatch.setattr(supervisor, "terminate_process_tree", terminate)
    monkeypatch.setattr(supervisor, "DEADLINE_GRACE_SECONDS", 0)
    deadline = datetime.now(timezone.utc) - timedelta(seconds=1)

    result = run_study_process(["study"], deadline, lambda _: None)

    assert result == 75
    assert process.returncode == 75


def write_completed_study(tmp_path):
    seed = 1
    timesteps = 1000
    deadline = "2026-08-27T23:59:59+08:00"
    model_path = tmp_path / "ppo-1.zip"
    model_path.write_bytes(b"completed-model")
    model_digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    training_manifest_path = tmp_path / "ppo-1.training_manifest.json"
    metrics_path = tmp_path / "ppo-1.development_metrics.json"
    training_manifest_path.write_text(
        json.dumps(
            {
                "training": {"seed": seed, "timesteps": timesteps},
                "model": {
                    "sha256": model_digest,
                    "size_bytes": model_path.stat().st_size,
                },
            }
        ),
        encoding="utf-8",
    )
    metrics_path.write_text(
        json.dumps({"model_sha256": model_digest}), encoding="utf-8"
    )
    run = {
        "seed": seed,
        "model_sha256": model_digest,
        "training_manifest": training_manifest_path.name,
        "training_manifest_sha256": hashlib.sha256(
            training_manifest_path.read_bytes()
        ).hexdigest(),
        "development_metrics": metrics_path.name,
        "development_metrics_sha256": hashlib.sha256(
            metrics_path.read_bytes()
        ).hexdigest(),
    }
    study_manifest = {
        "selection_status": "not_selected",
        "training_seeds": [seed],
        "timesteps_per_run": timesteps,
        "runs": [run],
    }
    (tmp_path / "study_manifest.json").write_text(
        json.dumps(study_manifest), encoding="utf-8"
    )
    state_path = tmp_path / "study_state.json"
    state_path.write_text(
        json.dumps({**study_manifest, "status": "completed", "deadline": deadline}),
        encoding="utf-8",
    )
    return state_path, model_path, deadline


def test_completed_study_must_remain_unselected_and_match_request(tmp_path):
    state_path, _, deadline = write_completed_study(tmp_path)

    validate_completed_study(
        state_path,
        seeds=[1],
        timesteps=1000,
        deadline=deadline,
    )
    state = json.loads(state_path.read_text())
    state["selection_status"] = "selected"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(RuntimeError, match="select"):
        validate_completed_study(
            state_path,
            seeds=[1],
            timesteps=1000,
            deadline=deadline,
        )


def test_completed_study_rejects_a_tampered_model(tmp_path):
    state_path, model_path, deadline = write_completed_study(tmp_path)
    model_path.write_bytes(b"tampered-model")

    with pytest.raises(RuntimeError, match="size|digest"):
        validate_completed_study(
            state_path,
            seeds=[1],
            timesteps=1000,
            deadline=deadline,
        )


def test_invalid_supervisor_state_is_archived_without_overwrite(tmp_path):
    state_path = tmp_path / "supervisor_state.json"
    state_path.write_text("{invalid", encoding="utf-8")

    archive = archive_invalid_state(
        state_path,
        tmp_path / "recovery",
        "invalid JSON",
    )

    assert not state_path.exists()
    assert (archive / state_path.name).read_text() == "{invalid"
    assert json.loads((archive / "recovery.json").read_text()) == {
        "reason": "invalid JSON"
    }

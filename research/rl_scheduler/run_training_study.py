import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from mineguard_rl.bandit import DEVELOPMENT_BANDIT_SEEDS
from mineguard_rl.checkpoints import (
    archive_checkpoint_partials,
    archive_training_checkpoint,
    atomic_write_json,
    discard_training_checkpoint,
    TRAINING_TRACE_LENGTH,
    training_source_digests,
    validate_training_checkpoint,
)
from mineguard_rl.integrity import (
    MAXIMUM_MODEL_ARTIFACT_BYTES,
    resolve_model_path,
    sha256_file,
)
from mineguard_rl.traces import EVALUATION_SEEDS, generate_trace, trace_sha256


DEFAULT_TRAINING_SEEDS = tuple(range(20260827, 20260832))
DEVELOPMENT_EVALUATION_SEEDS = tuple(range(20260812, 20260817))
LOCK_STALE_SECONDS = 120
MAXIMUM_RETRY_SECONDS = 300


def reject_json_constant(value: str):
    raise ValueError(f"invalid JSON constant: {value}")


def validate_training_seeds(seeds: list[int]) -> list[int]:
    if len(seeds) < 5 or len(set(seeds)) != len(seeds):
        raise ValueError("study requires at least five unique training seeds")
    if any(seed < 0 or seed > 2**32 - 1 for seed in seeds):
        raise ValueError("training seeds must be between 0 and 4294967295")
    reserved = set(EVALUATION_SEEDS) | set(DEVELOPMENT_EVALUATION_SEEDS)
    reserved |= set(DEVELOPMENT_BANDIT_SEEDS)
    if reserved.intersection(seeds):
        raise ValueError("training seeds must not reuse development or acceptance seeds")
    return seeds


def read_json(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise RuntimeError(f"study artifact is missing or oversized: {path}")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_json_constant,
    )
    if not isinstance(value, dict):
        raise RuntimeError(f"study artifact must be a JSON object: {path}")
    return value


def parse_deadline(value: str) -> datetime:
    try:
        deadline = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("deadline must be an ISO-8601 timestamp") from exc
    if deadline.tzinfo is None or deadline.utcoffset() is None:
        raise ValueError("deadline must include an explicit UTC offset")
    return deadline


def run_artifact_paths(output: Path) -> tuple[Path, Path, Path]:
    model_path = output if output.suffix.lower() == ".zip" else Path(f"{output}.zip")
    return (
        model_path,
        output.with_suffix(".development_metrics.json"),
        output.with_suffix(".training_manifest.json"),
    )


def validate_completed_run(output: Path, seed: int, timesteps: int) -> dict:
    model_path, metrics_path, manifest_path = run_artifact_paths(output)
    manifest = read_json(manifest_path)
    metrics = read_json(metrics_path)
    training = manifest.get("training")
    model = manifest.get("model")
    if not isinstance(training, dict) or not isinstance(model, dict):
        raise RuntimeError("training manifest structure is invalid")
    if training.get("seed") != seed or training.get("timesteps") != timesteps:
        raise RuntimeError("training manifest does not match the requested run")
    model_sha256 = model.get("sha256")
    if (
        not isinstance(model_sha256, str)
        or len(model_sha256) != 64
        or any(character not in "0123456789abcdef" for character in model_sha256)
    ):
        raise RuntimeError("training manifest contains an invalid model digest")
    resolved_model = resolve_model_path(model_path)
    model_size = model.get("size_bytes")
    if (
        not isinstance(model_size, int)
        or isinstance(model_size, bool)
        or not 0 < model_size <= MAXIMUM_MODEL_ARTIFACT_BYTES
        or model_size != resolved_model.stat().st_size
    ):
        raise RuntimeError("model size does not match the training manifest")
    if sha256_file(resolved_model) != model_sha256:
        raise RuntimeError("model digest does not match the training manifest")
    if metrics.get("model_sha256") != model_sha256:
        raise RuntimeError("development metrics are bound to a different model")
    return {
        "seed": seed,
        "model_sha256": model_sha256,
        "training_manifest": manifest_path.name,
        "training_manifest_sha256": sha256_file(manifest_path),
        "development_metrics": metrics_path.name,
        "development_metrics_sha256": sha256_file(metrics_path),
    }


def archive_incomplete_run(output: Path, recovery_root: Path, reason: str) -> Path | None:
    paths = [*run_artifact_paths(output), output]
    paths.extend(output.parent.glob(f".{output.name}.training-*"))
    existing = list(dict.fromkeys(path for path in paths if path.exists()))
    if not existing:
        return None
    archive = recovery_root / f"{output.name}-{int(time.time())}-{uuid4().hex[:8]}"
    archive.mkdir(parents=True, exist_ok=False)
    for path in existing:
        shutil.move(str(path), archive / path.name)
    atomic_write_json(archive / "recovery.json", {"reason": reason})
    return archive


def archive_invalid_state(path: Path, recovery_root: Path, reason: str) -> Path | None:
    if not path.exists():
        return None
    archive = recovery_root / f"state-{int(time.time())}-{uuid4().hex[:8]}"
    archive.mkdir(parents=True, exist_ok=False)
    shutil.move(str(path), archive / path.name)
    atomic_write_json(archive / "recovery.json", {"reason": reason})
    return archive


def process_is_running(pid: int) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_ulong,
        ]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.GetExitCodeProcess.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.GetExitCodeProcess.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(
            process_query_limited_information, False, pid
        )
        if not handle:
            return ctypes.get_last_error() == 5
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def lock_owner_is_live(heartbeat: dict) -> bool:
    return (
        heartbeat.get("host") == socket.gethostname()
        and process_is_running(heartbeat.get("pid"))
    )


class StudyLock:
    def __init__(self, output_dir: Path, stale_seconds: int = LOCK_STALE_SECONDS) -> None:
        self.path = output_dir / ".study.lock"
        self.recovery_root = output_dir / "recovery" / "locks"
        self.stale_seconds = stale_seconds
        self.owner = uuid4().hex
        self.acquired = False

    def acquire(self) -> None:
        for _ in range(3):
            try:
                self.path.mkdir()
            except FileExistsError:
                heartbeat_path = self.path / "heartbeat.json"
                try:
                    lock_updated_at = self.path.stat().st_mtime
                except OSError:
                    lock_updated_at = 0
                try:
                    heartbeat = read_json(heartbeat_path)
                    updated_at = float(heartbeat["updated_at_epoch"])
                except (KeyError, OSError, TypeError, ValueError, RuntimeError):
                    heartbeat = {}
                    updated_at = 0
                updated_at = max(updated_at, lock_updated_at)
                if (
                    lock_owner_is_live(heartbeat)
                    or time.time() - updated_at <= self.stale_seconds
                ):
                    raise RuntimeError("another training study process holds the live lock")
                self.recovery_root.mkdir(parents=True, exist_ok=True)
                archived_lock = self.recovery_root / (
                    f"stale-{int(time.time())}-{uuid4().hex[:8]}"
                )
                try:
                    os.replace(self.path, archived_lock)
                except (FileExistsError, FileNotFoundError, OSError):
                    continue
            else:
                self.acquired = True
                self.heartbeat()
                return
        raise RuntimeError("could not acquire the training study lock")

    def heartbeat(self) -> None:
        if not self.acquired:
            return
        atomic_write_json(
            self.path / "heartbeat.json",
            {
                "owner": self.owner,
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "updated_at_epoch": time.time(),
            },
        )

    def close(self) -> None:
        if not self.acquired:
            return
        try:
            try:
                heartbeat = read_json(self.path / "heartbeat.json")
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
                return
            if heartbeat.get("owner") != self.owner:
                return
            (self.path / "heartbeat.json").unlink(missing_ok=True)
            self.path.rmdir()
        finally:
            self.acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_):
        self.close()


def run_training_process(command: list[str], lock: StudyLock, deadline: datetime | None) -> int:
    process = subprocess.Popen(command)
    try:
        while process.poll() is None:
            lock.heartbeat()
            if deadline is not None and datetime.now(deadline.tzinfo) >= deadline:
                terminate_process(process)
                return 124
            time.sleep(5)
        return process.returncode
    finally:
        if process.poll() is None:
            terminate_process(process)


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def wait_for_retry(seconds: float, lock: StudyLock, deadline: datetime | None) -> None:
    wake_at = time.monotonic() + seconds
    while time.monotonic() < wake_at:
        lock.heartbeat()
        if deadline is not None and datetime.now(deadline.tzinfo) >= deadline:
            return
        time.sleep(min(5, max(wake_at - time.monotonic(), 0)))


def prepare_training_checkpoint(
    output: Path,
    *,
    seed: int,
    target_timesteps: int,
    source_sha256: dict[str, str],
    training_trace_sha256: str,
    recovery_root: Path,
) -> dict | None:
    try:
        checkpoint = validate_training_checkpoint(
            output,
            seed=seed,
            target_timesteps=target_timesteps,
            source_sha256=source_sha256,
            training_trace_sha256=training_trace_sha256,
        )
    except (json.JSONDecodeError, OSError, RuntimeError, ValueError) as exc:
        archive_training_checkpoint(
            output,
            recovery_root,
            f"{type(exc).__name__}: {exc}",
        )
        checkpoint = None
    archive_checkpoint_partials(
        output,
        recovery_root,
        "orphaned or superseded checkpoint artifact",
        keep_model=checkpoint["model_path"] if checkpoint else None,
    )
    return checkpoint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", nargs="+", type=int, default=DEFAULT_TRAINING_SEEDS)
    parser.add_argument("--timesteps", type=int, default=200_000)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/study"))
    parser.add_argument("--deadline", type=str)
    args = parser.parse_args()
    try:
        seeds = validate_training_seeds(list(args.seeds))
    except ValueError as exc:
        parser.error(str(exc))
    if not 1 <= args.timesteps <= 50_000_000:
        parser.error("--timesteps must be between 1 and 50000000")
    try:
        deadline = parse_deadline(args.deadline) if args.deadline else None
    except ValueError as exc:
        parser.error(str(exc))
    args.output_dir.mkdir(parents=True, exist_ok=True)

    train_script = Path(__file__).resolve().with_name("train.py")
    state_path = args.output_dir / "study_state.json"
    recovery_root = args.output_dir / "recovery" / "runs"
    checkpoint_recovery_root = args.output_dir / "recovery" / "checkpoints"
    project_root = Path(__file__).resolve().parent
    current_source_digests = training_source_digests(project_root)
    attempts = {str(seed): 0 for seed in seeds}

    runs = []
    with StudyLock(args.output_dir) as lock:
        if state_path.exists():
            try:
                previous_state = read_json(state_path)
            except (json.JSONDecodeError, OSError, RuntimeError, ValueError) as exc:
                archive_invalid_state(
                    state_path,
                    recovery_root,
                    f"invalid study state: {type(exc).__name__}",
                )
            else:
                if previous_state.get("training_seeds") != seeds or (
                    previous_state.get("timesteps_per_run") != args.timesteps
                ):
                    raise RuntimeError(
                        "study state does not match the requested seeds and timesteps"
                    )
                previous_attempts = previous_state.get("attempts")
                if not isinstance(previous_attempts, dict):
                    archive_invalid_state(
                        state_path,
                        recovery_root,
                        "invalid study state: attempts must be a JSON object",
                    )
                    previous_attempts = {}
                for seed in seeds:
                    value = previous_attempts.get(str(seed), 0)
                    if (
                        isinstance(value, int)
                        and not isinstance(value, bool)
                        and value >= 0
                    ):
                        attempts[str(seed)] = value
        for seed in seeds:
            output = args.output_dir / f"ppo-{seed}"
            training_trace_digest = trace_sha256(
                generate_trace(TRAINING_TRACE_LENGTH, seed)
            )
            while True:
                try:
                    completed = validate_completed_run(output, seed, args.timesteps)
                except (
                    FileNotFoundError,
                    json.JSONDecodeError,
                    RuntimeError,
                    OSError,
                    ValueError,
                ) as exc:
                    archive_incomplete_run(output, recovery_root, type(exc).__name__)
                else:
                    discard_training_checkpoint(output)
                    runs.append(completed)
                    break

                if deadline is not None and datetime.now(deadline.tzinfo) >= deadline:
                    checkpoint = prepare_training_checkpoint(
                        output,
                        seed=seed,
                        target_timesteps=args.timesteps,
                        source_sha256=current_source_digests,
                        training_trace_sha256=training_trace_digest,
                        recovery_root=checkpoint_recovery_root,
                    )
                    atomic_write_json(
                        state_path,
                        {
                            "selection_status": "not_selected",
                            "status": "deadline_reached",
                            "deadline": deadline.isoformat(),
                            "timesteps_per_run": args.timesteps,
                            "training_seeds": seeds,
                            "attempts": attempts,
                            "completed_runs": runs,
                            "resumable_checkpoint_timesteps": (
                                checkpoint["completed_timesteps"] if checkpoint else 0
                            ),
                        },
                    )
                    raise SystemExit(75)

                checkpoint = prepare_training_checkpoint(
                    output,
                    seed=seed,
                    target_timesteps=args.timesteps,
                    source_sha256=current_source_digests,
                    training_trace_sha256=training_trace_digest,
                    recovery_root=checkpoint_recovery_root,
                )

                attempts[str(seed)] += 1
                atomic_write_json(
                    state_path,
                    {
                        "selection_status": "not_selected",
                        "status": "training",
                        "deadline": deadline.isoformat() if deadline else None,
                        "current_seed": seed,
                        "timesteps_per_run": args.timesteps,
                        "training_seeds": seeds,
                        "attempts": attempts,
                        "completed_runs": runs,
                        "resumed_from_timesteps": (
                            checkpoint["completed_timesteps"] if checkpoint else 0
                        ),
                    },
                )
                return_code = run_training_process(
                    [
                        sys.executable,
                        str(train_script),
                        "--seed",
                        str(seed),
                        "--timesteps",
                        str(args.timesteps),
                        "--output",
                        str(output),
                    ],
                    lock,
                    deadline,
                )
                if return_code == 0:
                    continue
                archive_incomplete_run(
                    output,
                    recovery_root,
                    f"training process exited with code {return_code}",
                )
                if deadline is None:
                    raise RuntimeError(
                        f"training seed {seed} failed with exit code {return_code}"
                    )
                delay = min(2 ** min(attempts[str(seed)] - 1, 9), MAXIMUM_RETRY_SECONDS)
                wait_for_retry(delay, lock, deadline)
        study_manifest = {
            "selection_status": "not_selected",
            "timesteps_per_run": args.timesteps,
            "training_seeds": seeds,
            "runs": runs,
        }
        manifest_path = args.output_dir / "study_manifest.json"
        atomic_write_json(manifest_path, study_manifest)
        atomic_write_json(
            state_path,
            {
                **study_manifest,
                "status": "completed",
                "deadline": deadline.isoformat() if deadline else None,
                "attempts": attempts,
            },
        )
    print(manifest_path)


if __name__ == "__main__":
    main()

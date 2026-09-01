import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from mineguard_rl.checkpoints import atomic_write_json
from mineguard_rl.integrity import MAXIMUM_MODEL_ARTIFACT_BYTES, sha256_file


DEFAULT_TRAINING_SEEDS = tuple(range(20260827, 20260832))
DEFAULT_RESTART_DELAY_SECONDS = 30
MAXIMUM_RESTART_DELAY_SECONDS = 300
DEADLINE_GRACE_SECONDS = 45
SUPERVISOR_HEARTBEAT_SECONDS = 15


def reject_json_constant(value: str):
    raise ValueError(f"invalid JSON constant: {value}")


def parse_deadline(value: str) -> datetime:
    try:
        deadline = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("deadline must be an ISO-8601 timestamp") from exc
    if deadline.tzinfo is None or deadline.utcoffset() is None:
        raise ValueError("deadline must include an explicit UTC offset")
    return deadline


def read_json(path: Path) -> dict:
    if not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024:
        raise RuntimeError(f"supervisor artifact is missing or oversized: {path}")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_json_constant,
    )
    if not isinstance(value, dict):
        raise RuntimeError(f"supervisor artifact must be a JSON object: {path}")
    return value


def archive_invalid_state(path: Path, recovery_root: Path, reason: str) -> Path:
    archive = recovery_root / f"state-{int(time.time())}-{uuid4().hex[:8]}"
    archive.mkdir(parents=True, exist_ok=False)
    os.replace(path, archive / path.name)
    atomic_write_json(archive / "recovery.json", {"reason": reason})
    return archive


class SupervisorLock:
    def __init__(self, output_dir: Path) -> None:
        self.path = output_dir / ".supervisor.lock"
        self.artifact = None
        self.acquired = False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        artifact = self.path.open("a+b")
        try:
            artifact.seek(0, os.SEEK_END)
            if artifact.tell() == 0:
                artifact.write(b"\0")
                artifact.flush()
                os.fsync(artifact.fileno())
            artifact.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(artifact.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(artifact.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            artifact.close()
            raise RuntimeError("another training supervisor holds the lock") from exc
        self.artifact = artifact
        self.acquired = True

    def close(self) -> None:
        if not self.acquired or self.artifact is None:
            return
        try:
            self.artifact.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.artifact.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.artifact.fileno(), fcntl.LOCK_UN)
        finally:
            self.artifact.close()
            self.artifact = None
            self.acquired = False

    def __enter__(self):
        if not self.acquired:
            self.acquire()
        return self

    def __exit__(self, *_):
        self.close()


def terminate_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        taskkill = Path(os.environ.get("SystemRoot", "C:\\Windows")) / (
            "System32/taskkill.exe"
        )
        subprocess.run(
            [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.wait()


def run_study_process(
    command: list[str],
    deadline: datetime,
    heartbeat,
) -> int:
    process_options = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    process = subprocess.Popen(command, **process_options)
    grace_deadline = deadline + timedelta(seconds=DEADLINE_GRACE_SECONDS)
    next_heartbeat = 0.0
    try:
        while process.poll() is None:
            monotonic_now = time.monotonic()
            if monotonic_now >= next_heartbeat:
                heartbeat(process.pid)
                next_heartbeat = monotonic_now + SUPERVISOR_HEARTBEAT_SECONDS
            now = datetime.now(deadline.tzinfo)
            if now >= grace_deadline:
                terminate_process_tree(process)
                return 75
            time.sleep(5)
        return process.returncode
    finally:
        if process.poll() is None:
            terminate_process_tree(process)


def retry_delay(attempt: int, initial_delay: int) -> int:
    return min(
        initial_delay * 2 ** min(max(attempt - 1, 0), 9),
        MAXIMUM_RESTART_DELAY_SECONDS,
    )


def wait_for_restart(seconds: int, deadline: datetime, heartbeat) -> None:
    wake_at = time.monotonic() + seconds
    while time.monotonic() < wake_at:
        heartbeat(None)
        if datetime.now(deadline.tzinfo) >= deadline:
            return
        time.sleep(min(5, max(wake_at - time.monotonic(), 0)))


def validate_completed_study(
    state_path: Path,
    *,
    seeds: list[int],
    timesteps: int,
    deadline: str,
) -> None:
    state = read_json(state_path)
    if state.get("status") != "completed":
        raise RuntimeError("study process exited successfully without completed state")
    if state.get("selection_status") != "not_selected":
        raise RuntimeError("study process attempted to select a candidate automatically")
    if state.get("training_seeds") != seeds or state.get("timesteps_per_run") != timesteps:
        raise RuntimeError("completed study state does not match the supervisor request")
    if state.get("deadline") != deadline:
        raise RuntimeError("completed study state contains a different deadline")
    runs = state.get("runs")
    if not isinstance(runs, list) or len(runs) != len(seeds):
        raise RuntimeError("completed study state does not contain every training run")
    if [run.get("seed") for run in runs if isinstance(run, dict)] != seeds:
        raise RuntimeError("completed study run order or seed identity is invalid")

    manifest_path = state_path.parent / "study_manifest.json"
    study_manifest = read_json(manifest_path)
    expected_manifest = {
        "selection_status": "not_selected",
        "timesteps_per_run": timesteps,
        "training_seeds": seeds,
        "runs": runs,
    }
    if study_manifest != expected_manifest:
        raise RuntimeError("study manifest does not match completed study state")

    for seed, run in zip(seeds, runs, strict=True):
        expected_training_manifest = f"ppo-{seed}.training_manifest.json"
        expected_metrics = f"ppo-{seed}.development_metrics.json"
        if run.get("training_manifest") != expected_training_manifest:
            raise RuntimeError("training manifest filename is invalid")
        if run.get("development_metrics") != expected_metrics:
            raise RuntimeError("development metrics filename is invalid")
        model_path = state_path.parent / f"ppo-{seed}.zip"
        training_manifest_path = state_path.parent / expected_training_manifest
        metrics_path = state_path.parent / expected_metrics
        training_manifest = read_json(training_manifest_path)
        metrics = read_json(metrics_path)
        training = training_manifest.get("training")
        model = training_manifest.get("model")
        if not isinstance(training, dict) or not isinstance(model, dict):
            raise RuntimeError("training manifest structure is invalid")
        if training.get("seed") != seed or training.get("timesteps") != timesteps:
            raise RuntimeError("training manifest request binding is invalid")
        model_sha256 = run.get("model_sha256")
        if model.get("sha256") != model_sha256 or metrics.get(
            "model_sha256"
        ) != model_sha256:
            raise RuntimeError("model and development metric digests are not bound")
        if (
            not isinstance(model_sha256, str)
            or len(model_sha256) != 64
            or any(character not in "0123456789abcdef" for character in model_sha256)
        ):
            raise RuntimeError("completed study contains an invalid model digest")
        model_size = model.get("size_bytes")
        if (
            not isinstance(model_size, int)
            or isinstance(model_size, bool)
            or not 0 < model_size <= MAXIMUM_MODEL_ARTIFACT_BYTES
            or not model_path.is_file()
            or model_path.stat().st_size != model_size
        ):
            raise RuntimeError("completed study contains an invalid model size")
        if sha256_file(model_path) != model_sha256:
            raise RuntimeError("completed study model digest does not match")
        if sha256_file(training_manifest_path) != run.get(
            "training_manifest_sha256"
        ):
            raise RuntimeError("training manifest digest does not match study state")
        if sha256_file(metrics_path) != run.get("development_metrics_sha256"):
            raise RuntimeError("development metrics digest does not match study state")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", nargs="+", type=int, default=DEFAULT_TRAINING_SEEDS)
    parser.add_argument("--timesteps", type=int, default=200_000)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/study"))
    parser.add_argument("--deadline", required=True)
    parser.add_argument(
        "--restart-delay",
        type=int,
        default=DEFAULT_RESTART_DELAY_SECONDS,
    )
    args = parser.parse_args()
    seeds = list(args.seeds)
    if len(seeds) < 5 or len(set(seeds)) != len(seeds):
        parser.error("study requires at least five unique training seeds")
    if not 1 <= args.timesteps <= 50_000_000:
        parser.error("--timesteps must be between 1 and 50000000")
    if not 1 <= args.restart_delay <= MAXIMUM_RESTART_DELAY_SECONDS:
        parser.error("--restart-delay must be between 1 and 300")
    try:
        deadline = parse_deadline(args.deadline)
    except ValueError as exc:
        parser.error(str(exc))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    supervisor_lock = SupervisorLock(args.output_dir)
    supervisor_lock.acquire()
    state_path = args.output_dir / "supervisor_state.json"
    study_state_path = args.output_dir / "study_state.json"
    request = {
        "training_seeds": seeds,
        "timesteps_per_run": args.timesteps,
        "deadline": deadline.isoformat(),
    }
    attempts = 0
    try:
        if state_path.exists():
            try:
                previous_state = read_json(state_path)
            except (json.JSONDecodeError, OSError, RuntimeError, ValueError) as exc:
                archive_invalid_state(
                    state_path,
                    args.output_dir / "recovery" / "supervisor",
                    f"invalid supervisor state: {type(exc).__name__}",
                )
            else:
                if previous_state.get("request") != request:
                    raise RuntimeError(
                        "supervisor state does not match the requested study"
                    )
                previous_attempts = previous_state.get("attempts", 0)
                if (
                    previous_state.get("selection_status") == "not_selected"
                    and isinstance(previous_attempts, int)
                    and not isinstance(previous_attempts, bool)
                    and previous_attempts >= 0
                ):
                    attempts = previous_attempts
                else:
                    archive_invalid_state(
                        state_path,
                        args.output_dir / "recovery" / "supervisor",
                        "invalid supervisor state fields",
                    )
    except BaseException:
        supervisor_lock.close()
        raise

    try:
        study_script = Path(__file__).resolve().with_name("run_training_study.py")
        command = [
            sys.executable,
            str(study_script),
            "--seeds",
            *(str(seed) for seed in seeds),
            "--timesteps",
            str(args.timesteps),
            "--output-dir",
            str(args.output_dir),
            "--deadline",
            deadline.isoformat(),
        ]
    except BaseException:
        supervisor_lock.close()
        raise

    with supervisor_lock:
        try:
            validate_completed_study(
                study_state_path,
                seeds=seeds,
                timesteps=args.timesteps,
                deadline=deadline.isoformat(),
            )
        except (json.JSONDecodeError, OSError, RuntimeError, ValueError):
            pass
        else:
            atomic_write_json(
                state_path,
                {
                    "status": "completed",
                    "selection_status": "not_selected",
                    "request": request,
                    "attempts": attempts,
                    "updated_at": datetime.now(deadline.tzinfo).isoformat(),
                },
            )
            return
        while True:
            now = datetime.now(deadline.tzinfo)
            if now >= deadline:
                atomic_write_json(
                    state_path,
                    {
                        "status": "deadline_reached",
                        "selection_status": "not_selected",
                        "request": request,
                        "attempts": attempts,
                        "updated_at": now.isoformat(),
                    },
                )
                raise SystemExit(75)

            attempts += 1

            def heartbeat(child_pid) -> None:
                try:
                    atomic_write_json(
                        state_path,
                        {
                            "status": "running" if child_pid else "restarting",
                            "selection_status": "not_selected",
                            "request": request,
                            "attempts": attempts,
                            "study_pid": child_pid,
                            "updated_at": datetime.now(
                                deadline.tzinfo
                            ).isoformat(),
                        },
                    )
                except OSError:
                    return

            heartbeat(None)
            return_code = run_study_process(command, deadline, heartbeat)
            if return_code == 0:
                try:
                    validate_completed_study(
                        study_state_path,
                        seeds=seeds,
                        timesteps=args.timesteps,
                        deadline=deadline.isoformat(),
                    )
                except (json.JSONDecodeError, OSError, RuntimeError, ValueError):
                    return_code = 70
                else:
                    atomic_write_json(
                        state_path,
                        {
                            "status": "completed",
                            "selection_status": "not_selected",
                            "request": request,
                            "attempts": attempts,
                            "updated_at": datetime.now(
                                deadline.tzinfo
                            ).isoformat(),
                        },
                    )
                    return
            if return_code == 75 and datetime.now(deadline.tzinfo) >= deadline:
                atomic_write_json(
                    state_path,
                    {
                        "status": "deadline_reached",
                        "selection_status": "not_selected",
                        "request": request,
                        "attempts": attempts,
                        "study_exit_code": return_code,
                        "updated_at": datetime.now(
                            deadline.tzinfo
                        ).isoformat(),
                    },
                )
                raise SystemExit(75)
            if return_code == 2:
                atomic_write_json(
                    state_path,
                    {
                        "status": "configuration_failed",
                        "selection_status": "not_selected",
                        "request": request,
                        "attempts": attempts,
                        "study_exit_code": return_code,
                        "updated_at": datetime.now(
                            deadline.tzinfo
                        ).isoformat(),
                    },
                )
                raise SystemExit(2)

            delay = retry_delay(attempts, args.restart_delay)
            atomic_write_json(
                state_path,
                {
                    "status": "restarting",
                    "selection_status": "not_selected",
                    "request": request,
                    "attempts": attempts,
                    "study_exit_code": return_code,
                    "retry_delay_seconds": delay,
                    "updated_at": datetime.now(deadline.tzinfo).isoformat(),
                },
            )
            wait_for_restart(delay, deadline, heartbeat)


if __name__ == "__main__":
    main()

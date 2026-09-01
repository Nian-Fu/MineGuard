import argparse
import io
import importlib.metadata
import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.evaluation import evaluate_policy
from stable_baselines3.common.monitor import Monitor

from mineguard_rl.checkpoints import (
    archive_checkpoint_partials,
    archive_training_checkpoint,
    atomic_write_json,
    checkpoint_metadata_path,
    discard_training_checkpoint,
    discard_superseded_checkpoint_models,
    fsync_directory,
    PPO_ROLLOUT_STEPS,
    TRAINING_TRACE_LENGTH,
    training_source_digests,
    validate_training_checkpoint,
)
from mineguard_rl.environment import MineSchedulingEnv
from mineguard_rl.integrity import read_verified_artifact, resolve_model_path, sha256_file
from mineguard_rl.traces import generate_trace, trace_sha256

DEVELOPMENT_EVALUATION_SEEDS = tuple(range(20260812, 20260817))
DEVELOPMENT_TRACE_LENGTH = 1000
PPO_HYPERPARAMETERS = {
    "n_steps": PPO_ROLLOUT_STEPS,
    "batch_size": 256,
    "learning_rate": 3e-4,
    "gamma": 0.99,
    "gae_lambda": 0.95,
    "ent_coef": 0.01,
}
DEFAULT_CHECKPOINT_INTERVAL = 10_000


def model_output_path(output: Path) -> Path:
    return output if output.suffix.lower() == ".zip" else Path(f"{output}.zip")


def source_digests() -> dict[str, str]:
    project_root = Path(__file__).resolve().parent
    return training_source_digests(project_root)


def publish_checkpoint(
    model: PPO,
    output: Path,
    *,
    seed: int,
    target_timesteps: int,
    source_sha256: dict[str, str],
    training_trace_sha256: str,
) -> None:
    metadata_path = checkpoint_metadata_path(output)
    with tempfile.TemporaryDirectory(
        dir=output.parent,
        prefix=f".{output.name}.checkpoint-",
    ) as temporary_directory:
        temporary_output = Path(temporary_directory) / "model"
        model.save(temporary_output)
        temporary_model_path = resolve_model_path(temporary_output)
        with temporary_model_path.open("rb") as artifact:
            os.fsync(artifact.fileno())
        model_sha256 = sha256_file(temporary_model_path)
        model_size = temporary_model_path.stat().st_size
        checkpoint_model_path = output.parent / (
            f"{output.name}.checkpoint.{int(model.num_timesteps)}.{uuid4().hex}.zip"
        )
        os.replace(temporary_model_path, checkpoint_model_path)
        fsync_directory(output.parent)
        atomic_write_json(
            metadata_path,
            {
                "format_version": 1,
                "seed": seed,
                "target_timesteps": target_timesteps,
                "completed_timesteps": int(model.num_timesteps),
                "rollout_steps": PPO_ROLLOUT_STEPS,
                "training_trace_sha256": training_trace_sha256,
                "source_sha256": source_sha256,
                "model": {
                    "algorithm": "sha256",
                    "filename": checkpoint_model_path.name,
                    "sha256": model_sha256,
                    "size_bytes": model_size,
                },
            },
        )
        discard_superseded_checkpoint_models(output, checkpoint_model_path)


class AtomicCheckpointCallback(BaseCallback):
    def __init__(
        self,
        output: Path,
        *,
        interval: int,
        seed: int,
        target_timesteps: int,
        source_sha256: dict[str, str],
        training_trace_sha256: str,
        completed_timesteps: int,
    ) -> None:
        super().__init__()
        self.output = output
        self.interval = interval
        self.seed = seed
        self.target_timesteps = target_timesteps
        self.source_sha256 = source_sha256
        self.training_trace_sha256 = training_trace_sha256
        self.next_checkpoint = (
            (completed_timesteps // interval) + 1
        ) * interval

    def _on_rollout_start(self) -> None:
        if self.num_timesteps < self.next_checkpoint:
            return
        publish_checkpoint(
            self.model,
            self.output,
            seed=self.seed,
            target_timesteps=self.target_timesteps,
            source_sha256=self.source_sha256,
            training_trace_sha256=self.training_trace_sha256,
        )
        while self.next_checkpoint <= self.num_timesteps:
            self.next_checkpoint += self.interval

    def _on_step(self) -> bool:
        return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timesteps", type=int, default=200_000)
    parser.add_argument("--seed", type=int, default=20260821)
    parser.add_argument("--output", type=Path, default=Path("artifacts/ppo_scheduler"))
    parser.add_argument(
        "--checkpoint-interval", type=int, default=DEFAULT_CHECKPOINT_INTERVAL
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.timesteps <= 50_000_000:
        parser.error("--timesteps must be between 1 and 50000000")
    if not 0 <= args.seed <= 2**32 - 1:
        parser.error("--seed must be between 0 and 4294967295")
    if not 1 <= args.checkpoint_interval <= args.timesteps:
        parser.error("--checkpoint-interval must be between 1 and --timesteps")
    final_model_path = model_output_path(args.output)
    output_paths = (
        args.output,
        final_model_path,
        args.output.with_suffix(".development_metrics.json"),
        args.output.with_suffix(".training_manifest.json"),
    )
    if not args.overwrite and any(path.exists() for path in output_paths):
        parser.error("training output already exists; choose a new path or use --overwrite")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        dir=args.output.parent,
        prefix=f".{args.output.name}.training-",
    ) as temporary_directory:
        temporary_output = Path(temporary_directory) / "model"
        training_trace = generate_trace(TRAINING_TRACE_LENGTH, args.seed)
        training_trace_digest = trace_sha256(training_trace)
        current_source_digests = source_digests()
        training_env = Monitor(MineSchedulingEnv(training_trace))
        checkpoint_recovery_root = args.output.parent / "recovery" / "checkpoints"
        completed_timesteps = 0
        try:
            checkpoint = validate_training_checkpoint(
                args.output,
                seed=args.seed,
                target_timesteps=args.timesteps,
                source_sha256=current_source_digests,
                training_trace_sha256=training_trace_digest,
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            archive_training_checkpoint(
                args.output,
                checkpoint_recovery_root,
                f"{type(exc).__name__}: {exc}",
            )
            checkpoint = None

        archive_checkpoint_partials(
            args.output,
            checkpoint_recovery_root,
            "orphaned or superseded checkpoint artifact",
            keep_model=checkpoint["model_path"] if checkpoint else None,
        )

        if checkpoint is None:
            model = PPO(
                "MlpPolicy",
                training_env,
                seed=args.seed,
                verbose=1,
                **PPO_HYPERPARAMETERS,
            )
        else:
            try:
                checkpoint_bytes, _ = read_verified_artifact(
                    checkpoint["model_path"], checkpoint["model_sha256"]
                )
                model = PPO.load(io.BytesIO(checkpoint_bytes), env=training_env)
                if model.num_timesteps != checkpoint["completed_timesteps"]:
                    raise RuntimeError(
                        "checkpoint model timesteps do not match its metadata"
                    )
                completed_timesteps = checkpoint["completed_timesteps"]
            except Exception as exc:
                archive_training_checkpoint(
                    args.output,
                    checkpoint_recovery_root,
                    f"checkpoint load failed: {type(exc).__name__}: {exc}",
                )
                model = PPO(
                    "MlpPolicy",
                    training_env,
                    seed=args.seed,
                    verbose=1,
                    **PPO_HYPERPARAMETERS,
                )
                completed_timesteps = 0

        if completed_timesteps < args.timesteps:
            callback = AtomicCheckpointCallback(
                args.output,
                interval=args.checkpoint_interval,
                seed=args.seed,
                target_timesteps=args.timesteps,
                source_sha256=current_source_digests,
                training_trace_sha256=training_trace_digest,
                completed_timesteps=completed_timesteps,
            )
            model.learn(
                total_timesteps=args.timesteps - completed_timesteps,
                reset_num_timesteps=False,
                callback=callback,
            )
            publish_checkpoint(
                model,
                args.output,
                seed=args.seed,
                target_timesteps=args.timesteps,
                source_sha256=current_source_digests,
                training_trace_sha256=training_trace_digest,
            )
        model.save(temporary_output)
        temporary_model_path = resolve_model_path(temporary_output)
        model_sha256 = sha256_file(temporary_model_path)

        results = {}
        development_trace_digests = {}
        for seed in DEVELOPMENT_EVALUATION_SEEDS:
            development_trace = generate_trace(DEVELOPMENT_TRACE_LENGTH, seed)
            development_trace_digests[str(seed)] = trace_sha256(development_trace)
            evaluation_env = Monitor(MineSchedulingEnv(development_trace))
            mean_reward, std_reward = evaluate_policy(
                model, evaluation_env, n_eval_episodes=1
            )
            results[str(seed)] = {
                "mean_reward": float(mean_reward),
                "std_reward": float(std_reward),
            }

        development_metrics = {
            "model_sha256": model_sha256,
            "trace_sha256": development_trace_digests,
            "per_seed": results,
        }
        training_manifest = {
            "model": {
                "algorithm": "sha256",
                "sha256": model_sha256,
                "size_bytes": temporary_model_path.stat().st_size,
            },
            "training": {
                "algorithm": "PPO",
                "seed": args.seed,
                "timesteps": args.timesteps,
                "actual_timesteps": int(model.num_timesteps),
                "trace_length": len(training_trace),
                "trace_sha256": training_trace_digest,
                "hyperparameters": PPO_HYPERPARAMETERS,
                "development_evaluation_seeds": [
                    str(seed) for seed in DEVELOPMENT_EVALUATION_SEEDS
                ],
            },
            "runtime_versions": {
                package: importlib.metadata.version(package)
                for package in ("stable-baselines3", "gymnasium", "numpy")
            },
            "source_sha256": current_source_digests,
        }

        # The manifest is the commit marker and is always published last.
        os.replace(temporary_model_path, final_model_path)
        fsync_directory(final_model_path.parent)
        atomic_write_json(
            args.output.with_suffix(".development_metrics.json"),
            development_metrics,
        )
        atomic_write_json(
            args.output.with_suffix(".training_manifest.json"),
            training_manifest,
        )
        discard_training_checkpoint(args.output)


if __name__ == "__main__":
    main()

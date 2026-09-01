import argparse
import json
from pathlib import Path

from mineguard_rl.traces import protocol_candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    candidate = protocol_candidate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(candidate, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(
        "protocol candidate exported; acceptance remains blocked until its exact "
        "contents are independently reproduced, reviewed, and assigned to "
        "FROZEN_PROTOCOL_V3"
    )


if __name__ == "__main__":
    main()

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from app.edge.outbox import PersistentOutbox


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect and requeue retained MineGuard edge dead letters"
    )
    parser.add_argument("--database", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    list_parser = commands.add_parser("list")
    list_parser.add_argument("--limit", type=int, default=100)
    show_parser = commands.add_parser("show")
    show_parser.add_argument("id", type=int)
    requeue_parser = commands.add_parser("requeue")
    requeue_parser.add_argument("id", type=int)
    requeue_parser.add_argument("--resolution", required=True)
    args = parser.parse_args()

    if not args.database.is_file():
        parser.error("--database must reference an existing regular file")
    outbox = PersistentOutbox(args.database)
    if args.command == "list":
        records = []
        for item in outbox.dead_letters(args.limit):
            value = asdict(item)
            value.pop("payload")
            records.append(value)
        print(json.dumps(records, ensure_ascii=False, indent=2))
        return
    item = outbox.dead_letter(args.id)
    if args.command == "show":
        if item is None:
            raise SystemExit("active dead letter not found")
        print(json.dumps(asdict(item), ensure_ascii=False, indent=2))
        return
    if not outbox.requeue_dead_letter(args.id, args.resolution):
        raise SystemExit("active dead letter not found or event is already queued")
    print(json.dumps({"requeued": True, "id": args.id}))


if __name__ == "__main__":
    main()

import argparse

from app.company_demo_seed import seed_company_demo_data
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.seed import seed_database


def main() -> None:
    parser = argparse.ArgumentParser(description="MineGuard maintenance commands")
    parser.add_argument("command", choices=["seed", "seed-company-demo"])
    args = parser.parse_args()
    settings = get_settings()
    if args.command == "seed":
        if (
            settings.environment == "production"
            and settings.bootstrap_admin_enabled
            and settings.bootstrap_admin_password.get_secret_value()
            in {"MineGuard@123", "DevelopmentAdmin123"}
        ):
            raise SystemExit("refusing to seed production with the default administrator password")
        with SessionLocal() as db:
            seed_database(db)
    elif args.command == "seed-company-demo":
        with SessionLocal() as db:
            counts = seed_company_demo_data(db)
        print(
            "company demo data imported: "
            + ", ".join(f"{key}={value}" for key, value in counts.items())
        )


if __name__ == "__main__":
    main()

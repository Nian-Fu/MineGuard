import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import SecretStr

from app import cli, seed
from app.core.config import Settings


def test_seed_skips_bootstrap_admin_when_disabled(monkeypatch):
    settings = Settings(
        _env_file=None,
        environment="staging",
        bootstrap_admin_enabled=False,
    )
    db = Mock()
    monkeypatch.setattr(seed, "get_settings", lambda: settings)

    seed.seed_database(db)

    db.scalar.assert_not_called()
    db.add.assert_not_called()
    db.commit.assert_called_once_with()


def test_seed_cli_rejects_masked_default_production_password(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["mineguard", "seed"])
    monkeypatch.setattr(
        cli,
        "get_settings",
        lambda: SimpleNamespace(
            environment="production",
            bootstrap_admin_enabled=True,
            bootstrap_admin_password=SecretStr("DevelopmentAdmin123"),
        ),
    )

    with pytest.raises(SystemExit, match="refusing to seed production"):
        cli.main()

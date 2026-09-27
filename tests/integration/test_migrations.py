from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_initial_migration_upgrades_downgrades_and_reupgrades(
    temporary_database_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "alembic.ini")
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["database_url"] = temporary_database_url

    command.upgrade(config, "head")
    engine = create_engine(temporary_database_url)
    expected = {"users", "teams", "team_memberships", "authorization_scopes", "audit_events"}
    assert expected.issubset(set(inspect(engine).get_table_names()))

    command.downgrade(config, "base")
    assert not expected.intersection(inspect(engine).get_table_names())

    command.upgrade(config, "head")
    assert expected.issubset(set(inspect(engine).get_table_names()))
    engine.dispose()

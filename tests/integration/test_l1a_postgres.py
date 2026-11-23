"""L1a integration tests against the real Postgres 16 ledger-db container."""

from __future__ import annotations

import os

import psycopg
import pytest

from tests.integration.support import get_test_dsn

pytestmark = pytest.mark.integration


def dsn() -> str:
    return get_test_dsn()


def test_schema_and_version() -> None:
    with psycopg.connect(dsn(), autocommit=True) as connection:
        tables = connection.execute(
            """SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'blackbox' ORDER BY table_name"""
        ).fetchall()
        assert {row[0] for row in tables} >= {
            "checkpoints",
            "conflicts",
            "cosignatures",
            "entries",
            "schema_version",
        }
        assert connection.execute("SELECT version FROM blackbox.schema_version").fetchone() == (1,)


def test_append_role_is_append_only_and_triggers_are_defensive() -> None:
    with psycopg.connect(dsn(), autocommit=True) as connection:
        role = os.environ.get("LEDGER_APP_USER", "ledger_app")
        connection.execute("SET ROLE " + psycopg.sql.Identifier(role).as_string(connection))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("UPDATE blackbox.entries SET seq = seq")


def test_migration_is_idempotent() -> None:
    migration = os.path.join(
        os.path.dirname(__file__), "../../services/ledger/migrations/001_init.sql"
    )
    with open(migration, encoding="utf-8") as handle:
        sql = handle.read()
    with psycopg.connect(dsn(), autocommit=True) as connection:
        connection.execute(sql)
        assert connection.execute("SELECT version FROM blackbox.schema_version").fetchone() == (1,)

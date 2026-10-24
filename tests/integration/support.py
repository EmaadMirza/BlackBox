"""Shared real-Postgres integration setup with a destructive test-DB guard."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).parents[2]
MIGRATIONS = (
    ROOT / "services/ledger/migrations/001_init.sql",
    ROOT / "services/ledger/migrations/002_l1b_registry.sql",
)


def get_test_dsn() -> str:
    dsn = os.environ.get("LEDGER_TEST_DSN", "dbname=blackbox_ledger_test")
    database = conninfo_to_dict(dsn).get("dbname")
    if not isinstance(database, str) or "test" not in database.lower():
        raise RuntimeError("integration tests require a database name containing 'test'")
    return dsn


def reset_database() -> str:
    dsn = get_test_dsn()
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS blackbox CASCADE")
        for migration in MIGRATIONS:
            connection.execute(migration.read_text(encoding="utf-8"))
    return dsn


def execute(sql: str, params: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    with psycopg.connect(get_test_dsn()) as connection:
        return connection.execute(sql, params).fetchall()

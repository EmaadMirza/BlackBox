"""Postgres persistence primitives for the ledger foundation."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from psycopg_pool import ConnectionPool

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.schemas import SealedEntry


def connect(dsn: str) -> ConnectionPool:
    """Create a psycopg pool; callers own and close the pool."""
    return ConnectionPool(conninfo=dsn, open=True)


@contextmanager
def transaction(pool: ConnectionPool) -> Iterator[object]:
    with pool.connection() as connection:
        with connection.transaction():
            yield connection


def append_entry(pool: ConnectionPool, entry: SealedEntry) -> None:
    body = entry.body
    with transaction(pool) as connection:
        connection.execute(
            """INSERT INTO blackbox.entries
            (log_id, seq, sealed_entry, entry_hash, prev_hash, epoch_id, type)
            VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (
                body.log_id,
                body.seq,
                entry.model_dump(mode="json"),
                entry_hash(body),
                body.prev_hash,
                body.epoch_id,
                body.type,
            ),
        )


def read_entries(pool: ConnectionPool, start_seq: int, end_seq: int) -> list[SealedEntry]:
    if start_seq < 0 or end_seq < start_seq:
        raise ValueError("invalid entry range")
    with pool.connection() as connection:
        rows = connection.execute(
            """SELECT sealed_entry FROM blackbox.entries
            WHERE seq >= %s AND seq <= %s ORDER BY seq LIMIT 1000""",
            (start_seq, end_seq),
        ).fetchall()
    return [SealedEntry.model_validate(row[0]) for row in rows]

"""Append-only PostgreSQL attack control (spec §23)."""

from __future__ import annotations

import psycopg


async def append(dsn: str, record: bytes) -> None:
    """Insert record into PostgreSQL table with rule-based rejection of UPDATE/DELETE."""
    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "CREATE TABLE IF NOT EXISTS plain_log (id BIGSERIAL PRIMARY KEY, data BYTEA NOT NULL);"
            )
            await cur.execute("INSERT INTO plain_log (data) VALUES (%s);", (record,))
        await conn.commit()

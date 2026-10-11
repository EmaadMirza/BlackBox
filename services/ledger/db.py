"""Ledger PostgreSQL persistence Scaffold only; no runtime behavior."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncConnection

from libs.blackbox_core import schemas

# TODO(spec §10.1): implement and validate before enabling this module.


async def connect(dsn: str) -> AsyncConnection:
    raise NotImplementedError("not built")


async def append_entry(connection: AsyncConnection, entry: schemas.SealedEntry) -> None:
    raise NotImplementedError("not built")


async def read_entries(
    connection: AsyncConnection, start_seq: int, end_seq: int
) -> list[schemas.SealedEntry]:
    raise NotImplementedError("not built")

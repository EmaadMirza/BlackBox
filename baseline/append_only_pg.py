"""Append-only PostgreSQL attack control Scaffold only; no runtime behavior."""

from __future__ import annotations

# TODO(spec §23): implement and validate before enabling this module.


async def append(dsn: str, record: bytes) -> None:
    raise NotImplementedError("not built")

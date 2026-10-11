"""Persisted right frontier Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §10.2): implement and validate before enabling this module.


async def load_frontier(log_id: str) -> tuple[int, list[bytes | None]]:
    raise NotImplementedError("not built")


async def append(entry: schemas.SealedEntry) -> bytes:
    raise NotImplementedError("not built")

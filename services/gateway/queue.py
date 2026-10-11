"""Bounded disk queue and outage gap marker Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §10.5): implement and validate before enabling this module.


def enqueue(candidate: schemas.Entry) -> None:
    raise NotImplementedError("not built")


async def drain() -> list[schemas.SealedEntry]:
    raise NotImplementedError("not built")


def gap(outage_start: str, outage_end: str, queued_entries: int) -> schemas.Gap:
    raise NotImplementedError("not built")

"""Checkpoint scheduling and witness fan-out Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §10.3): implement and validate before enabling this module.


async def request_checkpoint() -> schemas.Checkpoint:
    raise NotImplementedError("not built")


async def fan_out(checkpoint: schemas.Checkpoint) -> list[schemas.Cosignature]:
    raise NotImplementedError("not built")


async def run(interval_seconds: int = 5) -> None:
    raise NotImplementedError("not built")

"""Ordered eight-step checkpoint processing Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §11.3): implement and validate before enabling this module.


async def process(
    checkpoint: schemas.Checkpoint, previous: schemas.Checkpoint | None
) -> schemas.Cosignature:
    raise NotImplementedError("not built")

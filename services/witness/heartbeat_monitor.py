"""Stall and contradictory-state checks Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §11.4): implement and validate before enabling this module.


def inspect(
    heartbeat: schemas.Heartbeat | None, checkpoint: schemas.Checkpoint | None, now: str
) -> list[str]:
    raise NotImplementedError("not built")

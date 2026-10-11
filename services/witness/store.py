"""Private append-only witness storage; fsync before cosigning Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §11.3): implement and validate before enabling this module.


def last_checkpoint(log_id: str) -> schemas.Checkpoint | None:
    raise NotImplementedError("not built")


def append_and_fsync(checkpoint: schemas.Checkpoint) -> None:
    raise NotImplementedError("not built")


def record_refusal(checkpoint: schemas.Checkpoint, reason: str) -> None:
    raise NotImplementedError("not built")

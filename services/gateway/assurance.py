"""Witness coverage and fail-closed wait Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.6): implement and validate before enabling this module.


async def wait_for_coverage(intent_seq: int, timeout_seconds: int = 10) -> schemas.Checkpoint:
    raise NotImplementedError("not built")

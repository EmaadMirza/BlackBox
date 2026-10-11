"""Signer heartbeat scheduler Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §9.2): implement and validate before enabling this module.


async def emit_heartbeat() -> schemas.Heartbeat:
    raise NotImplementedError("not built")


async def run(interval_seconds: int = 5) -> None:
    raise NotImplementedError("not built")

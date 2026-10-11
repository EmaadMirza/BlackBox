"""ledger service factory and planned handlers Scaffold only; no runtime behavior."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas

# TODO(spec §10.4): implement and validate before enabling this module.


def create_app() -> FastAPI:
    raise NotImplementedError("not built")


async def health() -> dict[str, str]:
    raise NotImplementedError("not built")


async def append_entry(entry: schemas.SealedEntry, signer_identity: str) -> None:
    raise NotImplementedError("not built")


async def entries(start_seq: int, end_seq: int) -> list[schemas.SealedEntry]:
    raise NotImplementedError("not built")


async def latest_checkpoint(witnessed: bool) -> schemas.Checkpoint | None:
    raise NotImplementedError("not built")


async def alarms() -> list[dict[str, str]]:
    raise NotImplementedError("not built")


async def findings() -> list[schemas.Finding]:
    raise NotImplementedError("not built")

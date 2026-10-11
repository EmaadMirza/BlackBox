"""approval service factory and planned handlers Scaffold only; no runtime behavior."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas

# TODO(spec §13.5): implement and validate before enabling this module.


def create_app() -> FastAPI:
    raise NotImplementedError("not built")


async def health() -> dict[str, str]:
    raise NotImplementedError("not built")


async def request_approval(intent: schemas.Intent) -> str:
    raise NotImplementedError("not built")


async def decide(receipt: schemas.ApprovalReceipt) -> None:
    raise NotImplementedError("not built")

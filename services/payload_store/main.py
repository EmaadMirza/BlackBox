"""payload_store service factory and planned handlers Scaffold only; no runtime behavior."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas

# TODO(spec §8.4): implement and validate before enabling this module.


def create_app() -> FastAPI:
    raise NotImplementedError("not built")


async def health() -> dict[str, str]:
    raise NotImplementedError("not built")


async def store_payload(value: bytes, salt: bytes) -> str:
    raise NotImplementedError("not built")


async def open_payload(reference: str, authorization: str) -> tuple[bytes, bytes]:
    raise NotImplementedError("not built")


async def resolve_action_payload(action: schemas.RequestAction) -> bytes:
    raise NotImplementedError("not built")

"""gateway service factory and planned handlers Scaffold only; no runtime behavior."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas

# TODO(spec §13.3): implement and validate before enabling this module.


def create_app() -> FastAPI:
    raise NotImplementedError("not built")


async def health() -> dict[str, str]:
    raise NotImplementedError("not built")


async def agent_request(request: schemas.RequestAction, authorization: str) -> bytes:
    raise NotImplementedError("not built")


async def web_request(body: bytes, headers: dict[str, str]) -> bytes:
    raise NotImplementedError("not built")

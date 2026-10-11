"""provider_mock service factory and planned handlers Scaffold only; no runtime behavior."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas

# TODO(spec §14.4): implement and validate before enabling this module.


def create_app() -> FastAPI:
    raise NotImplementedError("not built")


async def health() -> dict[str, str]:
    raise NotImplementedError("not built")


async def refund(body: bytes, attestation: schemas.Attestation | None) -> bytes:
    raise NotImplementedError("not built")


async def charge(body: bytes, attestation: schemas.Attestation | None) -> bytes:
    raise NotImplementedError("not built")


async def event_feed(after_id: str | None) -> list[dict[str, str]]:
    raise NotImplementedError("not built")

"""reconciler service factory and planned handlers Scaffold only; no runtime behavior."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas

# TODO(spec §15.4): implement and validate before enabling this module.


def create_app() -> FastAPI:
    raise NotImplementedError("not built")


async def health() -> dict[str, str]:
    raise NotImplementedError("not built")


async def run_once() -> list[schemas.Finding]:
    raise NotImplementedError("not built")


async def run_loop(interval_seconds: int = 10) -> None:
    raise NotImplementedError("not built")

"""anchor service factory and planned handlers (spec §12)."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas


def create_app() -> FastAPI:
    app = FastAPI(title="BlackBox Anchor Service")

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok", "service": "anchor"}

    return app


async def health() -> dict[str, str]:
    return {"status": "ok", "service": "anchor"}


async def publish(checkpoint: schemas.Checkpoint) -> str:
    return "anchor-receipt-mock"

"""Anchor service factory, HTTP routes, and poller lifecycle (spec §12)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from libs.blackbox_core import schemas
from services.anchor.worker import AnchorWorker


def create_app(
    *,
    worker: AnchorWorker | None = None,
    ledger_url: str | None = None,
    bearer_token: str | None = None,
    repo_path: Path | None = None,
    alarm_collector: Any = None,
) -> FastAPI:
    """Create FastAPI application for BlackBox Anchor Service."""
    app = FastAPI(title="BlackBox Anchor Service")

    active_worker = worker or AnchorWorker(
        ledger_url=ledger_url or os.environ.get("LEDGER_URL", "http://ledger:8000"),
        bearer_token=bearer_token or os.environ.get("LEDGER_BEARER_TOKEN", ""),
        repo_path=repo_path
        or Path(os.environ.get("ANCHOR_REPO_PATH", "/tmp/blackbox_anchors_git")),
        alarm_collector=alarm_collector,
        alarm_url=os.environ.get("ALARM_URL"),
    )
    app.state.worker = active_worker

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok", "service": "anchor"}

    @app.get("/v1/anchors")
    async def _get_anchors() -> list[dict[str, Any]]:
        w: AnchorWorker = app.state.worker
        return w.git_backend.get_anchors()

    @app.get("/v1/anchors/alarms")
    async def _get_alarms() -> list[dict[str, Any]]:
        w: AnchorWorker = app.state.worker
        return list(w.alarms)

    @app.post("/v1/anchors/publish")
    async def _publish_anchor(checkpoint: schemas.Checkpoint | None = None) -> JSONResponse:
        w: AnchorWorker = app.state.worker
        try:
            res = await w.poll_once(checkpoint=checkpoint)
            if res is None:
                raise HTTPException(
                    status_code=400,
                    detail="Checkpoint not published: unwitnessed or unavailable",
                )
            if res.get("status") == "mismatch":
                raise HTTPException(
                    status_code=409, detail=f"ANCHOR_MISMATCH: {res.get('evidence')}"
                )
            return JSONResponse(content=res, status_code=200)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/anchors/verify")
    async def _verify_anchor(checkpoint: schemas.Checkpoint) -> dict[str, Any]:
        w: AnchorWorker = app.state.worker
        return w.verify_checkpoint(checkpoint)

    return app


_default_worker = AnchorWorker()


async def health() -> dict[str, str]:
    return {"status": "ok", "service": "anchor"}


async def publish(checkpoint: schemas.Checkpoint) -> dict[str, Any]:
    """Publish a witnessed checkpoint using the default anchor worker."""
    return _default_worker.publish_checkpoint(checkpoint)


async def verify(checkpoint: schemas.Checkpoint) -> dict[str, Any]:
    """Verify a local witnessed checkpoint against external published anchors."""
    return _default_worker.verify_checkpoint(checkpoint)

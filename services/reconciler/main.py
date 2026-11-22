"""Reconciler service factory, execution loop and findings reporting."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI

from libs.blackbox_core import schemas
from services.reconciler.findings_store import FindingsStore
from services.reconciler.verdicts import classify
from services.signer.clock import system_utc_now


class Reconciler:
    def __init__(
        self,
        *,
        ledger_reader: Callable[[], list[schemas.SealedEntry]],
        event_reader: Callable[[], list[dict[str, Any]]],
        findings_store: FindingsStore,
        clock: Callable[[], str] | None = None,
        grace_seconds: int = 30,
    ) -> None:
        self.ledger_reader = ledger_reader
        self.event_reader = event_reader
        self.findings_store = findings_store
        self.clock = clock or system_utc_now
        self.grace_seconds = grace_seconds

    def run_once(self) -> list[schemas.Finding]:
        now = self.clock()
        entries = self.ledger_reader()
        events = self.event_reader()
        findings = classify(entries, events, now, grace_seconds=self.grace_seconds)
        for f in findings:
            self.findings_store.append(f)
        return findings


def create_app(*, reconciler: Reconciler | None = None) -> FastAPI:
    app = FastAPI(title="BlackBox Reconciler")

    if reconciler is None:
        ledger_url = os.environ.get("LEDGER_URL")
        events_url = os.environ.get("PROVIDER_EVENTS_URL")
        if ledger_url and events_url:

            def _read_ledger() -> list[schemas.SealedEntry]:
                try:
                    with httpx.Client(base_url=ledger_url.rstrip("/"), timeout=3.0) as client:
                        res = client.get("/entries")
                        if res.status_code == 200:
                            return [schemas.SealedEntry.model_validate(e) for e in res.json()]
                except Exception:
                    pass
                return []

            def _read_events() -> list[dict[str, Any]]:
                try:
                    with httpx.Client(timeout=3.0) as client:
                        res = client.get(events_url)
                        if res.status_code == 200:
                            return res.json()
                except Exception:
                    pass
                return []

            store_path = Path(os.environ.get("FINDINGS_STORE_PATH", "findings-store.json"))
            reconciler = Reconciler(
                ledger_reader=_read_ledger,
                event_reader=_read_events,
                findings_store=FindingsStore(store_path),
            )

    app.state.reconciler = reconciler

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/run_once")
    async def _run_once() -> list[dict[str, Any]]:
        rec: Reconciler | None = getattr(app.state, "reconciler", None)
        if rec is None:
            return []
        findings = rec.run_once()
        return [f.model_dump() for f in findings]

    @app.get("/v1/findings")
    async def _get_findings() -> list[dict[str, Any]]:
        rec: Reconciler | None = getattr(app.state, "reconciler", None)
        if rec is None:
            return []
        return [f.model_dump() for f in rec.findings_store.list_findings()]

    return app

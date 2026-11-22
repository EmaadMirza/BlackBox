"""Local alarm collector with durable deduplication and no external notifications."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from libs.blackbox_core.canonical import canonicalize


class AlarmCollector:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def collect(
        self, alarm_type: str, source: str, evidence_reference: str, severity: str, timestamp: str
    ) -> None:
        records = self.records()
        identity = hashlib.sha256(
            canonicalize({"type": alarm_type, "source": source, "evidence": evidence_reference})
        ).hexdigest()
        if any(item["id"] == identity for item in records):
            return
        with self.path.open("ab") as stream:
            stream.write(
                canonicalize(
                    {
                        "id": identity,
                        "type": alarm_type,
                        "source": source,
                        "severity": severity,
                        "evidence_reference": evidence_reference,
                        "time": timestamp,
                    }
                )
                + b"\n"
            )
            stream.flush()

    def records(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line]


def create_app(*, collector: AlarmCollector | None = None, bearer_token: str = "") -> FastAPI:
    app = FastAPI(title="BlackBox Alerting Service")
    active_collector = collector if collector is not None else AlarmCollector()
    app.state.collector = active_collector

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/alarms")
    async def alarms(request: Request) -> list[dict[str, object]]:
        if bearer_token and request.headers.get("authorization") != f"Bearer {bearer_token}":
            return JSONResponse(
                {"error": {"code": "unauthorized", "message": "Authentication required."}}, 401
            )
        return active_collector.records()

    return app


async def health() -> dict[str, str]:
    return {"status": "ok"}


async def collect(alarm_type: str, source: str, evidence_reference: str) -> None:
    return None

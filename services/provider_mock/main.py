"""Provider mock service factory, request dispatch, and attestation enforcement."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request

from libs.blackbox_core import schemas
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash
from services.provider_mock.attestation_check import AttestationMismatchError, verify_received_body
from services.provider_mock.events import ProviderEventLog
from services.signer.clock import system_utc_now


class ProviderMock:
    def __init__(
        self,
        *,
        event_log: ProviderEventLog | None = None,
        enforcement_enabled: bool = True,
        signer_public_key: bytes | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self.event_log = event_log or ProviderEventLog()
        self.enforcement_enabled = enforcement_enabled
        self.signer_public_key = signer_public_key
        self.clock = clock or system_utc_now
        self.received: list[tuple[bytes, dict[str, str]]] = []
        self._alarms: list[dict[str, str]] = []

    def request(
        self,
        body: bytes,
        headers: dict[str, str],
        *,
        tool_name: str = "action",
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        self.received.append((body, dict(headers)))
        now = self.clock()
        req_id = f"prov-{uuid4().hex[:12]}"
        received_digest = encode_hash(sha256(body))

        attestation_header = headers.get("X-BlackBox-Attestation")
        attestation: schemas.Attestation | None = None
        attestation_valid = False

        if attestation_header:
            try:
                raw = json.loads(attestation_header)
                # Could be raw attestation dict or {"attestation": ...} envelope
                att_data = raw.get("attestation", raw)
                attestation = schemas.Attestation.model_validate(att_data)
                if self.signer_public_key is not None:
                    verify_received_body(body, attestation, self.signer_public_key, now)
                else:
                    # Check body digest at minimum
                    if attestation.body_digest != received_digest:
                        raise AttestationMismatchError("ATTESTATION_BODY_MISMATCH")
                attestation_valid = True
            except AttestationMismatchError:
                self._alarms.append(
                    {"alarm_type": "ATTESTATION_BODY_MISMATCH", "request_id": req_id}
                )
                self.event_log.append(
                    intent_seq=getattr(attestation, "intent_seq", None),
                    idempotency_key=idempotency_key,
                    received_digest=received_digest,
                    action=tool_name,
                    provider_request_id=req_id,
                    timestamp=now,
                    attested=False,
                    status=400,
                )
                return {"status": 400, "error": "ATTESTATION_BODY_MISMATCH", "request_id": req_id}
            except Exception:
                attestation_valid = False

        if not attestation_valid:
            self._alarms.append({"alarm_type": "UNATTESTED_ACTION", "request_id": req_id})
            if self.enforcement_enabled:
                self.event_log.append(
                    intent_seq=getattr(attestation, "intent_seq", None),
                    idempotency_key=idempotency_key,
                    received_digest=received_digest,
                    action=tool_name,
                    provider_request_id=req_id,
                    timestamp=now,
                    attested=False,
                    status=403,
                )
                return {
                    "status": 403,
                    "error": "unattested action rejected under enforcement mode",
                    "request_id": req_id,
                }

        # Successful provider execution
        self.event_log.append(
            intent_seq=getattr(attestation, "intent_seq", None),
            idempotency_key=idempotency_key,
            received_digest=received_digest,
            action=tool_name,
            provider_request_id=req_id,
            timestamp=now,
            attested=attestation_valid,
            status=200,
            result_commitment="sha256:" + "0" * 64,
        )
        return {"status": 200, "request_id": req_id, "result": b'{"ok":true}'}


def create_app(*, provider: ProviderMock | None = None) -> FastAPI:
    app = FastAPI(title="BlackBox Provider Mock")
    app.state.provider = provider or ProviderMock()

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/refund")
    async def _refund(request: Request) -> dict[str, Any]:
        body = await request.body()
        headers = dict(request.headers)
        res = app.state.provider.request(body, headers, tool_name="refund")
        if res["status"] >= 400:
            raise HTTPException(status_code=res["status"], detail=res.get("error", "Error"))
        return {"status": "ok", "request_id": res["request_id"]}

    @app.post("/charge")
    async def _charge(request: Request) -> dict[str, Any]:
        body = await request.body()
        headers = dict(request.headers)
        res = app.state.provider.request(body, headers, tool_name="charge")
        if res["status"] >= 400:
            raise HTTPException(status_code=res["status"], detail=res.get("error", "Error"))
        return {"status": "ok", "request_id": res["request_id"]}

    @app.get("/events")
    async def _events(after_id: str | None = None) -> list[dict[str, Any]]:
        return app.state.provider.event_log.feed(after_id)

    return app


async def health() -> dict[str, str]:
    return {"status": "ok"}


async def refund(body: bytes, attestation: schemas.Attestation | None) -> bytes:
    raise NotImplementedError("use create_app with an injected ProviderMock")


async def charge(body: bytes, attestation: schemas.Attestation | None) -> bytes:
    raise NotImplementedError("use create_app with an injected ProviderMock")


async def event_feed(after_id: str | None) -> list[dict[str, str]]:
    raise NotImplementedError("use create_app with an injected ProviderMock")

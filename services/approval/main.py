"""Approval service factory, HTTP endpoints, and receipt verification boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import loads
from services.approval.registry import ApproverRegistry
from services.approval.verify import ApprovalVerificationError, ApprovalVerifier


class ApprovalRequestPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    intent: schemas.Intent | None = None
    intent_seq: int | None = None
    requester_id: str | None = None
    arguments_commitment: str | None = None


class DecisionPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    request_id: str | None = None
    decision: str  # "approve" | "deny"
    receipt: schemas.ApprovalReceipt | None = None
    reason: str | None = None
    requester_id: str | None = None
    arguments_commitment: str | None = None


class VerifyPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    receipt: schemas.ApprovalReceipt
    requester_id: str
    arguments_commitment: str


def create_app(
    *,
    verifier: ApprovalVerifier | None = None,
    registry: ApproverRegistry | None = None,
    nonce_path: Path | None = None,
    clock: Any = None,
) -> FastAPI:
    app = FastAPI(title="BlackBox Approval Service")

    if verifier is None:
        reg = registry or ApproverRegistry(Path("approval-registry.json"))
        np = nonce_path or Path("approval-nonces.json")
        clk = clock or (lambda: "2026-01-01T00:00:00.000Z")
        verifier = ApprovalVerifier(reg, np, clock=clk)

    app.state.verifier = verifier
    app.state.requests: dict[str, dict[str, Any]] = {}

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/requests")
    @app.post("/request_approval")
    async def _request_approval(request: Request) -> dict[str, Any]:
        body = await request.body()
        try:
            data = loads(body) if body else {}
        except Exception:
            data = {}

        req_id = str(uuid4())
        intent_seq = data.get("intent_seq")
        requester_id = data.get("requester_id")
        arguments_commitment = data.get("arguments_commitment")

        if "intent" in data and isinstance(data["intent"], dict):
            intent_data = data["intent"]
            intent_seq = intent_data.get("seq", intent_seq)
            principal = intent_data.get("principal") or {}
            requester_id = principal.get("agent_identity") or requester_id
            action = intent_data.get("action") or {}
            arguments_commitment = action.get("arguments_commitment") or arguments_commitment

        app.state.requests[req_id] = {
            "request_id": req_id,
            "status": "pending",
            "intent_seq": intent_seq,
            "requester_id": requester_id,
            "arguments_commitment": arguments_commitment,
            "decision": None,
            "receipt": None,
            "reason": None,
        }
        return {"request_id": req_id, "status": "pending"}

    @app.post("/v1/decide")
    @app.post("/decide")
    async def _decide(payload: DecisionPayload) -> dict[str, Any]:
        req = app.state.requests.get(payload.request_id or "") if payload.request_id else None
        requester_id = payload.requester_id or (req.get("requester_id") if req else None) or ""
        arguments_commitment = (
            payload.arguments_commitment or (req.get("arguments_commitment") if req else None) or ""
        )

        if payload.decision == "approve":
            if payload.receipt is None:
                return JSONResponse(
                    {"error": {"code": "missing_receipt", "message": "Approval receipt required."}},
                    400,
                )
            try:
                app.state.verifier.verify(payload.receipt, requester_id, arguments_commitment)
            except ApprovalVerificationError as exc:
                code = str(exc).replace(" ", "_")
                return JSONResponse(
                    {"error": {"code": code, "message": str(exc)}},
                    409,
                )
            if req:
                req["status"] = "approved"
                req["receipt"] = payload.receipt.model_dump()
                req["decision"] = "approve"
            return {"status": "approved", "receipt": payload.receipt.model_dump()}

        elif payload.decision == "deny":
            reason = payload.reason or "denied"
            if req:
                req["status"] = "denied"
                req["reason"] = reason
                req["decision"] = "deny"
            return {"status": "denied", "reason": reason}

        return JSONResponse(
            {"error": {"code": "invalid_decision", "message": "Invalid decision."}}, 400
        )

    @app.post("/v1/verify")
    @app.post("/verify")
    async def _verify(payload: VerifyPayload) -> dict[str, Any]:
        try:
            app.state.verifier.verify(
                payload.receipt, payload.requester_id, payload.arguments_commitment
            )
            return {"status": "ok", "valid": True}
        except ApprovalVerificationError as exc:
            code = str(exc).replace(" ", "_")
            return JSONResponse(
                {"error": {"code": code, "message": str(exc)}, "valid": False},
                409,
            )

    @app.get("/v1/requests/{request_id}")
    async def _get_request(request_id: str) -> dict[str, Any]:
        req = app.state.requests.get(request_id)
        if not req:
            return JSONResponse(
                {"error": {"code": "not_found", "message": "Approval request not found."}}, 404
            )
        return req

    return app


async def health() -> dict[str, str]:
    return {"status": "ok"}


async def request_approval(intent: schemas.Intent) -> str:
    raise NotImplementedError("use create_app with an authenticated ApprovalVerifier")


async def decide(receipt: schemas.ApprovalReceipt) -> None:
    raise NotImplementedError("use create_app with an authenticated ApprovalVerifier")

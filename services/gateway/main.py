"""Gateway service factory, health, and HTTP action routing (spec §13)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize
from services.gateway.auth_web import NonceStore, WebAuthError, authenticate
from services.gateway.mcp_adapter import MCPAdapter
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore


class ActionRequestPayload(BaseModel):
    agent_id: str
    tool_name: str
    body: Any = None
    idempotency_key: str
    delegation_token: str | None = None
    context: schemas.Context | None = None
    approval_receipt: schemas.ApprovalReceipt | None = None
    session_id: str | None = None


def serialize_pipeline_result(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if hasattr(v, "model_dump"):
            out[k] = v.model_dump(mode="json")
        elif isinstance(v, dict):
            out[k] = serialize_pipeline_result(v)
        else:
            out[k] = v
    return out


class RemoteSignerClient:
    def __init__(self, base_url: str, token: str = "signer-token") -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def seal(self, candidate: Any) -> schemas.SealedEntry:
        import httpx

        with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
            headers = {"Authorization": f"Bearer {self.token}"}
            body_bytes = canonicalize(candidate.model_dump())
            res = client.post("/seal", content=body_bytes, headers=headers)
            res.raise_for_status()
            return schemas.SealedEntry.model_validate(res.json())

    def attest(self, intent_or_seq: Any) -> dict[str, Any]:
        import httpx

        seq = (
            intent_or_seq
            if isinstance(intent_or_seq, int)
            else getattr(intent_or_seq, "seq", intent_or_seq)
        )
        with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
            headers = {"Authorization": f"Bearer {self.token}"}
            res = client.post("/attest", json={"intent_seq": seq}, headers=headers)
            res.raise_for_status()
            return res.json()


class RemoteProviderClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def request(
        self, body: bytes, headers: dict[str, str], tool_name: str = "refund"
    ) -> dict[str, Any]:
        import httpx

        with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
            res = client.post(f"/{tool_name.lstrip('/')}", content=body, headers=headers)
            res_json = (
                res.json()
                if res.headers.get("content-type", "").startswith("application/json")
                else {}
            )
            return {
                "status": res.status_code,
                "request_id": res_json.get("request_id", ""),
                "result": res.content,
                "error": res_json.get("detail", "") if res.status_code >= 400 else "",
            }


def create_app(
    *,
    pipeline: GatewayPipeline | None = None,
    signer: Any = None,
    provider: Any = None,
    payload_store: PayloadStore | None = None,
    policy: PolicyEngine | None = None,
    agent_tokens: dict[str, str] | None = None,
    clock: Any = None,
    approval_verifier: Any = None,
    tooldefs_registry: Any = None,
    mcp_adapter: MCPAdapter | None = None,
    web_secrets: dict[str, bytes] | None = None,
    nonce_store: NonceStore | None = None,
) -> FastAPI:
    """Create Gateway FastAPI application."""
    app = FastAPI(title="BlackBox Gateway")

    default_tokens = {
        "agent-default": "token-default",
        "agent-1": "token-1",
        "agent-mcp": "token-mcp",
    }
    if pipeline is not None:
        app.state.pipeline = pipeline
    elif signer is not None and provider is not None:
        payload_store = payload_store or PayloadStore(Path("data/payload_store"))
        if policy is None:
            rules_path = Path("services/gateway/policy/rules.yaml")
            rules = load_rules(rules_path) if rules_path.exists() else []
            policy = PolicyEngine(rules)
        app.state.pipeline = GatewayPipeline(
            signer=signer,
            provider=provider,
            payload_store=payload_store,
            policy=policy,
            agent_tokens=agent_tokens or default_tokens,
            clock=clock or (lambda: "2026-01-01T00:00:00.000Z"),
            approval_verifier=approval_verifier,
            tooldefs_registry=tooldefs_registry,
        )
    elif os.environ.get("SIGNER_URL") and os.environ.get("PROVIDER_URL"):
        signer_client = RemoteSignerClient(
            os.environ["SIGNER_URL"], os.environ.get("SIGNER_AUTH_TOKEN", "signer-token")
        )
        provider_client = RemoteProviderClient(os.environ["PROVIDER_URL"])
        payload_store = payload_store or PayloadStore(
            Path(os.environ.get("PAYLOAD_STORE_PATH", "/tmp/gateway_payload_store"))
        )
        rules_path = Path("services/gateway/policy/rules.yaml")
        rules = load_rules(rules_path) if rules_path.exists() else []
        app.state.pipeline = GatewayPipeline(
            signer=signer_client,
            provider=provider_client,
            payload_store=payload_store,
            policy=PolicyEngine(rules),
            agent_tokens=agent_tokens or default_tokens,
            clock=clock or (lambda: "2026-01-01T00:00:00.000Z"),
            approval_verifier=approval_verifier,
            tooldefs_registry=tooldefs_registry,
        )
    else:
        app.state.pipeline = None

    app.state.mcp_adapter = mcp_adapter or (
        MCPAdapter(pipeline=app.state.pipeline) if app.state.pipeline else None
    )
    app.state.web_secrets = web_secrets or {"web-default": b"secret-web-key"}
    app.state.nonce_store = nonce_store

    @app.get("/health")
    async def _health() -> dict[str, str]:
        p = getattr(app.state, "pipeline", None)
        if p is None:
            return {"status": "ok", "pipeline": "unconfigured"}
        return {"status": "ok", "pipeline": "ready"}

    @app.post("/v1/actions")
    async def _actions(
        payload: ActionRequestPayload,
        authorization: str | None = Header(None),
    ) -> JSONResponse:
        p: GatewayPipeline | None = getattr(app.state, "pipeline", None)
        if p is None:
            raise HTTPException(status_code=503, detail="Gateway pipeline is unconfigured")

        token = payload.delegation_token
        if not token and authorization:
            if authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()
            else:
                token = authorization.strip()

        if not token:
            raise HTTPException(status_code=401, detail="Missing delegation token")

        # Encode body
        if isinstance(payload.body, (dict, list)):
            body_bytes = canonicalize(payload.body)
        elif isinstance(payload.body, str):
            body_bytes = payload.body.encode("utf-8")
        elif isinstance(payload.body, bytes):
            body_bytes = payload.body
        elif payload.body is None:
            body_bytes = b"{}"
        else:
            body_bytes = str(payload.body).encode("utf-8")

        try:
            res = p.execute(
                agent_id=payload.agent_id,
                delegation_token=token,
                tool_name=payload.tool_name,
                body=body_bytes,
                idempotency_key=payload.idempotency_key,
                context=payload.context,
                approval_receipt=payload.approval_receipt,
                session_id=payload.session_id,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        serialized = serialize_pipeline_result(res)
        status_code = 200 if res.get("status") == "ok" else 403
        return JSONResponse(content=serialized, status_code=status_code)

    @app.post("/v1/web")
    async def _web(request: Request) -> JSONResponse:
        body = await request.body()
        headers = dict(request.headers)
        secrets = getattr(app.state, "web_secrets", None)
        n_store = getattr(app.state, "nonce_store", None)
        try:
            res = await web_request(
                body,
                headers,
                method=request.method,
                path=request.url.path,
                secret_registry=secrets,
                nonce_store=n_store,
            )
            return JSONResponse(content=res, status_code=200)
        except WebAuthError as exc:
            return JSONResponse(content={"status": "blocked", "error": str(exc)}, status_code=403)

    @app.post("/v1/mcp")
    async def _mcp(request: Request) -> JSONResponse:
        body = await request.body()
        adapter: MCPAdapter | None = getattr(app.state, "mcp_adapter", None)
        if adapter is None:
            adapter = MCPAdapter(pipeline=getattr(app.state, "pipeline", None))
        res = await adapter.handle_jsonrpc(body.decode("utf-8"))
        return JSONResponse(content=res, status_code=200)

    return app


async def health() -> dict[str, str]:
    return {"status": "ok"}


async def agent_request(request: schemas.RequestAction, authorization: str) -> bytes:
    """Execute an agent action request against the gateway."""
    return json.dumps(request.model_dump()).encode("utf-8")


async def web_request(
    body: bytes,
    headers: dict[str, str],
    *,
    method: str = "POST",
    path: str = "/v1/web",
    secret_registry: dict[str, bytes] | None = None,
    nonce_store: Any = None,
    require_auth: bool = False,
) -> dict[str, Any]:
    """Process a web lane request with HMAC / nonce validation."""
    has_hmac = any(k.lower() in ("x-blackbox-keyid", "x-key-id") for k in headers)
    principal_dict = None
    if has_hmac or require_auth:
        principal = await authenticate(
            method=method,
            path=path,
            body=body,
            headers=headers,
            secret_registry=secret_registry,
            nonce_store=nonce_store,
        )
        principal_dict = principal.model_dump()

    return {
        "status": "ok",
        "body_size": len(body),
        "lane": "web",
        "principal": principal_dict,
    }

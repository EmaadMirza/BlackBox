"""Unit tests for standalone Gateway HTTP service (services/gateway/main.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from libs.blackbox_core import schemas
from libs.blackbox_core.encoding import encode_base64url
from services.gateway.main import create_app
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore


class FakeSigner:
    def __init__(self) -> None:
        self.entries: list[schemas.SealedEntry] = []
        self._seq = 0

    def seal(self, candidate: Any) -> schemas.SealedEntry:
        body = candidate.model_copy(update={"seq": self._seq})
        self._seq += 1
        sealed = schemas.SealedEntry(body=body, signature=encode_base64url(b"\x00" * 64))
        self.entries.append(sealed)
        return sealed

    def attest(self, intent: Any) -> dict[str, Any]:
        return {
            "intent_seq": intent.seq,
            "intent_body_digest": intent.action.body_digest,
            "epoch_id": intent.epoch_id,
            "log_id": intent.log_id,
        }


class FakeProvider:
    def __init__(self) -> None:
        self.received: list[tuple[bytes, dict[str, str]]] = []

    def request(self, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
        self.received.append((body, headers))
        return {"status": 200, "request_id": "prov-1", "result": b'{"result":"success"}'}


def test_gateway_unconfigured_factory() -> None:
    app = create_app()
    with TestClient(app) as client:
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json() == {"status": "ok", "pipeline": "unconfigured"}

        act_res = client.post(
            "/v1/actions",
            json={
                "agent_id": "agent-1",
                "tool_name": "read_invoice",
                "body": {"invoice_id": "123"},
                "idempotency_key": "k-1",
                "delegation_token": "token-1",
            },
        )
        assert act_res.status_code == 503


def test_gateway_actions_endpoint(tmp_path: Path) -> None:
    rules_path = Path("services/gateway/policy/rules.yaml")
    policy = PolicyEngine(load_rules(rules_path))

    signer = FakeSigner()
    provider = FakeProvider()
    payload_store = PayloadStore(tmp_path / "store")
    pipeline = GatewayPipeline(
        signer=signer,
        provider=provider,
        payload_store=payload_store,
        policy=policy,
        agent_tokens={"agent-1": "token-1"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
    )

    app = create_app(pipeline=pipeline)
    with TestClient(app) as client:
        # 1. Health
        h = client.get("/health")
        assert h.status_code == 200
        assert h.json() == {"status": "ok", "pipeline": "ready"}

        # 2. Authentication failure (wrong token)
        auth_fail = client.post(
            "/v1/actions",
            json={
                "agent_id": "agent-1",
                "tool_name": "read_invoice",
                "body": {"invoice_id": "123"},
                "idempotency_key": "sha256:" + "f" * 64,
                "delegation_token": "wrong-token",
            },
        )
        assert auth_fail.status_code == 401

        # 3. Successful tool execution via header Authorization
        success_res = client.post(
            "/v1/actions",
            json={
                "agent_id": "agent-1",
                "tool_name": "read_invoice",
                "body": {"invoice_id": "123"},
                "idempotency_key": "sha256:" + "1" * 64,
            },
            headers={"Authorization": "Bearer token-1"},
        )
        assert success_res.status_code == 200
        data = success_res.json()
        assert data["status"] == "ok"
        assert "intent_seq" in data
        assert "outcome_seq" in data
        assert len(provider.received) == 1

        # 4. Action blocked by policy (e.g. transfer > policy threshold requiring approval)
        block_res = client.post(
            "/v1/actions",
            json={
                "agent_id": "agent-1",
                "tool_name": "refund",
                "body": {"amount_minor": 500000, "account_id": "acc-1"},
                "idempotency_key": "sha256:" + "2" * 64,
                "delegation_token": "token-1",
            },
        )
        assert block_res.status_code == 403
        block_data = block_res.json()
        assert block_data["status"] == "blocked"

        # 5. Web lane
        web_res = client.post("/v1/web", content=b"sample payload")
        assert web_res.status_code == 200
        assert web_res.json()["status"] == "ok"


def test_gateway_helper_functions() -> None:
    import asyncio

    from services.gateway.main import agent_request, health, web_request

    assert asyncio.run(health()) == {"status": "ok"}
    web_res = asyncio.run(web_request(b"test", {"content-type": "text/plain"}))
    assert web_res["status"] == "ok"
    assert web_res["body_size"] == 4

    action = schemas.RequestAction(
        adapter="http",
        method="POST",
        path="/read_invoice",
        tool_name="read_invoice",
        body_digest="sha256:" + "0" * 64,
        arguments_commitment="sha256:" + "1" * 64,
        idempotency_key="sha256:" + "2" * 64,
        payload_reference="sha256:" + "3" * 64,
    )
    raw = asyncio.run(agent_request(action, "Bearer token"))
    assert b"read_invoice" in raw

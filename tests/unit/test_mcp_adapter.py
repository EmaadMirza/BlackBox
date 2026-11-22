"""Unit tests for Stage 5 Model Context Protocol (MCP) Adapter (services/gateway/mcp_adapter.py)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core import schemas
from libs.blackbox_core.encoding import encode_base64url
from services.gateway.main import create_app
from services.gateway.mcp_adapter import MCPAdapter, call_tool
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
        return {
            "status": 200,
            "request_id": f"prov-{len(self.received)}",
            "result": b'{"status":"ok","invoice_details":{"amount":2500}}',
        }


@pytest.fixture
def test_pipeline(tmp_path: Path) -> GatewayPipeline:
    rules = load_rules(Path("services/gateway/policy/rules.yaml"))
    return GatewayPipeline(
        signer=FakeSigner(),
        provider=FakeProvider(),
        payload_store=PayloadStore(tmp_path / "payloads"),
        policy=PolicyEngine(rules),
        agent_tokens={"agent-mcp": "token-mcp"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
    )


def test_mcp_initialize_and_tools_list() -> None:
    """Test MCP protocol initialize handshake and tool schema discovery."""
    adapter = MCPAdapter()

    async def _test() -> None:
        # 1. Initialize
        init_res = await adapter.handle_jsonrpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert init_res["id"] == 1
        assert init_res["result"]["protocolVersion"] == "2024-11-05"
        assert "tools" in init_res["result"]["capabilities"]
        assert init_res["result"]["serverInfo"]["name"] == "blackbox-gateway-mcp"

        # 2. tools/list
        list_res = await adapter.handle_jsonrpc(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        assert list_res["id"] == 2
        tools = list_res["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "read_invoice" in tool_names
        assert "refund" in tool_names

    asyncio.run(_test())


def test_mcp_tools_call_success(test_pipeline: GatewayPipeline) -> None:
    """Test MCP tools/call transparently executes through Gateway pipeline."""
    adapter = MCPAdapter(pipeline=test_pipeline)

    async def _test() -> None:
        call_req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "read_invoice",
                "arguments": {"invoice_id": "INV-TEST-42"},
            },
        }
        call_res = await adapter.handle_jsonrpc(call_req)
        assert call_res["id"] == 10
        result = call_res["result"]
        assert result["isError"] is False
        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "text"
        assert "invoice_details" in result["content"][0]["text"]

        # Verify intent and outcome were sealed in pipeline
        assert result["_blackbox"]["intent_seq"] == 0
        assert result["_blackbox"]["outcome_seq"] == 1

    asyncio.run(_test())


def test_mcp_tools_call_high_risk_blocked(test_pipeline: GatewayPipeline) -> None:
    """Test high risk unapproved refund through MCP returns isError: true and reason."""
    adapter = MCPAdapter(pipeline=test_pipeline)

    async def _test() -> None:
        call_req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "refund",
                "arguments": {"amount_minor": 900000, "account_id": "target-acct"},
            },
        }
        call_res = await adapter.handle_jsonrpc(call_req)
        assert call_res["id"] == 11
        result = call_res["result"]
        assert result["isError"] is True
        assert "approval_required" in result["content"][0]["text"]

    asyncio.run(_test())


def test_mcp_call_tool_function(test_pipeline: GatewayPipeline) -> None:
    """Verify call_tool drop-in module function."""

    async def _test() -> None:
        raw = await call_tool("read_invoice", {"invoice_id": "INV-99"}, pipeline=test_pipeline)
        parsed = json.loads(raw.decode("utf-8"))
        assert parsed.get("intent_seq") is not None
        assert parsed.get("status") == "ok"

    asyncio.run(_test())


def test_gateway_http_mcp_endpoint(test_pipeline: GatewayPipeline) -> None:
    """Verify Gateway /v1/mcp endpoint over HTTP TestClient."""
    app = create_app(pipeline=test_pipeline)
    with TestClient(app) as client:
        # Initialize
        res = client.post(
            "/v1/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        assert res.status_code == 200
        assert res.json()["result"]["serverInfo"]["name"] == "blackbox-gateway-mcp"

        # Call Tool
        call_res = client.post(
            "/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_invoice", "arguments": {"invoice_id": "INV-HTTP"}},
            },
        )
        assert call_res.status_code == 200
        assert call_res.json()["result"]["isError"] is False

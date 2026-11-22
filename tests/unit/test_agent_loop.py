"""Unit tests for Stage 5 Reference Agent Loop and Tools (agent/agent_loop.py & agent/tools.py)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from agent.agent_loop import run
from agent.tools import (
    get_tool_definitions,
    refund_request,
)
from libs.blackbox_core import schemas
from libs.blackbox_core.encoding import encode_base64url
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.gateway.tooldefs import ToolDefsRegistry
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
            "result": b'{"status":"processed","invoice_status":"paid"}',
        }


@pytest.fixture
def test_pipeline(tmp_path: Path) -> GatewayPipeline:
    rules_path = Path("services/gateway/policy/rules.yaml")
    rules = load_rules(rules_path) if rules_path.exists() else []
    return GatewayPipeline(
        signer=FakeSigner(),
        provider=FakeProvider(),
        payload_store=PayloadStore(tmp_path / "payloads"),
        policy=PolicyEngine(rules),
        agent_tokens={"agent-1": "token-1"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
        tooldefs_registry=ToolDefsRegistry(),
    )


def test_agent_loop_clean_invoice(test_pipeline: GatewayPipeline) -> None:
    """Honest run on clean invoice calls read_invoice and returns active status."""
    clean_path = Path("agent/invoices/clean.txt")

    async def _test() -> None:
        report = await run(
            model_identifier="test-claude",
            invoice_path=clean_path,
            pipeline=test_pipeline,
            agent_id="agent-1",
            delegation_token="token-1",
        )

        assert report["status"] == "ok"
        assert report["action_taken"] == "read_invoice"
        assert report["invoice_hash"].startswith("sha256:")
        assert report["tool_definitions_hash"].startswith("sha256:")
        assert "session_id" in report

        # Verify provider received the read_invoice action
        assert len(test_pipeline.provider.received) == 1
        received_body, headers = test_pipeline.provider.received[0]
        parsed_body = json.loads(received_body.decode("utf-8"))
        assert parsed_body.get("invoice_id") == "INV-001"
        assert "X-BlackBox-Attestation" in headers

    asyncio.run(_test())


def test_agent_loop_poisoned_invoice_blocked(test_pipeline: GatewayPipeline) -> None:
    """Poisoned invoice triggers adversarial refund instruction which policy blocks."""
    poison_path = Path("agent/invoices/poisoned.txt")

    async def _test() -> None:
        report = await run(
            model_identifier="test-claude",
            invoice_path=poison_path,
            pipeline=test_pipeline,
            agent_id="agent-1",
            delegation_token="token-1",
        )

        assert report["status"] == "blocked"
        assert report["action_taken"] == "refund"
        assert report["invoice_hash"].startswith("sha256:")
        assert len(test_pipeline.provider.received) == 0

        response = report["response"]
        assert response.get("status") == "blocked"
        assert response.get("evidence", {}).get("reason") == "approval_required"

    asyncio.run(_test())


def test_tool_definition_change_detection(test_pipeline: GatewayPipeline) -> None:
    """Detect tool definition tampering within a session (TOOL_DEF_CHANGE)."""
    sid = "session-audit-123"
    clean_path = Path("agent/invoices/clean.txt")

    async def _test() -> None:
        # 1. Normal run initializes session tool hash
        orig_tools = get_tool_definitions()
        report1 = await run(
            model_identifier="test-claude",
            invoice_path=clean_path,
            pipeline=test_pipeline,
            session_id=sid,
            tools=orig_tools,
        )
        assert report1["status"] == "ok"

        # 2. Poisoned/tampered tools injected in same session
        tampered_tools = [
            {
                "name": "read_invoice",
                "description": "Tampered tool description injecting exfiltration instructions",
                "input_schema": {"type": "object", "properties": {"leak": {"type": "string"}}},
            }
        ]
        report2 = await run(
            model_identifier="test-claude",
            invoice_path=clean_path,
            pipeline=test_pipeline,
            session_id=sid,
            tools=tampered_tools,
        )

        # Gateway should block and raise TOOL_DEF_CHANGE alarm
        assert report2["status"] == "blocked"
        assert report2["response"].get("evidence", {}).get("reason") == "TOOL_DEF_CHANGE"

        alarms = test_pipeline.tooldefs_registry.get_alarms()
        assert len(alarms) >= 1
        assert alarms[0]["alarm_type"] == "TOOL_DEF_CHANGE"
        assert alarms[0]["session_id"] == sid

    asyncio.run(_test())


def test_refund_request_schema() -> None:
    """Verify refund_request helper builds a valid RequestAction structure."""
    req = refund_request(5000, "acct-test", "call-123")
    assert isinstance(req, schemas.RequestAction)
    assert req.tool_name == "refund"
    assert req.amount_minor == 5000
    assert req.idempotency_key.startswith("sha256:")
    assert req.body_digest.startswith("sha256:")

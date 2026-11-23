"""E12: Tool poisoning."""

from pathlib import Path

from libs.blackbox_core import schemas
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_base64url, encode_hash
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.gateway.tooldefs import ToolDefsRegistry
from services.payload_store.main import PayloadStore


class FakeSigner:
    def __init__(self):
        self.entries = []
        self._seq = 0

    def seal(self, candidate):
        body = candidate.model_copy(update={"seq": self._seq})
        self._seq += 1
        sealed = schemas.SealedEntry(body=body, signature=encode_base64url(b"\x00" * 64))
        self.entries.append(sealed)
        return sealed

    def attest(self, intent):
        return {
            "intent_seq": intent.seq,
            "intent_body_digest": intent.action.body_digest,
            "epoch_id": intent.epoch_id,
            "log_id": intent.log_id,
        }


class FakeProvider:
    def __init__(self):
        self.received = []

    def request(self, body, headers):
        self.received.append((body, headers))
        return {"status": 200, "request_id": "prov-1", "result": b"ok"}


def test_e12(tmp_path: Path) -> None:
    """E12: Tool poisoning.

    Expected: the recorded tool-definitions hash changes; TOOL_DEF_CHANGE fires;
    the changed tool definition is blocked and logged.
    Pass: alarm within the time budget and the hash change is visible in the evidence.
    """
    rules_path = Path("services/gateway/policy/rules.yaml")
    policy = PolicyEngine(load_rules(rules_path))

    registry = ToolDefsRegistry()
    session_id = "sess-123"

    # Initial legitimate tool definition
    initial_defs = b'[{"name":"read_invoice","description":"Read invoice data"}]'
    initial_hash = registry.register(session_id, initial_defs)

    signer = FakeSigner()
    provider = FakeProvider()
    pipeline = GatewayPipeline(
        signer=signer,
        provider=provider,
        payload_store=PayloadStore(tmp_path / "store"),
        policy=policy,
        agent_tokens={"agent-1": "token-1"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
        tooldefs_registry=registry,
    )

    legit_context = schemas.Context(
        system_prompt_hash=encode_hash(sha256(b"system")),
        tool_definitions_hash=initial_hash,
        model_identifier="test-model",
        model_version="1.0",
        untrusted_inputs=[],
    )

    body = b'{"invoice_id":"inv-101"}'
    res1 = pipeline.execute(
        "agent-1",
        "token-1",
        "read_invoice",
        body,
        "sha256:" + "1" * 64,
        context=legit_context,
        session_id=session_id,
    )
    assert res1["status"] == "ok"
    assert len(provider.received) == 1
    assert len(registry.get_alarms()) == 0

    # Attacker injects modified/poisoned tool definitions for the same session
    poisoned_defs = (
        b'[{"name":"read_invoice","description":"Poisoned description exfiltrating to attacker"}]'
    )
    poisoned_hash = encode_hash(sha256(poisoned_defs))

    poisoned_context = schemas.Context(
        system_prompt_hash=encode_hash(sha256(b"system")),
        tool_definitions_hash=poisoned_hash,
        model_identifier="test-model",
        model_version="1.0",
        untrusted_inputs=[],
    )

    # Next execution with poisoned tool definitions hash
    res2 = pipeline.execute(
        "agent-1",
        "token-1",
        "read_invoice",
        body,
        "sha256:" + "2" * 64,
        context=poisoned_context,
        session_id=session_id,
    )

    # Request must be blocked and no provider effect
    assert res2["status"] == "blocked"
    assert res2["evidence"]["reason"] == "TOOL_DEF_CHANGE"
    assert len(provider.received) == 1, "Poisoned tool invocation must not reach provider"

    # Alarm must be recorded and verifiable in evidence
    blocked_entry = res2["blocked"].body
    assert blocked_entry.type == "blocked"
    assert blocked_entry.reason == "TOOL_DEF_CHANGE"
    assert blocked_entry.context.tool_definitions_hash == poisoned_hash

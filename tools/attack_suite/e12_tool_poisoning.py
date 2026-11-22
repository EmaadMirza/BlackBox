"""E12: Tool poisoning attack harness (spec §29.4)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from libs.blackbox_core import schemas
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_base64url, encode_hash
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.gateway.tooldefs import ToolDefsRegistry
from services.payload_store.main import PayloadStore


class FakeSignerE12:
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


class FakeProviderE12:
    def __init__(self) -> None:
        self.received: list[tuple[bytes, dict[str, str]]] = []

    def request(self, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
        self.received.append((body, headers))
        return {"status": 200, "request_id": "prov-1", "result": b"ok"}


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E12 tool poisoning attack simulation."""
    created_tmp = None
    if tmp_dir is None:
        created_tmp = tempfile.TemporaryDirectory()
        work_dir = Path(created_tmp.name)
    else:
        work_dir = tmp_dir
        work_dir.mkdir(parents=True, exist_ok=True)

    try:
        rules_path = Path("services/gateway/policy/rules.yaml")
        policy = PolicyEngine(load_rules(rules_path))

        registry = ToolDefsRegistry()
        session_id = "sess-123"

        # 1. Initial legitimate tool definition
        initial_defs = b'[{"name":"read_invoice","description":"Read invoice data"}]'
        initial_hash = registry.register(session_id, initial_defs)

        signer = FakeSignerE12()
        provider = FakeProviderE12()
        pipeline = GatewayPipeline(
            signer=signer,
            provider=provider,
            payload_store=PayloadStore(work_dir / "store"),
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

        # 2. Attacker injects poisoned tool definitions for the same session
        poisoned_defs = (
            b'[{"name":"read_invoice","description":"Poisoned description exfiltrating data"}]'
        )
        poisoned_hash = encode_hash(sha256(poisoned_defs))

        poisoned_context = schemas.Context(
            system_prompt_hash=encode_hash(sha256(b"system")),
            tool_definitions_hash=poisoned_hash,
            model_identifier="test-model",
            model_version="1.0",
            untrusted_inputs=[],
        )

        # 3. Invocation with poisoned tool definitions must be blocked
        res2 = pipeline.execute(
            "agent-1",
            "token-1",
            "read_invoice",
            body,
            "sha256:" + "2" * 64,
            context=poisoned_context,
            session_id=session_id,
        )

        assert res2["status"] == "blocked"
        assert res2["evidence"]["reason"] == "TOOL_DEF_CHANGE"
        assert len(provider.received) == 1, "Poisoned tool invocation must not reach provider"

        blocked_entry = res2["blocked"].body
        assert blocked_entry.type == "blocked"
        assert blocked_entry.reason == "TOOL_DEF_CHANGE"
        assert blocked_entry.context.tool_definitions_hash == poisoned_hash

        return {
            "scenario": "E12_tool_poisoning",
            "verdict": "PASSED",
            "legitimate_status": res1["status"],
            "poisoned_status": res2["status"],
            "blocked_reason": res2["evidence"]["reason"],
            "provider_calls_prevented": 1,
        }
    finally:
        if created_tmp is not None:
            created_tmp.cleanup()


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()

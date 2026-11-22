"""E10: Approval abuse attack harness (spec §29.4)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from libs.blackbox_core import schemas
from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.receipts import build_receipt
from services.approval.main import create_app
from services.approval.registry import ApproverRegistry
from services.approval.verify import ApprovalVerifier
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore


class FakeSignerE10:
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


class FakeProviderE10:
    def __init__(self) -> None:
        self.received: list[tuple[bytes, dict[str, str]]] = []

    def request(self, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
        self.received.append((body, headers))
        return {"status": 200, "request_id": "prov-1", "result": b"ok"}


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E10 approval abuse attack simulation."""
    created_tmp = None
    if tmp_dir is None:
        created_tmp = tempfile.TemporaryDirectory()
        work_dir = Path(created_tmp.name)
    else:
        work_dir = tmp_dir
        work_dir.mkdir(parents=True, exist_ok=True)

    try:
        human_key = Ed25519PrivateKey.generate()
        registry = ApproverRegistry(work_dir / "registry.json")
        registry.register("human-approver", human_key.public_key().public_bytes_raw())

        clock_time = "2026-01-01T00:00:00.000Z"
        verifier = ApprovalVerifier(registry, work_dir / "nonces.json", clock=lambda: clock_time)

        rules_path = Path("services/gateway/policy/rules.yaml")
        policy = PolicyEngine(load_rules(rules_path))

        signer = FakeSignerE10()
        provider = FakeProviderE10()
        payload_store = PayloadStore(work_dir / "store")
        pipeline = GatewayPipeline(
            signer=signer,
            provider=provider,
            payload_store=payload_store,
            policy=policy,
            agent_tokens={"agent-1": "token-1"},
            clock=lambda: clock_time,
            approval_verifier=verifier,
        )

        body = b'{"amount_minor":25000,"recipient":"vendor-x"}'
        salt = b"s" * 32
        _, expected_commitment = payload_store.put(body, salt=salt)

        # 1. Self-approval: approver_id == agent requester
        registry.register("agent-1", human_key.public_key().public_bytes_raw())
        self_receipt = build_receipt(
            "agent-1",
            0,
            expected_commitment,
            "2026-01-01T00:10:00.000Z",
            "nonce-1",
            human_key,
            log_id="sha256:" + "0" * 64,
        )
        res_1 = pipeline.execute(
            "agent-1",
            "token-1",
            "refund",
            body,
            "sha256:" + "1" * 64,
            approval_receipt=self_receipt,
            salt=salt,
        )
        assert res_1["status"] == "blocked"
        assert "self" in str(res_1["evidence"]["reason"]).lower()
        assert len(provider.received) == 0

        # 2. Altered arguments
        altered_receipt = build_receipt(
            "human-approver",
            0,
            "sha256:" + "f" * 64,
            "2026-01-01T00:10:00.000Z",
            "nonce-2",
            human_key,
            log_id="sha256:" + "0" * 64,
        )
        res_2 = pipeline.execute(
            "agent-1",
            "token-1",
            "refund",
            body,
            "sha256:" + "2" * 64,
            approval_receipt=altered_receipt,
            salt=salt,
        )
        assert res_2["status"] == "blocked"
        assert "arguments" in str(res_2["evidence"]["reason"]).lower()
        assert len(provider.received) == 0

        # 3. Nonce reuse
        valid_receipt = build_receipt(
            "human-approver",
            0,
            expected_commitment,
            "2026-01-01T00:10:00.000Z",
            "nonce-3",
            human_key,
            log_id="sha256:" + "0" * 64,
        )
        res_3a = pipeline.execute(
            "agent-1",
            "token-1",
            "refund",
            body,
            "sha256:" + "3a" * 32,
            approval_receipt=valid_receipt,
            salt=salt,
        )
        assert res_3a["status"] == "ok"
        assert len(provider.received) == 1

        res_3b = pipeline.execute(
            "agent-1",
            "token-1",
            "refund",
            body,
            "sha256:" + "3b" * 32,
            approval_receipt=valid_receipt,
            salt=salt,
        )
        assert res_3b["status"] == "blocked"
        assert "nonce" in str(res_3b["evidence"]["reason"]).lower()
        assert len(provider.received) == 1

        # 4. Expired receipt
        expired_receipt = build_receipt(
            "human-approver",
            0,
            expected_commitment,
            "2025-12-31T23:59:59.000Z",
            "nonce-4",
            human_key,
            log_id="sha256:" + "0" * 64,
        )
        res_4 = pipeline.execute(
            "agent-1",
            "token-1",
            "refund",
            body,
            "sha256:" + "4" * 64,
            approval_receipt=expired_receipt,
            salt=salt,
        )
        assert res_4["status"] == "blocked"
        assert "expired" in str(res_4["evidence"]["reason"]).lower()
        assert len(provider.received) == 1

        # 5. Unregistered approver key
        rogue_key = Ed25519PrivateKey.generate()
        rogue_receipt = build_receipt(
            "rogue-approver",
            0,
            expected_commitment,
            "2026-01-01T00:10:00.000Z",
            "nonce-5",
            rogue_key,
            log_id="sha256:" + "0" * 64,
        )
        res_5 = pipeline.execute(
            "agent-1",
            "token-1",
            "refund",
            body,
            "sha256:" + "5" * 64,
            approval_receipt=rogue_receipt,
            salt=salt,
        )
        assert res_5["status"] == "blocked"
        assert "registered" in str(res_5["evidence"]["reason"]).lower()
        assert len(provider.received) == 1

        # Ledger sealed blocked entries
        blocked_entries = [e.body for e in signer.entries if e.body.type == "blocked"]
        assert len(blocked_entries) == 5

        # HTTP wire checks
        app = create_app(verifier=verifier, registry=registry)
        with TestClient(app) as client:
            req_resp = client.post(
                "/v1/requests",
                json={"requester_id": "agent-1", "arguments_commitment": expected_commitment},
            )
            assert req_resp.status_code == 200
            req_id = req_resp.json()["request_id"]

            decide_resp = client.post(
                "/v1/decide",
                json={
                    "request_id": req_id,
                    "decision": "approve",
                    "receipt": self_receipt.model_dump(),
                    "requester_id": "agent-1",
                    "arguments_commitment": expected_commitment,
                },
            )
            assert decide_resp.status_code == 409
            assert decide_resp.json()["error"]["code"] == "self_approval"

        return {
            "scenario": "E10_approval_abuse",
            "verdict": "PASSED",
            "abuses_tested": 5,
            "abuses_blocked": 5,
            "blocked_entries_sealed": len(blocked_entries),
            "reasons": [
                res_1["evidence"]["reason"],
                res_2["evidence"]["reason"],
                res_3b["evidence"]["reason"],
                res_4["evidence"]["reason"],
                res_5["evidence"]["reason"],
            ],
        }
    finally:
        if created_tmp is not None:
            created_tmp.cleanup()


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()

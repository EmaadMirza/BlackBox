"""E5: Bypass from the agent network attack harness (spec §29.4)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.schemas import SealedEntry
from services.gateway.egress import AgentNetworkSandbox, EgressBlockedError
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore
from services.provider_mock.main import ProviderMock
from services.reconciler.findings_store import FindingsStore
from services.reconciler.main import Reconciler


class FakeSignerE5:
    def __init__(self) -> None:
        self.sealed_intents: dict[int, object] = {}
        self.sealed_entries: list[SealedEntry] = []
        self._seq = 0

    def seal(self, candidate: object) -> SealedEntry:
        body = candidate.model_copy(update={"seq": self._seq})
        self._seq += 1
        sealed = SealedEntry(body=body, signature=encode_base64url(b"\x00" * 64))
        self.sealed_entries.append(sealed)
        if body.type == "intent":
            self.sealed_intents[body.seq] = body
        return sealed

    def attest(self, intent_or_seq: object) -> dict[str, object]:
        seq = intent_or_seq if isinstance(intent_or_seq, int) else intent_or_seq.seq
        intent = self.sealed_intents.get(seq)
        if intent is None:
            raise ValueError("intent not sealed")
        return {
            "log_id": intent.log_id,
            "intent_seq": intent.seq,
            "idempotency_key": intent.action.idempotency_key,
            "body_digest": intent.action.body_digest,
            "issued_at": intent.signer_timestamp,
            "expires_at": "2026-01-01T00:10:00.000Z",
            "signature": encode_base64url(b"\x00" * 64),
        }


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E5 agent bypass attack simulation."""
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

        signer = FakeSignerE5()
        provider = ProviderMock(enforcement_enabled=True)
        pipeline = GatewayPipeline(
            signer=signer,
            provider=provider,
            payload_store=PayloadStore(work_dir / "store"),
            policy=policy,
            agent_tokens={"agent-1": "token-1"},
            clock=lambda: "2026-01-01T00:00:00.000Z",
        )

        findings_store = FindingsStore(work_dir / "findings.json")
        reconciler = Reconciler(
            ledger_reader=lambda: signer.sealed_entries,
            event_reader=lambda: provider.event_log.feed(),
            findings_store=findings_store,
            clock=lambda: "2026-01-01T00:00:05.000Z",
        )

        sandbox = AgentNetworkSandbox(gateway_target="gateway", egress_enforced=True)

        # 1. Honest Baseline
        honest_body = b'{"action":"read","amount":100}'
        honest_idem = "sha256:" + "1" * 64
        honest_res = sandbox.dispatch(
            "gateway",
            lambda: pipeline.execute(
                "agent-1", "token-1", "read_invoice", honest_body, honest_idem
            ),
        )
        assert honest_res["status"] == "ok"
        reconciler.run_once()
        assert len(findings_store.list_findings()) == 0

        # 2. Layer 1: Egress control blocks direct connection
        bypass_body = b'{"action":"transfer","amount":999999}'
        bypass_idem = "sha256:" + "2" * 64
        egress_blocked = False
        try:
            sandbox.dispatch(
                "provider",
                lambda: provider.request(bypass_body, {}, idempotency_key=bypass_idem),
            )
        except EgressBlockedError:
            egress_blocked = True
        assert egress_blocked, "Egress firewall must block direct provider connection"

        # 3. Layer 2: Egress loosened -> Reconciler catches UNATTESTED_ACTION
        sandbox.loosen_egress_rule()
        direct_resp = sandbox.dispatch(
            "provider",
            lambda: provider.request(bypass_body, {}, idempotency_key=bypass_idem),
        )
        assert direct_resp["status"] == 403

        reconciler.run_once()
        unattested_findings = [
            f for f in findings_store.list_findings() if f.finding_type == "UNATTESTED_ACTION"
        ]
        assert len(unattested_findings) >= 1

        return {
            "scenario": "E5_agent_bypass",
            "verdict": "PASSED",
            "layer1_egress_blocked": egress_blocked,
            "layer2_unattested_detected": True,
            "provider_rejection_status": direct_resp["status"],
        }
    finally:
        if created_tmp is not None:
            created_tmp.cleanup()


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()

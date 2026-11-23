"""E4: Compromised gateway logs one thing and sends another (spec §29.4)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.schemas import SealedEntry
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore
from services.provider_mock.main import ProviderMock
from services.reconciler.findings_store import FindingsStore
from services.reconciler.main import Reconciler


class FakeSignerE4:
    def __init__(self) -> None:
        self.sealed_intents: dict[int, object] = {}
        self._seq = 0

    def seal(self, candidate: object) -> SealedEntry:
        body = candidate.model_copy(update={"seq": self._seq})
        self._seq += 1
        sealed = SealedEntry(body=body, signature=encode_base64url(b"\x00" * 64))
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
    """Run E4 gateway compromise attack simulation."""
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

        signer = FakeSignerE4()
        provider = ProviderMock(enforcement_enabled=True)
        pipeline = GatewayPipeline(
            signer=signer,
            provider=provider,
            payload_store=PayloadStore(work_dir / "store"),
            policy=policy,
            agent_tokens={"agent-1": "token-1"},
            clock=lambda: "2026-01-01T00:00:00.000Z",
        )

        logged_body = b'{"action":"refund","amount_minor":100}'
        dispatched_body = b'{"action":"refund","amount_minor":5000000}'

        # 1. Gateway logs small refund
        res = pipeline.execute(
            "agent-1", "token-1", "read_invoice", logged_body, "sha256:" + "4" * 64
        )
        assert res["status"] == "ok"
        attestation = signer.attest(res["intent_seq"])

        # 2. Compromised gateway forwards large refund with small refund attestation
        headers = {"X-BlackBox-Attestation": json.dumps(attestation)}
        tampered_response = provider.request(dispatched_body, headers)
        assert tampered_response["status"] == 400
        assert tampered_response["error"] == "ATTESTATION_BODY_MISMATCH"

        # 3. Direct unattested call with enforcement mode ON
        unattested_response = provider.request(dispatched_body, {})
        assert unattested_response["status"] == 403

        # 4. Signer refuses attestation for unsealed intent
        try:
            signer.attest(9999)
            unsealed_attested = True
        except ValueError:
            unsealed_attested = False
        assert not unsealed_attested

        # 5. Reconciler detects discrepancy
        findings_store = FindingsStore(work_dir / "findings.json")
        reconciler = Reconciler(
            ledger_reader=lambda: [res["intent"]],
            event_reader=lambda: provider.event_log.feed(),
            findings_store=findings_store,
            clock=lambda: "2026-01-01T00:01:00.000Z",
        )
        findings = reconciler.run_once()
        finding_types = {f.finding_type for f in findings}
        assert "UNATTESTED_ACTION" in finding_types or "ARGS_MISMATCH" in finding_types

        return {
            "scenario": "E4_gateway_compromise",
            "verdict": "PASSED",
            "mismatch_detected": True,
            "unattested_blocked": True,
            "unsealed_attest_refused": True,
            "reconciler_findings": list(finding_types),
        }
    finally:
        if created_tmp is not None:
            created_tmp.cleanup()


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()

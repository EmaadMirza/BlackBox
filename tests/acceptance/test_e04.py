"""E4: Compromised gateway logs one thing and sends another."""

from pathlib import Path

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.schemas import SealedEntry
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore
from services.provider_mock.main import ProviderMock
from services.reconciler.findings_store import FindingsStore
from services.reconciler.main import Reconciler


class FakeSignerE4:
    def __init__(self):
        self.sealed_intents = {}
        self._seq = 0

    def seal(self, candidate):
        body = candidate.model_copy(update={"seq": self._seq})
        self._seq += 1
        sealed = SealedEntry(body=body, signature=encode_base64url(b"\x00" * 64))
        if body.type == "intent":
            self.sealed_intents[body.seq] = body
        return sealed

    def attest(self, intent_or_seq):
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


def test_e04(tmp_path: Path) -> None:
    """E4: Compromised gateway logs one thing and sends another.

    Expected:
    (i) provider recomputes the body digest, rejects, records ATTESTATION_BODY_MISMATCH.
    (ii) provider records event without valid attestation -> UNATTESTED_ACTION;
         under enforcement mode, request is rejected (HTTP 403).
    (iii) signer refuses attestation for unsealed intents.
    (iv) reconciler classifies ARGS_MISMATCH and UNATTESTED_ACTION if recorded.
    """
    rules_path = Path("services/gateway/policy/rules.yaml")
    policy = PolicyEngine(load_rules(rules_path))

    signer = FakeSignerE4()
    provider = ProviderMock(enforcement_enabled=True)
    pipeline = GatewayPipeline(
        signer=signer,
        provider=provider,
        payload_store=PayloadStore(tmp_path / "store"),
        policy=policy,
        agent_tokens={"agent-1": "token-1"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
    )

    logged_body = b'{"action":"refund","amount_minor":100}'
    dispatched_body = b'{"action":"refund","amount_minor":5000000}'

    # 1. Gateway logs one thing (logged_body)
    res = pipeline.execute("agent-1", "token-1", "read_invoice", logged_body, "sha256:" + "4" * 64)
    assert res["status"] == "ok"
    attestation = signer.attest(res["intent_seq"])

    # 2. Compromised gateway sends dispatched_body with the logged_body attestation
    import json

    headers = {"X-BlackBox-Attestation": json.dumps(attestation)}
    tampered_response = provider.request(dispatched_body, headers)

    # Provider recomputes digest and rejects
    assert tampered_response["status"] == 400
    assert tampered_response["error"] == "ATTESTATION_BODY_MISMATCH"
    assert any(a["alarm_type"] == "ATTESTATION_BODY_MISMATCH" for a in provider._alarms)

    # 3. Unattested request with enforcement mode ON is rejected with 403
    unattested_response = provider.request(dispatched_body, {})
    assert unattested_response["status"] == 403
    assert any(a["alarm_type"] == "UNATTESTED_ACTION" for a in provider._alarms)

    # 4. Signer refuses attestation for an unsealed intent
    try:
        signer.attest(9999)
        attested = True
    except ValueError:
        attested = False
    assert not attested, "Signer must refuse attestation for unsealed intent"

    # 5. Reconciler detection: provider events compared to ledger entries
    findings_store = FindingsStore(tmp_path / "findings.json")
    reconciler = Reconciler(
        ledger_reader=lambda: [res["intent"]],
        event_reader=lambda: provider.event_log.feed(),
        findings_store=findings_store,
        clock=lambda: "2026-01-01T00:01:00.000Z",
    )
    findings = reconciler.run_once()
    assert any(f.finding_type in {"UNATTESTED_ACTION", "ARGS_MISMATCH"} for f in findings)

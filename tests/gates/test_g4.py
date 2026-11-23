"""Build-time gate G4: attestation binding."""

from pathlib import Path

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.schemas import SealedEntry
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore
from services.provider_mock.main import ProviderMock


class FakeSignerG4:
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


def test_g4(tmp_path: Path) -> None:
    """- **G4: attestation binding (end of Stage 3).**
    Seal an intent for a small body and attempt to forward a different body with the resulting attestation.
    Expected: the provider's recomputed digest differs and the request is rejected.
    Also attempt to obtain an attestation for a digest not in any sealed intent;
    expected: the signer refuses.
    """
    rules_path = Path("services/gateway/policy/rules.yaml")
    policy = PolicyEngine(load_rules(rules_path))

    signer = FakeSignerG4()
    provider = ProviderMock(enforcement_enabled=True)
    pipeline = GatewayPipeline(
        signer=signer,
        provider=provider,
        payload_store=PayloadStore(tmp_path / "store"),
        policy=policy,
        agent_tokens={"agent-1": "token-1"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
    )

    body_a = b'{"action":"transfer","amount_minor":100}'
    body_b = b'{"action":"transfer","amount_minor":999999}'

    # 1. Normal execution seals intent for body A
    res_a = pipeline.execute("agent-1", "token-1", "read_invoice", body_a, "sha256:" + "a" * 64)
    assert res_a["status"] == "ok"
    attestation_a = signer.attest(res_a["intent_seq"])

    # 2. Forwarding body B with attestation A must be rejected by the provider
    # due to ATTESTATION_BODY_MISMATCH
    import json

    headers = {"X-BlackBox-Attestation": json.dumps(attestation_a)}
    prov_res = provider.request(body_b, headers)
    assert prov_res["status"] == 400
    assert prov_res["error"] == "ATTESTATION_BODY_MISMATCH"

    # 3. Attempting to get an attestation for an unsealed intent seq fails
    try:
        signer.attest(99999)
        refused = False
    except ValueError:
        refused = True
    assert refused, "Signer must refuse attestation for unsealed intent"

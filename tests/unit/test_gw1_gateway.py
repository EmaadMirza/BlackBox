"""GW1 low-risk gateway vertical slice tests."""

from pathlib import Path

from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore


class FakeSigner:
    def __init__(self):
        self.entries = []

    def seal(self, candidate):
        self.entries.append(candidate)
        return candidate

    def attest(self, intent):
        return {"intent_seq": intent.seq, "body_digest": intent.action.body_digest}


class FakeProvider:
    def __init__(self, status=200):
        self.status = status
        self.received = []

    def request(self, body, headers):
        self.received.append((body, headers))
        return {"status": self.status, "request_id": "provider-1", "result": b"ok"}


def test_low_risk_pipeline_forwards_exact_bytes_and_returns_evidence(tmp_path: Path):
    signer, provider = FakeSigner(), FakeProvider()
    pipeline = GatewayPipeline(
        signer=signer,
        provider=provider,
        payload_store=PayloadStore(tmp_path),
        policy=PolicyEngine(load_rules(Path("services/gateway/policy/rules.yaml"))),
        agent_tokens={"agent-1": "delegation"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
    )
    body = b'{"invoice_id":"i-1"}'
    result = pipeline.execute("agent-1", "delegation", "read_invoice", body, "sha256:" + "d" * 64)
    assert result["intent_seq"] == 0
    assert result["outcome_seq"] == 1
    assert provider.received[0][0] == body
    assert "X-BlackBox-Attestation" in provider.received[0][1]


def test_retry_reuses_idempotency_and_denial_does_not_attest(tmp_path: Path):
    signer, provider = FakeSigner(), FakeProvider()
    pipeline = GatewayPipeline(
        signer=signer,
        provider=provider,
        payload_store=PayloadStore(tmp_path),
        policy=PolicyEngine(load_rules(Path("services/gateway/policy/rules.yaml"))),
        agent_tokens={"agent-1": "delegation"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
    )
    body = b'{"invoice_id":"i-1"}'
    first = pipeline.execute("agent-1", "delegation", "read_invoice", body, "sha256:" + "e" * 64)
    second = pipeline.execute("agent-1", "delegation", "read_invoice", body, "sha256:" + "e" * 64)
    assert first == second
    denied = pipeline.execute("agent-1", "delegation", "unknown", body, "sha256:" + "f" * 64)
    assert denied["status"] == "blocked"
    assert len(provider.received) == 1

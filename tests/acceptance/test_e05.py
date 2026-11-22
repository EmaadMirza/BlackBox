"""E5: Bypass from the agent network (spec §29.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

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
    """Signer supporting honest pipeline execution and attestation."""

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


def test_e05(tmp_path: Path) -> None:
    """E5: Bypass from the agent network (spec §29.4).

    Claim: 2 (Completeness).
    Expected:
      - Layer 1 (Egress control ON): agent network connections to the provider
        fail closed (refused), and nothing reaches the provider event log.
      - Layer 2 (Egress rule loosened): requests bypass the Gateway and reach the
        provider directly without an attestation. In enforcement mode, the
        provider rejects with HTTP 403 and records an UNATTESTED event; the
        reconciler independently raises UNATTESTED_ACTION within the time budget.
      - Control: without egress control and enforcement mode, direct calls
        succeed silently at the provider (HTTP 200), but the reconciler STILL
        detects UNATTESTED_ACTION, demonstrating the forensic safety net.
    """
    rules_path = Path("services/gateway/policy/rules.yaml")
    policy = PolicyEngine(load_rules(rules_path))

    signer = FakeSignerE5()
    provider = ProviderMock(enforcement_enabled=True)
    pipeline = GatewayPipeline(
        signer=signer,
        provider=provider,
        payload_store=PayloadStore(tmp_path / "store"),
        policy=policy,
        agent_tokens={"agent-1": "token-1"},
        clock=lambda: "2026-01-01T00:00:00.000Z",
    )

    findings_store = FindingsStore(tmp_path / "findings.json")
    reconciler = Reconciler(
        ledger_reader=lambda: signer.sealed_entries,
        event_reader=lambda: provider.event_log.feed(),
        findings_store=findings_store,
        clock=lambda: "2026-01-01T00:00:05.000Z",
    )

    sandbox = AgentNetworkSandbox(gateway_target="gateway", egress_enforced=True)

    honest_body = b'{"action":"read","amount":100}'
    honest_idem = "sha256:" + "1" * 64

    # 1. Honest Baseline: Agent calls Gateway through authorized egress
    honest_res = sandbox.dispatch(
        "gateway",
        lambda: pipeline.execute("agent-1", "token-1", "read_invoice", honest_body, honest_idem),
    )
    assert honest_res["status"] == "ok"
    assert len(provider.event_log.feed()) == 1
    assert provider.event_log.feed()[0]["attested"] is True

    # Reconciler sees honest correspondence -> zero findings
    reconciler.run_once()
    assert len(findings_store.list_findings()) == 0

    # 2. Layer 1: Egress control ON -> Agent attempts direct call to provider
    bypass_body = b'{"action":"transfer","amount":999999}'
    bypass_idem = "sha256:" + "2" * 64

    with pytest.raises(EgressBlockedError, match="blocked direct egress"):
        sandbox.dispatch(
            "provider",
            lambda: provider.request(bypass_body, {}, idempotency_key=bypass_idem),
        )

    # Provider received nothing from the blocked attempt
    assert len(provider.event_log.feed()) == 1
    assert len(sandbox.blocked_attempts) == 1
    assert sandbox.blocked_attempts[0] == "provider"

    # 3. Layer 2: Loosen egress rule -> Agent reaches provider without attestation
    sandbox.loosen_egress_rule()
    assert not sandbox.egress_enforced

    # Direct request arrives at provider without X-BlackBox-Attestation header
    direct_resp = sandbox.dispatch(
        "provider",
        lambda: provider.request(bypass_body, {}, idempotency_key=bypass_idem),
    )

    # Under enforcement mode: provider rejects with HTTP 403 and alarms
    assert direct_resp["status"] == 403
    assert "unattested action rejected" in direct_resp["error"]
    assert any(alarm["alarm_type"] == "UNATTESTED_ACTION" for alarm in provider._alarms)

    # Provider event log records the unattested attempt
    events = provider.event_log.feed()
    assert len(events) == 2
    unattested_ev = events[1]
    assert unattested_ev["attested"] is False
    assert unattested_ev["status"] == 403
    assert unattested_ev["idempotency_key"] == bypass_idem

    # Reconciler runs: flags UNATTESTED_ACTION finding
    reconciler.run_once()
    unattested_findings = [
        f for f in findings_store.list_findings() if f.finding_type == "UNATTESTED_ACTION"
    ]
    assert len(unattested_findings) >= 1
    assert unattested_findings[0].provider_event_ids == [unattested_ev["request_id"]]
    assert unattested_findings[0].ledger_seqs == []

    # 4. Control Case: Egress loosened AND Enforcement Mode disabled
    audit_provider = ProviderMock(enforcement_enabled=False)
    audit_findings_store = FindingsStore(tmp_path / "audit_findings.json")
    audit_reconciler = Reconciler(
        ledger_reader=lambda: signer.sealed_entries,
        event_reader=lambda: audit_provider.event_log.feed(),
        findings_store=audit_findings_store,
        clock=lambda: "2026-01-01T00:00:15.000Z",
    )

    control_body = b'{"action":"audit_control","amount":500}'
    control_idem = "sha256:" + "3" * 64

    # Direct call to non-enforcing provider succeeds silently (HTTP 200)
    control_resp = sandbox.dispatch(
        "provider",
        lambda: audit_provider.request(control_body, {}, idempotency_key=control_idem),
    )
    assert control_resp["status"] == 200
    control_ev = audit_provider.event_log.feed()[0]
    assert control_ev["attested"] is False
    assert control_ev["status"] == 200

    # But Reconciler STILL detects UNATTESTED_ACTION!
    audit_reconciler.run_once()
    control_findings = [
        f for f in audit_findings_store.list_findings() if f.finding_type == "UNATTESTED_ACTION"
    ]
    assert len(control_findings) >= 1
    assert control_findings[0].provider_event_ids == [control_ev["request_id"]]

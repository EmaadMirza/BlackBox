"""E3: Ledger-host rewrite."""

from pathlib import Path

from fastapi.testclient import TestClient

from libs.blackbox_core.checkpoint import build_checkpoint, sign_checkpoint
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import SealedEntry
from libs.blackbox_core.sealing import sealed_bytes
from services.reconciler.findings_store import FindingsStore
from services.reconciler.main import Reconciler
from services.witness.main import WitnessConfig, create_app
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def test_e03(tmp_path: Path) -> None:
    """E3: Ledger-host rewrite.

    - Expected alarms: WITNESS_REFUSAL from every witness within the time budget.
    - Expected verdicts: the verifier marks the deleted range MISSING or TAMPERED
      against the last witnessed checkpoint; the reconciler raises UNRECORDED_ACTION
      for the refund still present in the provider's event log.
    - Pass: all three witnesses refuse; no quorum is reached; all verdicts and
      findings as listed.
    """
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
    original_entries = [SealedEntry.model_validate(entry) for entry in bundle.entries]
    first_checkpoint = bundle.checkpoints[-1].checkpoint
    assert first_checkpoint.tree_size == 10

    # 1. Simulate ledger rewrite: entry 5 (e.g. a refund) is deleted/replaced
    rewritten_entries = list(original_entries)
    refund_entry = rewritten_entries[5]
    # Delete entry 5 by replacing it
    rewritten_entries[5] = rewritten_entries[5].model_copy(
        update={"body": rewritten_entries[5].body.model_copy(update={"action_name": "rewritten"})}
    )
    rewritten_tree = MerkleTree(
        [sealed_bytes(entry) for entry in rewritten_entries] + [sealed_bytes(original_entries[-1])]
    )
    rewritten_checkpoint = sign_checkpoint(
        build_checkpoint(
            first_checkpoint.log_id,
            12,
            encode_hash(rewritten_tree.root()),
            11,
            first_checkpoint.epoch_id,
            "2026-01-01T00:09:59.000Z",
            latest_entry_hash=first_checkpoint.latest_entry_hash,
        ),
        keys[3][0],
    )

    # 2. All 3 witnesses must refuse the rewritten checkpoint
    witness_clients = []
    witness_ids = ["w0", "w1", "w2"]
    refusal_count = 0

    for idx, w_id in enumerate(witness_ids):
        w_key = keys[4 + idx]
        key_path = tmp_path / f"{w_id}.raw"
        key_path.write_bytes(w_key[0].private_bytes_raw())
        key_path.chmod(0o600)
        config = WitnessConfig(
            root_public_key=pins.root_public_key,
            witness_set=bundle.witness_set,
            intermediates=bundle.intermediates,
            epochs=bundle.epochs,
            witness_id=w_id,
            witness_key_path=key_path,
            state_dir=tmp_path / f"state_{w_id}",
            evidence_dir=tmp_path / f"evidence_{w_id}",
            bearer_token="token",
            clock=lambda: "2026-01-01T01:00:00.000Z",
        )
        client = TestClient(create_app(config))
        headers = {"Authorization": "Bearer token"}

        # Accept genuine initial checkpoint
        resp_init = client.post(
            "/v1/checkpoint",
            json={
                "log_id": first_checkpoint.log_id,
                "checkpoint": first_checkpoint.model_dump(mode="json"),
                "from_size": 0,
                "consistency_proof": [],
            },
            headers=headers,
        )
        assert resp_init.status_code == 200

        # Attempt to submit rewritten checkpoint
        resp_rewrite = client.post(
            "/v1/checkpoint",
            json={
                "log_id": first_checkpoint.log_id,
                "checkpoint": rewritten_checkpoint.model_dump(mode="json"),
                "from_size": 10,
                "consistency_proof": [],
            },
            headers=headers,
        )
        assert resp_rewrite.status_code == 409
        refusal_count += 1

        # Check alarm
        alarms_resp = client.get(
            "/v1/alarms", params={"log_id": first_checkpoint.log_id}, headers=headers
        )
        alarms = alarms_resp.json()
        assert any(a.get("alarm_type") == "WITNESS_REFUSAL" for a in alarms)
        witness_clients.append(client)

    assert refusal_count == 3, "All three witnesses must refuse the rewrite"

    # 3. Offline verifier marks rewritten bundle TAMPERED / MISSING
    rewritten_bundle = bundle.model_copy(
        update={"entries": [entry.model_dump(mode="json") for entry in rewritten_entries]}
    )
    verification_report = verify_evidence(rewritten_bundle, pins)
    assert verification_report.verdict in {"TAMPERED", "MISSING"}

    # 4. Reconciler raises UNRECORDED_ACTION for the action still in the provider event log
    provider_events = [
        {
            "request_id": "prov-refund-1",
            "intent_seq": refund_entry.body.seq,
            "body_digest": getattr(
                getattr(refund_entry.body, "action", None), "body_digest", "sha256:" + "0" * 64
            ),
            "attested": True,
        }
    ]
    # In rewritten ledger, entry with refund_entry.body.seq is missing or altered
    findings_store = FindingsStore(tmp_path / "findings.json")
    reconciler = Reconciler(
        ledger_reader=lambda: [e for e in rewritten_entries if e.body.seq != refund_entry.body.seq],
        event_reader=lambda: provider_events,
        findings_store=findings_store,
        clock=lambda: "2026-01-01T01:00:00.000Z",
    )
    findings = reconciler.run_once()
    assert any(f.finding_type == "UNRECORDED_ACTION" for f in findings)
    assert len(findings_store.list_findings()) >= 1

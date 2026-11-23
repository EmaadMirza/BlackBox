"""E3: Ledger-host rewrite attack harness (spec §29.4)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

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


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E3 ledger-host rewrite attack simulation."""
    created_tmp = None
    if tmp_dir is None:
        created_tmp = tempfile.TemporaryDirectory()
        work_dir = Path(created_tmp.name)
    else:
        work_dir = tmp_dir
        work_dir.mkdir(parents=True, exist_ok=True)

    try:
        keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
        bundle, pins = build_demo(keys)
        original_entries = [SealedEntry.model_validate(entry) for entry in bundle.entries]
        first_checkpoint = bundle.checkpoints[-1].checkpoint
        assert first_checkpoint.tree_size == 10

        # 1. Simulate ledger rewrite: entry 5 is altered on disk
        rewritten_entries = list(original_entries)
        refund_entry = rewritten_entries[5]
        rewritten_entries[5] = rewritten_entries[5].model_copy(
            update={
                "body": rewritten_entries[5].body.model_copy(update={"action_name": "rewritten"})
            }
        )
        rewritten_tree = MerkleTree(
            [sealed_bytes(entry) for entry in rewritten_entries]
            + [sealed_bytes(original_entries[-1])]
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

        # 2. All 3 witnesses refuse the rewritten checkpoint
        witness_ids = ["w0", "w1", "w2"]
        refusal_count = 0

        for idx, w_id in enumerate(witness_ids):
            w_key = keys[4 + idx]
            key_path = work_dir / f"{w_id}.raw"
            key_path.write_bytes(w_key[0].private_bytes_raw())
            key_path.chmod(0o600)
            config = WitnessConfig(
                root_public_key=pins.root_public_key,
                witness_set=bundle.witness_set,
                intermediates=bundle.intermediates,
                epochs=bundle.epochs,
                witness_id=w_id,
                witness_key_path=key_path,
                state_dir=work_dir / f"state_{w_id}",
                evidence_dir=work_dir / f"evidence_{w_id}",
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

            # Submit rewritten checkpoint
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
            assert resp_rewrite.json()["error"]["code"] == "bad_proof"
            refusal_count += 1

        assert refusal_count == 3, f"Expected 3 witness refusals, got {refusal_count}"

        # 3. Offline verifier flags altered bundle
        tampered_bundle = bundle.model_copy(
            update={"entries": [e.model_dump(mode="json") for e in rewritten_entries]}
        )
        report = verify_evidence(tampered_bundle, pins)
        assert report.verdict in ("TAMPERED", "MISSING")

        # 4. Reconciler flags UNRECORDED_ACTION
        findings_store = FindingsStore(work_dir / "findings.json")
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
        reconciler = Reconciler(
            ledger_reader=lambda: [
                e for e in rewritten_entries if e.body.seq != refund_entry.body.seq
            ],
            event_reader=lambda: provider_events,
            findings_store=findings_store,
            clock=lambda: "2026-01-01T01:00:00.000Z",
        )
        findings = reconciler.run_once()
        has_unrecorded = any(f.finding_type == "UNRECORDED_ACTION" for f in findings)
        assert has_unrecorded

        return {
            "scenario": "E3_ledger_rewrite",
            "verdict": "PASSED",
            "witness_refusals": refusal_count,
            "verifier_verdict": report.verdict,
            "reconciler_finding": "UNRECORDED_ACTION",
        }
    finally:
        if created_tmp is not None:
            created_tmp.cleanup()


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()

"""G3: a witness refuses a correctly signed checkpoint over rewritten history."""

from __future__ import annotations

from fastapi.testclient import TestClient

from libs.blackbox_core.checkpoint import build_checkpoint, sign_checkpoint, verify_checkpoint
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import SealedEntry
from libs.blackbox_core.sealing import sealed_bytes
from services.witness.main import WitnessConfig, create_app
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def test_g3_witness_refuses_rewritten_history_and_plain_ledger_control(tmp_path):
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
    original_entries = [SealedEntry.model_validate(entry) for entry in bundle.entries]
    first = bundle.checkpoints[-1].checkpoint
    assert first.tree_size == 10

    rewritten = list(original_entries)
    rewritten[5] = rewritten[5].model_copy(
        update={"body": rewritten[5].body.model_copy(update={"action_name": "rewritten"})}
    )
    rewritten_tree = MerkleTree(
        [sealed_bytes(entry) for entry in rewritten] + [sealed_bytes(original_entries[-1])]
    )
    genuine_rewrite = sign_checkpoint(
        build_checkpoint(
            first.log_id,
            12,
            encode_hash(rewritten_tree.root()),
            11,
            first.epoch_id,
            "2026-01-01T00:09:59.000Z",
            latest_entry_hash=first.latest_entry_hash,
        ),
        keys[3][0],
    )
    config = WitnessConfig(
        root_public_key=pins.root_public_key,
        witness_set=bundle.witness_set,
        intermediates=bundle.intermediates,
        epochs=bundle.epochs,
        witness_id="w0",
        witness_key_path=tmp_path / "w0.raw",
        state_dir=tmp_path / "state",
        evidence_dir=tmp_path / "evidence",
        bearer_token="token",
        clock=lambda: "2026-01-01T01:00:00.000Z",
    )
    config.witness_key_path.write_bytes(keys[4][0].private_bytes_raw())
    config.witness_key_path.chmod(0o600)
    with TestClient(create_app(config)) as client:
        headers = {"Authorization": "Bearer token"}
        assert (
            client.post(
                "/v1/checkpoint",
                json={
                    "log_id": first.log_id,
                    "checkpoint": first.model_dump(mode="json"),
                    "from_size": 0,
                    "consistency_proof": [],
                },
                headers=headers,
            ).status_code
            == 200
        )
        response = client.post(
            "/v1/checkpoint",
            json={
                "log_id": first.log_id,
                "checkpoint": genuine_rewrite.model_dump(mode="json"),
                "from_size": 10,
                "consistency_proof": [],
            },
            headers=headers,
        )
        alarms = client.get("/v1/alarms", params={"log_id": first.log_id}, headers=headers)
        repeated = client.post(
            "/v1/checkpoint",
            json={
                "log_id": first.log_id,
                "checkpoint": genuine_rewrite.model_dump(mode="json"),
                "from_size": 10,
                "consistency_proof": [],
            },
            headers=headers,
        )
    assert verify_checkpoint(genuine_rewrite, keys[3][0].public_key().public_bytes_raw())
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "bad_proof"
    assert len(alarms.json()) == 1
    assert alarms.json()[0]["alarm_type"] == "WITNESS_REFUSAL"
    assert repeated.status_code == 409
    assert verify_checkpoint(first, keys[3][0].public_key().public_bytes_raw())
    assert verify_evidence(bundle, pins).verdict == "VERIFIED"
    rewritten_bundle = bundle.model_copy(
        update={"entries": [entry.model_dump(mode="json") for entry in rewritten]}
    )
    assert verify_evidence(rewritten_bundle, pins).verdict in {"TAMPERED", "MISSING"}

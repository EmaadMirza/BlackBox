"""HTTP-level witness processor tests including bad_proof refusal."""

from pathlib import Path

from fastapi.testclient import TestClient

from libs.blackbox_core.checkpoint import build_checkpoint, sign_checkpoint
from libs.blackbox_core.encoding import encode_hash
from services.witness.main import WitnessConfig, create_app
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo


def test_witness_http_processor_refuses_bad_proof(tmp_path: Path) -> None:
    """HTTP-level verification that witness refuses checkpoints with bad consistency proofs."""
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
    first_checkpoint = bundle.checkpoints[-1].checkpoint

    # Configure witness
    w_key = keys[4]
    key_path = tmp_path / "w0.raw"
    key_path.write_bytes(w_key[0].private_bytes_raw())
    key_path.chmod(0o600)
    config = WitnessConfig(
        root_public_key=pins.root_public_key,
        witness_set=bundle.witness_set,
        intermediates=bundle.intermediates,
        epochs=bundle.epochs,
        witness_id="w0",
        witness_key_path=key_path,
        state_dir=tmp_path / "state",
        evidence_dir=tmp_path / "evidence",
        bearer_token="test-token",
        clock=lambda: "2026-01-01T01:00:00.000Z",
    )

    app = create_app(config)
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer test-token"}

        # 1. First checkpoint accepted
        resp1 = client.post(
            "/v1/checkpoint",
            json={
                "log_id": first_checkpoint.log_id,
                "checkpoint": first_checkpoint.model_dump(mode="json"),
                "from_size": 0,
                "consistency_proof": [],
            },
            headers=headers,
        )
        assert resp1.status_code == 200
        assert "witness_signature" in resp1.json()

        # 2. Next checkpoint with fake/bad consistency proof
        tree_size_2 = first_checkpoint.tree_size + 2
        next_checkpoint = sign_checkpoint(
            build_checkpoint(
                first_checkpoint.log_id,
                tree_size_2,
                encode_hash(b"f" * 32),
                first_checkpoint.tree_size + 1,
                first_checkpoint.epoch_id,
                "2026-01-01T00:09:59.000Z",
                latest_entry_hash="sha256:" + "9" * 64,
            ),
            keys[3][0],
        )

        resp2 = client.post(
            "/v1/checkpoint",
            json={
                "log_id": first_checkpoint.log_id,
                "checkpoint": next_checkpoint.model_dump(mode="json"),
                "from_size": first_checkpoint.tree_size,
                "consistency_proof": ["sha256:" + "0" * 64],  # Invalid proof
            },
            headers=headers,
        )
        assert resp2.status_code == 409
        assert resp2.json()["error"]["code"] == "bad_proof"

        # 3. Check alarm was emitted
        alarms_resp = client.get(
            "/v1/alarms", params={"log_id": first_checkpoint.log_id}, headers=headers
        )
        assert alarms_resp.status_code == 200
        alarms = alarms_resp.json()
        assert len(alarms) >= 1
        assert alarms[-1]["alarm_type"] == "WITNESS_REFUSAL"

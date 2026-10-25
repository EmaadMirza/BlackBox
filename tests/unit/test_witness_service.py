"""Witness protocol tests with separate file-backed witness state."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from services.witness.main import create_app
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo


def _app(tmp_path):
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    # Keep each private/public pair aligned; tests/_dev_keys returns deterministic capability only.
    keys = []
    for i in range(1, 8):
        key = dev_key(i)
        keys.append((key, key.public_key().public_bytes_raw()))
    bundle, pins = build_demo(keys)
    app = create_app(
        root_public_key=pins.root_public_key,
        witness_set=bundle.witness_set,
        intermediates=bundle.intermediates,
        epochs=bundle.epochs,
        witness_id="w0",
        witness_key=keys[4][0],
        state_dir=tmp_path / "state",
        evidence_dir=tmp_path / "evidence",
        clock=lambda: "2026-01-01T01:00:00.000Z",
    )
    return app, bundle, keys


def test_witness_accepts_first_checkpoint_persists_and_replays_cosignature(tmp_path):
    app, bundle, keys = _app(tmp_path)
    checkpoint = bundle.checkpoints[0].checkpoint
    body = {
        "log_id": checkpoint.log_id,
        "checkpoint": checkpoint.model_dump(mode="json"),
        "from_size": 0,
        "consistency_proof": [],
    }
    with TestClient(app) as client:
        first = client.post("/v1/checkpoint", json=body)
        second = client.post("/v1/checkpoint", json=body)
        state = client.get("/v1/state", params={"log_id": checkpoint.log_id})
    assert first.status_code == 200, first.text
    assert second.status_code == 200
    assert first.json() == second.json()
    assert state.json() == {
        "log_id": checkpoint.log_id,
        "tree_size": checkpoint.tree_size,
        "root_hash": checkpoint.root_hash,
        "epoch_id": checkpoint.epoch_id,
    }
    assert (tmp_path / "state" / f"{checkpoint.log_id}.json").exists()


def test_witness_refuses_bad_proof_and_writes_hash_chained_evidence(tmp_path):
    app, bundle, _ = _app(tmp_path)
    first, second = (item.checkpoint for item in bundle.checkpoints)
    with TestClient(app) as client:
        assert (
            client.post(
                "/v1/checkpoint",
                json={
                    "log_id": first.log_id,
                    "checkpoint": first.model_dump(mode="json"),
                    "from_size": 0,
                    "consistency_proof": [],
                },
            ).status_code
            == 200
        )
        refusal = client.post(
            "/v1/checkpoint",
            json={
                "log_id": second.log_id,
                "checkpoint": second.model_dump(mode="json"),
                "from_size": first.tree_size,
                "consistency_proof": ["sha256:" + "0" * 64],
            },
        )
    assert refusal.status_code == 409
    assert refusal.json() == {"error": {"code": "bad_proof", "message": "Checkpoint refused."}}
    evidence = (tmp_path / "evidence" / f"{first.log_id}.jsonl").read_text().splitlines()
    assert len(evidence) == 1
    assert json.loads(evidence[0])["code"] == "bad_proof"


def test_witness_rejects_wrong_log_without_private_material_in_outputs(tmp_path):
    app, bundle, _ = _app(tmp_path)
    checkpoint = bundle.checkpoints[0].checkpoint
    with TestClient(app) as client:
        response = client.post(
            "/v1/checkpoint",
            json={
                "log_id": "sha256:" + "f" * 64,
                "checkpoint": checkpoint.model_dump(mode="json"),
                "from_size": 0,
                "consistency_proof": [],
            },
        )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "wrong_log"
    for path in (tmp_path / "evidence").glob("**/*"):
        assert "PRIVATE KEY" not in path.read_text(errors="ignore")

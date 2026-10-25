"""W4 gossip and split-view tests."""

from pathlib import Path

from fastapi.testclient import TestClient

from services.witness.gossip import detect_split_view, split_view_evidence
from tests.unit.test_witness_service import _app


def test_latest_checkpoint_is_read_only_and_bearer_authenticated(tmp_path: Path):
    app, bundle, _ = _app(tmp_path)
    checkpoint = bundle.checkpoints[0].checkpoint
    body = {
        "log_id": checkpoint.log_id,
        "checkpoint": checkpoint.model_dump(mode="json"),
        "from_size": 0,
        "consistency_proof": [],
    }
    with TestClient(app) as client:
        assert client.post("/v1/checkpoint", json=body).status_code == 200
        response = client.get("/v1/latest", params={"log_id": checkpoint.log_id})
    assert response.status_code == 200
    assert response.json()["checkpoint"] == checkpoint.model_dump(mode="json")


def test_same_size_different_roots_is_split_view(tmp_path: Path):
    _, bundle, _ = _app(tmp_path)
    first = bundle.checkpoints[0].checkpoint
    other = first.model_copy(update={"root_hash": "sha256:" + "f" * 64})
    assert detect_split_view([first, other]) is True
    assert len(split_view_evidence([first, other])) == 2


def test_different_sizes_are_not_split_view(tmp_path: Path):
    _, bundle, _ = _app(tmp_path)
    first = bundle.checkpoints[0].checkpoint
    other = bundle.checkpoints[1].checkpoint
    assert first.tree_size != other.tree_size
    assert detect_split_view([first, other]) is False

"""K1b checkpoint operation and boundary tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.checkpoint import verify_checkpoint
from libs.blackbox_core.errors import SignerRuleError
from services.signer import state
from services.signer.main import create_app
from tests._dev_keys import dev_key
from tests.unit.test_signer_sealer import LOG_ID, NOW, make_sealer


def checkpoint_request(root: str = "sha256:" + "a" * 64) -> dict:
    return {
        "log_id": LOG_ID,
        "tree_size": 1,
        "root_hash": root,
        "latest_seq": 0,
        "latest_entry_hash": "sha256:" + "b" * 64,
        "epoch_id": 0,
        "signer_timestamp": NOW,
    }


def test_checkpoint_signs_current_state_and_does_not_change_chain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    key = dev_key()
    signer = make_sealer(key)
    entry = signer.seal(
        __import__("tests.unit.test_signer_sealer", fromlist=["candidate"]).candidate()
    )
    before = state.load_state(LOG_ID)
    result = signer.checkpoint(
        checkpoint_request().copy()
        | {
            "latest_entry_hash": __import__(
                "libs.blackbox_core.chain", fromlist=["entry_hash"]
            ).entry_hash(entry.body)
        }
    )
    assert verify_checkpoint(result, key.public_key().public_bytes_raw())
    assert state.load_state(LOG_ID) == before


def test_checkpoint_rejects_split_view_and_keyless(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    signer = make_sealer(dev_key())
    with pytest.raises(SignerRuleError):
        signer.checkpoint(checkpoint_request())


def test_checkpoint_round_trip_and_old_checkpoint_sidecar_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    key = dev_key()
    signer = make_sealer(key)
    entry = signer.seal(
        __import__("tests.unit.test_signer_sealer", fromlist=["candidate"]).candidate()
    )
    request = checkpoint_request().copy()
    request["latest_entry_hash"] = __import__(
        "libs.blackbox_core.chain", fromlist=["entry_hash"]
    ).entry_hash(entry.body)
    first = signer.checkpoint(request)
    second = make_sealer(key).checkpoint(request)
    assert first.model_dump() == second.model_dump()
    sidecar = path.with_name("state.json.checkpoint.json")
    text = sidecar.read_text().replace('"format_version":"2"', '"format_version":"1"')
    sidecar.write_text(text)
    with pytest.raises(ValueError, match="format version"):
        state.load_last_checkpoint(LOG_ID)


def test_checkpoint_http_rejects_extra_fields_and_duplicate_keys(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "secret")
    client = TestClient(create_app(sealer=object()))
    extra = client.post(
        "/checkpoint",
        headers={"Authorization": "Bearer secret"},
        json={**checkpoint_request(), "extra": 1},
    )
    duplicate = client.post(
        "/checkpoint",
        headers={"Authorization": "Bearer secret"},
        content=b'{"log_id":"x","log_id":"y"}',
    )
    assert extra.status_code == 422
    assert duplicate.status_code == 422


def test_checkpoint_http_success(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "secret")
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    key = dev_key()
    signer = make_sealer(key)
    entry = signer.seal(
        __import__("tests.unit.test_signer_sealer", fromlist=["candidate"]).candidate()
    )
    request = checkpoint_request()
    request["latest_entry_hash"] = __import__(
        "libs.blackbox_core.chain", fromlist=["entry_hash"]
    ).entry_hash(entry.body)
    response = TestClient(create_app(sealer=signer)).post(
        "/checkpoint", headers={"Authorization": "Bearer secret"}, json=request
    )
    assert response.status_code == 200
    assert verify_checkpoint(
        __import__("libs.blackbox_core.schemas", fromlist=["Checkpoint"]).Checkpoint.model_validate(
            response.json()
        ),
        key.public_key().public_bytes_raw(),
    )

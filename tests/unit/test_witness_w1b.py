"""W1b witness durability, custody and HTTP contract tests."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.checkpoint import verify_cosignature
from libs.blackbox_core.encoding import decode_base64url
from services.witness.main import WitnessConfig, WitnessKey, create_app
from services.witness.store import WitnessStore, WitnessStoreError
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo


def fixture(tmp_path: Path):
    keys = []
    for index in range(1, 8):
        key = dev_key(index)
        keys.append((key, key.public_key().public_bytes_raw()))
    bundle, pins = build_demo(keys)
    config = WitnessConfig(
        root_public_key=pins.root_public_key,
        witness_set=bundle.witness_set,
        intermediates=bundle.intermediates,
        epochs=bundle.epochs,
        witness_id="w0",
        witness_key_path=tmp_path / "w0.pem",
        state_dir=tmp_path / "state",
        evidence_dir=tmp_path / "evidence",
        bearer_token="submit-token",
        clock=lambda: "2026-01-01T01:00:00.000Z",
    )
    config.witness_key_path.write_bytes(keys[4][0].private_bytes_raw())
    os.chmod(config.witness_key_path, 0o600)
    return config, bundle, keys


def submit_body(checkpoint, proof=None, from_size=0):
    return {
        "log_id": checkpoint.log_id,
        "checkpoint": checkpoint.model_dump(mode="json"),
        "from_size": from_size,
        "consistency_proof": proof or [],
    }


def test_key_refuses_wider_permissions_and_store_has_versioned_state(tmp_path):
    key_path = tmp_path / "w.pem"
    key = dev_key(44)
    key_path.write_bytes(key.private_bytes_raw())
    os.chmod(key_path, 0o640)
    with pytest.raises(ValueError, match="0600"):
        WitnessKey.load(key_path)

    store = WitnessStore(tmp_path / "state", tmp_path / "evidence")
    assert store.format_version == "1"
    assert store.read("sha256:" + "0" * 64) is None
    store.initialized_path("sha256:" + "0" * 64).write_bytes(b"1\n")
    with pytest.raises(WitnessStoreError):
        store.read("sha256:" + "0" * 64)


def test_http_auth_schema_bounds_and_duplicate_keys_are_sanitized(tmp_path):
    config, bundle, _ = fixture(tmp_path)
    with TestClient(create_app(config)) as client:
        checkpoint = bundle.checkpoints[0].checkpoint
        body = submit_body(checkpoint)
        assert client.post("/v1/checkpoint", json=body).status_code == 401
        assert client.get("/health").json() == {"status": "ok"}
        assert (
            client.post(
                "/v1/checkpoint", json=body, headers={"Authorization": "Bearer submit-token"}
            ).status_code
            == 200
        )
        duplicate = (
            '{"log_id":"%s","log_id":"%s","checkpoint":%s,"from_size":0,"consistency_proof":[]}'
            % (checkpoint.log_id, checkpoint.log_id, json.dumps(checkpoint.model_dump(mode="json")))
        )
        response = client.post(
            "/v1/checkpoint",
            content=duplicate,
            headers={"Authorization": "Bearer submit-token", "Content-Type": "application/json"},
        )
        assert response.status_code == 422
        assert response.json() == {"error": {"code": "malformed", "message": "Malformed request."}}


def test_cosignature_is_verified_and_only_key_file_contains_private_bytes(tmp_path):
    config, bundle, keys = fixture(tmp_path)
    with TestClient(create_app(config)) as client:
        checkpoint = bundle.checkpoints[0].checkpoint
        response = client.post(
            "/v1/checkpoint",
            json=submit_body(checkpoint),
            headers={"Authorization": "Bearer submit-token"},
        )
    from libs.blackbox_core.schemas import Cosignature

    assert verify_cosignature(
        Cosignature.model_validate(response.json()),
        decode_base64url(bundle.witness_set.witnesses[0].public_key),
    )
    private = keys[4][0].private_bytes_raw()
    for directory in (tmp_path / "state", tmp_path / "evidence"):
        for path in directory.glob("**/*"):
            assert private not in path.read_bytes()


def test_two_witnesses_have_independent_keys_and_state(tmp_path):
    config, bundle, keys = fixture(tmp_path)
    second = replace(
        config,
        witness_id="w1",
        witness_key_path=tmp_path / "w1.pem",
        state_dir=tmp_path / "state-1",
        evidence_dir=tmp_path / "evidence-1",
    )
    second.witness_key_path.write_bytes(keys[5][0].private_bytes_raw())
    os.chmod(second.witness_key_path, 0o600)
    with (
        TestClient(create_app(config)) as first_client,
        TestClient(create_app(second)) as second_client,
    ):
        checkpoint = bundle.checkpoints[0].checkpoint
        body = submit_body(checkpoint)
        first = first_client.post(
            "/v1/checkpoint", json=body, headers={"Authorization": "Bearer submit-token"}
        )
        other = second_client.post(
            "/v1/checkpoint", json=body, headers={"Authorization": "Bearer submit-token"}
        )
    assert first.status_code == other.status_code == 200
    assert first.json()["witness_id"] != other.json()["witness_id"]


def test_replace_failure_releases_nothing_and_restart_accepts_same_checkpoint(
    tmp_path, monkeypatch
):
    config, bundle, _ = fixture(tmp_path)
    original = os.replace
    calls = {"count": 0}

    def fail_once(source, destination):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("injected replace failure")
        return original(source, destination)

    monkeypatch.setattr(os, "replace", fail_once)
    checkpoint = bundle.checkpoints[0].checkpoint
    with TestClient(create_app(config), raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/checkpoint",
            json=submit_body(checkpoint),
            headers={"Authorization": "Bearer submit-token"},
        )
    assert response.status_code == 500
    assert not config.state_dir.joinpath(f"{checkpoint.log_id}.json").exists()
    monkeypatch.setattr(os, "replace", original)
    with TestClient(create_app(config)) as client:
        retry = client.post(
            "/v1/checkpoint",
            json=submit_body(checkpoint),
            headers={"Authorization": "Bearer submit-token"},
        )
    assert retry.status_code == 200


def test_failure_after_commit_returns_stored_cosignature_on_resubmission(tmp_path, monkeypatch):
    config, bundle, _ = fixture(tmp_path)
    checkpoint = bundle.checkpoints[0].checkpoint
    app = create_app(config)
    app.state.store = WitnessStore(config.state_dir, config.evidence_dir)
    original = app.state.store.commit

    def commit_then_fail(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("injected response failure")

    app.state.store.commit = commit_then_fail
    with TestClient(app, raise_server_exceptions=False) as client:
        failed = client.post(
            "/v1/checkpoint",
            json=submit_body(checkpoint),
            headers={"Authorization": "Bearer submit-token"},
        )
    assert failed.status_code == 500
    app2 = create_app(config)
    with TestClient(app2) as client:
        retry = client.post(
            "/v1/checkpoint",
            json=submit_body(checkpoint),
            headers={"Authorization": "Bearer submit-token"},
        )
    assert retry.status_code == 200


def test_conflicting_checkpoint_is_refused_after_stored_checkpoint(tmp_path):
    config, bundle, _ = fixture(tmp_path)
    checkpoint = bundle.checkpoints[0].checkpoint
    altered = checkpoint.model_copy(update={"root_hash": "sha256:" + "f" * 64})
    with TestClient(create_app(config)) as client:
        headers = {"Authorization": "Bearer submit-token"}
        assert (
            client.post("/v1/checkpoint", json=submit_body(checkpoint), headers=headers).status_code
            == 200
        )
        response = client.post("/v1/checkpoint", json=submit_body(altered), headers=headers)
    assert response.status_code == 409
    assert response.json()["error"]["code"] in {"bad_signature", "root_mismatch"}


def test_ceremony_witness_set_is_root_authenticated(tmp_path):
    from libs.blackbox_core.encoding import decode_base64url
    from libs.blackbox_core.schemas import WitnessSet
    from libs.blackbox_core.signing import verify_structure
    from tools.ceremony import prepare_ceremony, prepare_witness_set

    ceremony = prepare_ceremony("w1b", tmp_path / "ceremony")
    output = prepare_witness_set(
        ceremony / "root.dev-private.pem",
        ceremony / "identity.json",
        tmp_path / "witnesses",
    )
    witness_set = WitnessSet.model_validate_json((output / "witness-set.json").read_bytes())
    identity = json.loads((ceremony / "identity.json").read_text())
    assert verify_structure(
        witness_set, decode_base64url(identity["root_public_key"]), "witness_set"
    )
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.glob("w*.private.raw"))

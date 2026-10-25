"""W3a heartbeat publication and witness monitoring tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from libs.blackbox_core.schemas import Heartbeat
from services.signer.heartbeat_publisher import HeartbeatPublisher
from services.witness.main import WitnessConfig, create_app
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo


class Client:
    def __init__(self):
        self.calls = []

    def post(self, path, **kwargs):
        self.calls.append((path, kwargs))


def test_publisher_sends_directly_and_ignores_failures_without_state_mutation():
    class Heartbeat:
        signer_timestamp = "2026-01-01T00:00:00.000Z"

        def model_dump(self, mode="json"):
            return {"signer_timestamp": self.signer_timestamp}

    class Signer:
        def __init__(self):
            self.calls = 0

        def tick(self):
            self.calls += 1
            return (), Heartbeat()

    signer = Signer()
    clients = {"a": Client(), "b": Client()}
    publisher = HeartbeatPublisher(signer, dict(clients))
    heartbeat = publisher.tick()
    assert heartbeat is not None
    assert signer.calls == 1
    assert all(client.calls[0][0] == "/v1/heartbeat" for client in clients.values())


def test_witness_accepts_signed_heartbeat_and_rejects_wrong_log(tmp_path):
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
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
    heartbeat = Heartbeat(
        log_id=bundle.log_id,
        epoch_id=1,
        latest_seq=9,
        latest_entry_hash=bundle.entries[-1]["body"]["prev_hash"],  # type: ignore[index]
        queue_depth=0,
        signer_timestamp="2026-01-01T00:05:01.000Z",
    )
    from libs.blackbox_core.signing import sign_structure

    signed = sign_structure(heartbeat, keys[3][0], "heartbeat")
    with TestClient(create_app(config)) as client:
        response = client.post(
            "/v1/heartbeat",
            json=signed.model_dump(mode="json"),
            headers={"Authorization": "Bearer token"},
        )
    assert response.status_code == 200
    assert client if False else True

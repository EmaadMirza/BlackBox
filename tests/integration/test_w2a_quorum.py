"""W2a real-Postgres ledger fan-out and quorum integration tests."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.evidence import Bundle, PinnedKeys
from libs.blackbox_core.schemas import WitnessIdentity, WitnessSet
from libs.blackbox_core.signing import sign_structure
from services.ledger.checkpointer import InProcessSignerTransport
from services.ledger.main import create_app
from services.signer import delivery
from services.signer.main import create_app as create_signer_app
from services.witness.main import WitnessConfig
from services.witness.main import create_app as create_witness_app
from tests.integration.test_l2_delivery_e2e import InProcessPostgresTransport, _drain, _setup
from tests.integration.test_l3c_checkpointer import _signer_head
from tools.verifier.verify import verify_evidence

pytestmark = pytest.mark.integration
AUTH = {"Authorization": "Bearer ledger-token"}


def _witnesses(material, tmp_path):
    root, _, _, log_id, intermediate, _, witness_set, pins = material
    result = {}
    witness_keys = [
        __import__("tests._dev_keys", fromlist=["dev_key"]).dev_key(i) for i in (4, 5, 6)
    ]
    witness_set = sign_structure(
        WitnessSet(
            log_id=log_id,
            version=1,
            witnesses=[
                WitnessIdentity(
                    witness_id=f"w{i}",
                    public_key=encode_base64url(key.public_key().public_bytes_raw()),
                )
                for i, key in enumerate(witness_keys)
            ],
            quorum=2,
            effective_time="2026-01-01T00:00:00.000Z",
        ),
        root,
        "witness_set",
    )
    for key, witness_id in zip(witness_keys, ("w0", "w1", "w2")):
        key_path = tmp_path / f"{witness_id}.raw"
        key_path.write_bytes(key.private_bytes_raw())
        key_path.chmod(0o600)
        config = WitnessConfig(
            root_public_key=pins.root_public_key,
            witness_set=witness_set,
            intermediates=[intermediate],
            epochs=[material[5]],
            witness_id=witness_id,
            witness_key_path=key_path,
            state_dir=tmp_path / f"state-{witness_id}",
            evidence_dir=tmp_path / f"evidence-{witness_id}",
            bearer_token="witness-token",
            clock=lambda: "2026-01-01T01:00:00.000Z",
        )
        result[witness_id] = TestClient(create_witness_app(config))
    return result, witness_set


def test_real_postgres_fanout_quorum_and_offline_bundle(monkeypatch, tmp_path):
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, _, witness_set, pins = material
    _drain(
        delivery.DeliveryWorker(
            signer, InProcessPostgresTransport(ledger_client), bearer_token="ledger-token"
        ),
        1,
    )
    witnesses, witness_set = _witnesses(material, tmp_path)
    pins = pins.model_copy(
        update={
            "witness_public_keys": {
                item.witness_id: item.public_key for item in witness_set.witnesses
            }
        }
    )
    signer_client = TestClient(create_signer_app(sealer=signer))
    os.environ["SIGNER_AUTH_TOKEN"] = "signer-token"
    transport = InProcessSignerTransport(signer_client, head_provider=lambda: _signer_head(log_id))
    app = create_app(
        signer_transport=transport,
        checkpoint_log_id=log_id,
        run_checkpoint_scheduler=False,
        witnesses=witnesses,
        witness_set=witness_set,
        witness_bearer_token="witness-token",
        bundle_log_name=pins.log_name,
        bundle_witness_set=witness_set,
        bundle_log_id=log_id,
    )
    try:
        with TestClient(app) as client:
            response = client.post("/checkpoint/now", headers=AUTH)
            assert response.status_code == 200, response.text
            witnessed = client.get("/checkpoint/witnessed", headers=AUTH)
            assert witnessed.status_code == 200
            assert len(witnessed.json()) == 1
            assert len(witnessed.json()[0]["cosignatures"]) == 3
            bundle_response = client.get("/bundle", params={"from": 0, "to": 0}, headers=AUTH)
            assert bundle_response.status_code == 200, bundle_response.text
            bundle = Bundle.model_validate(bundle_response.json())
            assert verify_evidence(bundle, PinnedKeys.model_validate(pins)).verdict == "VERIFIED"
    finally:
        signer_client.close()
        ledger_client.close()
        for client in witnesses.values():
            client.close()


def test_quorum_requires_distinct_valid_members(tmp_path, monkeypatch):
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, _, witness_set, _ = material
    _drain(
        delivery.DeliveryWorker(
            signer, InProcessPostgresTransport(ledger_client), bearer_token="ledger-token"
        ),
        1,
    )
    witnesses, witness_set = _witnesses(material, tmp_path)
    signer_client = TestClient(create_signer_app(sealer=signer))
    os.environ["SIGNER_AUTH_TOKEN"] = "signer-token"
    app = create_app(
        signer_transport=InProcessSignerTransport(
            signer_client, head_provider=lambda: _signer_head(log_id)
        ),
        checkpoint_log_id=log_id,
        witnesses={"w0": witnesses["w0"]},
        witness_set=witness_set,
        witness_bearer_token="witness-token",
    )
    try:
        with TestClient(app) as client:
            assert client.post("/checkpoint/now", headers=AUTH).status_code == 200
            assert client.get("/checkpoint/witnessed", headers=AUTH).json() == []
    finally:
        signer_client.close()
        ledger_client.close()
        for client in witnesses.values():
            client.close()

"""L3c real-Postgres checkpoint scheduler integration tests."""

from __future__ import annotations

import psycopg
import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.checkpoint import verify_checkpoint
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import Checkpoint, SealedEntry
from libs.blackbox_core.sealing import sealed_bytes
from libs.blackbox_core.signing import structure_hash
from services.ledger import checkpointer as checkpointer_module
from services.ledger.checkpointer import (
    CheckpointScheduler,
    InProcessSignerTransport,
    SignerHead,
    SignerRejection,
)
from services.ledger.main import create_app
from services.signer import delivery, state
from services.signer.main import create_app as create_signer_app
from tests.integration.support import execute, get_test_dsn
from tests.integration.test_l2_delivery_e2e import (
    InProcessPostgresTransport,
    _drain,
    _setup,
)
from tests.unit.test_schemas import action
from tools.verifier.verify import verify_evidence

pytestmark = pytest.mark.integration

AUTH = {"Authorization": "Bearer ledger-token"}


def _signer_head(log_id: str) -> SignerHead:
    last_seq, last_hash, epoch_id = state.load_state(log_id)
    return SignerHead(log_id, last_seq, last_hash, epoch_id)


def _append_next(ledger_client: TestClient, signer, log_id: str, epoch_certificate_id: str):
    last_seq, previous_hash, _ = state.load_state(log_id)
    body = action()
    body.update(
        log_id=log_id,
        epoch_id=0,
        seq=last_seq + 1,
        prev_hash=previous_hash,
        epoch_certificate_id=epoch_certificate_id,
        signer_timestamp="2026-01-01T00:01:00.000Z",
    )
    sealed = signer.seal(
        __import__("libs.blackbox_core.schemas", fromlist=["parse_entry"]).parse_entry(body)
    )
    worker = delivery.DeliveryWorker(
        signer,
        InProcessPostgresTransport(ledger_client),
        bearer_token="ledger-token",
    )
    assert worker.run_once() is True
    return sealed


def _checkpoint_app(material, signer, *, entry_interval: int = 100, clock=None):
    _, _, _, log_id, _, epoch_cert, _, _ = material
    signer_client = TestClient(create_signer_app(sealer=signer))
    import os

    os.environ["SIGNER_AUTH_TOKEN"] = "signer-token"
    transport = InProcessSignerTransport(
        signer_client,
        head_provider=lambda: _signer_head(log_id),
    )
    app = create_app(
        signer_transport=transport,
        checkpoint_log_id=log_id,
        checkpoint_entry_interval=entry_interval,
        checkpoint_clock=clock,
        run_checkpoint_scheduler=False,
    )
    return app, signer_client, structure_hash(epoch_cert)


def test_on_demand_checkpoint_is_signed_stored_and_readable(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, epoch, log_id, _, epoch_cert, _, _ = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    app, signer_client, _ = _checkpoint_app(material, signer)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post("/checkpoint/now", headers=AUTH)
            assert response.status_code == 200, response.text
            checkpoint = Checkpoint.model_validate(response.json())
            assert verify_checkpoint(checkpoint, epoch.public_key().public_bytes_raw())
            assert checkpoint.log_id == log_id
            assert checkpoint.tree_size == 1
            assert checkpoint.latest_seq == 0
            assert client.get("/checkpoint/latest", headers=AUTH).json() == response.json()
            assert client.get("/checkpoint/witnessed", headers=AUTH).json() == []
    finally:
        signer_client.close()
        ledger_client.close()

    assert execute("SELECT count(*) FROM blackbox.checkpoints")[0][0] == 1
    assert execute("SELECT count(*) FROM blackbox.alarms")[0][0] == 0


def test_entry_and_time_triggers_use_injected_clock(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, epoch_cert, _, _ = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    now = [0.0]
    app, signer_client, _ = _checkpoint_app(
        material, signer, entry_interval=2, clock=lambda: now[0]
    )
    try:
        with TestClient(app) as client:
            scheduler: CheckpointScheduler = app.state.checkpointer
            assert scheduler.tick() is not None
            _append_next(ledger_client, signer, log_id, structure_hash(epoch_cert))
            assert scheduler.tick() is None
            _append_next(ledger_client, signer, log_id, structure_hash(epoch_cert))
            assert scheduler.tick().tree_size == 3

            _append_next(ledger_client, signer, log_id, structure_hash(epoch_cert))
            now[0] = 4.0
            assert scheduler.tick() is None
            now[0] = 6.0
            assert scheduler.tick().tree_size == 4
            assert client.get("/checkpoint/latest", headers=AUTH).json()["tree_size"] == 4
    finally:
        signer_client.close()
        ledger_client.close()


def test_head_mismatch_and_signer_rejection_are_alarm_events(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, epoch_cert, _, _ = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )

    class MismatchTransport:
        calls = 0

        def delivered_head(self, _: str) -> SignerHead:
            return SignerHead(log_id, 99, "sha256:" + "f" * 64, 0)

        def checkpoint(self, request, _: str):
            self.calls += 1
            raise AssertionError("checkpoint must not be requested on a head mismatch")

    mismatch = CheckpointScheduler(
        pool=__import__("services.ledger.db", fromlist=["connect"]).connect(get_test_dsn()),
        log_id=log_id,
        signer_transport=MismatchTransport(),
        bearer_token="signer-token",
    )
    assert mismatch.tick() is None
    assert (
        execute("SELECT code FROM blackbox.alarms ORDER BY alarm_id")[0][0]
        == "checkpoint_head_mismatch"
    )

    class RejectTransport:
        def delivered_head(self, _: str) -> SignerHead:
            return _signer_head(log_id)

        def checkpoint(self, request, _: str):
            raise SignerRejection(409, "checkpoint_stale", "Request conflicts with signer rules.")

    rejected = CheckpointScheduler(
        pool=__import__("services.ledger.db", fromlist=["connect"]).connect(get_test_dsn()),
        log_id=log_id,
        signer_transport=RejectTransport(),
        bearer_token="signer-token",
    )
    assert rejected.tick() is None
    assert rejected.tick() is None
    assert (
        execute("SELECT count(*) FROM blackbox.alarms WHERE code=%s", ("checkpoint_stale",))[0][0]
        == 1
    )
    mismatch.pool.close()
    rejected.pool.close()
    ledger_client.close()


def test_frontier_root_mismatch_fails_closed(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, _, _, _ = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute(
            "ALTER TABLE blackbox.merkle_frontiers DISABLE TRIGGER merkle_frontiers_no_mutation"
        )
        connection.execute(
            "UPDATE blackbox.merkle_frontiers SET root_hash=%s WHERE log_id=%s",
            ("sha256:" + "f" * 64, log_id),
        )
        connection.execute(
            "ALTER TABLE blackbox.merkle_frontiers ENABLE TRIGGER merkle_frontiers_no_mutation"
        )
    app, signer_client, _ = _checkpoint_app(material, signer)
    try:
        with TestClient(app) as client:
            response = client.post("/checkpoint/now", headers=AUTH)
            assert response.status_code == 503
            assert response.json()["error"]["code"] == "checkpoint_root_mismatch"
            assert execute("SELECT code FROM blackbox.alarms ORDER BY alarm_id")[0][0] == (
                "checkpoint_root_mismatch"
            )
    finally:
        signer_client.close()
        ledger_client.close()


def test_restart_re_request_is_idempotent_for_one_tree_size(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, _, _, _ = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    app1, signer_client1, _ = _checkpoint_app(material, signer)
    with TestClient(app1) as client:
        first = client.post("/checkpoint/now", headers=AUTH)
        assert first.status_code == 200
    signer_client1.close()

    app2, signer_client2, _ = _checkpoint_app(material, signer)
    try:
        with TestClient(app2) as client:
            second = client.post("/checkpoint/now", headers=AUTH)
            assert second.status_code == 200
            assert second.json() == first.json()
    finally:
        signer_client2.close()
        ledger_client.close()
    assert (
        execute("SELECT count(*) FROM blackbox.checkpoints WHERE log_id=%s", (log_id,))[0][0] == 1
    )


def test_crash_after_signing_can_retry_without_two_checkpoints(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, _, _, _ = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    app, signer_client, _ = _checkpoint_app(material, signer)
    original_store = checkpointer_module._store_checkpoint
    failed = [False]

    def fail_once(pool, checkpoint):
        if not failed[0]:
            failed[0] = True
            raise OSError("simulated crash after signing")
        return original_store(pool, checkpoint)

    monkeypatch.setattr(checkpointer_module, "_store_checkpoint", fail_once)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            first = client.post("/checkpoint/now", headers=AUTH)
            assert first.status_code == 500
            second = client.post("/checkpoint/now", headers=AUTH)
            assert second.status_code == 200
            assert (
                execute(
                    "SELECT count(*) FROM blackbox.checkpoints WHERE log_id=%s AND tree_size=1",
                    (log_id,),
                )[0][0]
                == 1
            )
    finally:
        signer_client.close()
        ledger_client.close()


def test_checkpoint_and_exported_bundle_are_core_verifiable(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    root, _, epoch, log_id, intermediate_cert, epoch_cert, witness_set, pins = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    app, signer_client, _ = _checkpoint_app(material, signer)
    try:
        with TestClient(app) as client:
            checkpoint_response = client.post("/checkpoint/now", headers=AUTH)
            checkpoint = Checkpoint.model_validate(checkpoint_response.json())
            rows = execute(
                "SELECT sealed_entry FROM blackbox.entries WHERE log_id=%s ORDER BY seq",
                (log_id,),
            )
            entries = [SealedEntry.model_validate(row[0]) for row in rows]
            tree = MerkleTree([sealed_bytes(entry) for entry in entries])
            bundle_data = {
                "format_version": "4",
                "log_id": log_id,
                "log_name": pins.log_name,
                "entries": [entry.model_dump() for entry in entries],
                "intermediates": [intermediate_cert],
                "epochs": [epoch_cert],
                "witness_set": witness_set,
                "checkpoints": [{"checkpoint": checkpoint, "cosignatures": []}],
                "inclusion_proofs": [
                    {
                        "seq": 0,
                        "tree_size": 1,
                        "proof": [encode_hash(item) for item in tree.inclusion_proof(0, 1)],
                    }
                ],
                "consistency_proofs": [],
            }
            from libs.blackbox_core.evidence import Bundle

            report = verify_evidence(Bundle.model_validate(bundle_data), pins)
            assert report.verdict == "UNVERIFIED"
            assert verify_checkpoint(checkpoint, epoch.public_key().public_bytes_raw())
    finally:
        signer_client.close()
        ledger_client.close()

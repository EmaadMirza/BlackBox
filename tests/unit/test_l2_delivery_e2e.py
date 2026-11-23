"""L2b-2 in-process signer-to-ledger delivery coverage."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.checkpoint import build_checkpoint, build_cosignature, sign_checkpoint
from libs.blackbox_core.encoding import encode_base64url, encode_hash
from libs.blackbox_core.epochs import (
    build_epoch_certificate,
    build_intermediate_certificate,
    certificate_id,
)
from libs.blackbox_core.evidence import (
    Bundle,
    CheckpointEvidence,
    InclusionProof,
    PinnedKeys,
)
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import (
    EpochCertificate,
    EpochStart,
    IntermediateCertificate,
    SealedEntry,
    WitnessIdentity,
    WitnessSet,
    parse_entry,
)
from libs.blackbox_core.sealing import seal, sealed_bytes
from libs.blackbox_core.signing import sign_structure, structure_hash
from services.ledger.main import create_app
from services.ledger.store import InMemoryLedgerStore, StoredEntry
from services.signer import delivery, state
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action
from tests.unit.test_signer_epoch_rollover import manager
from tools.attack_suite.fixture import build_demo
from tools.ceremony import generate_dev_keys
from tools.verifier.verify import verify_evidence

LOG_ID = "sha256:" + "1" * 64
START = "2026-01-01T00:00:00.000Z"
END = "2026-01-01T00:05:00.000Z"
NOW = "2026-01-01T00:01:00.000Z"


def signer_material() -> tuple[
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    IntermediateCertificate,
    EpochCertificate,
]:
    root = dev_key(1)
    intermediate = dev_key(2)
    epoch = dev_key(3)
    intermediate_certificate = build_intermediate_certificate(
        LOG_ID,
        "intermediate-0",
        encode_base64url(intermediate.public_key().public_bytes_raw()),
        START,
        "2026-02-01T00:00:00.000Z",
        root,
    )
    epoch_certificate = build_epoch_certificate(
        0,
        encode_base64url(epoch.public_key().public_bytes_raw()),
        START,
        END,
        "intermediate-0",
        log_id=LOG_ID,
        signing_operation=intermediate,
    )
    return root, intermediate, epoch, intermediate_certificate, epoch_certificate


def verified_e2e_setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[InMemoryLedgerStore, TestClient, SignerSealer, SealedEntry]:
    root, intermediate, epoch, intermediate_certificate, epoch_certificate = signer_material()
    log_name = "l2b2-e2e"
    log_id = derive_log_id(root.public_key().public_bytes_raw(), log_name)
    intermediate_certificate = build_intermediate_certificate(
        log_id,
        intermediate_certificate.intermediate_id,
        intermediate_certificate.public_key,
        intermediate_certificate.valid_from,
        intermediate_certificate.valid_until,
        root,
    )
    # Re-sign the epoch certificate under the same intermediate key after binding the test log.
    from libs.blackbox_core.epochs import build_epoch_certificate

    epoch_certificate = build_epoch_certificate(
        0,
        epoch_certificate.epoch_public_key,
        epoch_certificate.valid_from,
        epoch_certificate.valid_until,
        epoch_certificate.intermediate_id,
        log_id=log_id,
        signing_operation=intermediate,
    )
    start_body = EpochStart(
        format_version="4",
        log_id=log_id,
        epoch_id=0,
        seq=0,
        signer_timestamp=START,
        prev_hash=GENESIS_PREV_HASH,
        lane="agent",
        epoch_certificate_id=certificate_id(epoch_certificate),
        type="epoch_start",
        certificate=epoch_certificate,
    )
    start_entry = seal(start_body, epoch)
    action_body = action()
    action_body.update(
        log_id=log_id,
        epoch_id=0,
        seq=1,
        prev_hash=entry_hash(start_body),
        epoch_certificate_id=certificate_id(epoch_certificate),
        signer_timestamp=NOW,
    )
    action_entry = seal(parse_entry(action_body), epoch)
    witness = dev_key(4)
    witness_set = sign_structure(
        WitnessSet(
            log_id=log_id,
            version=1,
            witnesses=[
                WitnessIdentity(
                    witness_id="w0",
                    public_key=encode_base64url(witness.public_key().public_bytes_raw()),
                )
            ],
            quorum=1,
            effective_time=START,
        ),
        root,
        "witness_set",
    )
    tree = MerkleTree([sealed_bytes(start_entry), sealed_bytes(action_entry)])
    checkpoint = sign_checkpoint(
        build_checkpoint(
            log_id,
            2,
            encode_hash(tree.root()),
            1,
            0,
            NOW,
        ),
        epoch,
    )
    checkpoint_evidence = CheckpointEvidence(
        checkpoint=checkpoint,
        cosignatures=[
            build_cosignature(structure_hash(checkpoint), "w0", NOW, witness, log_id=log_id)
        ],
    )
    bundle = Bundle(
        format_version="4",
        log_id=log_id,
        log_name=log_name,
        entries=[],
        intermediates=[intermediate_certificate],
        epochs=[epoch_certificate],
        witness_set=witness_set,
        checkpoints=[checkpoint_evidence],
        inclusion_proofs=[
            InclusionProof(
                seq=seq,
                tree_size=2,
                proof=[encode_hash(item) for item in tree.inclusion_proof(seq, 2)],
            )
            for seq in range(2)
        ],
        consistency_proofs=[],
    )
    pins = PinnedKeys(
        log_id=log_id,
        log_name=log_name,
        root_public_key=encode_base64url(root.public_key().public_bytes_raw()),
        witness_public_keys={"w0": encode_base64url(witness.public_key().public_bytes_raw())},
        minimum_tree_size=2,
    )
    store = InMemoryLedgerStore(
        pinned_roots={log_id: pins.root_public_key},
        intermediates={intermediate_certificate.intermediate_id: intermediate_certificate},
        epochs={f"{log_id}:0": epoch_certificate},
        bundle=bundle,
        pinned_keys=pins,
    )
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(
        0,
        entry_hash(start_body),
        0,
        log_id,
        outbox_append=(start_entry,),
    )
    os.environ["LEDGER_AUTH_TOKEN"] = "ledger-token"
    client = TestClient(create_app(store=store))
    signer = SignerSealer(
        log_id=log_id,
        epoch_id=0,
        epoch_certificate_id=certificate_id(epoch_certificate),
        valid_from=START,
        valid_until=END,
        clock=lambda: NOW,
        signing_operation=epoch,
    )
    return store, client, signer, action_entry


def make_memory_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[InMemoryLedgerStore, TestClient, SignerSealer, str, object]:
    root, _intermediate, epoch, intermediate_certificate, epoch_certificate = signer_material()
    store = InMemoryLedgerStore(
        pinned_roots={LOG_ID: encode_base64url(root.public_key().public_bytes_raw())},
        intermediates={intermediate_certificate.intermediate_id: intermediate_certificate},
        epochs={f"{LOG_ID}:0": epoch_certificate},
    )
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    os.environ["LEDGER_AUTH_TOKEN"] = "ledger-token"
    client = TestClient(create_app(store=store))
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=certificate_id(epoch_certificate),
        valid_from=START,
        valid_until=END,
        clock=lambda: NOW,
        signing_operation=epoch,
    )
    return store, client, signer, certificate_id(epoch_certificate), epoch


def candidate(
    seq: int = 0,
    previous: str = GENESIS_PREV_HASH,
    certificate: str = "",
    log_id: str = LOG_ID,
) -> dict[str, object]:
    value = action()
    value.update(
        log_id=log_id,
        epoch_id=0,
        epoch_certificate_id=certificate,
        seq=seq,
        prev_hash=previous,
        signer_timestamp=NOW,
    )
    return value


class InProcessLedgerTransport:
    def __init__(self, client: TestClient, *, down: bool = False) -> None:
        self.client = client
        self.down = down
        self.calls: list[int] = []

    def append(self, entry: SealedEntry, bearer_token: str) -> delivery.LedgerResponse:
        if self.down:
            raise ConnectionError("ledger down")
        self.calls.append(entry.body.seq)
        response = self.client.post(
            "/entries",
            json=entry.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {bearer_token}"},
        )
        payload = response.json()
        code = payload.get("error", {}).get("code") if response.status_code >= 400 else None
        return delivery.LedgerResponse(response.status_code, payload.get("entry_hash"), code)


def test_signer_outbox_delivery_ack_and_verified_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store, client, signer, expected_action = verified_e2e_setup(monkeypatch, tmp_path)
    sealed = signer.seal(
        candidate(
            seq=1,
            previous=expected_action.body.prev_hash,
            certificate=expected_action.body.epoch_certificate_id,
            log_id=expected_action.body.log_id,
        )
    )
    transport = InProcessLedgerTransport(client)
    worker = delivery.DeliveryWorker(signer, transport, bearer_token="ledger-token")

    assert worker.run_once() is True
    assert worker.run_once() is True
    assert signer.pending_outbox() == ()
    assert transport.calls == [0, 1]
    exported = store.export_bundle(expected_action.body.log_id)
    assert verify_evidence(exported, store.pinned_keys).verdict == "VERIFIED"
    assert sealed == expected_action


def test_rollover_tick_entries_reach_the_in_memory_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    epochs = manager()
    root_public_key = getattr(epochs.intermediate_signer, "_root_public_key")
    store = InMemoryLedgerStore(
        pinned_roots={LOG_ID: encode_base64url(root_public_key)},
        intermediates={
            epochs.intermediate_signer.certificate.intermediate_id: epochs.intermediate_signer.certificate
        },
        epochs={f"{LOG_ID}:0": epochs.certificate},
    )
    os.environ["LEDGER_AUTH_TOKEN"] = "ledger-token"
    client = TestClient(create_app(store=store))
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id=epochs.certificate_id,
        valid_from=START,
        valid_until=END,
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=dev_key(5),
        epoch_manager=epochs,
    )
    rollover, _ = signer.tick()
    store.register_epoch(epochs.certificate)
    transport = InProcessLedgerTransport(client)
    worker = delivery.DeliveryWorker(signer, transport, bearer_token="ledger-token")

    assert [entry.body.type for entry in rollover] == ["epoch_end", "epoch_start"]
    assert worker.run_once() is True
    assert worker.run_once() is True
    assert transport.calls == [0, 1]
    assert signer.pending_outbox() == ()


def test_ledger_down_accumulates_then_drains_in_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store, client, signer, certificate, _epoch = make_memory_ledger(monkeypatch, tmp_path)
    first = signer.seal(candidate(certificate=certificate))
    second = signer.seal(candidate(1, entry_hash(first.body), certificate))
    transport = InProcessLedgerTransport(client, down=True)
    worker = delivery.DeliveryWorker(
        signer, transport, bearer_token="ledger-token", clock=lambda: 10.0
    )

    assert worker.run_once() is False
    assert worker.run_once() is False
    assert len(signer.pending_outbox()) == 2
    transport.down = False
    clock = [worker.next_attempt_at]
    worker = delivery.DeliveryWorker(
        signer, transport, bearer_token="ledger-token", clock=lambda: clock[0]
    )
    assert worker.run_once() is True
    clock[0] = worker.next_attempt_at
    assert worker.run_once() is True
    assert transport.calls == [0, 1]
    assert signer.pending_outbox() == ()
    assert store.get_entry(LOG_ID, first.body.seq) is not None
    assert store.get_entry(LOG_ID, second.body.seq) is not None


def test_signer_recreated_from_disk_delivers_one_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    store, client, signer, certificate_id_value, _epoch_value = make_memory_ledger(
        monkeypatch, tmp_path
    )
    first = signer.seal(candidate(certificate=certificate_id_value))
    _, _, epoch, _intermediate, epoch_certificate = signer_material()
    restarted = SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=certificate_id(epoch_certificate),
        valid_from=START,
        valid_until=END,
        clock=lambda: NOW,
        signing_operation=epoch,
    )
    transport = InProcessLedgerTransport(client)
    worker = delivery.DeliveryWorker(restarted, transport, bearer_token="ledger-token")

    assert worker.run_once() is True
    assert transport.calls == [0]
    assert len(store.entries) == 1
    assert first.body.seq == 0


def test_tampered_in_memory_row_is_caught_by_offline_verifier() -> None:
    bundle, pins = build_demo(generate_dev_keys())
    store = InMemoryLedgerStore.from_bundle(bundle, pins)
    original = store.entries[(bundle.log_id, 5)]
    tampered_body = original.entry.body.model_copy(update={"action_name": "tampered"})
    store.entries[(bundle.log_id, 5)] = StoredEntry(
        original.entry.model_copy(update={"body": tampered_body}), original.entry_hash
    )

    assert verify_evidence(store.export_bundle(bundle.log_id), pins).verdict == "TAMPERED"


def test_equivocation_stops_worker_and_records_both_hashes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store, client, signer, certificate, _epoch = make_memory_ledger(monkeypatch, tmp_path)
    sealed = signer.seal(candidate(certificate=certificate))
    alternate_body = parse_entry({**candidate(certificate=certificate), "action_name": "different"})
    alternate = seal(alternate_body, dev_key(3))
    store.insert_entry(StoredEntry(alternate, entry_hash(alternate.body)))
    transport = InProcessLedgerTransport(client)
    worker = delivery.DeliveryWorker(signer, transport, bearer_token="ledger-token")

    assert worker.run_once() is False
    assert worker.alarm_code == delivery.LEDGER_EQUIVOCATION
    assert signer.health_reason == delivery.LEDGER_EQUIVOCATION
    assert len(store.conflicts) == 1
    assert {store.conflicts[0]["existing_hash"], store.conflicts[0]["rejected_hash"]} == {
        entry_hash(alternate.body),
        entry_hash(sealed.body),
    }
    assert signer.pending_outbox() == (sealed,)


def test_out_of_order_stops_worker_without_removing_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store, client, signer, certificate, _epoch = make_memory_ledger(monkeypatch, tmp_path)
    sealed = signer.seal(candidate(certificate=certificate))
    out_of_order = seal(parse_entry(candidate(5, GENESIS_PREV_HASH, certificate)), dev_key(3))
    store.entries[(LOG_ID, 5)] = StoredEntry(out_of_order, entry_hash(out_of_order.body))
    transport = InProcessLedgerTransport(client)
    worker = delivery.DeliveryWorker(signer, transport, bearer_token="ledger-token")

    assert worker.run_once() is False
    assert worker.alarm_code == delivery.LEDGER_OUT_OF_ORDER
    assert signer.pending_outbox() == (sealed,)

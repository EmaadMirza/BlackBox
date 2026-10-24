"""L2b-2 signer-to-ledger delivery against real local PostgreSQL."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.checkpoint import build_checkpoint, build_cosignature, sign_checkpoint
from libs.blackbox_core.encoding import encode_base64url, encode_hash
from libs.blackbox_core.epochs import build_epoch_certificate, build_intermediate_certificate
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
from services.signer import delivery, state
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.integration.support import execute, get_test_dsn, reset_database
from tests.unit.test_schemas import action
from tests.unit.test_signer_epoch_rollover import manager
from tools.verifier.verify import verify_evidence

pytestmark = pytest.mark.integration

START = "2026-01-01T00:00:00.000Z"
NOW = "2026-01-01T00:01:00.000Z"
END = "2026-01-01T00:05:00.000Z"


class InProcessPostgresTransport:
    def __init__(self, client: TestClient, *, down: bool = False) -> None:
        self.client = client
        self.down = down
        self.calls: list[int] = []
        self.responses: list[tuple[int, str | None, str | None]] = []

    def append(self, entry: SealedEntry, bearer_token: str) -> delivery.LedgerResponse:
        if self.down:
            raise ConnectionError("ledger unavailable")
        self.calls.append(entry.body.seq)
        response = self.client.post(
            "/entries",
            json=entry.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {bearer_token}"},
        )
        body = response.json()
        self.responses.append(
            (response.status_code, body.get("entry_hash"), body.get("error", {}).get("code"))
        )
        return delivery.LedgerResponse(
            response.status_code,
            body.get("entry_hash"),
            body.get("error", {}).get("code"),
        )


def _material() -> tuple[
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    str,
    IntermediateCertificate,
    EpochCertificate,
    WitnessSet,
    PinnedKeys,
]:
    root, intermediate, epoch = dev_key(1), dev_key(2), dev_key(3)
    log_name = "l2b2-postgres"
    log_id = derive_log_id(root.public_key().public_bytes_raw(), log_name)
    intermediate_cert = build_intermediate_certificate(
        log_id,
        "intermediate-0",
        encode_base64url(intermediate.public_key().public_bytes_raw()),
        START,
        "2026-02-01T00:00:00.000Z",
        root,
    )
    epoch_cert = build_epoch_certificate(
        0,
        encode_base64url(epoch.public_key().public_bytes_raw()),
        START,
        END,
        intermediate_cert.intermediate_id,
        log_id=log_id,
        signing_operation=intermediate,
    )
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
    pins = PinnedKeys(
        log_id=log_id,
        log_name=log_name,
        root_public_key=encode_base64url(root.public_key().public_bytes_raw()),
        witness_public_keys={"w0": witness_set.witnesses[0].public_key},
        minimum_tree_size=0,
    )
    return root, intermediate, epoch, log_id, intermediate_cert, epoch_cert, witness_set, pins


def _seed_registry(material) -> None:
    _, _, _, log_id, intermediate_cert, epoch_cert, _, pins = material
    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute(
            "INSERT INTO blackbox.pinned_roots(log_id, root_public_key) VALUES (%s, %s)",
            (log_id, pins.root_public_key),
        )
        connection.execute(
            "INSERT INTO blackbox.intermediates(intermediate_id, log_id, certificate) VALUES (%s, %s, %s)",
            (
                intermediate_cert.intermediate_id,
                log_id,
                Jsonb(intermediate_cert.model_dump(mode="json")),
            ),
        )
        connection.execute(
            "INSERT INTO blackbox.epochs(epoch_certificate_id, log_id, epoch_id, certificate) VALUES (%s, %s, %s, %s)",
            (
                structure_hash(epoch_cert),
                log_id,
                epoch_cert.epoch_id,
                Jsonb(epoch_cert.model_dump(mode="json")),
            ),
        )


def _start_entry(epoch: Ed25519PrivateKey, log_id: str, cert: EpochCertificate) -> SealedEntry:
    body = EpochStart(
        format_version="4",
        log_id=log_id,
        epoch_id=0,
        seq=0,
        signer_timestamp=START,
        prev_hash=GENESIS_PREV_HASH,
        lane="agent",
        epoch_certificate_id=structure_hash(cert),
        type="epoch_start",
        certificate=cert,
    )
    return seal(body, epoch)


def _setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    reset_database()
    material = _material()
    _seed_registry(material)
    root, intermediate, epoch, log_id, intermediate_cert, epoch_cert, witness_set, pins = material
    start = _start_entry(epoch, log_id, epoch_cert)
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(0, entry_hash(start.body), 0, log_id, outbox_append=(start,))
    os.environ["LEDGER_DATABASE_URL"] = get_test_dsn()
    os.environ["LEDGER_AUTH_TOKEN"] = "ledger-token"
    client = TestClient(create_app(), raise_server_exceptions=False)
    signer = SignerSealer(
        log_id=log_id,
        epoch_id=0,
        epoch_certificate_id=structure_hash(epoch_cert),
        valid_from=START,
        valid_until=END,
        clock=lambda: NOW,
        signing_operation=epoch,
    )
    return material, start, client, signer


def _export_bundle(log_id: str, material) -> tuple[Bundle, PinnedKeys]:
    root, _, epoch_key, _, intermediate_cert, epoch_cert, witness_set, pins = material
    rows = execute(
        "SELECT sealed_entry FROM blackbox.entries WHERE log_id=%s ORDER BY seq", (log_id,)
    )
    entries = [SealedEntry.model_validate(row[0]) for row in rows]
    tree = MerkleTree([sealed_bytes(entry) for entry in entries])
    latest = entries[-1].body
    checkpoint = sign_checkpoint(
        build_checkpoint(
            log_id, len(entries), encode_hash(tree.root()), len(entries) - 1, latest.epoch_id, NOW
        ),
        epoch_key,
    )
    witness_key = dev_key(4)
    evidence = CheckpointEvidence(
        checkpoint=checkpoint,
        cosignatures=[
            build_cosignature(structure_hash(checkpoint), "w0", NOW, witness_key, log_id=log_id)
        ],
    )
    bundle = Bundle(
        format_version="4",
        log_id=log_id,
        log_name=pins.log_name,
        entries=[entry.model_dump() for entry in entries],
        intermediates=[intermediate_cert],
        epochs=[epoch_cert],
        witness_set=witness_set,
        checkpoints=[evidence],
        inclusion_proofs=[
            InclusionProof(
                seq=seq,
                tree_size=len(entries),
                proof=[encode_hash(item) for item in tree.inclusion_proof(seq, len(entries))],
            )
            for seq in range(len(entries))
        ],
        consistency_proofs=[],
    )
    return bundle, pins


def _drain(worker: delivery.DeliveryWorker, count: int, transport=None) -> None:
    for _ in range(count):
        assert worker.run_once() is True, (
            worker.alarm_code,
            worker.next_attempt_at,
            worker.signer.pending_outbox(),
            getattr(transport, "calls", None),
            getattr(transport, "responses", None),
        )


def test_integration_database_guard_requires_test_name() -> None:
    assert "test" in get_test_dsn().lower()


def test_real_postgres_end_to_end_and_offline_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    material, start, client, signer = _setup(monkeypatch, tmp_path)
    _, _, epoch, log_id, _, epoch_cert, _, _ = material
    body = action()
    body.update(
        log_id=log_id,
        epoch_id=0,
        seq=1,
        prev_hash=entry_hash(start.body),
        epoch_certificate_id=structure_hash(epoch_cert),
        signer_timestamp=NOW,
    )
    signer.seal(parse_entry(body))
    transport = InProcessPostgresTransport(client)
    worker = delivery.DeliveryWorker(signer, transport, bearer_token="ledger-token")
    _drain(worker, 2, transport)
    assert signer.pending_outbox() == ()
    bundle, pins = _export_bundle(log_id, material)
    assert verify_evidence(bundle, pins).verdict == "VERIFIED"


def test_ledger_down_then_drains_in_order(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    material, start, client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, epoch_cert, _, _ = material
    previous_hash = entry_hash(start.body)
    for seq in (1, 2):
        body = action()
        body.update(
            log_id=log_id,
            epoch_id=0,
            seq=seq,
            prev_hash=previous_hash,
            epoch_certificate_id=structure_hash(epoch_cert),
            signer_timestamp=NOW,
        )
        previous_hash = entry_hash(signer.seal(parse_entry(body)).body)
    transport = InProcessPostgresTransport(client, down=True)
    worker = delivery.DeliveryWorker(
        signer, transport, bearer_token="ledger-token", clock=lambda: 0.0
    )
    assert worker.run_once() is False
    assert len(signer.pending_outbox()) == 3
    transport.down = False
    worker.next_attempt_at = 0.0
    _drain(worker, 3, transport)
    assert signer.pending_outbox() == ()
    assert transport.calls == [0, 1, 2]


def test_tick_rollover_entries_reach_real_postgres(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    reset_database()
    epochs = manager()
    log_id = epochs.log_id
    intermediate_cert = epochs.intermediate_signer.certificate
    root_public_key = getattr(epochs.intermediate_signer, "_root_public_key")
    epoch_cert = epochs.certificate
    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute(
            "INSERT INTO blackbox.pinned_roots(log_id, root_public_key) VALUES (%s, %s)",
            (log_id, encode_base64url(root_public_key)),
        )
        connection.execute(
            "INSERT INTO blackbox.intermediates(intermediate_id, log_id, certificate) VALUES (%s, %s, %s)",
            (
                intermediate_cert.intermediate_id,
                log_id,
                Jsonb(intermediate_cert.model_dump(mode="json")),
            ),
        )
        connection.execute(
            "INSERT INTO blackbox.epochs(epoch_certificate_id, log_id, epoch_id, certificate) VALUES (%s, %s, %s, %s)",
            (
                structure_hash(epoch_cert),
                log_id,
                epoch_cert.epoch_id,
                Jsonb(epoch_cert.model_dump(mode="json")),
            ),
        )
    start = _start_entry(epochs.signing_operation, log_id, epoch_cert)
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(0, entry_hash(start.body), 0, log_id, outbox_append=(start,))
    os.environ["LEDGER_DATABASE_URL"] = get_test_dsn()
    os.environ["LEDGER_AUTH_TOKEN"] = "ledger-token"
    client = TestClient(create_app(), raise_server_exceptions=False)
    signer = SignerSealer(
        log_id=log_id,
        epoch_certificate_id=structure_hash(epoch_cert),
        valid_from=START,
        valid_until=END,
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=epochs.signing_operation,
        epoch_manager=epochs,
    )
    rollover, _ = signer.tick()
    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute(
            "INSERT INTO blackbox.epochs(epoch_certificate_id, log_id, epoch_id, certificate) VALUES (%s, %s, %s, %s)",
            (
                structure_hash(epochs.certificate),
                log_id,
                epochs.certificate.epoch_id,
                Jsonb(epochs.certificate.model_dump(mode="json")),
            ),
        )
    transport = InProcessPostgresTransport(client)
    worker = delivery.DeliveryWorker(signer, transport, bearer_token="ledger-token")
    _drain(worker, 3, transport)
    assert [entry.body.type for entry in rollover] == ["epoch_end", "epoch_start"]
    assert [row[0] for row in execute("SELECT seq FROM blackbox.entries ORDER BY seq")] == [0, 1, 2]
    assert signer.pending_outbox() == ()


def test_restart_delivers_each_row_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    material, start, client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, epoch_cert, _, _ = material
    initial_worker = delivery.DeliveryWorker(
        signer, InProcessPostgresTransport(client), bearer_token="ledger-token"
    )
    assert initial_worker.run_once() is True
    body = action()
    body.update(
        log_id=log_id,
        epoch_id=0,
        seq=1,
        prev_hash=entry_hash(start.body),
        epoch_certificate_id=structure_hash(epoch_cert),
        signer_timestamp=NOW,
    )
    sealed = signer.seal(parse_entry(body))
    restarted = SignerSealer(
        log_id=log_id,
        epoch_id=0,
        epoch_certificate_id=structure_hash(epoch_cert),
        valid_from=START,
        valid_until=END,
        clock=lambda: NOW,
        signing_operation=material[2],
    )
    transport = InProcessPostgresTransport(client)
    worker = delivery.DeliveryWorker(restarted, transport, bearer_token="ledger-token")
    _drain(worker, 1)
    assert len(execute("SELECT seq FROM blackbox.entries WHERE log_id=%s", (log_id,))) == 2
    assert sealed.body.seq == 1


def test_owner_row_tamper_is_detected_offline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    material, _, client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, epoch_cert, _, _ = material
    transport = InProcessPostgresTransport(client)
    _drain(delivery.DeliveryWorker(signer, transport, bearer_token="ledger-token"), 1)
    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute("ALTER TABLE blackbox.entries DISABLE TRIGGER entries_no_mutation")
        connection.execute(
            "UPDATE blackbox.entries SET sealed_entry = jsonb_set(sealed_entry, '{body,seq}', '99') WHERE log_id=%s AND seq=0",
            (log_id,),
        )
        connection.execute("ALTER TABLE blackbox.entries ENABLE TRIGGER entries_no_mutation")
    bundle, pins = _export_bundle(log_id, material)
    assert verify_evidence(bundle, pins).verdict == "TAMPERED"


def test_equivocation_records_conflict_and_degrades_signer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    material, start, client, signer = _setup(monkeypatch, tmp_path)
    _, _, epoch, log_id, _, epoch_cert, _, _ = material
    initial_worker = delivery.DeliveryWorker(
        signer, InProcessPostgresTransport(client), bearer_token="ledger-token"
    )
    assert initial_worker.run_once() is True
    body = action()
    body.update(
        log_id=log_id,
        epoch_id=0,
        seq=1,
        prev_hash=entry_hash(start.body),
        epoch_certificate_id=structure_hash(epoch_cert),
        signer_timestamp=NOW,
    )
    sealed = signer.seal(parse_entry(body))
    alternate = seal(parse_entry({**body, "action_name": "different"}), epoch)
    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute("ALTER TABLE blackbox.entries DISABLE TRIGGER entries_contiguous")
        connection.execute(
            "INSERT INTO blackbox.entries(log_id, seq, sealed_entry, entry_hash, prev_hash, epoch_id, type) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (
                log_id,
                1,
                Jsonb(alternate.model_dump(mode="json")),
                entry_hash(alternate.body),
                alternate.body.prev_hash,
                0,
                alternate.body.type,
            ),
        )
        connection.execute("ALTER TABLE blackbox.entries ENABLE TRIGGER entries_contiguous")
    worker = delivery.DeliveryWorker(
        signer, InProcessPostgresTransport(client), bearer_token="ledger-token"
    )
    assert worker.run_once() is False
    assert worker.alarm_code == delivery.LEDGER_EQUIVOCATION
    assert signer.health_reason == delivery.LEDGER_EQUIVOCATION
    conflict = execute(
        "SELECT existing_hash, rejected_hash FROM blackbox.conflicts WHERE log_id=%s", (log_id,)
    )
    assert {conflict[0][0], conflict[0][1]} == {entry_hash(alternate.body), entry_hash(sealed.body)}


def test_out_of_order_stops_worker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    material, start, client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, epoch_cert, _, _ = material
    body = action()
    body.update(
        log_id=log_id,
        epoch_id=0,
        seq=1,
        prev_hash=entry_hash(start.body),
        epoch_certificate_id=structure_hash(epoch_cert),
        signer_timestamp=NOW,
    )
    signer.seal(parse_entry(body))
    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute("ALTER TABLE blackbox.entries DISABLE TRIGGER entries_contiguous")
        connection.execute(
            "INSERT INTO blackbox.entries(log_id, seq, sealed_entry, entry_hash, prev_hash, epoch_id, type) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (log_id, 5, Jsonb(body), "sha256:" + "f" * 64, GENESIS_PREV_HASH, 0, "action"),
        )
        connection.execute("ALTER TABLE blackbox.entries ENABLE TRIGGER entries_contiguous")
    worker = delivery.DeliveryWorker(
        signer, InProcessPostgresTransport(client), bearer_token="ledger-token"
    )
    assert worker.run_once() is False
    assert worker.alarm_code == delivery.LEDGER_OUT_OF_ORDER


def test_ledger_app_cannot_mutate_entries() -> None:
    with psycopg.connect(get_test_dsn(), autocommit=True) as connection:
        connection.execute("SET ROLE ledger_app")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("UPDATE blackbox.entries SET seq = seq")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("DELETE FROM blackbox.entries")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("TRUNCATE blackbox.entries")

"""K1c witnessed checkpoint evidence tests."""

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.checkpoint import (
    WitnessedCheckpointEvidence,
    build_checkpoint,
    build_cosignature,
    sign_checkpoint,
)
from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.schemas import WitnessIdentity, WitnessSet
from libs.blackbox_core.signing import sign_structure, structure_hash
from services.signer.history import HistoryEntryEvidence, HistoryRecord
from tests._dev_keys import dev_key
from tests.unit.test_attestation_a1b import make_sealer, setup_history
from tools.attack_suite.fixture import build_demo


def test_witnessed_checkpoint_evidence_requires_distinct_quorum() -> None:
    bundle, pins = build_demo(
        [(key, key.public_key().public_bytes_raw()) for key in [dev_key(i) for i in range(1, 8)]]
    )
    evidence = bundle.checkpoints[-1]
    root_public_key = dev_key(1).public_key().public_bytes_raw()
    witness_set = bundle.witness_set
    valid = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=evidence.cosignatures,
        witness_set=witness_set,
        root_public_key=root_public_key,
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    assert valid.covers(9, pins.log_id)
    duplicate = valid.__class__(
        **{**valid.__dict__, "cosignatures": [evidence.cosignatures[0]] * 2}
    )
    assert not duplicate.covers(9, pins.log_id)


def test_witnessed_checkpoint_rejects_forged_and_noncovering_evidence() -> None:
    bundle, pins = build_demo(
        [(key, key.public_key().public_bytes_raw()) for key in [dev_key(i) for i in range(1, 8)]]
    )
    evidence = bundle.checkpoints[-1]
    value = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=evidence.cosignatures,
        witness_set=bundle.witness_set,
        root_public_key=dev_key(1).public_key().public_bytes_raw(),
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    forged = value.__class__(
        **{
            **value.__dict__,
            "cosignatures": [
                evidence.cosignatures[0].model_copy(update={"witness_signature": ""}),
                evidence.cosignatures[1].model_copy(update={"witness_signature": ""}),
                evidence.cosignatures[2],
            ],
        }
    )
    assert not forged.covers(9, pins.log_id)
    assert not value.covers(99, pins.log_id)


def test_high_risk_attest_requires_real_witnessed_evidence(tmp_path, monkeypatch) -> None:
    root, epoch_key, epoch, intent, _, source = setup_history()
    intent = intent.model_copy(
        update={
            "policy": intent.policy.model_copy(update={"severity": "high"}),
            "signer_timestamp": "2026-01-01T00:01:00.000Z",
        }
    )
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    signer, _ = make_sealer(tmp_path, source, epoch_key, epoch)
    sealed = signer.seal(intent)
    original = source.record.entries[0]
    source.record = HistoryRecord(
        entries=(
            HistoryEntryEvidence(
                entry=sealed,
                epoch_certificate=original.epoch_certificate,
                intermediate_certificate=original.intermediate_certificate,
                root_public_key=original.root_public_key,
            ),
        ),
        target_seq=0,
    )
    witnesses = [dev_key(i) for i in (20, 21, 22)]
    witness_set = sign_structure(
        WitnessSet(
            log_id=epoch.log_id,
            version=1,
            witnesses=[
                WitnessIdentity(
                    witness_id=f"w{i}",
                    public_key=encode_base64url(key.public_key().public_bytes_raw()),
                )
                for i, key in enumerate(witnesses)
            ],
            quorum=2,
            effective_time=epoch.valid_from,
        ),
        root,
        "witness_set",
    )
    checkpoint = sign_checkpoint(
        build_checkpoint(
            epoch.log_id,
            1,
            "sha256:" + "c" * 64,
            0,
            epoch.epoch_id,
            "2026-01-01T00:01:00.000Z",
            latest_entry_hash=entry_hash(sealed.body),
        ),
        epoch_key,
    )
    cosigs = [
        build_cosignature(
            structure_hash(checkpoint),
            f"w{i}",
            "2026-01-01T00:01:01.000Z",
            key,
            log_id=epoch.log_id,
        )
        for i, key in enumerate(witnesses)
    ]
    evidence = WitnessedCheckpointEvidence(
        checkpoint=checkpoint,
        cosignatures=cosigs,
        witness_set=witness_set,
        root_public_key=root.public_key().public_bytes_raw(),
        intermediate_certificate=original.intermediate_certificate,
        epoch_certificate=epoch,
    )
    assert signer.attest(0, checkpoint_evidence=evidence).body_digest == intent.action.body_digest

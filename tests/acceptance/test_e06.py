"""E6: Witness outage and availability attacks (in-process, not network-separated)."""

from libs.blackbox_core.checkpoint import WitnessedCheckpointEvidence
from libs.blackbox_core.schemas import Checkpoint, Heartbeat
from services.witness.heartbeat_monitor import checkpoint_stall
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo


def test_e06() -> None:
    """E6: Witness outage and availability attacks (in-process, not network-separated).

    Points to existing W2a quorum logic and W3b stall/alarm monitoring.
    Expected:
    (a) Quorum holds with 1 witness down (2 of 3 valid distinct cosignatures);
        insufficient distinct witnesses fail quorum.
    (b) CHECKPOINT_STALL fires when unverified window exceeds bounds.
    """
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
    evidence = bundle.checkpoints[-1]
    root_public_key = keys[0][0].public_key().public_bytes_raw()
    witness_set = bundle.witness_set
    assert witness_set.quorum == 2
    assert len(evidence.cosignatures) >= 2

    # Case (a): 2 of 3 witnesses available -> Quorum holds
    valid = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=evidence.cosignatures[:2],  # 1 witness absent, 2 present
        witness_set=witness_set,
        root_public_key=root_public_key,
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    assert valid.covers(9, pins.log_id), "2/3 quorum must be met with 1 witness down"

    # Insufficient quorum: only 1 witness available -> Fails closed
    insufficient = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=evidence.cosignatures[:1],  # Only 1 witness
        witness_set=witness_set,
        root_public_key=root_public_key,
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    assert not insufficient.covers(9, pins.log_id), "Must fail closed when quorum is not met"

    # Duplicated witness key (same witness cosigning twice) -> Fails closed
    duplicate = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=[evidence.cosignatures[0], evidence.cosignatures[0]],
        witness_set=witness_set,
        root_public_key=root_public_key,
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    assert not duplicate.covers(9, pins.log_id), "Duplicate cosignatures must not satisfy quorum"

    # Case (b): Checkpoint stall detection when progress halts
    heartbeat = Heartbeat(
        log_id=pins.log_id,
        epoch_id=0,
        latest_seq=9,
        latest_entry_hash="sha256:" + "b" * 64,
        queue_depth=0,
        signer_timestamp="2026-01-01T00:00:01.000Z",
    )
    checkpoint = Checkpoint(
        log_id=pins.log_id,
        tree_size=10,
        root_hash="sha256:" + "c" * 64,
        latest_seq=9,
        latest_entry_hash="sha256:" + "d" * 64,
        epoch_id=0,
        signer_timestamp="2026-01-01T00:00:00.000Z",
    )
    stalls = checkpoint_stall(
        heartbeat, checkpoint, "2026-01-01T00:00:20.000Z", unverified_window=15
    )
    assert "CHECKPOINT_STALL" in stalls

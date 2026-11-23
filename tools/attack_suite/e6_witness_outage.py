"""E6: Witness outage and availability attacks (spec §29.4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from libs.blackbox_core.checkpoint import WitnessedCheckpointEvidence
from libs.blackbox_core.schemas import Checkpoint, Heartbeat
from services.witness.heartbeat_monitor import checkpoint_stall
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E6 witness outage and availability attack simulation."""
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
    evidence = bundle.checkpoints[-1]
    root_public_key = keys[0][0].public_key().public_bytes_raw()
    witness_set = bundle.witness_set
    assert witness_set.quorum == 2
    assert len(evidence.cosignatures) >= 2

    # Case 1: Quorum holds with 1 witness down (2 of 3 valid cosignatures)
    valid_with_1_down = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=evidence.cosignatures[:2],
        witness_set=witness_set,
        root_public_key=root_public_key,
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    quorum_holds = valid_with_1_down.covers(9, pins.log_id)
    assert quorum_holds, "2/3 quorum must be met with 1 witness down"

    # Case 2: Insufficient quorum: only 1 witness available -> Fails closed
    insufficient = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=evidence.cosignatures[:1],
        witness_set=witness_set,
        root_public_key=root_public_key,
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    insufficient_fails = not insufficient.covers(9, pins.log_id)
    assert insufficient_fails, "Must fail closed when quorum is not met"

    # Case 3: Duplicate witness key cosigning twice -> Fails closed
    duplicate = WitnessedCheckpointEvidence(
        checkpoint=evidence.checkpoint,
        cosignatures=[evidence.cosignatures[0], evidence.cosignatures[0]],
        witness_set=witness_set,
        root_public_key=root_public_key,
        intermediate_certificate=bundle.intermediates[0],
        epoch_certificate=bundle.epochs[1],
    )
    duplicate_fails = not duplicate.covers(9, pins.log_id)
    assert duplicate_fails, "Duplicate cosignatures must not satisfy quorum"

    # Case 4: Checkpoint stall detection when progress halts
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

    return {
        "scenario": "E6_witness_outage",
        "verdict": "PASSED",
        "quorum_with_one_down": quorum_holds,
        "insufficient_quorum_blocked": insufficient_fails,
        "duplicate_cosignature_blocked": duplicate_fails,
        "alarms_fired": stalls,
    }


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()

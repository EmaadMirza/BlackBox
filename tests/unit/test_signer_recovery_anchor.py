"""Unit tests for recovery anchor and startup enforcement (Task E)."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.signer import recovery, state

LOG_ID = "sha256:" + "c" * 64
HASH_1 = "sha256:" + "1" * 64
HASH_2 = "sha256:" + "2" * 64


def test_recovery_anchor_creation_and_load(tmp_path: Path) -> None:
    anchor_path = tmp_path / "state.json.recovery.json"

    assert recovery.load_recovery_anchor(anchor_path) is None

    anchor = recovery.create_recovery_anchor(
        log_id=LOG_ID,
        outcome="same_log_continuation",
        frontier_seq=15,
        frontier_hash=HASH_1,
        operator_id="operator-alice",
        reason="crash_recovery",
        recovery_generation=1,
        burned_range=[10, 14],
        path=anchor_path,
    )

    assert anchor.recovery_outcome == "same_log_continuation"
    assert anchor.recovery_generation == 1
    assert anchor.frontier_seq == 15
    assert anchor.frontier_hash == HASH_1
    assert anchor.burned_range == [10, 14]

    loaded = recovery.load_recovery_anchor(anchor_path)
    assert loaded == anchor


def test_startup_recovery_accepts_valid_frontier(tmp_path: Path) -> None:
    anchor_path = tmp_path / "state.json.recovery.json"
    recovery.create_recovery_anchor(
        log_id=LOG_ID,
        outcome="same_log_continuation",
        frontier_seq=10,
        frontier_hash=HASH_1,
        operator_id="operator-1",
        reason="recovery",
        path=anchor_path,
    )

    # Sequence at frontier with matching hash passes
    recovery.validate_startup_recovery(10, HASH_1, LOG_ID, path=anchor_path)

    # Sequence above frontier passes
    recovery.validate_startup_recovery(11, HASH_2, LOG_ID, path=anchor_path)


def test_startup_recovery_rejects_state_below_frontier(tmp_path: Path) -> None:
    anchor_path = tmp_path / "state.json.recovery.json"
    recovery.create_recovery_anchor(
        log_id=LOG_ID,
        outcome="same_log_continuation",
        frontier_seq=10,
        frontier_hash=HASH_1,
        operator_id="operator-1",
        reason="recovery",
        path=anchor_path,
    )

    with pytest.raises(recovery.RecoveryError, match="below recovery frontier"):
        recovery.validate_startup_recovery(9, HASH_1, LOG_ID, path=anchor_path)


def test_startup_recovery_rejects_hash_disagreement_at_frontier(tmp_path: Path) -> None:
    anchor_path = tmp_path / "state.json.recovery.json"
    recovery.create_recovery_anchor(
        log_id=LOG_ID,
        outcome="same_log_continuation",
        frontier_seq=10,
        frontier_hash=HASH_1,
        operator_id="operator-1",
        reason="recovery",
        path=anchor_path,
    )

    with pytest.raises(recovery.RecoveryError, match="does not match anchor"):
        recovery.validate_startup_recovery(10, HASH_2, LOG_ID, path=anchor_path)


def test_state_load_state_enforces_recovery_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_file = tmp_path / "state.json"
    anchor_file = tmp_path / "state.json.recovery.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    monkeypatch.setenv("SIGNER_RECOVERY_ANCHOR_PATH", str(anchor_file))

    # Persist state at seq 5
    state.persist_state(5, HASH_1, 0, LOG_ID, {})

    # Create anchor requiring frontier at seq 10
    recovery.create_recovery_anchor(
        log_id=LOG_ID,
        outcome="same_log_continuation",
        frontier_seq=10,
        frontier_hash=HASH_2,
        operator_id="operator-1",
        reason="recovery",
        path=anchor_file,
    )

    # Loading state should fail closed because durable state is below recovery frontier
    with pytest.raises(recovery.RecoveryError, match="below recovery frontier"):
        state.load_state(LOG_ID)

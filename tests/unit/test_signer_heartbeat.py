"""K2a heartbeat operation tests."""

from pathlib import Path

import pytest

from libs.blackbox_core.checkpoint import build_checkpoint
from libs.blackbox_core.heartbeat import heartbeat_matches_checkpoint, verify_heartbeat
from libs.blackbox_core.signing import verify_structure
from services.signer import state
from tests._dev_keys import dev_key
from tests.unit.test_signer_sealer import LOG_ID, NOW, make_sealer


def test_heartbeat_claims_durable_state_and_does_not_change_chain(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    key = dev_key()
    signer = make_sealer(key)
    signer.seal(__import__("tests.unit.test_signer_sealer", fromlist=["candidate"]).candidate())
    before = state.load_state(LOG_ID)
    heartbeat = signer.heartbeat()
    assert heartbeat.latest_seq == before[0]
    assert heartbeat.latest_entry_hash == before[1]
    assert heartbeat.epoch_id == before[2]
    assert verify_heartbeat(
        heartbeat, key.public_key().public_bytes_raw(), "2026-01-01T00:01:01.000Z"
    )
    assert verify_structure(heartbeat, key.public_key().public_bytes_raw(), "heartbeat")
    assert state.load_state(LOG_ID) == before


def test_expired_epoch_heartbeat_rejected(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    signer = make_sealer(dev_key())
    signer._clock = lambda: "2026-01-01T00:05:00.000Z"
    with pytest.raises(Exception):
        signer.heartbeat()


def test_heartbeat_checkpoint_contradiction_is_detectable() -> None:
    heartbeat = __import__("libs.blackbox_core.schemas", fromlist=["Heartbeat"]).Heartbeat(
        log_id=LOG_ID,
        epoch_id=0,
        latest_seq=2,
        latest_entry_hash="sha256:" + "a" * 64,
        queue_depth=0,
        signer_timestamp=NOW,
    )
    checkpoint = build_checkpoint(
        LOG_ID,
        3,
        "sha256:" + "b" * 64,
        2,
        0,
        NOW,
        latest_entry_hash="sha256:" + "b" * 64,
    )
    assert not heartbeat_matches_checkpoint(heartbeat, checkpoint)

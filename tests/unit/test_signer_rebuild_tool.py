"""Unit and CLI tests for the signer state rebuild tool (Task C, E, R)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.schemas import parse_entry
from libs.blackbox_core.sealing import seal
from services.signer import journal, quarantine, rebuild, state
from tools.rebuild import main as cli_main

LOG_ID = "sha256:" + "d" * 64
KEY = Ed25519PrivateKey.generate()


def create_sample_history(count: int = 3) -> list:
    entries = []
    prev_hash = GENESIS_PREV_HASH

    for seq in range(count):
        raw = {
            "format_version": "4",
            "type": "action",
            "seq": seq,
            "prev_hash": prev_hash,
            "log_id": LOG_ID,
            "epoch_id": 0,
            "signer_timestamp": f"2026-01-01T00:0{seq}:00.000Z",
            "lane": "agent",
            "epoch_certificate_id": "sha256:" + "0" * 64,
            "action_name": "audit",
            "reason": "test",
            "target_reference": f"target-{seq}",
        }
        candidate = parse_entry(raw)
        sealed = seal(candidate, KEY.sign)
        prev_hash = entry_hash(sealed.body)
        entries.append(sealed)

    return entries


def test_signer_status_reporting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))

    # Not initialized
    status = rebuild.get_signer_status(state_file)
    assert not status.healthy
    assert not status.initialized

    # Initialize cleanly
    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})
    status = rebuild.get_signer_status(state_file)
    assert status.healthy
    assert status.last_seq == 0
    assert status.log_id == LOG_ID

    # Add commit marker
    marker = tmp_path / ".state.json.commit"
    marker.write_text("{}", encoding="utf-8")
    status = rebuild.get_signer_status(state_file)
    assert not status.healthy
    assert status.marker_present
    assert status.quarantined


def test_rebuild_from_marker_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    marker = tmp_path / ".state.json.commit"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))

    # Existing state
    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})
    # Crash marker left behind
    marker.write_text('{"unclean": true}', encoding="utf-8")
    quarantine.enter_quarantine(log_id=LOG_ID, reason="marker_detected", path=state_file)

    assert quarantine.is_quarantined(state_file)

    history = create_sample_history(3)
    frontier_seq = history[-1].body.seq
    frontier_hash = entry_hash(history[-1].body)

    anchor = rebuild.rebuild_same_log(
        state_path=state_file,
        expected_log_id=LOG_ID,
        frontier_seq=frontier_seq,
        frontier_hash=frontier_hash,
        history_entries=history,
        operator_id="operator-alice",
        reason="crash_recovery",
    )

    assert anchor.recovery_outcome == "same_log_continuation"
    assert anchor.frontier_seq == frontier_seq
    assert anchor.frontier_hash == frontier_hash
    assert not marker.exists()
    assert not quarantine.is_quarantined(state_file)

    # State can now be loaded cleanly
    last_seq, last_hash, epoch_id = state.load_state(LOG_ID)
    assert last_seq == frontier_seq
    assert last_hash == frontier_hash


def test_rebuild_rejects_broken_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})

    history = create_sample_history(3)
    # Break chain on entry 2
    broken_body = history[2].body.model_copy(update={"prev_hash": "sha256:" + "f" * 64})
    broken_entry = seal(broken_body, KEY.sign)
    history[2] = broken_entry

    with pytest.raises(rebuild.RebuildError, match="prev_hash") as exc:
        rebuild.rebuild_same_log(
            state_path=state_file,
            expected_log_id=LOG_ID,
            frontier_seq=2,
            frontier_hash=entry_hash(history[2].body),
            history_entries=history,
            operator_id="operator-1",
            reason="recovery",
        )
    assert exc.value.code == "chain_break"


def test_burn_uncertain_sequence_range(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    journal_file = tmp_path / "state.json.journal.jsonl"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    monkeypatch.setenv("SIGNER_JOURNAL_PATH", str(journal_file))

    # Signer was at seq 2 in epoch 0
    state.persist_state(2, "sha256:" + "2" * 64, 0, LOG_ID, {})

    # Sequences 3, 4, 5 were uncertain/lost. Burn range [3, 5] under new epoch 1
    new_epoch_key = Ed25519PrivateKey.generate()

    sealed_rec, anchor = rebuild.burn_discontinuity(
        state_path=state_file,
        expected_log_id=LOG_ID,
        burned_first_seq=3,
        burned_last_seq=5,
        last_known_hash="sha256:" + "2" * 64,
        lost_epoch_id=0,
        new_epoch_id=1,
        signing_operation=new_epoch_key.sign,
        operator_id="operator-bob",
        reason="burned_lost_responses",
    )

    rec_body = sealed_rec.body
    assert rec_body.type == "recovery"
    assert rec_body.seq == 6  # burned_last_seq + 1
    assert rec_body.burned_first_seq == 3
    assert rec_body.burned_last_seq == 5
    assert rec_body.prev_hash == "sha256:" + "2" * 64
    assert rec_body.epoch_id == 1

    # Check updated durable state
    last_seq, last_hash, epoch_id = state.load_state(LOG_ID)
    assert last_seq == 6
    assert epoch_id == 1
    assert last_hash == entry_hash(rec_body)

    # Check journal has the recovery entry
    journal_records = journal.read_journal(path=journal_file, expected_log_id=LOG_ID)
    assert len(journal_records) == 1
    assert journal_records[0].seq == 6
    assert journal_records[0].entry_type == "recovery"


def test_cli_status_and_quarantine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})

    # CLI status (healthy)
    with pytest.raises(SystemExit) as exc:
        cli_main(["status", "--state-path", str(state_file)])
    assert exc.value.code == 0

    # CLI quarantine
    cli_main(
        [
            "quarantine",
            "--state-path",
            str(state_file),
            "--log-id",
            LOG_ID,
            "--reason",
            "audit_hold",
            "--details",
            "operator hold",
        ]
    )

    assert quarantine.is_quarantined(state_file)

    # CLI status (now unhealthy/quarantined -> exit 1)
    with pytest.raises(SystemExit) as exc:
        cli_main(["status", "--state-path", str(state_file)])
    assert exc.value.code == 1


def test_cli_rebuild_and_burn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})

    # 1. Test CLI rebuild
    history = create_sample_history(3)
    history_file = tmp_path / "history.json"
    history_file.write_text(json.dumps([e.model_dump() for e in history]), encoding="utf-8")

    cli_main(
        [
            "rebuild",
            "--state-path",
            str(state_file),
            "--log-id",
            LOG_ID,
            "--frontier-seq",
            "2",
            "--frontier-hash",
            entry_hash(history[-1].body),
            "--history-file",
            str(history_file),
            "--operator-id",
            "op-1",
            "--reason",
            "cli_test",
        ]
    )

    last_seq, _, _ = state.load_state(LOG_ID)
    assert last_seq == 2

    # 2. Test CLI burn
    key = Ed25519PrivateKey.generate()
    key_file = tmp_path / "epoch1.pem"
    key_file.write_bytes(
        key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )

    cli_main(
        [
            "burn",
            "--state-path",
            str(state_file),
            "--log-id",
            LOG_ID,
            "--burned-first-seq",
            "3",
            "--burned-last-seq",
            "4",
            "--last-known-hash",
            entry_hash(history[-1].body),
            "--lost-epoch-id",
            "0",
            "--new-epoch-id",
            "1",
            "--key-file",
            str(key_file),
            "--operator-id",
            "op-1",
            "--reason",
            "burned_test",
        ]
    )

    last_seq, _, epoch_id = state.load_state(LOG_ID)
    assert last_seq == 5  # 4 + 1
    assert epoch_id == 1

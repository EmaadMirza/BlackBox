"""Unit tests for the signer issuance journal (Task E2b)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.schemas import parse_entry
from services.signer import journal, state
from services.signer.sealer import SignerSealer

LOG_ID = "sha256:" + "a" * 64
KEY = Ed25519PrivateKey.generate()


def test_append_and_read_journal_records(tmp_path: Path) -> None:
    journal_path = tmp_path / "test.journal.jsonl"

    rec1 = journal.IssuanceRecord(
        log_id=LOG_ID,
        seq=0,
        entry_hash="sha256:" + "1" * 64,
        epoch_id=0,
        entry_type="epoch_start",
        issued_at="2026-01-01T00:00:00.000Z",
    )
    rec2 = journal.IssuanceRecord(
        log_id=LOG_ID,
        seq=1,
        entry_hash="sha256:" + "2" * 64,
        epoch_id=0,
        entry_type="intent",
        issued_at="2026-01-01T00:00:01.000Z",
        idempotency_key="sha256:" + "f" * 64,
    )
    rec3 = journal.IssuanceRecord(
        log_id=LOG_ID,
        seq=2,
        entry_hash="sha256:" + "3" * 64,
        epoch_id=0,
        entry_type="outcome",
        issued_at="2026-01-01T00:00:02.000Z",
        intent_seq=1,
        idempotency_key="sha256:" + "f" * 64,
    )

    journal.append_issuance(rec1, path=journal_path)
    journal.append_issuance(rec2, path=journal_path)
    journal.append_issuance(rec3, path=journal_path)

    records = journal.read_journal(path=journal_path, expected_log_id=LOG_ID)
    assert len(records) == 3
    assert records[0] == rec1
    assert records[1] == rec2
    assert records[2] == rec3

    frontier = journal.get_journal_frontier(path=journal_path, log_id=LOG_ID)
    assert frontier == (2, "sha256:" + "3" * 64)


def test_find_by_seq_and_idempotency(tmp_path: Path) -> None:
    journal_path = tmp_path / "test.journal.jsonl"
    rec = journal.IssuanceRecord(
        log_id=LOG_ID,
        seq=5,
        entry_hash="sha256:" + "5" * 64,
        epoch_id=0,
        entry_type="intent",
        issued_at="2026-01-01T00:00:05.000Z",
        idempotency_key="sha256:" + "e" * 64,
    )
    journal.append_issuance(rec, path=journal_path)

    found_seq = journal.find_issued_by_seq(5, path=journal_path, log_id=LOG_ID)
    assert found_seq == rec
    assert journal.find_issued_by_seq(99, path=journal_path, log_id=LOG_ID) is None

    found_idem = journal.find_issued_by_idempotency(
        "sha256:" + "e" * 64, path=journal_path, log_id=LOG_ID
    )
    assert found_idem == rec
    assert (
        journal.find_issued_by_idempotency("sha256:" + "0" * 64, path=journal_path, log_id=LOG_ID)
        is None
    )


def test_corrupt_journal_line_fails_closed(tmp_path: Path) -> None:
    journal_path = tmp_path / "test.journal.jsonl"
    journal_path.write_text('{"log_id": "not json valid\n', encoding="utf-8")

    with pytest.raises(journal.JournalIntegrityError, match="Corrupt JSON"):
        journal.read_journal(path=journal_path)


def test_non_monotonic_sequence_fails_closed(tmp_path: Path) -> None:
    journal_path = tmp_path / "test.journal.jsonl"
    rec1 = journal.IssuanceRecord(
        log_id=LOG_ID,
        seq=5,
        entry_hash="sha256:" + "1" * 64,
        epoch_id=0,
        entry_type="intent",
        issued_at="2026-01-01T00:00:00.000Z",
    )
    rec2 = journal.IssuanceRecord(
        log_id=LOG_ID,
        seq=3,  # regression
        entry_hash="sha256:" + "2" * 64,
        epoch_id=0,
        entry_type="intent",
        issued_at="2026-01-01T00:00:01.000Z",
    )
    # Write manually to simulate corrupted journal
    with open(journal_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(rec1.to_dict()) + "\n")
        f.write(json.dumps(rec2.to_dict()) + "\n")

    with pytest.raises(journal.JournalIntegrityError, match="Non-monotonic sequence"):
        journal.read_journal(path=journal_path)


def test_sealer_automatically_journals_sealed_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_file = tmp_path / "state.json"
    journal_file = tmp_path / "state.json.journal.jsonl"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    monkeypatch.setenv("SIGNER_JOURNAL_PATH", str(journal_file))

    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})

    sealer = SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id="sha256:" + "2" * 64,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2027-01-01T00:00:00.000Z",
        clock=lambda: "2026-01-01T00:01:00.000Z",
        signing_operation=KEY.sign,
    )

    from tests.unit.test_signer_seal_http import candidate as make_candidate

    cand_dict = make_candidate(seq=1, prev_hash="sha256:" + "0" * 64, log_id=LOG_ID)
    cand = parse_entry(cand_dict)

    sealed = sealer.seal(cand)

    # Check that journal file was written
    assert journal_file.exists()
    records = journal.read_journal(path=journal_file, expected_log_id=LOG_ID)
    assert len(records) == 1
    assert records[0].seq == 1
    assert records[0].entry_hash == entry_hash(sealed.body)

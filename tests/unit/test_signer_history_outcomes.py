"""Hybrid signer history verification and durable outcome-index tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.epochs import certificate_id
from libs.blackbox_core.sealing import seal
from services.signer import state
from services.signer.history import (
    HistoryEntryEvidence,
    HistoryIntegrityError,
    HistoryRecord,
    verify_history_record,
)
from services.signer.sealer import SignerSealer
from tests.unit.test_epochs_rules import certificates, request_pair

LOG_ID = "sha256:" + "1" * 64
NOW = "2026-01-01T00:01:00.000Z"
VALID_FROM = "2026-01-01T00:00:00.000Z"
VALID_UNTIL = "2026-01-01T00:05:00.000Z"
CERTIFICATE_ID = "sha256:" + "2" * 64


@dataclass
class FakeHistorySource:
    log_id: str
    intent_record: HistoryRecord
    outcome_record: HistoryRecord | None = None

    def get_intent(self, log_id: str, intent_seq: int) -> HistoryRecord:
        assert log_id == self.log_id
        assert intent_seq == 0
        return self.intent_record

    def get_outcome(self, log_id: str, intent_seq: int, outcome_hash: str) -> HistoryRecord:
        assert log_id == self.log_id
        assert intent_seq == 0
        if self.outcome_record is None:
            raise RuntimeError("outcome not available")
        assert entry_hash(self.outcome_record.entries[-1].entry.body) == outcome_hash
        return self.outcome_record


@pytest.fixture
def history_fixture() -> tuple:
    root, _intermediate_key, epoch_key, intermediate, epoch = certificates()
    _, intent, outcome = request_pair()
    sealed_intent = seal(intent, epoch_key)
    outcome = outcome.model_copy(update={"seq": 1, "prev_hash": entry_hash(sealed_intent.body)})
    sealed_outcome = seal(outcome, epoch_key)
    root_public_key = root.public_key().public_bytes_raw()

    def evidence(entry):
        return HistoryEntryEvidence(
            entry=entry,
            epoch_certificate=epoch,
            intermediate_certificate=intermediate,
            root_public_key=root_public_key,
        )

    intent_record = HistoryRecord(entries=(evidence(sealed_intent),), target_seq=0)
    outcome_record = HistoryRecord(
        entries=(evidence(sealed_intent), evidence(sealed_outcome)), target_seq=1
    )
    return (
        root,
        epoch_key,
        epoch,
        sealed_intent,
        sealed_outcome,
        intent_record,
        outcome_record,
        sealed_intent.body.log_id,
    )


def configure_state(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))


def make_sealer(
    key,
    source,
    *,
    log_id: str = LOG_ID,
    epoch_certificate_id: str = CERTIFICATE_ID,
    now: str = NOW,
    rate_cap: int = 1000,
) -> SignerSealer:
    return SignerSealer(
        log_id=log_id,
        epoch_id=0,
        epoch_certificate_id=epoch_certificate_id,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        clock=lambda: now,
        signing_operation=key,
        rate_cap=rate_cap,
        history_source=source,
    )


def test_complete_prefix_history_verifies(history_fixture: tuple) -> None:
    _, _, _, _, _, intent_record, _, log_id = history_fixture

    verified = verify_history_record(intent_record, log_id, target_seq=0)

    assert verified.body.type == "intent"
    assert verified.body.log_id == log_id


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: record.entries[0].entry.model_copy(update={"signature": ""}),
        lambda record: record.__class__(
            entries=(
                record.entries[0].__class__(
                    entry=record.entries[0].entry.model_copy(
                        update={"body": record.entries[0].entry.body.model_copy(update={"seq": 1})}
                    ),
                    epoch_certificate=record.entries[0].epoch_certificate,
                    intermediate_certificate=record.entries[0].intermediate_certificate,
                    root_public_key=record.entries[0].root_public_key,
                ),
            ),
            target_seq=0,
        ),
    ],
)
def test_tampered_or_broken_history_fails_closed(history_fixture: tuple, mutate) -> None:
    _, _, _, _, _, intent_record, _, log_id = history_fixture

    with pytest.raises(HistoryIntegrityError):
        verify_history_record(mutate(intent_record), log_id, target_seq=0)


def test_missing_history_source_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, history_fixture: tuple
) -> None:
    _, epoch_key, epoch, sealed_intent, _, _, _, log_id = history_fixture
    configure_state(monkeypatch, tmp_path / "state.json")
    state.persist_state(0, entry_hash(sealed_intent.body), 0, log_id)
    _, _, outcome = request_pair()
    outcome = outcome.model_copy(update={"seq": 1, "prev_hash": entry_hash(sealed_intent.body)})

    operation = make_sealer(
        epoch_key, None, log_id=log_id, epoch_certificate_id=certificate_id(epoch)
    )
    with pytest.raises(Exception, match="history"):
        operation.seal(outcome)


def test_outcome_is_verified_from_history_and_index_is_persisted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, history_fixture: tuple
) -> None:
    (
        _,
        epoch_key,
        epoch,
        sealed_intent,
        sealed_outcome,
        intent_record,
        outcome_record,
        log_id,
    ) = history_fixture
    configure_state(monkeypatch, tmp_path / "state.json")
    state.persist_state(0, entry_hash(sealed_intent.body), 0, log_id)
    source = FakeHistorySource(log_id, intent_record, outcome_record)
    outcome = outcome_record.entries[-1].entry.body

    sealed = make_sealer(
        epoch_key,
        source,
        log_id=log_id,
        epoch_certificate_id=certificate_id(epoch),
        now=outcome.signer_timestamp,
    ).seal(outcome)

    assert sealed.body.type == "outcome"
    assert state.load_outcome_index(log_id) == {0: entry_hash(sealed.body)}
    assert (tmp_path / "state.json.outcomes.json").exists()


def test_duplicate_outcome_is_rejected_from_own_index(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, history_fixture: tuple
) -> None:
    (
        _,
        epoch_key,
        epoch,
        sealed_intent,
        sealed_outcome,
        intent_record,
        outcome_record,
        log_id,
    ) = history_fixture
    configure_state(monkeypatch, tmp_path / "state.json")
    state.persist_state(
        1, entry_hash(sealed_outcome.body), 0, log_id, {0: entry_hash(sealed_outcome.body)}
    )
    source = FakeHistorySource(log_id, intent_record, outcome_record)
    candidate = outcome_record.entries[-1].entry.body.model_copy(
        update={"seq": 2, "prev_hash": entry_hash(sealed_outcome.body), "retry": False}
    )

    with pytest.raises(Exception, match="outcome"):
        make_sealer(
            epoch_key, source, log_id=log_id, epoch_certificate_id=certificate_id(epoch)
        ).seal(candidate)


def test_same_key_retry_verifies_prior_outcome_and_updates_index(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, history_fixture: tuple
) -> None:
    (
        _,
        epoch_key,
        epoch,
        sealed_intent,
        sealed_outcome,
        intent_record,
        outcome_record,
        log_id,
    ) = history_fixture
    prior_hash = entry_hash(sealed_outcome.body)
    configure_state(monkeypatch, tmp_path / "state.json")
    state.persist_state(1, prior_hash, 0, log_id, {0: prior_hash})
    source = FakeHistorySource(log_id, intent_record, outcome_record)
    candidate = outcome_record.entries[-1].entry.body.model_copy(
        update={"seq": 2, "prev_hash": prior_hash, "retry": True}
    )

    sealed = make_sealer(
        epoch_key,
        source,
        log_id=log_id,
        epoch_certificate_id=certificate_id(epoch),
        now=candidate.signer_timestamp,
    ).seal(candidate)

    assert sealed.body.seq == 2
    assert state.load_outcome_index(log_id) == {0: entry_hash(sealed.body)}


def test_history_disagreement_is_alarm_grade_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, history_fixture: tuple
) -> None:
    _, epoch_key, epoch, sealed_intent, _, intent_record, _, log_id = history_fixture
    configure_state(monkeypatch, tmp_path / "state.json")
    state.persist_state(0, entry_hash(sealed_intent.body), 0, log_id)
    _, _, bad_outcome = request_pair()
    bad_outcome = bad_outcome.model_copy(
        update={
            "seq": 1,
            "prev_hash": entry_hash(sealed_intent.body),
            "action": bad_outcome.action.model_copy(
                update={"idempotency_key": "sha256:" + "f" * 64}
            ),
        }
    )
    source = FakeHistorySource(log_id, intent_record, None)

    operation = make_sealer(
        epoch_key, source, log_id=log_id, epoch_certificate_id=certificate_id(epoch)
    )
    with pytest.raises(HistoryIntegrityError, match="idempotency"):
        operation.seal(bad_outcome)
    assert operation.health_reason == "HISTORY_INTEGRITY"


def test_missing_or_corrupt_outcome_index_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, history_fixture: tuple
) -> None:
    _, epoch_key, _, sealed_intent, _, _, _, log_id = history_fixture
    configure_state(monkeypatch, tmp_path / "state.json")
    state.persist_state(0, entry_hash(sealed_intent.body), 0, log_id)
    index_path = tmp_path / "state.json.outcomes.json"
    index_path.unlink()

    with pytest.raises(Exception, match="outcome index"):
        state.load_outcome_index(log_id)

    index_path.write_text(
        json.dumps({"format_version": "0", "log_id": log_id, "outcomes": {}}),
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="outcome index"):
        state.load_outcome_index(log_id)


def test_compaction_is_lossless_and_deterministic() -> None:
    values = {9: "sha256:" + "9" * 64, 1: "sha256:" + "1" * 64}

    compacted = state.compact_outcome_index(values)

    assert list(compacted) == [1, 9]
    assert compacted == values

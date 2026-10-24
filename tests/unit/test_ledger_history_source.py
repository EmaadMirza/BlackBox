"""Ledger-backed HistorySource transport and fail-closed behavior."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from libs.blackbox_core.chain import entry_hash
from services.signer.history import (
    HistoryIntegrityError,
    HistoryRecord,
    HistorySourceError,
    LedgerHistorySource,
)
from tests.unit.test_signer_history_outcomes import history_fixture as _history_fixture


@pytest.fixture
def history_fixture() -> tuple:
    return _history_fixture.__wrapped__()


@dataclass
class FakeTransport:
    intent: object
    outcome: object | None = None

    def get_intent(self, log_id: str, intent_seq: int) -> object:
        return self.intent

    def get_outcome(self, log_id: str, intent_seq: int, outcome_hash: str) -> object:
        if self.outcome is None:
            raise HistorySourceError("ledger unavailable")
        return self.outcome


def test_ledger_history_source_verifies_records_before_returning(history_fixture: tuple) -> None:
    _, _, _, _, _, intent_record, outcome_record, log_id = history_fixture
    source = LedgerHistorySource(FakeTransport(intent_record, outcome_record))

    assert source.get_intent(log_id, 0) == intent_record
    assert (
        source.get_outcome(log_id, 0, entry_hash(outcome_record.entries[-1].entry.body))
        == outcome_record
    )


@pytest.mark.parametrize(
    "response",
    [None, {"target_seq": 0, "entries": []}, {"target_seq": 1, "entries": [{"bad": 1}]}],
)
def test_unavailable_malformed_and_truncated_ledger_answers_fail_closed(
    history_fixture: tuple, response: object
) -> None:
    _, _, _, _, _, _, _, log_id = history_fixture
    source = LedgerHistorySource(FakeTransport(response))

    with pytest.raises((HistorySourceError, HistoryIntegrityError)):
        source.get_intent(log_id, 0)


def test_ledger_outcome_must_match_requested_hash(history_fixture: tuple) -> None:
    _, _, _, _, _, intent_record, outcome_record, log_id = history_fixture
    source = LedgerHistorySource(FakeTransport(intent_record, outcome_record))

    with pytest.raises(HistoryIntegrityError):
        source.get_outcome(log_id, 0, "sha256:" + "f" * 64)


def test_ledger_source_requires_complete_history_record(history_fixture: tuple) -> None:
    _, _, _, _, _, intent_record, _, log_id = history_fixture
    incomplete = HistoryRecord(entries=intent_record.entries, target_seq=1)
    source = LedgerHistorySource(FakeTransport(incomplete))

    with pytest.raises(HistoryIntegrityError):
        source.get_intent(log_id, 0)

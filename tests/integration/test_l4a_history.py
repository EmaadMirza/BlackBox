"""L4a real-Postgres ledger-backed signer history integration tests."""

from __future__ import annotations

import pytest

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.epochs import certificate_id
from services.signer import delivery, state
from services.signer.history import (
    HistoryIntegrityError,
    HistorySourceError,
    InProcessLedgerHistoryTransport,
    LedgerHistorySource,
)
from services.signer.sealer import SignerSealer
from tests.integration.support import execute
from tests.integration.test_l2_delivery_e2e import InProcessPostgresTransport, _drain, _setup
from tests.unit.test_epochs_rules import request_pair

pytestmark = pytest.mark.integration

AUTH = {"Authorization": "Bearer ledger-token"}


def _make_intent(log_id: str, epoch_certificate_id: str, previous_hash: str):
    _, intent, outcome = request_pair()
    intent = intent.model_copy(
        update={
            "log_id": log_id,
            "epoch_id": 0,
            "seq": 1,
            "prev_hash": previous_hash,
            "epoch_certificate_id": epoch_certificate_id,
            "signer_timestamp": "2026-01-01T00:01:00.000Z",
        }
    )
    outcome = outcome.model_copy(
        update={
            "log_id": log_id,
            "epoch_id": 0,
            "seq": 2,
            "prev_hash": "",
            "epoch_certificate_id": epoch_certificate_id,
            "signer_timestamp": "2026-01-01T00:01:00.000Z",
            "intent_seq": 1,
            "action": intent.action,
        }
    )
    return intent, outcome


def test_ledger_history_source_reads_verified_prefix_and_fails_closed(
    monkeypatch, tmp_path
) -> None:
    material, start, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, _, epoch_cert, _, _ = material
    epoch_id = certificate_id(epoch_cert)
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    intent, _ = _make_intent(log_id, epoch_id, entry_hash(start.body))
    sealed_intent = signer.seal(intent)
    worker = delivery.DeliveryWorker(
        signer,
        InProcessPostgresTransport(ledger_client),
        bearer_token="ledger-token",
    )
    assert worker.run_once() is True

    source = LedgerHistorySource(
        InProcessLedgerHistoryTransport(ledger_client, bearer_token="ledger-token")
    )
    record = source.get_intent(log_id, 1)
    assert record.target_seq == 1
    assert record.entries[-1].entry == sealed_intent

    with pytest.raises((HistoryIntegrityError, HistorySourceError)):
        source.get_intent(log_id, 2)

    ledger_client.close()


def test_outcome_after_compacted_index_is_accepted_once_then_duplicate_rejected(
    monkeypatch, tmp_path
) -> None:
    material, start, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, epoch, log_id, _, epoch_cert, _, _ = material
    epoch_id = certificate_id(epoch_cert)
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    intent, outcome = _make_intent(log_id, epoch_id, entry_hash(start.body))
    sealed_intent = signer.seal(intent)
    worker = delivery.DeliveryWorker(
        signer,
        InProcessPostgresTransport(ledger_client),
        bearer_token="ledger-token",
    )
    assert worker.run_once() is True

    # Simulate a lossless compaction whose signer-owned outcome index has no
    # prior outcome yet; the ledger remains the positive-evidence source.
    source = LedgerHistorySource(
        InProcessLedgerHistoryTransport(ledger_client, bearer_token="ledger-token")
    )
    assert state.load_outcome_index(log_id) == {}
    restarted = SignerSealer(
        log_id=log_id,
        epoch_id=0,
        epoch_certificate_id=epoch_id,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2026-01-01T00:05:00.000Z",
        clock=lambda: "2026-01-01T00:01:00.000Z",
        signing_operation=epoch,
        history_source=source,
    )
    candidate = outcome.model_copy(update={"prev_hash": entry_hash(sealed_intent.body)})
    sealed_outcome = restarted.seal(candidate)
    assert sealed_outcome.body.type == "outcome"
    assert state.load_outcome_index(log_id) == {1: entry_hash(sealed_outcome.body)}

    assert worker.run_once() is True
    assert execute("SELECT count(*) FROM blackbox.entries WHERE log_id=%s", (log_id,))[0][0] == 3

    duplicate = candidate.model_copy(
        update={
            "seq": 3,
            "prev_hash": entry_hash(sealed_outcome.body),
            "retry": False,
        }
    )
    with pytest.raises(Exception, match="outcome"):
        restarted.seal(duplicate)
    assert restarted.health_reason == "HISTORY_INTEGRITY" or restarted.health_reason is None
    ledger_client.close()

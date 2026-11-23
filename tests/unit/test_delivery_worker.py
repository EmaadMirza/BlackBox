"""L2b-1 cooperative signer outbox delivery tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.schemas import SealedEntry, parse_entry
from libs.blackbox_core.sealing import seal
from services.signer import delivery, state
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action

LOG_ID = "sha256:" + "1" * 64
CERTIFICATE_ID = "sha256:" + "2" * 64
NOW = "2026-01-01T00:01:00.000Z"


def signed(seq: int, previous: str) -> SealedEntry:
    body = action()
    body.update(
        log_id=LOG_ID,
        seq=seq,
        prev_hash=previous,
        epoch_certificate_id=CERTIFICATE_ID,
        signer_timestamp=NOW,
    )
    return seal(parse_entry(body), dev_key())


def configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))


def seed_signer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SignerSealer:
    configure(monkeypatch, tmp_path)
    return SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2026-01-01T00:05:00.000Z",
        clock=lambda: NOW,
        signing_operation=dev_key(),
    )


@dataclass
class FakeLedger:
    responses: list[object]
    calls: list[tuple[SealedEntry, str]] = field(default_factory=list)

    def append(self, entry: SealedEntry, bearer_token: str) -> object:
        self.calls.append((entry, bearer_token))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def response(entry: SealedEntry, *, status_code: int = 200, code: str | None = None):
    return delivery.LedgerResponse(status_code, entry_hash(entry.body), code)


def test_delivers_first_entry_and_acknowledges_exact_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    first = signer.seal(
        {
            **action(),
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    ledger = FakeLedger([response(first)])
    worker = delivery.DeliveryWorker(signer, ledger, bearer_token="secret", clock=lambda: 0.0)

    assert worker.tick_once() is True
    assert ledger.calls == [(first, "secret")]
    assert signer.pending_outbox() == ()


def test_only_first_pending_entry_is_in_flight_and_ordered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    first = signer.seal(
        action()
        | {
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    second = signed(1, entry_hash(first.body))
    state.persist_state(1, entry_hash(second.body), 0, LOG_ID, outbox_append=(second,))
    ledger = FakeLedger([response(first), response(second)])
    worker = delivery.DeliveryWorker(signer, ledger, bearer_token="secret", clock=lambda: 0.0)

    assert worker.run_once() is True
    assert [entry.body.seq for entry, _ in ledger.calls] == [0]
    assert worker.run_once() is True
    assert [entry.body.seq for entry, _ in ledger.calls] == [0, 1]


def test_bad_ack_never_advances_signer() -> None:
    class FakeSigner:
        def __init__(self, entry: SealedEntry) -> None:
            self.entry = entry
            self.ack_calls = []

        def pending_outbox(self, limit=None):
            return (self.entry,)

        def acknowledge_outbox(self, seq, entry_hash_value):
            self.ack_calls.append((seq, entry_hash_value))

    entry = signed(0, GENESIS_PREV_HASH)
    ledger = FakeLedger([delivery.LedgerResponse(200, "sha256:" + "f" * 64)])
    signer = FakeSigner(entry)
    worker = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)

    assert worker.run_once() is False
    assert signer.ack_calls == []
    assert worker.alarm_code == delivery.BAD_ACK


def test_unreachable_retries_with_bounded_backoff_and_keeps_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    entry = signer.seal(
        action()
        | {
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    now = [0.0]
    ledger = FakeLedger([TimeoutError("offline"), response(entry)])
    worker = delivery.DeliveryWorker(
        signer,
        ledger,
        bearer_token="token",
        clock=lambda: now[0],
        random_seed=7,
        base_delay=1.0,
        max_delay=2.0,
    )

    assert worker.run_once() is False
    assert signer.pending_outbox() == (entry,)
    assert worker.next_attempt_at > 0
    assert worker.next_attempt_at <= 2.0
    assert worker.run_once() is False
    now[0] = worker.next_attempt_at
    assert worker.run_once() is True
    assert signer.pending_outbox() == ()


def test_lost_response_is_replayed_and_idempotently_acked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    entry = signer.seal(
        action()
        | {
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    now = [0.0]
    ledger = FakeLedger([TimeoutError("response lost"), response(entry)])
    worker = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: now[0])

    assert worker.run_once() is False
    now[0] = worker.next_attempt_at
    assert worker.run_once() is True
    assert [call[0].body.seq for call in ledger.calls] == [0, 0]


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (409, "equivocation", delivery.LEDGER_EQUIVOCATION),
        (409, "out_of_order", delivery.LEDGER_OUT_OF_ORDER),
        (418, "teapot", delivery.LEDGER_REJECTED),
        (503, "temporary", None),
    ],
)
def test_ledger_rejection_stops_worker_and_requires_reset(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: int,
    code: str,
    expected: str | None,
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    entry = signer.seal(
        action()
        | {
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    ledger = FakeLedger([delivery.LedgerResponse(status, None, code), response(entry)])
    worker = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)

    assert worker.run_once() is False
    if expected is None:
        assert worker.alarm_code is None
        assert worker.next_attempt_at > 0
        return
    assert worker.alarm_code == expected
    assert signer.health_reason == expected
    assert worker.run_once() is False
    assert len(ledger.calls) == 1
    assert signer.pending_outbox() == (entry,)
    worker.reset_alarm()
    assert worker.alarm_code is None
    assert signer.health_reason is None
    assert worker.run_once() is True


def test_new_worker_honors_existing_signer_alarm_until_reset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    entry = signer.seal(
        action()
        | {
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    ledger = FakeLedger([delivery.LedgerResponse(409, None, "equivocation"), response(entry)])
    first = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)
    assert first.run_once() is False

    second = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)
    assert second.alarm_code == delivery.LEDGER_EQUIVOCATION
    assert second.run_once() is False
    second.reset_alarm()
    assert second.run_once() is True


def test_two_workers_share_single_flight_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    entry = signer.seal(
        action()
        | {
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    ledger = FakeLedger([response(entry)])
    first = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)
    second = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)
    lock = delivery.DeliveryWorker.signer_lock(signer)
    assert lock.acquire(blocking=False)
    try:
        assert second.run_once() is False
        assert ledger.calls == []
    finally:
        lock.release()
    assert first.run_once() is True


def test_ack_failure_after_ledger_success_leaves_entry_for_next_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    entry = signer.seal(
        action()
        | {
            "log_id": LOG_ID,
            "epoch_id": 0,
            "epoch_certificate_id": CERTIFICATE_ID,
            "signer_timestamp": NOW,
        }
    )
    ledger = FakeLedger([response(entry), response(entry)])
    original_ack = signer.acknowledge_outbox
    failures = [RuntimeError("crash before ack")]

    def fail_once(seq, hash_value):
        if failures:
            raise failures.pop()
        return original_ack(seq, hash_value)

    monkeypatch.setattr(signer, "acknowledge_outbox", fail_once)
    first = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)
    with pytest.raises(RuntimeError, match="crash before ack"):
        first.run_once()
    second = delivery.DeliveryWorker(signer, ledger, bearer_token="token", clock=lambda: 0.0)
    assert second.run_once() is True
    assert signer.pending_outbox() == ()


def test_token_is_required_and_not_exposed_in_worker_state_or_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = seed_signer(monkeypatch, tmp_path)
    ledger = FakeLedger([])
    monkeypatch.setenv("LEDGER_AUTH_TOKEN", "from-config")
    worker = delivery.DeliveryWorker(signer, ledger, clock=lambda: 0.0)
    assert worker.token_configured is True
    assert "from-config" not in repr(worker)

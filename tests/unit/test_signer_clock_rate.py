"""Live signer time and durable quota integration at the signing boundary."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.crypto import SigningOperation
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.sealing import verify_entry
from services.signer import clock, rate_limit, sealer, state
from tests._dev_keys import dev_key
from tests.unit.test_signer_sealer import (
    CERTIFICATE_ID,
    LOG_ID,
    NOW,
    VALID_FROM,
    VALID_UNTIL,
    candidate,
)

NEXT_SECOND = "2026-01-01T00:01:01.000Z"
LATER_MILLISECOND = "2026-01-01T00:01:00.999Z"


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))


def make_sealer(
    signing_operation: SigningOperation,
    *,
    live_clock: Callable[[], str] | None = lambda: NOW,
    rate_cap: int = 1,
) -> sealer.SignerSealer:
    kwargs = {} if live_clock is None else {"clock": live_clock}
    return sealer.SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        signing_operation=signing_operation,
        rate_cap=rate_cap,
        **kwargs,
    )


@pytest.mark.parametrize("candidate_time", [NOW, VALID_UNTIL])
def test_epoch_expires_after_construction_even_with_old_candidate_time(
    candidate_time: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    current = NOW
    calls = []
    key = dev_key()

    def live_clock() -> str:
        calls.append(current)
        return current

    signed = []

    def sign(message: bytes) -> bytes:
        signed.append(message)
        return key.sign(message)

    operation = make_sealer(sign, live_clock=live_clock)
    assert calls == []
    current = VALID_UNTIL
    persisted = []
    monkeypatch.setattr(state, "persist_state", lambda *args: persisted.append(args))

    with pytest.raises(SignerRuleError, match="expired epoch"):
        operation.seal(candidate(signer_timestamp=candidate_time))

    assert calls == [VALID_UNTIL]
    assert signed == persisted == []
    assert not (tmp_path / "state.json.rate.sqlite3").exists()


def test_cap_resets_in_next_second_and_same_time_is_used_for_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    times = iter([NOW, NEXT_SECOND])
    sampled = []
    reserved = []
    original_reserve = rate_limit.DurableRateLimiter.reserve

    def live_clock() -> str:
        now = next(times)
        sampled.append(now)
        return now

    def reserve(self, now: str, rate_cap: int) -> None:
        reserved.append((now, rate_cap))
        original_reserve(self, now, rate_cap)

    monkeypatch.setattr(rate_limit.DurableRateLimiter, "reserve", reserve)
    key = dev_key()
    operation = make_sealer(key, live_clock=live_clock)
    first = operation.seal(candidate())
    second = operation.seal(
        candidate(seq=1, prev_hash=entry_hash(first.body), signer_timestamp=NEXT_SECOND)
    )

    assert sampled == [NOW, NEXT_SECOND]
    assert reserved == [(NOW, 1), (NEXT_SECOND, 1)]
    assert verify_entry(second, key.public_key().public_bytes_raw())
    assert state.load_state(LOG_ID) == (1, entry_hash(second.body), 0)


def test_milliseconds_within_one_second_share_quota() -> None:
    current = NOW
    key = dev_key()
    operation = make_sealer(key, live_clock=lambda: current)
    first = operation.seal(candidate())
    previous = state.load_state()
    current = LATER_MILLISECOND

    with pytest.raises(SignerRuleError, match="rate cap"):
        operation.seal(candidate(seq=1, prev_hash=entry_hash(first.body), signer_timestamp=current))

    assert state.load_state() == previous


def test_recreating_sealer_does_not_reset_quota(tmp_path: Path) -> None:
    key = dev_key()
    first = make_sealer(key).seal(candidate())
    previous = state.load_state()

    with pytest.raises(SignerRuleError, match="rate cap"):
        make_sealer(key).seal(candidate(seq=1, prev_hash=entry_hash(first.body)))

    assert state.load_state() == previous
    assert (tmp_path / "state.json.rate.sqlite3").is_file()


@pytest.mark.parametrize(
    "bad_time",
    [None, 42, "", "2026-01-01T00:01:00Z", "2026-02-30T00:01:00.000Z"],
)
def test_invalid_clock_never_signs_persists_or_reserves(
    bad_time: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signed = []
    persisted = []
    key = dev_key()

    def sign(message: bytes) -> bytes:
        signed.append(message)
        return key.sign(message)

    monkeypatch.setattr(state, "persist_state", lambda *args: persisted.append(args))
    operation = make_sealer(sign, live_clock=lambda: bad_time)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        operation.seal(candidate())

    assert signed == persisted == []
    assert not (tmp_path / "state.json.rate.sqlite3").exists()
    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)


def test_failing_clock_never_signs_persists_or_reserves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signed = []
    persisted = []
    key = dev_key()

    def sign(message: bytes) -> bytes:
        signed.append(message)
        return key.sign(message)

    def failed_clock() -> str:
        raise RuntimeError("clock unavailable")

    operation = make_sealer(sign, live_clock=failed_clock)
    monkeypatch.setattr(state, "persist_state", lambda *args: persisted.append(args))
    with pytest.raises(RuntimeError, match="clock unavailable"):
        operation.seal(candidate())

    assert signed == persisted == []
    assert not (tmp_path / "state.json.rate.sqlite3").exists()


def test_signing_failure_retains_quota_across_recreation() -> None:
    key = dev_key()
    signatures = []

    def failed_sign(message: bytes) -> bytes:
        signatures.append(key.sign(message))
        raise RuntimeError("signing failed after signature")

    with pytest.raises(RuntimeError, match="signing failed"):
        make_sealer(failed_sign).seal(candidate())
    with pytest.raises(SignerRuleError, match="rate cap"):
        make_sealer(key).seal(candidate())

    assert len(signatures) == 1
    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)


def test_persistence_failure_retains_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = dev_key()

    def fail_persist(*_args) -> None:
        raise OSError("persistence failed")

    original_persist = state.persist_state
    monkeypatch.setattr(state, "persist_state", fail_persist)
    with pytest.raises(OSError, match="persistence failed"):
        make_sealer(key).seal(candidate())
    monkeypatch.setattr(state, "persist_state", original_persist)
    with pytest.raises(SignerRuleError, match="rate cap"):
        make_sealer(key).seal(candidate())

    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)


def test_rate_store_failure_never_calls_signing_or_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed = []
    persisted = []
    key = dev_key()

    def sign(message: bytes) -> bytes:
        signed.append(message)
        return key.sign(message)

    def failed_reserve(self, now: str, rate_cap: int) -> None:
        raise OSError("rate store unavailable")

    monkeypatch.setattr(rate_limit.DurableRateLimiter, "reserve", failed_reserve)
    monkeypatch.setattr(state, "persist_state", lambda *args: persisted.append(args))
    with pytest.raises(OSError, match="rate store unavailable"):
        make_sealer(sign).seal(candidate())

    assert signed == persisted == []


@pytest.mark.parametrize(
    "updates",
    [
        {"unknown": 1},
        {"seq": 1},
        {"prev_hash": "sha256:" + "a" * 64},
        {"epoch_id": 1},
        {"epoch_certificate_id": "sha256:" + "a" * 64},
        {"signer_timestamp": NEXT_SECOND},
    ],
)
def test_invalid_request_does_not_reserve_quota(updates: dict[str, object], tmp_path: Path) -> None:
    key = dev_key()
    operation = make_sealer(key)
    with pytest.raises(SignerRuleError):
        operation.seal(candidate(**updates))

    assert not (tmp_path / "state.json.rate.sqlite3").exists()
    sealed = operation.seal(candidate())
    assert verify_entry(sealed, key.public_key().public_bytes_raw())


def test_default_system_clock_is_live_utc_milliseconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instants = iter(
        [
            datetime(2026, 1, 1, 0, 1, 0, 999, tzinfo=timezone.utc),
            datetime(2026, 1, 1, 0, 1, 1, 999, tzinfo=timezone.utc),
        ]
    )
    sampled_zones = []

    class DatetimeSource:
        @staticmethod
        def now(zone):
            sampled_zones.append(zone)
            return next(instants)

    monkeypatch.setattr(clock, "datetime", DatetimeSource)
    key = dev_key()
    operation = make_sealer(key, live_clock=None)
    assert sampled_zones == []
    first = operation.seal(candidate())
    second = operation.seal(
        candidate(seq=1, prev_hash=entry_hash(first.body), signer_timestamp=NEXT_SECOND)
    )

    assert sampled_zones == [timezone.utc, timezone.utc]
    assert second.body.signer_timestamp == NEXT_SECOND
    assert verify_entry(second, key.public_key().public_bytes_raw())

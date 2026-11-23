"""K2c cooperative tick coverage."""

import asyncio
from pathlib import Path

import pytest

from services.signer import state
from services.signer.heartbeat import TickRunner, run
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.unit.test_signer_epoch_rollover import END, LOG_ID, manager


class FakeSigner:
    def __init__(self) -> None:
        self.calls = 0

    def tick(self):
        self.calls += 1
        return (), None


def test_runner_stops_cleanly_without_threads_or_sleep() -> None:
    signer = FakeSigner()
    runner = TickRunner(signer)
    assert runner.tick_once() == ((), None)
    runner.stop()
    assert runner.tick_once() == ((), None)
    assert signer.calls == 1


def test_tick_rollover_returns_entries_and_commits_once(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(4, "sha256:" + "a" * 64, 0, LOG_ID, {})
    epochs = manager()
    commits = []
    original = state.persist_state

    def persist(*args, **kwargs):
        commits.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(state, "persist_state", persist)
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id=epochs.certificate_id,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until=END,
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=dev_key(5),
        epoch_manager=epochs,
    )
    rollover, heartbeat = signer.tick()
    assert [entry.body.type for entry in rollover] == ["epoch_end", "epoch_start"]
    assert commits == [6]
    assert heartbeat is None


def test_tick_before_expiry_and_interval_leaves_state_unchanged(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    previous = "sha256:" + "a" * 64
    state.persist_state(4, previous, 0, LOG_ID, {})
    epochs = manager()
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id=epochs.certificate_id,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until=END,
        clock=lambda: "2026-01-01T00:01:00.000Z",
        signing_operation=dev_key(5),
        epoch_manager=epochs,
    )
    before = state.load_state(LOG_ID)
    assert signer.tick() == ((), None)
    assert state.load_state(LOG_ID) == before


def test_tick_failed_epoch_is_degraded_noop(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(4, "sha256:" + "a" * 64, 0, LOG_ID, {})
    epochs = manager()
    epochs.fail_closed()
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id=epochs.certificate_id,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until=END,
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=dev_key(5),
        epoch_manager=epochs,
    )
    before = state.load_state(LOG_ID)
    assert signer.tick() == ((), None)
    assert signer.health_reason == "new_epoch_required"
    assert state.load_state(LOG_ID) == before


def test_tick_intermediate_failure_fails_closed_without_state_change(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    previous = "sha256:" + "a" * 64
    state.persist_state(4, previous, 0, LOG_ID, {})
    epochs = manager()

    def unavailable(_certificate):
        raise OSError("intermediate unavailable")

    monkeypatch.setattr(epochs.intermediate_signer, "sign_epoch_certificate", unavailable)
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id=epochs.certificate_id,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until=END,
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=dev_key(5),
        epoch_manager=epochs,
    )
    before = state.load_state(LOG_ID)
    with pytest.raises(OSError, match="intermediate unavailable"):
        signer.tick()
    assert epochs.degraded is True
    assert signer.health_reason == "new_epoch_required"
    assert state.load_state(LOG_ID) == before


def test_tick_commit_failure_discards_release_and_keeps_state(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    previous = "sha256:" + "a" * 64
    state.persist_state(4, previous, 0, LOG_ID, {})
    epochs = manager()
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id=epochs.certificate_id,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until=END,
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=dev_key(5),
        epoch_manager=epochs,
    )
    before = state.load_state(LOG_ID)
    state_path = Path(tmp_path / "state.json")
    before_bytes = state_path.read_bytes()

    def fail(*_args, **_kwargs):
        raise OSError("replace failed")

    monkeypatch.setattr(state, "persist_state", fail)
    with pytest.raises(OSError, match="replace failed"):
        signer.tick()
    assert epochs.degraded is True
    assert signer.health_reason == "new_epoch_required"
    assert state.load_state(LOG_ID) == before
    assert state_path.read_bytes() == before_bytes


def test_run_is_a_thin_cooperative_loop(monkeypatch) -> None:
    class OneTick:
        stopped = False

        def tick_once(self):
            self.stopped = True

    monkeypatch.setattr("services.signer.heartbeat.TickRunner", lambda _: OneTick())

    async def no_sleep(_):
        return None

    monkeypatch.setattr("services.signer.heartbeat.asyncio.sleep", no_sleep)
    asyncio.run(run(object(), 0))

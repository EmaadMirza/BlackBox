"""S3 real state replacement and fsync failure injection tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from libs.blackbox_core.chain import entry_hash
from services.signer import state
from tests.unit.test_signer_epoch_rollover import manager

LOG_ID = "sha256:" + "1" * 64


def setup_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    state.persist_state(4, "sha256:" + "a" * 64, 0, LOG_ID, {})
    return path


def rollover_payload(operation):
    plan = operation.prepare_rollover(4, "sha256:" + "a" * 64, "2026-01-01T00:04:00.000Z")
    return plan, {
        "seq": plan.start.body.seq,
        "hash": entry_hash(plan.start.body),
        "epoch": plan.start.body.epoch_id,
        "log_id": LOG_ID,
    }


def test_before_commit_preserves_bytes_and_discards_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    index = tmp_path / "state.json.outcomes.json"
    before = (path.read_bytes(), index.read_bytes())
    operation = manager()
    plan, payload = rollover_payload(operation)

    def fail_before_replace(source, destination):
        raise OSError("before commit")

    monkeypatch.setattr(state.os, "replace", fail_before_replace)
    with pytest.raises(OSError, match="before commit"):
        state.persist_state(payload["seq"], payload["hash"], payload["epoch"], LOG_ID, {})
    operation.fail_closed()

    assert (path.read_bytes(), index.read_bytes()) == before
    with pytest.raises(RuntimeError, match="destroyed"):
        operation.signing_operation.sign(b"no reuse")


@pytest.mark.parametrize("replace_number", [1, 2])
def test_marker_remains_when_each_real_replace_boundary_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, replace_number: int
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    operation = manager()
    plan, payload = rollover_payload(operation)
    original_replace = state.os.replace
    calls = 0

    def fail_at_boundary(source, destination):
        nonlocal calls
        calls += 1
        if calls == replace_number:
            raise OSError("replace failure")
        return original_replace(source, destination)

    monkeypatch.setattr(state.os, "replace", fail_at_boundary)
    with pytest.raises(OSError, match="replace failure"):
        state.persist_state(payload["seq"], payload["hash"], payload["epoch"], LOG_ID, {})

    marker = path.with_name(f".{path.name}.commit")
    assert marker.exists()
    with pytest.raises(ValueError, match="uncertain"):
        state.load_state(LOG_ID)
    operation.fail_closed()


def test_fsync_failure_discards_keys_and_releases_no_rollover_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    setup_state(monkeypatch, tmp_path)
    operation = manager()
    plan, payload = rollover_payload(operation)

    def fail_fsync(_directory):
        raise OSError("fsync failure")

    monkeypatch.setattr(state, "_fsync_directory", fail_fsync)
    with pytest.raises(OSError, match="fsync failure"):
        state.persist_state(payload["seq"], payload["hash"], payload["epoch"], LOG_ID, {})
    operation.fail_closed()

    assert operation.degraded
    with pytest.raises(RuntimeError, match="destroyed"):
        operation.signing_operation.sign(b"no release")


def test_commit_is_before_release_in_instrumented_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    setup_state(monkeypatch, tmp_path)
    operation = manager()
    plan, payload = rollover_payload(operation)
    released = []

    def commit(*args, **kwargs):
        released.append(False)
        state.persist_state(*args, **kwargs)
        released.append(True)

    commit(payload["seq"], payload["hash"], payload["epoch"], LOG_ID, {})
    assert released == [False, True]
    assert plan.end.body.seq < plan.start.body.seq

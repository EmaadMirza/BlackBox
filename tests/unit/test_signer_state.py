"""Durable signer sequence, hash-chain, and epoch state."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from libs.blackbox_core.chain import GENESIS_PREV_HASH
from services.signer import state

LOG_ID = "sha256:" + "1" * 64
OTHER_LOG_ID = "sha256:" + "2" * 64


def state_path(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))


def test_fresh_state_uses_genesis_and_default_location(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert state.DEFAULT_STATE_PATH == Path("/var/lib/blackbox/signer/state.json")
    default_path = tmp_path / "default" / "state.json"
    monkeypatch.delenv("SIGNER_STATE_PATH", raising=False)
    monkeypatch.setattr(state, "DEFAULT_STATE_PATH", default_path)

    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)


def test_round_trip_and_file_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "nested" / "state.json"
    state_path(monkeypatch, path)
    value = (7, "sha256:" + "a" * 64, 3)

    state.persist_state(*value, LOG_ID)

    assert state.load_state(LOG_ID) == value
    assert path.parent.is_dir()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "last_seq": 7,
        "last_hash": "sha256:" + "a" * 64,
        "epoch_id": 3,
        "log_id": LOG_ID,
    }


@pytest.mark.parametrize(
    "contents",
    [
        "{",
        '{"last_seq": 1, "last_hash": "sha256:' + "a" * 64 + '", "epoch_id": 0} trailing',
        '{"last_seq": 1.0, "last_hash": "sha256:' + "a" * 64 + '", "epoch_id": 0}',
        '{"last_seq": 1, "last_hash": "sha256:' + "a" * 64 + '", "epoch_id": 0, "extra": 1}',
    ],
)
def test_load_rejects_malformed_trailing_float_and_unknown_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, contents: str
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError):
        state.load_state()


def test_load_rejects_duplicate_fields_and_invalid_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)

    path.write_text(
        '{"last_seq": 1, "last_seq": 2, "last_hash": "sha256:' + "a" * 64 + '", "epoch_id": 0}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        state.load_state()

    path.write_text(
        '{"last_seq": 1, "last_hash": "SHA256:' + "a" * 64 + '", "epoch_id": 0}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        state.load_state()


def test_persist_rejects_negative_epoch_and_rollbacks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)
    previous = (5, "sha256:" + "a" * 64, 2)
    state.persist_state(*previous, LOG_ID)

    with pytest.raises(ValueError):
        state.persist_state(6, "sha256:" + "b" * 64, -1, LOG_ID)
    with pytest.raises(ValueError):
        state.persist_state(4, "sha256:" + "b" * 64, 3, LOG_ID)
    with pytest.raises(ValueError):
        state.persist_state(5, "sha256:" + "b" * 64, 2, LOG_ID)

    assert state.load_state() == previous


def test_replace_failure_preserves_previous_state_and_cleans_temp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)
    previous = (1, "sha256:" + "a" * 64, 0)
    state.persist_state(*previous, LOG_ID)
    previous_bytes = path.read_bytes()

    def fail_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(state.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        state.persist_state(2, "sha256:" + "b" * 64, 0, LOG_ID)

    assert path.read_bytes() == previous_bytes
    with pytest.raises(ValueError, match="uncertain"):
        state.load_state(LOG_ID)
    assert list(tmp_path.glob(".state.json.*.tmp")) == []


def test_reusing_state_for_another_log_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)
    state.persist_state(0, "sha256:" + "a" * 64, 0, LOG_ID)

    with pytest.raises(ValueError, match="log identity"):
        state.load_state(OTHER_LOG_ID)
    with pytest.raises(ValueError, match="log identity"):
        state.persist_state(1, "sha256:" + "b" * 64, 0, OTHER_LOG_ID)


def test_legacy_state_without_log_id_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)
    path.write_text(
        json.dumps(
            {
                "last_seq": 0,
                "last_hash": "sha256:" + "a" * 64,
                "epoch_id": 0,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exactly"):
        state.load_state()


def test_missing_state_after_initialization_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)
    state.persist_state(0, "sha256:" + "a" * 64, 0, LOG_ID)
    path.unlink()

    with pytest.raises(ValueError, match="initialized signer state is missing"):
        state.load_state(LOG_ID)


def test_directory_fsync_failure_after_replace_poison_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    state_path(monkeypatch, path)
    state.persist_state(0, "sha256:" + "a" * 64, 0, LOG_ID)
    calls = 0
    original_fsync = state._fsync_directory

    def fail_after_replace(directory: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory fsync failed after replacement")
        original_fsync(directory)

    monkeypatch.setattr(state, "_fsync_directory", fail_after_replace)
    with pytest.raises(OSError, match="directory fsync failed"):
        state.persist_state(1, "sha256:" + "b" * 64, 0, LOG_ID)

    assert calls == 2
    with pytest.raises(ValueError, match="uncertain"):
        state.load_state(LOG_ID)

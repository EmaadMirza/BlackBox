"""L2a-2 signer state/outbox persistence integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.schemas import Checkpoint, SealedEntry, parse_entry
from libs.blackbox_core.sealing import seal
from services.signer import outbox, state
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action

LOG_ID = "sha256:" + "1" * 64
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
CERTIFICATE_ID = "sha256:" + "2" * 64


def configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    return path


def signed_action(seq: int, previous: str) -> SealedEntry:
    body = action()
    body.update(log_id=LOG_ID, seq=seq, prev_hash=previous)
    return seal(parse_entry(body), dev_key())


def setup_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = configure(monkeypatch, tmp_path)
    state.persist_state(0, HASH_A, 0, LOG_ID)
    return path


def test_first_commit_creates_empty_outbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = configure(monkeypatch, tmp_path)

    state.persist_state(0, HASH_A, 0, LOG_ID)

    assert state.load_state(LOG_ID) == (0, HASH_A, 0)
    assert state.load_outbox(LOG_ID) == outbox.OutboxSnapshot(LOG_ID, 0, HASH_A, ())
    assert path.with_name("state.json.outbox.json").is_file()


def test_state_commit_appends_and_validates_outbox_tail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    setup_state(monkeypatch, tmp_path)
    entry = signed_action(1, HASH_A)
    head = entry_hash(entry.body)

    state.persist_state(1, head, 0, LOG_ID, outbox_append=(entry,))

    assert state.load_state(LOG_ID) == (1, head, 0)
    assert state.load_outbox(LOG_ID).entries == (entry,)


def test_missing_corrupt_legacy_and_inconsistent_outbox_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    outbox_path = path.with_name("state.json.outbox.json")
    outbox_path.unlink()
    with pytest.raises(outbox.OutboxError) as missing:
        state.load_state(LOG_ID)
    assert missing.value.code == "outbox_missing"

    outbox_path.write_text(
        json.dumps(
            {
                "format_version": "0",
                "log_id": LOG_ID,
                "delivered_seq": 0,
                "delivered_hash": HASH_A,
                "entries": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(outbox.OutboxError) as legacy:
        state.load_state(LOG_ID)
    assert legacy.value.code == "outbox_version_unsupported"

    entry = signed_action(1, HASH_A)
    outbox.write_outbox_atomic(
        outbox_path,
        outbox.OutboxSnapshot(LOG_ID, 0, HASH_A, ()),
    )
    state.persist_state(1, entry_hash(entry.body), 0, LOG_ID, outbox_append=(entry,))
    outbox.write_outbox_atomic(
        outbox_path,
        outbox.OutboxSnapshot(LOG_ID, 0, HASH_A, ()),
    )
    with pytest.raises(outbox.OutboxError) as inconsistent:
        state.load_state(LOG_ID)
    assert inconsistent.value.code == "outbox_head_mismatch"


def _full_commit_inputs(entry: SealedEntry) -> tuple[dict[str, object], Checkpoint]:
    metadata = {
        "format_version": state.EPOCH_METADATA_FORMAT_VERSION,
        "log_id": LOG_ID,
        "epoch_id": 1,
        "epoch_certificate": {
            "epoch_id": 1,
            "log_id": LOG_ID,
            "epoch_public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "valid_from": "2026-01-01T00:05:00.000Z",
            "valid_until": "2026-01-01T00:10:00.000Z",
            "intermediate_id": "intermediate-0",
            "signature": "",
        },
        "valid_from": "2026-01-01T00:05:00.000Z",
        "valid_until": "2026-01-01T00:10:00.000Z",
    }
    checkpoint = Checkpoint(
        log_id=LOG_ID,
        tree_size=2,
        root_hash=HASH_B,
        latest_seq=1,
        latest_entry_hash=entry_hash(entry.body),
        epoch_id=1,
        signer_timestamp="2026-01-01T00:05:00.000Z",
        signature="",
    )
    return metadata, checkpoint


@pytest.mark.parametrize("replace_number", [1, 2, 3, 4, 5])
def test_each_commit_replace_boundary_leaves_marker_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, replace_number: int
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    entry = signed_action(1, HASH_A)
    metadata, checkpoint = _full_commit_inputs(entry)
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
        state.persist_state(
            1,
            entry_hash(entry.body),
            1,
            LOG_ID,
            {},
            metadata,
            checkpoint,
            outbox_append=(entry,),
        )

    marker = path.with_name(".state.json.commit")
    assert marker.exists()
    with pytest.raises(ValueError, match="uncertain"):
        state.load_state(LOG_ID)


def test_directory_fsync_failure_leaves_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    entry = signed_action(1, HASH_A)
    calls = 0
    original_fsync = state._fsync_directory

    def fail_after_replacements(directory: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory fsync failure")
        original_fsync(directory)

    monkeypatch.setattr(state, "_fsync_directory", fail_after_replacements)
    with pytest.raises(OSError, match="directory fsync failure"):
        state.persist_state(1, entry_hash(entry.body), 0, LOG_ID, outbox_append=(entry,))

    assert path.with_name(".state.json.commit").exists()
    with pytest.raises(ValueError, match="uncertain"):
        state.load_state(LOG_ID)


def test_marker_unlink_failure_leaves_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    entry = signed_action(1, HASH_A)
    original_unlink = Path.unlink

    def fail_marker_unlink(self: Path, *args, **kwargs):
        if self == path.with_name(".state.json.commit"):
            raise OSError("marker unlink failure")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_marker_unlink)
    with pytest.raises(OSError, match="marker unlink failure"):
        state.persist_state(1, entry_hash(entry.body), 0, LOG_ID, outbox_append=(entry,))

    assert path.with_name(".state.json.commit").exists()
    with pytest.raises(ValueError, match="uncertain"):
        state.load_state(LOG_ID)


def test_ack_is_marker_free_idempotent_and_prefix_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    first = signed_action(1, HASH_A)
    second = signed_action(2, entry_hash(first.body))
    first_hash = entry_hash(first.body)
    state.persist_state(2, entry_hash(second.body), 0, LOG_ID, outbox_append=(first, second))
    outbox_path = path.with_name("state.json.outbox.json")

    with pytest.raises(outbox.OutboxError):
        state.acknowledge_outbox(LOG_ID, 2, entry_hash(second.body))
    assert state.load_outbox(LOG_ID).entries == (first, second)
    before = outbox_path.read_bytes()
    with pytest.raises(outbox.OutboxError):
        state.acknowledge_outbox(LOG_ID, 1, HASH_B)
    assert outbox_path.read_bytes() == before

    acknowledged = state.acknowledge_outbox(LOG_ID, 1, first_hash)
    assert acknowledged.entries == (second,)
    assert not path.with_name(".state.json.commit").exists()
    repeated = state.acknowledge_outbox(LOG_ID, 1, first_hash)
    assert repeated == acknowledged
    assert state.load_state(LOG_ID) == (2, entry_hash(second.body), 0)


def test_ack_replace_failure_preserves_old_outbox_and_startup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    entry = signed_action(1, HASH_A)
    entry_hash_value = entry_hash(entry.body)
    state.persist_state(1, entry_hash_value, 0, LOG_ID, outbox_append=(entry,))
    outbox_path = path.with_name("state.json.outbox.json")
    before = outbox_path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("ack replace failure")

    monkeypatch.setattr(state.outbox.os, "replace", fail_replace)
    with pytest.raises(OSError, match="ack replace failure"):
        state.acknowledge_outbox(LOG_ID, 1, entry_hash_value)

    assert outbox_path.read_bytes() == before
    assert state.load_state(LOG_ID) == (1, entry_hash_value, 0)


def test_outbox_tail_must_equal_durable_state_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = setup_state(monkeypatch, tmp_path)
    first = signed_action(1, HASH_A)
    second = signed_action(2, entry_hash(first.body))
    state.persist_state(2, entry_hash(second.body), 0, LOG_ID, outbox_append=(first, second))
    outbox.write_outbox_atomic(
        path.with_name("state.json.outbox.json"),
        outbox.OutboxSnapshot(LOG_ID, 0, HASH_A, (first,)),
    )

    with pytest.raises(outbox.OutboxError) as exc:
        state.load_state(LOG_ID)
    assert exc.value.code == "outbox_head_mismatch"

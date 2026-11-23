"""Pure versioned signer outbox behavior."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.schemas import EpochEnd, SealedEntry, parse_entry
from libs.blackbox_core.sealing import seal
from services.signer import outbox
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action

LOG_ID = "sha256:" + "1" * 64
OTHER_LOG_ID = "sha256:" + "2" * 64
CERTIFICATE_ID = "sha256:" + "2" * 64


def signed_action(seq: int, prev_hash: str, *, log_id: str = LOG_ID) -> SealedEntry:
    body = action()
    body.update(log_id=log_id, seq=seq, prev_hash=prev_hash)
    return seal(parse_entry(body), dev_key())


def signed_epoch_end(seq: int, prev_hash: str) -> SealedEntry:
    body = EpochEnd(
        format_version="4",
        log_id=LOG_ID,
        epoch_id=0,
        seq=seq,
        signer_timestamp="2026-01-01T00:01:00.000Z",
        prev_hash=prev_hash,
        lane="agent",
        epoch_certificate_id=CERTIFICATE_ID,
        type="epoch_end",
    )
    return seal(body, dev_key())


def snapshot(
    *entries: SealedEntry, delivered_seq: int = -1, delivered_hash: str = GENESIS_PREV_HASH
):
    return outbox.OutboxSnapshot(LOG_ID, delivered_seq, delivered_hash, tuple(entries))


def test_round_trip_and_file_mode(tmp_path: Path) -> None:
    first = signed_action(0, GENESIS_PREV_HASH)
    value = snapshot(first)

    encoded = outbox.encode(value)
    decoded = outbox.decode(encoded, LOG_ID)

    assert decoded == value
    path = tmp_path / "state.outbox.json"
    outbox.write_outbox_atomic(path, value)
    assert outbox.read_outbox(path, LOG_ID) == value
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "document",
    [
        {
            "format_version": "0",
            "log_id": LOG_ID,
            "delivered_seq": -1,
            "delivered_hash": GENESIS_PREV_HASH,
            "entries": [],
        },
        {
            "format_version": "1",
            "log_id": LOG_ID,
            "delivered_seq": -1,
            "delivered_hash": GENESIS_PREV_HASH,
            "entries": [],
            "extra": 1,
        },
        {
            "format_version": "1",
            "log_id": OTHER_LOG_ID,
            "delivered_seq": -1,
            "delivered_hash": GENESIS_PREV_HASH,
            "entries": [],
        },
        {
            "format_version": "1",
            "log_id": LOG_ID,
            "delivered_seq": -1.0,
            "delivered_hash": GENESIS_PREV_HASH,
            "entries": [],
        },
    ],
)
def test_decode_rejects_strict_schema(document: dict[str, object]) -> None:
    with pytest.raises(outbox.OutboxError):
        outbox.decode(json.dumps(document), LOG_ID)


def test_decode_rejects_duplicate_keys_and_empty_signature() -> None:
    duplicate = (
        '{"format_version":"1","format_version":"1",'
        + f'"log_id":"{LOG_ID}","delivered_seq":-1,'
        + f'"delivered_hash":"{GENESIS_PREV_HASH}","entries":[]'
        + "}"
    )
    with pytest.raises(outbox.OutboxError):
        outbox.decode(duplicate, LOG_ID)

    raw = json.loads(outbox.encode(snapshot(signed_action(0, GENESIS_PREV_HASH))))
    raw["entries"][0]["signature"] = ""
    with pytest.raises(outbox.OutboxError):
        outbox.decode(json.dumps(raw), LOG_ID)


def test_validate_rejects_gap_broken_link_wrong_tail_and_empty_mismatch() -> None:
    first = signed_action(0, GENESIS_PREV_HASH)
    second = signed_action(1, entry_hash(first.body))
    with pytest.raises(outbox.OutboxError):
        outbox.validate_snapshot(snapshot(second), LOG_ID)
    broken = second.model_copy(
        update={"body": second.body.model_copy(update={"prev_hash": "sha256:" + "f" * 64})}
    )
    with pytest.raises(outbox.OutboxError):
        outbox.validate_snapshot(snapshot(first, broken), LOG_ID)
    with pytest.raises(outbox.OutboxError):
        outbox.validate_snapshot(
            snapshot(first), LOG_ID, expected_head=(1, entry_hash(second.body))
        )
    with pytest.raises(outbox.OutboxError):
        outbox.validate_snapshot(
            snapshot(delivered_seq=0, delivered_hash=entry_hash(first.body)),
            LOG_ID,
            expected_head=(-1, GENESIS_PREV_HASH),
        )


def test_append_returns_new_snapshot_and_preserves_chain() -> None:
    first = signed_action(0, GENESIS_PREV_HASH)
    second = signed_action(1, entry_hash(first.body))
    original = snapshot(first)

    updated = outbox.append(original, (second,))

    assert updated is not original
    assert original.entries == (first,)
    assert updated.entries == (first, second)
    outbox.validate_snapshot(updated, LOG_ID, expected_head=(1, entry_hash(second.body)))


def test_ack_requires_first_exact_hash_and_is_idempotent() -> None:
    first = signed_action(0, GENESIS_PREV_HASH)
    second = signed_action(1, entry_hash(first.body))
    value = snapshot(first, second)

    with pytest.raises(outbox.OutboxError):
        outbox.ack(value, 1, entry_hash(second.body))
    with pytest.raises(outbox.OutboxError):
        outbox.ack(value, 0, "sha256:" + "f" * 64)

    acknowledged = outbox.ack(value, 0, entry_hash(first.body))
    assert acknowledged.entries == (second,)
    assert value.entries == (first, second)
    repeated = outbox.ack(acknowledged, acknowledged.delivered_seq, acknowledged.delivered_hash)
    assert repeated == acknowledged


def test_capacity_and_reserved_slots() -> None:
    with pytest.raises(outbox.OutboxError) as wrong_reserved_type:
        outbox.append(snapshot(), (signed_action(0, GENESIS_PREV_HASH),), reserved=True)
    assert wrong_reserved_type.value.code == "outbox_reserved_entry"

    entries = []
    previous = GENESIS_PREV_HASH
    for seq in range(4):
        item = signed_action(seq, previous)
        entries.append(item)
        previous = entry_hash(item.body)
    value = snapshot(*entries)
    with pytest.raises(outbox.OutboxError) as normal:
        outbox.append(value, (signed_action(4, previous),), max_pending=4)
    assert normal.value.code == "outbox_full"

    reserved = signed_epoch_end(4, previous)
    expanded = outbox.append(value, (reserved,), max_pending=4, reserved=True)
    assert len(expanded.entries) == 5
    assert outbox.is_high_water(value, 8) is True

    full = expanded
    previous = entry_hash(reserved.body)
    for seq in range(5, 12):
        item = signed_epoch_end(seq, previous)
        full = outbox.append(full, (item,), max_pending=4, reserved=True)
        previous = entry_hash(item.body)
    with pytest.raises(outbox.OutboxError) as exhausted:
        outbox.append(full, (signed_epoch_end(12, previous),), max_pending=4, reserved=True)
    assert exhausted.value.code == "outbox_full"


@given(st.lists(st.booleans(), min_size=1, max_size=30))
def test_random_append_ack_sequences_preserve_invariants(actions: list[bool]) -> None:
    value = snapshot()
    next_seq = 0
    head = (-1, GENESIS_PREV_HASH)
    for do_append in actions:
        if do_append and len(value.entries) < 100:
            item = signed_action(
                next_seq, head[1] if not value.entries else entry_hash(value.entries[-1].body)
            )
            value = outbox.append(value, (item,), max_pending=100)
            next_seq += 1
            head = (item.body.seq, entry_hash(item.body))
        elif value.entries:
            item = value.entries[0]
            value = outbox.ack(value, item.body.seq, entry_hash(item.body))
        outbox.validate_snapshot(value, LOG_ID, expected_head=head)

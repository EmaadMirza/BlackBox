"""Pure, versioned persistence model for the signer's delivery outbox."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from libs.blackbox_core.chain import entry_hash as _entry_hash
from libs.blackbox_core.encoding import decode_hash
from libs.blackbox_core.schemas import SealedEntry

OUTBOX_FORMAT_VERSION = "1"
OUTBOX_SUFFIX = ".outbox.json"
OUTBOX_FILE_SUFFIX = OUTBOX_SUFFIX
DEFAULT_MAX_PENDING = 1000
RESERVED_HEADROOM = 8
MAX_PENDING = DEFAULT_MAX_PENDING
RESERVED_SLOTS = RESERVED_HEADROOM
RESERVED_ENTRY_TYPES = frozenset({"epoch_end", "epoch_start", "recovery"})
_OUTBOX_FIELDS = frozenset(
    {"format_version", "log_id", "delivered_seq", "delivered_hash", "entries"}
)


class OutboxError(ValueError):
    """Stable, fail-closed outbox validation or operation error."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


@dataclass(frozen=True)
class OutboxSnapshot:
    log_id: str
    delivered_seq: int
    delivered_hash: str
    entries: tuple[SealedEntry, ...]


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OutboxError("outbox_invalid", "duplicate JSON key")
        result[key] = value
    return result


def _reject_json_number(value: str) -> None:
    raise OutboxError("outbox_invalid", "floating-point and non-finite numbers are forbidden")


def _hash(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise OutboxError("outbox_invalid", f"{field} must be a hash string")
    try:
        decode_hash(value)
    except (TypeError, ValueError) as exc:
        raise OutboxError("outbox_invalid", f"{field} is invalid") from exc
    return value


def _validate_expected_head(expected_head: tuple[int, str] | None) -> tuple[int, str] | None:
    if expected_head is None:
        return None
    if (
        not isinstance(expected_head, tuple)
        or len(expected_head) != 2
        or type(expected_head[0]) is not int
        or expected_head[0] < -1
    ):
        raise OutboxError("outbox_head_mismatch", "expected head is invalid")
    return expected_head[0], _hash(expected_head[1], field="expected head hash")


def validate_snapshot(
    snapshot: OutboxSnapshot,
    expected_log_id: str,
    expected_head: tuple[int, str] | None = None,
) -> None:
    """Validate the local queue and, optionally, its relationship to signer state."""

    if not isinstance(snapshot, OutboxSnapshot):
        raise OutboxError("outbox_invalid", "snapshot type is invalid")
    _hash(expected_log_id, field="expected log id")
    if snapshot.log_id != expected_log_id:
        raise OutboxError("outbox_log_mismatch", "outbox log identity does not match")
    if type(snapshot.delivered_seq) is not int or snapshot.delivered_seq < -1:
        raise OutboxError("outbox_invalid", "delivered sequence is invalid")
    delivered_hash = _hash(snapshot.delivered_hash, field="delivered hash")
    if not isinstance(snapshot.entries, tuple):
        raise OutboxError("outbox_invalid", "entries must be a tuple")

    previous_hash = delivered_hash
    expected_seq = snapshot.delivered_seq + 1
    actual_tail: tuple[int, str] | None = None
    for entry in snapshot.entries:
        try:
            parsed = SealedEntry.model_validate(entry)
        except (TypeError, ValueError) as exc:
            raise OutboxError("outbox_invalid", "sealed entry is invalid") from exc
        if not parsed.signature:
            raise OutboxError("outbox_empty_signature", "outbox entries must be signed")
        if parsed.body.log_id != expected_log_id:
            raise OutboxError("outbox_log_mismatch", "entry log identity does not match")
        if parsed.body.seq != expected_seq:
            raise OutboxError("outbox_inconsistent", "pending sequences are not contiguous")
        if parsed.body.prev_hash != previous_hash:
            raise OutboxError("outbox_inconsistent", "pending hash chain is broken")
        previous_hash = _entry_hash(parsed.body)
        actual_tail = (parsed.body.seq, previous_hash)
        expected_seq += 1

    head = _validate_expected_head(expected_head)
    if head is not None:
        if actual_tail is None:
            if (snapshot.delivered_seq, snapshot.delivered_hash) != head:
                raise OutboxError("outbox_head_mismatch", "empty outbox does not reach signer head")
        elif actual_tail != head:
            raise OutboxError("outbox_head_mismatch", "outbox tail does not reach signer head")


def _snapshot_document(snapshot: OutboxSnapshot) -> dict[str, object]:
    validate_snapshot(snapshot, snapshot.log_id)
    return {
        "format_version": OUTBOX_FORMAT_VERSION,
        "log_id": snapshot.log_id,
        "delivered_seq": snapshot.delivered_seq,
        "delivered_hash": snapshot.delivered_hash,
        "entries": [entry.model_dump(mode="json") for entry in snapshot.entries],
    }


def encode(snapshot: OutboxSnapshot) -> bytes:
    """Encode a validated snapshot using deterministic strict JSON."""

    return json.dumps(
        _snapshot_document(snapshot), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def decode(data: str | bytes, expected_log_id: str | None = None) -> OutboxSnapshot:
    """Decode and strictly validate an outbox document."""

    try:
        document = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_fields,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except OutboxError:
        raise
    except (TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise OutboxError("outbox_invalid", "outbox JSON is invalid") from exc

    if type(document) is not dict or set(document) != _OUTBOX_FIELDS:
        raise OutboxError("outbox_invalid", "outbox fields are invalid")
    if document["format_version"] != OUTBOX_FORMAT_VERSION:
        raise OutboxError("outbox_version_unsupported", "outbox format version is unsupported")
    log_id = _hash(document["log_id"], field="log id")
    if expected_log_id is not None:
        _hash(expected_log_id, field="expected log id")
        if log_id != expected_log_id:
            raise OutboxError("outbox_log_mismatch", "outbox log identity does not match")
    delivered_seq = document["delivered_seq"]
    if type(delivered_seq) is not int or delivered_seq < -1:
        raise OutboxError("outbox_invalid", "delivered sequence is invalid")
    delivered_hash = _hash(document["delivered_hash"], field="delivered hash")
    raw_entries = document["entries"]
    if type(raw_entries) is not list:
        raise OutboxError("outbox_invalid", "outbox entries must be a list")
    entries: list[SealedEntry] = []
    for raw_entry in raw_entries:
        try:
            entry = SealedEntry.model_validate(raw_entry)
        except (TypeError, ValueError) as exc:
            raise OutboxError("outbox_invalid", "sealed entry is invalid") from exc
        if not entry.signature:
            raise OutboxError("outbox_empty_signature", "outbox entries must be signed")
        entries.append(entry)
    snapshot = OutboxSnapshot(log_id, delivered_seq, delivered_hash, tuple(entries))
    validate_snapshot(snapshot, log_id)
    return snapshot


def append(
    snapshot: OutboxSnapshot,
    entries: Iterable[SealedEntry],
    reserved: bool = False,
    *,
    max_pending: int = DEFAULT_MAX_PENDING,
    reserved_slots: int = RESERVED_HEADROOM,
) -> OutboxSnapshot:
    """Return a new snapshot with a contiguous signed suffix appended."""

    validate_snapshot(snapshot, snapshot.log_id)
    if type(max_pending) is not int or max_pending <= 0:
        raise OutboxError("outbox_invalid", "max_pending is invalid")
    if type(reserved_slots) is not int or reserved_slots < 0:
        raise OutboxError("outbox_invalid", "reserved slots are invalid")
    additions = tuple(entries)
    if not additions:
        return OutboxSnapshot(
            snapshot.log_id, snapshot.delivered_seq, snapshot.delivered_hash, snapshot.entries
        )

    parsed_additions: list[SealedEntry] = []
    for raw_entry in additions:
        try:
            entry = SealedEntry.model_validate(raw_entry)
        except (TypeError, ValueError) as exc:
            raise OutboxError("outbox_invalid", "sealed entry is invalid") from exc
        if not entry.signature:
            raise OutboxError("outbox_empty_signature", "outbox entries must be signed")
        parsed_additions.append(entry)
    if reserved and any(entry.body.type not in RESERVED_ENTRY_TYPES for entry in parsed_additions):
        raise OutboxError(
            "outbox_reserved_entry", "reserved slots require rollover or recovery entries"
        )

    pending = len(snapshot.entries)
    limit = max_pending + reserved_slots if reserved else max_pending
    if pending >= limit or pending + len(additions) > limit:
        raise OutboxError("outbox_full", "outbox capacity is exhausted")

    previous_hash = (
        snapshot.delivered_hash if not snapshot.entries else _entry_hash(snapshot.entries[-1].body)
    )
    expected_seq = snapshot.delivered_seq + len(snapshot.entries) + 1
    for entry in parsed_additions:
        if entry.body.log_id != snapshot.log_id:
            raise OutboxError("outbox_log_mismatch", "entry log identity does not match")
        if entry.body.seq != expected_seq or entry.body.prev_hash != previous_hash:
            raise OutboxError("outbox_inconsistent", "appended entries do not continue the chain")
        previous_hash = _entry_hash(entry.body)
        expected_seq += 1

    result = OutboxSnapshot(
        snapshot.log_id,
        snapshot.delivered_seq,
        snapshot.delivered_hash,
        snapshot.entries + tuple(parsed_additions),
    )
    validate_snapshot(result, snapshot.log_id)
    return result


def ack(snapshot: OutboxSnapshot, seq: int, entry_hash: str) -> OutboxSnapshot:
    """Acknowledge exactly the first pending entry, or repeat the last ack."""

    validate_snapshot(snapshot, snapshot.log_id)
    supplied_hash = _hash(entry_hash, field="acknowledged hash")
    if (
        type(seq) is int
        and seq == snapshot.delivered_seq
        and supplied_hash == snapshot.delivered_hash
    ):
        return OutboxSnapshot(
            snapshot.log_id, snapshot.delivered_seq, snapshot.delivered_hash, snapshot.entries
        )
    if not snapshot.entries:
        raise OutboxError("outbox_ack_invalid", "outbox acknowledgement is not pending")
    first = snapshot.entries[0]
    actual_hash = _entry_hash(first.body)
    if type(seq) is not int or seq != first.body.seq or supplied_hash != actual_hash:
        raise OutboxError("outbox_ack_invalid", "only the first pending entry may be acknowledged")
    result = OutboxSnapshot(snapshot.log_id, seq, actual_hash, snapshot.entries[1:])
    validate_snapshot(result, snapshot.log_id)
    return result


def is_high_water(snapshot: OutboxSnapshot, max_pending: int = DEFAULT_MAX_PENDING) -> bool:
    """Return whether pending delivery has reached the 50% alarm threshold."""

    validate_snapshot(snapshot, snapshot.log_id)
    if type(max_pending) is not int or max_pending <= 0:
        raise OutboxError("outbox_invalid", "max_pending is invalid")
    return len(snapshot.entries) * 2 >= max_pending


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_outbox_atomic(path: Path, snapshot: OutboxSnapshot) -> None:
    """Write an outbox through a durable temporary-file replacement."""

    payload = encode(snapshot)
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    open_descriptor: int | None = descriptor
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            open_descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        _fsync_directory(parent)
    finally:
        if open_descriptor is not None:
            os.close(open_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def read_outbox(path: Path, expected_log_id: str) -> OutboxSnapshot:
    """Read and strictly validate one outbox sidecar."""

    return decode(Path(path).read_bytes(), expected_log_id)

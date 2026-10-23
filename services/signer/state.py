"""Crash-safe persistence for the signer's durable chain state."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from libs.blackbox_core.chain import GENESIS_PREV_HASH
from libs.blackbox_core.encoding import decode_hash
from libs.blackbox_core.schemas import SealedEntry
from services.signer import outbox

DEFAULT_STATE_PATH = Path("/var/lib/blackbox/signer/state.json")
CHECKPOINT_STATE_FORMAT_VERSION = "2"
_STATE_FIELDS = frozenset({"last_seq", "last_hash", "epoch_id", "log_id"})
_MARKER_SUFFIX = ".commit"
_INITIALIZED_SUFFIX = ".initialized"
_OUTCOME_SUFFIX = ".outcomes.json"
_EPOCH_SUFFIX = ".epoch.json"
OUTCOME_INDEX_FORMAT_VERSION = "1"
EPOCH_METADATA_FORMAT_VERSION = "1"
_OUTCOME_FIELDS = frozenset({"format_version", "log_id", "outcomes"})


def _state_path() -> Path:
    configured_path = os.environ.get("SIGNER_STATE_PATH")
    return Path(configured_path) if configured_path else DEFAULT_STATE_PATH


def _marker_path(path: Path) -> Path:
    return path.with_name(f".{path.name}{_MARKER_SUFFIX}")


def _initialized_path(path: Path) -> Path:
    return path.with_name(f".{path.name}{_INITIALIZED_SUFFIX}")


def _outcome_index_path(path: Path | None = None) -> Path:
    path = _state_path() if path is None else path
    return path.with_name(f"{path.name}{_OUTCOME_SUFFIX}")


def _epoch_metadata_path(path: Path | None = None) -> Path:
    path = _state_path() if path is None else path
    return path.with_name(f"{path.name}{_EPOCH_SUFFIX}")


def _outbox_path(path: Path | None = None) -> Path:
    path = _state_path() if path is None else path
    return path.with_name(f"{path.name}{outbox.OUTBOX_SUFFIX}")


def epoch_metadata_exists() -> bool:
    return _epoch_metadata_path().exists()


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate signer state field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_values(
    last_seq: object, last_hash: object, epoch_id: object, log_id: object
) -> tuple[int, str, int, str]:
    if type(last_seq) is not int or last_seq < -1:
        raise ValueError("last_seq must be an integer greater than or equal to -1")
    if type(epoch_id) is not int or epoch_id < 0:
        raise ValueError("epoch_id must be a non-negative integer")
    if not isinstance(last_hash, str):
        raise ValueError("last_hash must be a string")
    try:
        decode_hash(last_hash)
    except ValueError as exc:
        raise ValueError("last_hash must be a lowercase SHA-256 hash") from exc
    try:
        decode_hash(log_id)
    except ValueError as exc:
        raise ValueError("log_id must be a lowercase SHA-256 hash") from exc
    return last_seq, last_hash, epoch_id, log_id


def _validate_document(document: object) -> tuple[int, str, int, str]:
    if type(document) is not dict or set(document) != _STATE_FIELDS:
        raise ValueError(
            "signer state must contain exactly last_seq, last_hash, epoch_id, and log_id"
        )
    return _validate_values(
        document["last_seq"], document["last_hash"], document["epoch_id"], document["log_id"]
    )


def load_outbox(expected_log_id: str) -> outbox.OutboxSnapshot:
    """Read the signer outbox, refusing uncertain or initialized missing storage."""

    path = _state_path()
    if _marker_path(path).exists():
        raise outbox.OutboxError(
            "outbox_uncertain", "uncertain signer state commit; recovery is required"
        )
    outbox_path = _outbox_path(path)
    initialized = _initialized_path(path)
    if not outbox_path.exists():
        if path.exists() or initialized.exists():
            raise outbox.OutboxError("outbox_missing", "initialized signer outbox is missing")
        empty = outbox.OutboxSnapshot(expected_log_id, -1, GENESIS_PREV_HASH, ())
        outbox.validate_snapshot(empty, expected_log_id)
        return empty
    if not path.exists() and not initialized.exists():
        raise outbox.OutboxError("outbox_orphaned", "outbox exists without signer state")
    try:
        return outbox.read_outbox(outbox_path, expected_log_id)
    except outbox.OutboxError:
        raise
    except OSError as exc:
        raise outbox.OutboxError("outbox_unavailable", "signer outbox is unreadable") from exc


def load_state(expected_log_id: str | None = None) -> tuple[int, str, int]:
    """Load chain state, refusing uncertain commits or a different configured log."""

    path = _state_path()
    marker = _marker_path(path)
    if marker.exists():
        raise ValueError("uncertain signer state commit; recovery is required")
    initialized = _initialized_path(path)
    try:
        with path.open("r", encoding="utf-8") as state_file:
            try:
                document = json.load(
                    state_file,
                    object_pairs_hook=_reject_duplicate_fields,
                    parse_constant=_reject_json_constant,
                )
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("invalid signer state JSON") from exc
    except FileNotFoundError:
        if initialized.exists():
            raise ValueError("initialized signer state is missing; recovery is required")
        return -1, GENESIS_PREV_HASH, 0
    last_seq, last_hash, epoch_id, log_id = _validate_document(document)
    if expected_log_id is not None:
        try:
            decode_hash(expected_log_id)
        except ValueError as exc:
            raise ValueError("configured log_id is invalid") from exc
        if log_id != expected_log_id:
            raise ValueError("durable state log identity does not match configuration")
    load_outcome_index(log_id)
    signer_outbox = load_outbox(log_id)
    outbox.validate_snapshot(signer_outbox, log_id, expected_head=(last_seq, last_hash))
    return last_seq, last_hash, epoch_id


def load_last_checkpoint(expected_log_id: str):
    path = _state_path().with_name(f"{_state_path().name}.checkpoint.json")
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream, object_pairs_hook=_reject_duplicate_fields)
    if set(document) != {"format_version", "log_id", "checkpoint"}:
        raise ValueError("checkpoint state fields are invalid")
    if document["format_version"] != CHECKPOINT_STATE_FORMAT_VERSION:
        raise ValueError("checkpoint state format version is unsupported")
    if document["log_id"] != expected_log_id:
        raise ValueError("durable state log identity does not match configuration")
    from libs.blackbox_core.schemas import Checkpoint

    return (
        None
        if document["checkpoint"] is None
        else Checkpoint.model_validate(document["checkpoint"])
    )


class OutcomeIndexError(ValueError):
    """The signer-owned outcome index is absent, corrupt or incompatible."""


def compact_outcome_index(outcomes: Mapping[int, str]) -> dict[int, str]:
    """Return a deterministic, lossless index; no outcome may be discarded."""

    compacted: dict[int, str] = {}
    for intent_seq, outcome_hash in outcomes.items():
        if type(intent_seq) is not int or intent_seq < 0:
            raise OutcomeIndexError("outcome index sequence is invalid")
        try:
            decode_hash(outcome_hash)
        except (TypeError, ValueError) as exc:
            raise OutcomeIndexError("outcome index hash is invalid") from exc
        compacted[intent_seq] = outcome_hash
    return dict(sorted(compacted.items()))


def _validate_outcome_document(document: object, expected_log_id: str) -> dict[int, str]:
    if type(document) is not dict or set(document) != _OUTCOME_FIELDS:
        raise OutcomeIndexError("outcome index fields are invalid")
    if document["format_version"] != OUTCOME_INDEX_FORMAT_VERSION:
        raise OutcomeIndexError("outcome index format version is unsupported")
    if document["log_id"] != expected_log_id:
        raise OutcomeIndexError("outcome index log identity does not match configuration")
    raw_outcomes = document["outcomes"]
    if type(raw_outcomes) is not dict:
        raise OutcomeIndexError("outcome index mapping is invalid")
    parsed: dict[int, str] = {}
    for raw_seq, outcome_hash in raw_outcomes.items():
        if not isinstance(raw_seq, str) or not raw_seq.isdecimal() or str(int(raw_seq)) != raw_seq:
            raise OutcomeIndexError("outcome index sequence is invalid")
        parsed[int(raw_seq)] = outcome_hash
    return compact_outcome_index(parsed)


def load_outcome_index(expected_log_id: str) -> dict[int, str]:
    """Load the versioned index; initialized deployments never get an empty fallback."""

    path = _state_path()
    marker = _marker_path(path)
    if marker.exists():
        raise OutcomeIndexError("uncertain signer state commit; recovery is required")
    try:
        decode_hash(expected_log_id)
    except (TypeError, ValueError) as exc:
        raise OutcomeIndexError("configured log_id is invalid") from exc
    index_path = _outcome_index_path(path)
    initialized = _initialized_path(path)
    if not index_path.exists():
        if initialized.exists() or path.exists():
            raise OutcomeIndexError("initialized signer outcome index is missing")
        return {}
    if not path.exists() and not initialized.exists():
        raise OutcomeIndexError("outcome index exists without signer state")
    try:
        with index_path.open("r", encoding="utf-8") as index_file:
            document = json.load(
                index_file,
                object_pairs_hook=_reject_duplicate_fields,
                parse_constant=_reject_json_constant,
            )
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise OutcomeIndexError("outcome index is unreadable or corrupt") from exc
    try:
        return _validate_outcome_document(document, expected_log_id)
    except OutcomeIndexError:
        raise
    except (TypeError, ValueError) as exc:
        raise OutcomeIndexError("outcome index is malformed") from exc


def load_epoch_metadata(expected_log_id: str) -> dict[str, Any]:
    """Load versioned public epoch metadata; private key material is never accepted."""

    path = _epoch_metadata_path()
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = json.load(
                stream,
                object_pairs_hook=_reject_duplicate_fields,
                parse_constant=_reject_json_constant,
            )
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("epoch metadata is unreadable or corrupt") from exc
    required = {
        "format_version",
        "log_id",
        "epoch_id",
        "epoch_certificate",
        "valid_from",
        "valid_until",
    }
    if type(document) is not dict or set(document) != required:
        raise ValueError("epoch metadata fields are invalid")
    if document["format_version"] != EPOCH_METADATA_FORMAT_VERSION:
        raise ValueError("epoch metadata format version is unsupported")
    if document["log_id"] != expected_log_id:
        raise ValueError("epoch metadata log identity does not match configuration")
    if type(document["epoch_id"]) is not int or document["epoch_id"] < 0:
        raise ValueError("epoch metadata epoch id is invalid")
    from libs.blackbox_core.schemas import EpochCertificate

    certificate = EpochCertificate.model_validate(document["epoch_certificate"])
    if certificate.log_id != expected_log_id or certificate.epoch_id != document["epoch_id"]:
        raise ValueError("epoch metadata certificate identity is invalid")
    if (
        certificate.valid_from != document["valid_from"]
        or certificate.valid_until != document["valid_until"]
    ):
        raise ValueError("epoch metadata window is invalid")
    return document


def _fsync_directory(directory: Path) -> None:
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _commit_files(
    *,
    parent: Path,
    marker: Path,
    initialized: Path,
    marker_document: Mapping[str, object],
    payloads: Iterable[tuple[Path, bytes]],
) -> None:
    """Commit all supplied sidecars behind the signer's one pre-commit marker."""

    marker_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(marker_fd, "w", encoding="utf-8") as marker_file:
            marker_fd = -1
            json.dump(
                marker_document,
                marker_file,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            marker_file.flush()
            os.fsync(marker_file.fileno())
        _fsync_directory(parent)
    except BaseException:
        if marker_fd >= 0:
            os.close(marker_fd)
        raise

    temporary_pairs: list[tuple[str, Path]] = []
    open_descriptors: list[int] = []
    try:
        for destination, payload in payloads:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".tmp", dir=parent
            )
            open_descriptors.append(descriptor)
            temporary_pairs.append((temporary_name, destination))
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as temporary_file:
                open_descriptors.remove(descriptor)
                temporary_file.write(payload)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())

        for index, (temporary_name, destination) in enumerate(temporary_pairs):
            os.replace(temporary_name, destination)
            temporary_pairs[index] = ("", destination)

        _fsync_directory(parent)
        if not initialized.exists():
            initialized_fd = os.open(initialized, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.fsync(initialized_fd)
            finally:
                os.close(initialized_fd)
            _fsync_directory(parent)
        # If this unlink is not durable, a restart conservatively sees the marker
        # and refuses to sign until an operator completes recovery.
        marker.unlink()
    finally:
        for descriptor in open_descriptors:
            os.close(descriptor)
        for temporary_name, _ in temporary_pairs:
            if temporary_name:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass


def persist_state(
    last_seq: int,
    last_hash: str,
    epoch_id: int,
    log_id: str,
    outcome_index: Mapping[int, str] | None = None,
    epoch_metadata: Mapping[str, Any] | None = None,
    last_checkpoint: Any = None,
    outbox_append: Iterable[SealedEntry] = (),
    reserved: bool = False,
) -> None:
    """Persist signer state with a detectable pre-commit marker."""

    candidate = _validate_values(last_seq, last_hash, epoch_id, log_id)
    path = _state_path()
    marker = _marker_path(path)
    if marker.exists():
        raise ValueError("uncertain signer state commit; recovery is required")
    previous = load_state(log_id)
    if not path.exists():
        previous = None

    if previous is not None:
        previous_seq, previous_hash, previous_epoch = previous
        if candidate[0] < previous_seq:
            raise ValueError("cannot roll back last_seq")
        if candidate[2] < previous_epoch:
            raise ValueError("cannot roll back epoch_id")
        if candidate[0] == previous_seq and candidate[1] != previous_hash:
            raise ValueError("cannot change last_hash without advancing last_seq")

    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    elif not parent.is_dir():
        raise OSError(f"signer state parent is not a directory: {parent}")

    index_path = _outcome_index_path(path)
    checkpoint_path = path.with_name(f"{path.name}.checkpoint.json")
    epoch_path = _epoch_metadata_path(path)
    initialized = _initialized_path(path)
    outbox_path = _outbox_path(path)
    if outcome_index is None:
        if path.exists() or initialized.exists():
            outcome_index = load_outcome_index(log_id)
        elif index_path.exists():
            raise OutcomeIndexError("outcome index exists without signer state")
        else:
            outcome_index = {}
    compacted_index = compact_outcome_index(outcome_index)

    appended = tuple(outbox_append)
    if path.exists() or initialized.exists():
        current_outbox = load_outbox(log_id)
    elif outbox_path.exists():
        raise outbox.OutboxError("outbox_orphaned", "outbox exists without signer state")
    else:
        current_outbox = outbox.OutboxSnapshot(log_id, -1, GENESIS_PREV_HASH, ())
    if appended:
        next_outbox = outbox.append(current_outbox, appended, reserved=reserved)
    elif current_outbox.entries:
        next_outbox = current_outbox
    else:
        next_outbox = outbox.OutboxSnapshot(log_id, candidate[0], candidate[1], ())
    outbox.validate_snapshot(next_outbox, log_id, expected_head=(candidate[0], candidate[1]))

    payload = json.dumps(
        {
            "last_seq": candidate[0],
            "last_hash": candidate[1],
            "epoch_id": candidate[2],
            "log_id": candidate[3],
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    index_payload = json.dumps(
        {
            "format_version": OUTCOME_INDEX_FORMAT_VERSION,
            "log_id": log_id,
            "outcomes": {str(seq): value for seq, value in compacted_index.items()},
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    epoch_payload = None
    if epoch_metadata is not None:
        epoch_document = dict(epoch_metadata)
        if epoch_document.get("format_version") != EPOCH_METADATA_FORMAT_VERSION:
            raise ValueError("epoch metadata format version is unsupported")
        if epoch_document.get("log_id") != log_id:
            raise ValueError("epoch metadata log identity does not match configuration")
        load_epoch_metadata_document = epoch_document
        epoch_payload = json.dumps(
            load_epoch_metadata_document, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
    checkpoint_payload = None
    if last_checkpoint is not None:
        checkpoint_payload = json.dumps(
            {
                "format_version": CHECKPOINT_STATE_FORMAT_VERSION,
                "log_id": log_id,
                "checkpoint": last_checkpoint.model_dump(),
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    payloads: list[tuple[Path, bytes]] = [
        (path, payload.encode("utf-8")),
        (index_path, index_payload.encode("utf-8")),
    ]
    if epoch_payload is not None:
        payloads.append((epoch_path, epoch_payload.encode("utf-8")))
    if checkpoint_payload is not None:
        payloads.append((checkpoint_path, checkpoint_payload.encode("utf-8")))
    payloads.append((outbox_path, outbox.encode(next_outbox)))
    _commit_files(
        parent=parent,
        marker=marker,
        initialized=initialized,
        marker_document={
            "last_seq": candidate[0],
            "last_hash": candidate[1],
            "epoch_id": candidate[2],
            "log_id": candidate[3],
        },
        payloads=payloads,
    )


def acknowledge_outbox(expected_log_id: str, seq: int, entry_hash: str) -> outbox.OutboxSnapshot:
    """Acknowledge one outbox prefix entry without touching the commit marker."""

    last_seq, last_hash, _ = load_state(expected_log_id)
    current = load_outbox(expected_log_id)
    updated = outbox.ack(current, seq, entry_hash)
    outbox.validate_snapshot(updated, expected_log_id, expected_head=(last_seq, last_hash))
    outbox.write_outbox_atomic(_outbox_path(), updated)
    return updated

"""Crash-safe persistence for the signer's durable chain state."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from libs.blackbox_core.chain import GENESIS_PREV_HASH
from libs.blackbox_core.encoding import decode_hash

DEFAULT_STATE_PATH = Path("/var/lib/blackbox/signer/state.json")
_STATE_FIELDS = frozenset({"last_seq", "last_hash", "epoch_id", "log_id"})
_MARKER_SUFFIX = ".commit"
_INITIALIZED_SUFFIX = ".initialized"


def _state_path() -> Path:
    configured_path = os.environ.get("SIGNER_STATE_PATH")
    return Path(configured_path) if configured_path else DEFAULT_STATE_PATH


def _marker_path(path: Path) -> Path:
    return path.with_name(f".{path.name}{_MARKER_SUFFIX}")


def _initialized_path(path: Path) -> Path:
    return path.with_name(f".{path.name}{_INITIALIZED_SUFFIX}")


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
    return last_seq, last_hash, epoch_id


def _fsync_directory(directory: Path) -> None:
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def persist_state(last_seq: int, last_hash: str, epoch_id: int, log_id: str) -> None:
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

    marker_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(marker_fd, "w", encoding="utf-8") as marker_file:
            marker_fd = -1
            json.dump(
                {
                    "last_seq": candidate[0],
                    "last_hash": candidate[1],
                    "epoch_id": candidate[2],
                    "log_id": candidate[3],
                },
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
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    open_descriptor: int | None = file_descriptor
    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as temporary_file:
            open_descriptor = None
            temporary_file.write(payload)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        _fsync_directory(parent)
        initialized = _initialized_path(path)
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
        if open_descriptor is not None:
            os.close(open_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass

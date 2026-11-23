"""Append-only issuance journal for crash/lost-response reconciliation (Task E2b)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from libs.blackbox_core.encoding import decode_hash
from libs.blackbox_core.schemas import Intent, Outcome, SealedEntry
from services.signer import state

JOURNAL_SUFFIX = ".journal.jsonl"
_JOURNAL_FIELDS = frozenset(
    {
        "log_id",
        "seq",
        "entry_hash",
        "epoch_id",
        "entry_type",
        "issued_at",
        "intent_seq",
        "idempotency_key",
    }
)


class JournalError(ValueError):
    """Base error for issuance journal failures."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


class JournalIntegrityError(JournalError):
    """Raised when journal contents fail integrity or sequence validation."""


@dataclass(frozen=True)
class IssuanceRecord:
    """Durable record of an entry issued to a caller."""

    log_id: str
    seq: int
    entry_hash: str
    epoch_id: int
    entry_type: str
    issued_at: str
    intent_seq: int | None = None
    idempotency_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _journal_path(path: Path | None = None) -> Path:
    if path is not None:
        if path.name.endswith(JOURNAL_SUFFIX):
            return path
        return path.with_name(f"{path.name}{JOURNAL_SUFFIX}")
    configured = os.environ.get("SIGNER_JOURNAL_PATH")
    if configured:
        return Path(configured)
    base_state_path = state._state_path()
    return base_state_path.with_name(f"{base_state_path.name}{JOURNAL_SUFFIX}")


def _fsync_dir(directory: Path) -> None:
    try:
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def record_from_sealed(sealed: SealedEntry, now: str) -> IssuanceRecord:
    """Build an issuance record from a sealed entry."""
    body = sealed.body
    intent_seq: int | None = None
    idempotency_key: str | None = None

    if isinstance(body, Outcome):
        intent_seq = body.intent_seq
        idempotency_key = body.action.idempotency_key
    elif isinstance(body, Intent):
        idempotency_key = body.action.idempotency_key

    from libs.blackbox_core.chain import entry_hash

    return IssuanceRecord(
        log_id=body.log_id,
        seq=body.seq,
        entry_hash=entry_hash(body),
        epoch_id=body.epoch_id,
        entry_type=body.type,
        issued_at=now,
        intent_seq=intent_seq,
        idempotency_key=idempotency_key,
    )


def append_issuance(record: IssuanceRecord, path: Path | None = None) -> Path:
    """Append and fsync an issuance record before returning to the caller.

    Guarantees the reservation is durable before external observation.
    """
    decode_hash(record.log_id)
    decode_hash(record.entry_hash)
    if record.seq < 0:
        raise JournalIntegrityError("invalid_seq", "Sequence number must be non-negative")
    if record.epoch_id < 0:
        raise JournalIntegrityError("invalid_epoch", "Epoch ID must be non-negative")

    journal_file_path = _journal_path(path)
    journal_file_path.parent.mkdir(parents=True, exist_ok=True)

    payload = (
        json.dumps(
            record.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )

    fd = os.open(journal_file_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)

    _fsync_dir(journal_file_path.parent)
    return journal_file_path


def read_journal(
    path: Path | None = None, expected_log_id: str | None = None
) -> list[IssuanceRecord]:
    """Read all valid records from the issuance journal, verifying continuity."""
    journal_file_path = _journal_path(path)
    if not journal_file_path.exists():
        return []

    records: list[IssuanceRecord] = []
    last_seq = -1

    try:
        with open(journal_file_path, "r", encoding="utf-8") as file:
            for line_no, line in enumerate(file, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    data = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise JournalIntegrityError(
                        "corrupt_line", f"Corrupt JSON at line {line_no}"
                    ) from exc

                if not isinstance(data, dict):
                    raise JournalIntegrityError(
                        "invalid_record", f"Record at line {line_no} is not a JSON object"
                    )

                missing = _JOURNAL_FIELDS - set(data.keys())
                if missing:
                    raise JournalIntegrityError(
                        "missing_fields", f"Missing fields at line {line_no}: {missing}"
                    )

                if expected_log_id and data["log_id"] != expected_log_id:
                    raise JournalIntegrityError(
                        "log_mismatch",
                        f"Log mismatch at line {line_no}: expected {expected_log_id}, got {data['log_id']}",
                    )

                seq = data["seq"]
                if seq <= last_seq:
                    raise JournalIntegrityError(
                        "sequence_regression",
                        f"Non-monotonic sequence at line {line_no}: {seq} <= {last_seq}",
                    )
                last_seq = seq

                records.append(
                    IssuanceRecord(
                        log_id=data["log_id"],
                        seq=data["seq"],
                        entry_hash=data["entry_hash"],
                        epoch_id=data["epoch_id"],
                        entry_type=data["entry_type"],
                        issued_at=data["issued_at"],
                        intent_seq=data.get("intent_seq"),
                        idempotency_key=data.get("idempotency_key"),
                    )
                )
    except OSError as exc:
        raise JournalError("journal_unreadable", f"Cannot read journal: {exc}") from exc

    return records


def find_issued_by_seq(
    seq: int, path: Path | None = None, log_id: str | None = None
) -> IssuanceRecord | None:
    """Look up an issued record by its sequence number."""
    for record in read_journal(path, expected_log_id=log_id):
        if record.seq == seq:
            return record
    return None


def find_issued_by_idempotency(
    idempotency_key: str, path: Path | None = None, log_id: str | None = None
) -> IssuanceRecord | None:
    """Look up an issued record by idempotency key."""
    for record in read_journal(path, expected_log_id=log_id):
        if record.idempotency_key == idempotency_key:
            return record
    return None


def get_journal_frontier(
    path: Path | None = None, log_id: str | None = None
) -> tuple[int, str] | None:
    """Return the (seq, entry_hash) of the latest journaled entry, or None if empty."""
    records = read_journal(path, expected_log_id=log_id)
    if not records:
        return None
    latest = records[-1]
    return latest.seq, latest.entry_hash

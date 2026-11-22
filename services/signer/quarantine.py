"""Durable quarantine storage and enforcement for signer crash recovery (Task E)."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from libs.blackbox_core.encoding import decode_hash
from services.signer import clock, state

QUARANTINE_SUFFIX = ".quarantine.json"
QUARANTINE_FORMAT_VERSION = "1"
_QUARANTINE_FIELDS = frozenset(
    {
        "format_version",
        "log_id",
        "status",
        "reason",
        "details",
        "quarantined_at",
        "last_known_seq",
        "last_known_hash",
        "recovery_generation",
        "recovered_at",
        "recovery_receipt",
    }
)


class QuarantineError(ValueError):
    """Base error for quarantine operations."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


class QuarantineActiveError(QuarantineError):
    """Raised when an operation is attempted while signer is quarantined."""

    def __init__(self, reason: str, details: str = "") -> None:
        self.reason = reason
        self.details = details
        super().__init__("quarantined", f"Signer is quarantined: {reason}")


@dataclass(frozen=True)
class QuarantineRecord:
    """Durable record of quarantine state."""

    format_version: str
    log_id: str
    status: str  # "quarantined" or "recovered"
    reason: str
    details: str
    quarantined_at: str
    last_known_seq: int
    last_known_hash: str
    recovery_generation: int
    recovered_at: str | None = None
    recovery_receipt: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _quarantine_path(path: Path | None = None) -> Path:
    if path is not None:
        if path.name.endswith(QUARANTINE_SUFFIX):
            return path
        return path.with_name(f"{path.name}{QUARANTINE_SUFFIX}")
    configured = os.environ.get("SIGNER_QUARANTINE_PATH")
    if configured:
        return Path(configured)
    base_state_path = state._state_path()
    return base_state_path.with_name(f"{base_state_path.name}{QUARANTINE_SUFFIX}")


def _fsync_dir(directory: Path) -> None:
    try:
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def is_quarantined(path: Path | None = None) -> bool:
    """Return True if signer is currently quarantined or marker is present."""
    base_state_path = state._state_path() if path is None else path
    marker = state._marker_path(base_state_path)
    if marker.exists():
        return True

    record = load_quarantine(path)
    if record is not None and record.status == "quarantined":
        return True
    return False


def get_quarantine_reason(path: Path | None = None) -> str | None:
    """Return the active quarantine reason, or None if healthy."""
    base_state_path = state._state_path() if path is None else path
    marker = state._marker_path(base_state_path)
    if marker.exists():
        return "marker_detected"

    record = load_quarantine(path)
    if record is not None and record.status == "quarantined":
        return record.reason
    return None


def load_quarantine(path: Path | None = None) -> QuarantineRecord | None:
    """Load and validate the durable quarantine record if present."""
    q_path = _quarantine_path(path)
    if not q_path.exists():
        return None

    try:
        with open(q_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise QuarantineError("corrupt_quarantine", f"Cannot parse quarantine file: {exc}") from exc

    if not isinstance(data, dict):
        raise QuarantineError("invalid_quarantine", "Quarantine file is not a JSON object")

    missing = _QUARANTINE_FIELDS - set(data.keys())
    if missing:
        raise QuarantineError("missing_fields", f"Quarantine record missing fields: {missing}")

    return QuarantineRecord(
        format_version=data["format_version"],
        log_id=data["log_id"],
        status=data["status"],
        reason=data["reason"],
        details=data["details"],
        quarantined_at=data["quarantined_at"],
        last_known_seq=data["last_known_seq"],
        last_known_hash=data["last_known_hash"],
        recovery_generation=data["recovery_generation"],
        recovered_at=data.get("recovered_at"),
        recovery_receipt=data.get("recovery_receipt"),
    )


def enter_quarantine(
    log_id: str,
    reason: str,
    details: str = "",
    last_known_seq: int = -1,
    last_known_hash: str = "sha256:" + "0" * 64,
    recovery_generation: int = 0,
    path: Path | None = None,
    now: str | None = None,
) -> QuarantineRecord:
    """Durably record that the signer has entered quarantine."""
    decode_hash(log_id)
    timestamp = now or clock.system_utc_now()
    q_path = _quarantine_path(path)
    q_path.parent.mkdir(parents=True, exist_ok=True)

    record = QuarantineRecord(
        format_version=QUARANTINE_FORMAT_VERSION,
        log_id=log_id,
        status="quarantined",
        reason=reason,
        details=details,
        quarantined_at=timestamp,
        last_known_seq=last_known_seq,
        last_known_hash=last_known_hash,
        recovery_generation=recovery_generation,
    )

    _write_atomic(q_path, record.to_dict())
    return record


def lift_quarantine(
    recovery_receipt: dict[str, Any],
    path: Path | None = None,
    now: str | None = None,
) -> QuarantineRecord:
    """Durably record that recovery was completed and quarantine is lifted."""
    existing = load_quarantine(path)
    if existing is None:
        raise QuarantineError("no_quarantine", "Cannot lift non-existent quarantine")

    timestamp = now or clock.system_utc_now()
    q_path = _quarantine_path(path)

    updated = QuarantineRecord(
        format_version=QUARANTINE_FORMAT_VERSION,
        log_id=existing.log_id,
        status="recovered",
        reason=existing.reason,
        details=existing.details,
        quarantined_at=existing.quarantined_at,
        last_known_seq=existing.last_known_seq,
        last_known_hash=existing.last_known_hash,
        recovery_generation=existing.recovery_generation + 1,
        recovered_at=timestamp,
        recovery_receipt=recovery_receipt,
    )

    _write_atomic(q_path, updated.to_dict())
    return updated


def _write_atomic(target_path: Path, document: dict[str, Any]) -> None:
    parent = target_path.parent
    payload = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )

    descriptor, temp_path_str = tempfile.mkstemp(
        prefix=f".{target_path.name}.", suffix=".tmp", dir=parent
    )
    temp_path = Path(temp_path_str)
    try:
        with os.fdopen(descriptor, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, target_path)
        _fsync_dir(parent)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass

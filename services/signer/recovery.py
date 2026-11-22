"""Startup-enforced recovery anchor and receipt management (Task E)."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from libs.blackbox_core.encoding import decode_hash
from services.signer import clock, state

ANCHOR_SUFFIX = ".recovery.json"
ANCHOR_FORMAT_VERSION = "1"
_ANCHOR_FIELDS = frozenset(
    {
        "format_version",
        "log_id",
        "recovery_outcome",
        "recovery_generation",
        "frontier_seq",
        "frontier_hash",
        "operator_id",
        "reason",
        "recovered_at",
        "burned_range",
        "old_log_id",
        "recovery_entry_hash",
    }
)


class RecoveryError(ValueError):
    """Base error for recovery anchor and validation failures."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


@dataclass(frozen=True)
class RecoveryAnchor:
    """Durable receipt and anchor of an authorized recovery."""

    format_version: str
    log_id: str
    recovery_outcome: Literal["same_log_continuation", "new_log_restart"]
    recovery_generation: int
    frontier_seq: int
    frontier_hash: str
    operator_id: str
    reason: str
    recovered_at: str
    burned_range: list[int] | None = None
    old_log_id: str | None = None
    recovery_entry_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _anchor_path(path: Path | None = None) -> Path:
    if path is not None:
        if path.name.endswith(ANCHOR_SUFFIX):
            return path
        return path.with_name(f"{path.name}{ANCHOR_SUFFIX}")
    configured = os.environ.get("SIGNER_RECOVERY_ANCHOR_PATH")
    if configured:
        return Path(configured)
    base_state_path = state._state_path()
    return base_state_path.with_name(f"{base_state_path.name}{ANCHOR_SUFFIX}")


def _fsync_dir(directory: Path) -> None:
    try:
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def load_recovery_anchor(path: Path | None = None) -> RecoveryAnchor | None:
    """Load and parse the durable recovery anchor if present."""
    a_path = _anchor_path(path)
    if not a_path.exists():
        return None

    try:
        with open(a_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError("corrupt_anchor", f"Cannot parse recovery anchor: {exc}") from exc

    if not isinstance(data, dict):
        raise RecoveryError("invalid_anchor", "Recovery anchor is not a JSON object")

    missing = _ANCHOR_FIELDS - set(data.keys())
    if missing:
        raise RecoveryError("missing_fields", f"Recovery anchor missing fields: {missing}")

    return RecoveryAnchor(
        format_version=data["format_version"],
        log_id=data["log_id"],
        recovery_outcome=data["recovery_outcome"],
        recovery_generation=data["recovery_generation"],
        frontier_seq=data["frontier_seq"],
        frontier_hash=data["frontier_hash"],
        operator_id=data["operator_id"],
        reason=data["reason"],
        recovered_at=data["recovered_at"],
        burned_range=data.get("burned_range"),
        old_log_id=data.get("old_log_id"),
        recovery_entry_hash=data.get("recovery_entry_hash"),
    )


def create_recovery_anchor(
    log_id: str,
    outcome: Literal["same_log_continuation", "new_log_restart"],
    frontier_seq: int,
    frontier_hash: str,
    operator_id: str,
    reason: str,
    recovery_generation: int = 1,
    burned_range: list[int] | None = None,
    old_log_id: str | None = None,
    recovery_entry_hash: str | None = None,
    path: Path | None = None,
    now: str | None = None,
) -> RecoveryAnchor:
    """Durably persist an authorized recovery anchor."""
    decode_hash(log_id)
    decode_hash(frontier_hash)
    if old_log_id:
        decode_hash(old_log_id)
    if recovery_generation < 1:
        raise RecoveryError("invalid_generation", "Recovery generation must be a positive integer")

    timestamp = now or clock.system_utc_now()
    a_path = _anchor_path(path)
    a_path.parent.mkdir(parents=True, exist_ok=True)

    anchor = RecoveryAnchor(
        format_version=ANCHOR_FORMAT_VERSION,
        log_id=log_id,
        recovery_outcome=outcome,
        recovery_generation=recovery_generation,
        frontier_seq=frontier_seq,
        frontier_hash=frontier_hash,
        operator_id=operator_id,
        reason=reason,
        recovered_at=timestamp,
        burned_range=burned_range,
        old_log_id=old_log_id,
        recovery_entry_hash=recovery_entry_hash,
    )

    parent = a_path.parent
    payload = json.dumps(
        anchor.to_dict(), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")

    descriptor, temp_path_str = tempfile.mkstemp(
        prefix=f".{a_path.name}.", suffix=".tmp", dir=parent
    )
    temp_path = Path(temp_path_str)
    try:
        with os.fdopen(descriptor, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, a_path)
        _fsync_dir(parent)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass

    return anchor


def validate_startup_recovery(
    state_seq: int,
    state_hash: str,
    log_id: str,
    path: Path | None = None,
) -> None:
    """Enforce recovery anchor invariants during signer startup.

    Rejects stale or rolled-back state that is below the durable recovery frontier.
    """
    anchor = load_recovery_anchor(path)
    if anchor is None:
        return

    if anchor.log_id != log_id:
        raise RecoveryError(
            "log_mismatch",
            f"Recovery anchor log_id {anchor.log_id} does not match configured {log_id}",
        )

    if state_seq < anchor.frontier_seq:
        raise RecoveryError(
            "state_below_recovery_frontier",
            f"Durable state sequence {state_seq} is below recovery frontier {anchor.frontier_seq}",
        )

    if state_seq == anchor.frontier_seq and state_hash != anchor.frontier_hash:
        raise RecoveryError(
            "frontier_hash_mismatch",
            f"State hash at frontier ({state_hash}) does not match anchor ({anchor.frontier_hash})",
        )

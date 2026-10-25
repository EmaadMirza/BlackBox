"""Witness heartbeat validation and stable stall/mismatch decisions."""

from __future__ import annotations

from libs.blackbox_core.heartbeat import heartbeat_matches_checkpoint
from libs.blackbox_core.schemas import Checkpoint, Heartbeat

# TODO(spec §11.4): implement and validate before enabling this module.


def inspect(
    heartbeat: Heartbeat | None,
    checkpoint: Checkpoint | None,
    now: str,
    *,
    interval_seconds: int = 5,
    tolerance: int = 3,
) -> list[str]:
    alarms: list[str] = []
    if heartbeat is None:
        return ["HEARTBEAT_STALL"]
    if checkpoint is not None and not heartbeat_matches_checkpoint(heartbeat, checkpoint):
        alarms.append("HEARTBEAT_MISMATCH")
    if heartbeat.signer_timestamp > now:
        alarms.append("HEARTBEAT_STALL")
    return alarms


def checkpoint_stall(
    heartbeat: Heartbeat | None,
    checkpoint: Checkpoint | None,
    now: str,
    *,
    interval_seconds: int = 5,
    tolerance: int = 3,
    unverified_window: int = 0,
) -> list[str]:
    if heartbeat is None or checkpoint is None:
        return []
    if heartbeat.signer_timestamp <= now and heartbeat.latest_seq <= checkpoint.latest_seq:
        return ["CHECKPOINT_STALL"] if unverified_window >= interval_seconds * tolerance else []
    return []

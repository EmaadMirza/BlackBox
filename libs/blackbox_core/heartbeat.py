"""Heartbeat construction, expiry checks, and checkpoint contradiction checks."""

from libs.blackbox_core.epochs import in_window
from libs.blackbox_core.schemas import Checkpoint, Heartbeat
from libs.blackbox_core.signing import verify_structure


def verify_heartbeat(
    heartbeat: Heartbeat,
    public_key: bytes,
    now: str,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> bool:
    if (
        valid_from is not None
        and valid_until is not None
        and not in_window(heartbeat.signer_timestamp, valid_from, valid_until)
    ):
        return False
    return heartbeat.signer_timestamp <= now and verify_structure(
        heartbeat, public_key, "heartbeat"
    )


def heartbeat_matches_checkpoint(heartbeat: Heartbeat, checkpoint: Checkpoint) -> bool:
    return (
        heartbeat.log_id == checkpoint.log_id
        and heartbeat.latest_seq >= checkpoint.latest_seq
        and heartbeat.latest_entry_hash == checkpoint.latest_entry_hash
    )

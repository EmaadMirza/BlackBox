"""Manual migration for pre-outbox signer state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from services.signer import outbox, state


class MigrationError(ValueError):
    """Stable refusal raised when migration cannot prove a safe empty queue."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


def migrate_outbox(
    state_path: Path,
    expected_log_id: str,
    ledger_seq: int,
    ledger_hash: str,
) -> Path:
    """Create an empty outbox only after operator-supplied head reconciliation."""

    state_path = Path(state_path)
    marker = state._marker_path(state_path)
    initialized = state._initialized_path(state_path)
    outbox_path = state._outbox_path(state_path)
    if marker.exists():
        raise MigrationError("uncertain_commit", "signer commit marker is present")
    if not state_path.exists():
        raise MigrationError("state_missing", "signer state is missing")
    if not initialized.exists():
        raise MigrationError("not_initialized", "signer state is not initialized")
    if outbox_path.exists():
        raise MigrationError("outbox_exists", "signer outbox already exists")
    try:
        document = json.loads(
            state_path.read_text(encoding="utf-8"),
            object_pairs_hook=state._reject_duplicate_fields,
            parse_constant=state._reject_json_constant,
        )
        last_seq, last_hash, _, log_id = state._validate_document(document)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise MigrationError("state_invalid", "signer state is invalid") from exc
    if log_id != expected_log_id:
        raise MigrationError("log_mismatch", "configured log identity does not match state")
    try:
        if type(ledger_seq) is not int or ledger_seq < -1:
            raise ValueError
        from libs.blackbox_core.encoding import decode_hash

        decode_hash(ledger_hash)
    except (TypeError, ValueError) as exc:
        raise MigrationError("ledger_head_invalid", "ledger head is invalid") from exc
    if (ledger_seq, ledger_hash) != (last_seq, last_hash):
        raise MigrationError("ledger_head_mismatch", "ledger head does not match signer state")
    snapshot = outbox.OutboxSnapshot(expected_log_id, ledger_seq, ledger_hash, ())
    outbox.validate_snapshot(snapshot, expected_log_id, expected_head=(last_seq, last_hash))
    outbox.write_outbox_atomic(outbox_path, snapshot)
    return outbox_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a reconciled empty signer outbox")
    parser.add_argument("--state-path", type=Path, required=True)
    parser.add_argument("--log-id", required=True)
    parser.add_argument("--ledger-seq", type=int, required=True)
    parser.add_argument("--ledger-hash", required=True)
    args = parser.parse_args()
    print(migrate_outbox(args.state_path, args.log_id, args.ledger_seq, args.ledger_hash))


if __name__ == "__main__":
    main()

"""Automated operator rebuild and crash recovery engine (Task C, E, R)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from libs.blackbox_core import canonical, sealing
from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.encoding import decode_hash
from libs.blackbox_core.schemas import Outcome, SealedEntry, parse_entry
from services.signer import clock, journal, outbox, quarantine, recovery, state


class RebuildError(ValueError):
    """Base error for operator rebuild and recovery failures."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


@dataclass(frozen=True)
class SignerStorageStatus:
    """Diagnostic status of signer durable storage."""

    state_path: str
    log_id: str | None
    last_seq: int | None
    last_hash: str | None
    epoch_id: int | None
    marker_present: bool
    initialized: bool
    outcomes_count: int
    outbox_pending_count: int
    journal_records_count: int
    quarantined: bool
    quarantine_reason: str | None
    recovery_generation: int
    healthy: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_path": self.state_path,
            "log_id": self.log_id,
            "last_seq": self.last_seq,
            "last_hash": self.last_hash,
            "epoch_id": self.epoch_id,
            "marker_present": self.marker_present,
            "initialized": self.initialized,
            "outcomes_count": self.outcomes_count,
            "outbox_pending_count": self.outbox_pending_count,
            "journal_records_count": self.journal_records_count,
            "quarantined": self.quarantined,
            "quarantine_reason": self.quarantine_reason,
            "recovery_generation": self.recovery_generation,
            "healthy": self.healthy,
        }


def get_signer_status(state_path: Path | None = None) -> SignerStorageStatus:
    """Inspect signer storage and return diagnostic health status."""
    path = state._state_path() if state_path is None else Path(state_path)
    marker = state._marker_path(path)
    initialized = state._initialized_path(path)
    marker_present = marker.exists()
    init_present = initialized.exists()

    last_seq: int | None = None
    last_hash: str | None = None
    epoch_id: int | None = None
    log_id: str | None = None

    if path.exists() and not marker_present:
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            last_seq, last_hash, epoch_id, log_id = state._validate_document(doc)
        except Exception:
            pass

    outcomes_count = 0
    if log_id:
        try:
            idx = state.load_outcome_index(log_id)
            outcomes_count = len(idx)
        except Exception:
            pass

    outbox_count = 0
    if log_id and not marker_present:
        try:
            snapshot = state.load_outbox(log_id)
            outbox_count = len(snapshot.entries)
        except Exception:
            pass

    journal_count = 0
    try:
        records = journal.read_journal(path, expected_log_id=log_id)
        journal_count = len(records)
    except Exception:
        pass

    quarantined = quarantine.is_quarantined(path)
    q_reason = quarantine.get_quarantine_reason(path)

    rec_anchor = recovery.load_recovery_anchor(path)
    rec_gen = rec_anchor.recovery_generation if rec_anchor else 0

    healthy = (
        not marker_present
        and not quarantined
        and init_present
        and path.exists()
        and log_id is not None
    )

    return SignerStorageStatus(
        state_path=str(path),
        log_id=log_id,
        last_seq=last_seq,
        last_hash=last_hash,
        epoch_id=epoch_id,
        marker_present=marker_present,
        initialized=init_present,
        outcomes_count=outcomes_count,
        outbox_pending_count=outbox_count,
        journal_records_count=journal_count,
        quarantined=quarantined,
        quarantine_reason=q_reason,
        recovery_generation=rec_gen,
        healthy=healthy,
    )


def rebuild_same_log(
    *,
    state_path: Path,
    expected_log_id: str,
    frontier_seq: int,
    frontier_hash: str,
    history_entries: Iterable[SealedEntry],
    operator_id: str,
    reason: str,
    now: str | None = None,
) -> recovery.RecoveryAnchor:
    """Rebuild coherent state and outcome index from authenticated history prefix.

    Safely clears commit markers, restores state and index, persists recovery anchor,
    and lifts durable quarantine.
    """
    decode_hash(expected_log_id)
    decode_hash(frontier_hash)
    if frontier_seq < -1:
        raise RebuildError("invalid_frontier", "Frontier sequence must be >= -1")

    path = Path(state_path)
    entries = list(history_entries)

    # Validate complete-prefix history up to frontier
    outcome_index: dict[int, str] = {}
    last_seq = -1
    last_hash = GENESIS_PREV_HASH
    last_epoch = 0

    if frontier_seq >= 0:
        if not entries:
            raise RebuildError(
                "empty_history", "History entries required for positive frontier sequence"
            )

        for idx, entry in enumerate(entries):
            body = entry.body
            if body.log_id != expected_log_id:
                raise RebuildError(
                    "log_mismatch",
                    f"Entry {idx} log_id {body.log_id} != expected {expected_log_id}",
                )
            if body.seq != last_seq + 1:
                raise RebuildError(
                    "sequence_gap",
                    f"Entry {idx} sequence {body.seq} != expected {last_seq + 1}",
                )
            if body.prev_hash != last_hash:
                raise RebuildError(
                    "chain_break",
                    f"Entry {idx} prev_hash {body.prev_hash} != expected {last_hash}",
                )

            current_hash = entry_hash(body)
            last_seq = body.seq
            last_hash = current_hash
            last_epoch = body.epoch_id

            if isinstance(body, Outcome):
                outcome_index[body.intent_seq] = current_hash

            if last_seq == frontier_seq:
                break

        if last_seq != frontier_seq:
            raise RebuildError(
                "frontier_not_reached",
                f"History ended at sequence {last_seq}, frontier is {frontier_seq}",
            )
        if last_hash != frontier_hash:
            raise RebuildError(
                "frontier_hash_mismatch",
                f"Computed hash {last_hash} != declared frontier hash {frontier_hash}",
            )

    # Obtain current recovery generation
    existing_anchor = recovery.load_recovery_anchor(path)
    next_gen = (existing_anchor.recovery_generation + 1) if existing_anchor else 1

    # Atomic write of rebuilt files
    marker = state._marker_path(path)
    initialized = state._initialized_path(path)
    if marker.exists():
        marker.unlink()

    state_payload = canonical.canonicalize(
        {
            "epoch_id": last_epoch,
            "last_hash": last_hash,
            "last_seq": last_seq,
            "log_id": expected_log_id,
        }
    )

    index_payload = canonical.canonicalize(
        {
            "format_version": state.OUTCOME_INDEX_FORMAT_VERSION,
            "log_id": expected_log_id,
            "outcomes": outcome_index,
        }
    )

    outbox_snapshot = outbox.OutboxSnapshot(
        log_id=expected_log_id,
        delivered_seq=last_seq,
        delivered_hash=last_hash,
        entries=(),
    )
    outbox_payload = canonical.canonicalize(outbox._snapshot_document(outbox_snapshot))

    # Replace durable files atomically
    state._commit_files(
        parent=path.parent,
        marker=marker,
        initialized=initialized,
        marker_document={"rebuild": True, "frontier_seq": frontier_seq},
        payloads=[
            (path, state_payload),
            (state._outcome_index_path(path), index_payload),
            (state._outbox_path(path), outbox_payload),
        ],
    )

    # Persist recovery anchor
    anchor = recovery.create_recovery_anchor(
        log_id=expected_log_id,
        outcome="same_log_continuation",
        frontier_seq=last_seq,
        frontier_hash=last_hash,
        operator_id=operator_id,
        reason=reason,
        recovery_generation=next_gen,
        path=path,
        now=now,
    )

    # Lift quarantine if present
    if quarantine.load_quarantine(path) is not None:
        quarantine.lift_quarantine(
            recovery_receipt=anchor.to_dict(),
            path=path,
            now=now,
        )

    return anchor


def burn_discontinuity(
    *,
    state_path: Path,
    expected_log_id: str,
    burned_first_seq: int,
    burned_last_seq: int,
    last_known_hash: str,
    lost_epoch_id: int,
    new_epoch_id: int,
    signing_operation: Callable[[bytes], bytes],
    operator_id: str,
    reason: str,
    now: str | None = None,
) -> tuple[SealedEntry, recovery.RecoveryAnchor]:
    """Mint a signed Recovery entry burning an uncertain sequence range (Spec Amendment 001).

    Produces a valid new-epoch recovery entry, advances chain state, appends to the
    issuance journal, and creates a recovery anchor.
    """
    decode_hash(expected_log_id)
    decode_hash(last_known_hash)
    if burned_first_seq > burned_last_seq:
        raise RebuildError("invalid_range", "burned_first_seq > burned_last_seq")
    if new_epoch_id <= lost_epoch_id:
        raise RebuildError("invalid_epoch", "new_epoch_id must be > lost_epoch_id")

    timestamp = now or clock.system_utc_now()
    path = Path(state_path)
    recovery_seq = burned_last_seq + 1

    recovery_candidate = parse_entry(
        {
            "format_version": "4",
            "type": "recovery",
            "seq": recovery_seq,
            "prev_hash": last_known_hash,
            "log_id": expected_log_id,
            "epoch_id": new_epoch_id,
            "signer_timestamp": timestamp,
            "lane": "agent",
            "epoch_certificate_id": "sha256:" + "0" * 64,
            "burned_first_seq": burned_first_seq,
            "burned_last_seq": burned_last_seq,
            "last_known_entry_hash": last_known_hash,
            "lost_epoch_id": lost_epoch_id,
        }
    )

    sealed_recovery = sealing.seal(recovery_candidate, signing_operation)
    new_hash = entry_hash(sealed_recovery.body)

    # Load existing outcome index
    outcome_index: Mapping[int, str] = {}
    try:
        outcome_index = state.load_outcome_index(expected_log_id)
    except Exception:
        pass

    # Durable commit of state, outbox, and journal
    state.persist_state(
        recovery_seq,
        new_hash,
        new_epoch_id,
        expected_log_id,
        outcome_index,
        outbox_append=(sealed_recovery,),
        reserved=True,
    )

    # Append to issuance journal
    journal.append_issuance(
        journal.record_from_sealed(sealed_recovery, timestamp),
        path=path,
    )

    # Update recovery anchor
    existing_anchor = recovery.load_recovery_anchor(path)
    next_gen = (existing_anchor.recovery_generation + 1) if existing_anchor else 1

    anchor = recovery.create_recovery_anchor(
        log_id=expected_log_id,
        outcome="same_log_continuation",
        frontier_seq=recovery_seq,
        frontier_hash=new_hash,
        operator_id=operator_id,
        reason=reason,
        recovery_generation=next_gen,
        burned_range=[burned_first_seq, burned_last_seq],
        recovery_entry_hash=new_hash,
        path=path,
        now=timestamp,
    )

    if quarantine.load_quarantine(path) is not None:
        quarantine.lift_quarantine(
            recovery_receipt=anchor.to_dict(),
            path=path,
            now=timestamp,
        )

    return sealed_recovery, anchor

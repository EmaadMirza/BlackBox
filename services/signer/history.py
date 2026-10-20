"""Authenticated history-source contract for signer outcome validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.encoding import decode_base64url
from libs.blackbox_core.epochs import certificate_id, validate_contiguity, verify_epoch_certificate
from libs.blackbox_core.schemas import EpochEnd, EpochStart, SealedEntry
from libs.blackbox_core.sealing import verify_entry


class HistorySourceError(OSError):
    """The advisory history source is unavailable or returned no evidence."""


class HistoryIntegrityError(ValueError):
    """Returned history failed authenticated evidence validation."""


class OutcomeConflictError(ValueError):
    """The signer-owned outcome index conflicts with a new outcome."""


@dataclass(frozen=True)
class HistoryEntryEvidence:
    """One sealed entry plus the certificate material needed to verify it."""

    entry: SealedEntry
    epoch_certificate: object
    intermediate_certificate: object
    root_public_key: bytes


@dataclass(frozen=True)
class HistoryRecord:
    """A complete authenticated prefix ending at the requested entry."""

    entries: tuple[HistoryEntryEvidence, ...]
    target_seq: int


class HistorySource(Protocol):
    """Future ledger-backed positive-evidence queries.

    Neither method represents absence of an outcome. The signer-owned outcome
    index is the authority for uniqueness; a source is queried only for a
    positive intent or prior outcome that can be cryptographically verified.
    """

    def get_intent(self, log_id: str, intent_seq: int) -> HistoryRecord: ...

    def get_outcome(self, log_id: str, intent_seq: int, outcome_hash: str) -> HistoryRecord: ...


def verify_history_record(
    record: HistoryRecord, expected_log_id: str, *, target_seq: int
) -> SealedEntry:
    """Verify a complete prefix and return its target entry.

    A partial segment is deliberately not accepted: the signer needs a genesis
    anchored chain, not an advisory database row. Every returned entry is
    signature-, hash-, log- and epoch-certificate-checked.
    """

    if not isinstance(record, HistoryRecord) or type(target_seq) is not int or target_seq < 0:
        raise HistoryIntegrityError("history record shape is invalid")
    if not record.entries or record.target_seq != target_seq:
        raise HistoryIntegrityError("history record target is stale or missing")
    first_root: bytes | None = None
    previous: HistoryEntryEvidence | None = None
    for expected_seq, evidence in enumerate(record.entries):
        try:
            entry = SealedEntry.model_validate(evidence.entry)
            cert = evidence.epoch_certificate
            intermediate = evidence.intermediate_certificate
            root = evidence.root_public_key
            body = entry.body
            if body.seq != expected_seq or body.log_id != expected_log_id:
                raise HistoryIntegrityError("history sequence or log identity mismatch")
            if not isinstance(root, bytes) or len(root) != 32:
                raise HistoryIntegrityError("history root key is invalid")
            if first_root is None:
                first_root = root
            elif root != first_root:
                raise HistoryIntegrityError("history root key changed")
            if cert.log_id != expected_log_id or intermediate.log_id != expected_log_id:
                raise HistoryIntegrityError("history certificate log mismatch")
            if body.epoch_certificate_id != certificate_id(cert):
                raise HistoryIntegrityError("history epoch certificate reference mismatch")
            if not verify_epoch_certificate(cert, intermediate, root, body.signer_timestamp):
                raise HistoryIntegrityError("history epoch certificate is not valid")
            if not verify_entry(entry, decode_base64url(cert.epoch_public_key)):
                raise HistoryIntegrityError("history entry signature is invalid")
            if expected_seq == 0:
                if body.prev_hash != GENESIS_PREV_HASH:
                    raise HistoryIntegrityError("history genesis link is invalid")
            else:
                if previous is None or body.prev_hash != entry_hash(previous.entry.body):
                    raise HistoryIntegrityError("history chain link is invalid")
                if body.epoch_id != previous.entry.body.epoch_id:
                    if not isinstance(previous.entry.body, EpochEnd) or not isinstance(
                        body, EpochStart
                    ):
                        raise HistoryIntegrityError("history epoch transition is invalid")
                    validate_contiguity(previous.epoch_certificate, cert)
            previous = evidence
        except HistoryIntegrityError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            raise HistoryIntegrityError("history evidence is malformed") from exc
    if previous is None or previous.entry.body.seq != target_seq:
        raise HistoryIntegrityError("history record does not end at target")
    return previous.entry

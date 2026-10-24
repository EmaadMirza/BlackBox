"""Authenticated history-source contract for signer outcome validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.encoding import decode_base64url
from libs.blackbox_core.epochs import certificate_id, validate_contiguity, verify_epoch_certificate
from libs.blackbox_core.schemas import (
    EpochCertificate,
    EpochEnd,
    EpochStart,
    IntermediateCertificate,
    SealedEntry,
)
from libs.blackbox_core.sealing import verify_entry


class HistorySourceError(OSError):
    """The advisory history source is unavailable or returned no evidence."""

    code = "history_unavailable"


class HistoryIntegrityError(ValueError):
    """Returned history failed authenticated evidence validation."""

    code = "history_integrity"
    alarm_code = "HISTORY_INTEGRITY"


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


class LedgerHistoryTransport(Protocol):
    """Read-only in-process transport for complete-prefix ledger evidence."""

    def get_intent(self, log_id: str, intent_seq: int) -> object: ...

    def get_outcome(self, log_id: str, intent_seq: int, outcome_hash: str) -> object: ...


class InProcessLedgerHistoryTransport:
    """Adapt a ledger FastAPI client to the advisory history transport."""

    def __init__(self, client: object, *, bearer_token: str) -> None:
        self._client = client
        self._bearer_token = bearer_token

    def get_intent(self, log_id: str, intent_seq: int) -> object:
        return self._get("/history/intent", {"log_id": log_id, "seq": intent_seq})

    def get_outcome(self, log_id: str, intent_seq: int, outcome_hash: str) -> object:
        return self._get(
            "/history/outcome",
            {"log_id": log_id, "intent_seq": intent_seq, "outcome_hash": outcome_hash},
        )

    def _get(self, path: str, params: dict[str, object]) -> object:
        try:
            response = cast("object", self._client).get(  # type: ignore[attr-defined]
                path,
                params=params,
                headers={"Authorization": f"Bearer {self._bearer_token}"},
            )
            if response.status_code != 200:  # type: ignore[attr-defined]
                raise HistorySourceError("ledger history is unavailable")
            return response.json()  # type: ignore[attr-defined]
        except HistorySourceError:
            raise
        except Exception as exc:
            raise HistorySourceError("ledger history is unavailable") from exc


class LedgerHistorySource:
    """Authenticated advisory history source backed by the ledger transport."""

    def __init__(self, transport: LedgerHistoryTransport) -> None:
        self._transport = transport

    def get_intent(self, log_id: str, intent_seq: int) -> HistoryRecord:
        raw = self._transport.get_intent(log_id, intent_seq)
        record = _record_from_wire(raw, log_id, intent_seq)
        _verified_target(record, log_id, intent_seq)
        return record

    def get_outcome(self, log_id: str, intent_seq: int, outcome_hash: str) -> HistoryRecord:
        raw = self._transport.get_outcome(log_id, intent_seq, outcome_hash)
        record = _record_from_wire(raw, log_id, None)
        target = record.target_seq
        target_entry = _verified_target(record, log_id, target)
        if entry_hash(target_entry.body) != outcome_hash:
            raise HistoryIntegrityError("ledger outcome disagrees with requested hash")
        if getattr(target_entry.body, "intent_seq", None) != intent_seq:
            raise HistoryIntegrityError("ledger outcome intent disagrees with request")
        return record


def _record_from_wire(
    raw: object, expected_log_id: str, expected_target: int | None
) -> HistoryRecord:
    if isinstance(raw, HistoryRecord):
        return raw
    if not isinstance(raw, dict) or set(raw) != {"target_seq", "entries"}:
        raise HistoryIntegrityError("ledger history response shape is invalid")
    target_seq = raw["target_seq"]
    entries = raw["entries"]
    if type(target_seq) is not int or target_seq < 0 or not isinstance(entries, list):
        raise HistoryIntegrityError("ledger history response is malformed")
    if expected_target is not None and target_seq != expected_target:
        raise HistoryIntegrityError("ledger history target is stale")
    evidence: list[HistoryEntryEvidence] = []
    try:
        for item in entries:
            if not isinstance(item, dict) or set(item) != {
                "entry",
                "epoch_certificate",
                "intermediate_certificate",
                "root_public_key",
            }:
                raise HistoryIntegrityError("ledger history evidence is malformed")
            evidence.append(
                HistoryEntryEvidence(
                    entry=SealedEntry.model_validate(item["entry"]),
                    epoch_certificate=EpochCertificate.model_validate(item["epoch_certificate"]),
                    intermediate_certificate=IntermediateCertificate.model_validate(
                        item["intermediate_certificate"]
                    ),
                    root_public_key=decode_base64url(cast(str, item["root_public_key"])),
                )
            )
    except HistoryIntegrityError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise HistoryIntegrityError("ledger history evidence is malformed") from exc
    record = HistoryRecord(entries=tuple(evidence), target_seq=target_seq)
    if not record.entries or record.entries[-1].entry.body.log_id != expected_log_id:
        raise HistoryIntegrityError("ledger history log identity is invalid")
    return record


def _verified_target(record: HistoryRecord, log_id: str, target_seq: int) -> SealedEntry:
    return verify_history_record(record, log_id, target_seq=target_seq)


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

"""Injectable ledger stores for the service-layer L1b semantics."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, Protocol

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.evidence import Bundle
from libs.blackbox_core.schemas import (
    EpochCertificate,
    IntermediateCertificate,
    SealedEntry,
)

if TYPE_CHECKING:
    from libs.blackbox_core.evidence import PinnedKeys


@dataclass(frozen=True)
class StoredEntry:
    entry: SealedEntry
    entry_hash: str


class LedgerStore(Protocol):
    """Storage operations used by the in-memory ledger service path."""

    def get_entry(self, log_id: str, seq: int) -> StoredEntry | None: ...

    def latest_entry(self, log_id: str) -> StoredEntry | None: ...

    def insert_entry(self, record: StoredEntry) -> None: ...

    def record_conflict(
        self,
        log_id: str,
        seq: int,
        existing_hash: str,
        rejected_hash: str,
        evidence: dict[str, object],
    ) -> None: ...

    def read_entries(self, start_seq: int, end_seq: int) -> list[SealedEntry]: ...

    def get_epoch(self, log_id: str, epoch_id: int) -> EpochCertificate | None: ...

    def get_intermediate(self, intermediate_id: str) -> IntermediateCertificate | None: ...

    def get_root(self, log_id: str) -> str | None: ...


class InMemoryLedgerStore:
    """Thread-safe store mirroring the L1b service-visible ledger behavior."""

    def __init__(
        self,
        *,
        pinned_roots: dict[str, str] | None = None,
        intermediates: dict[str, IntermediateCertificate] | None = None,
        epochs: dict[str, EpochCertificate] | None = None,
        bundle: Bundle | None = None,
        pinned_keys: PinnedKeys | None = None,
    ) -> None:
        self.entries: dict[tuple[str, int], StoredEntry] = {}
        self.conflicts: list[dict[str, object]] = []
        self.pinned_roots = dict(pinned_roots or {})
        self.intermediates = dict(intermediates or {})
        self.epochs = dict(epochs or {})
        self._bundle = bundle
        self._pinned_keys = pinned_keys
        self._lock = RLock()

    @classmethod
    def from_bundle(cls, bundle: Bundle, pinned_keys: PinnedKeys) -> InMemoryLedgerStore:
        store = cls(
            pinned_roots={bundle.log_id: pinned_keys.root_public_key},
            intermediates={cert.intermediate_id: cert for cert in bundle.intermediates},
            epochs={f"{cert.log_id}:{cert.epoch_id}": cert for cert in bundle.epochs},
            bundle=bundle,
            pinned_keys=pinned_keys,
        )
        for raw in bundle.entries:
            entry = SealedEntry.model_validate(raw)
            store.insert_entry(StoredEntry(entry, entry_hash(entry.body)))
        return store

    def register_root(self, log_id: str, root_public_key: str) -> None:
        with self._lock:
            self.pinned_roots[log_id] = root_public_key

    def register_intermediate(self, certificate: IntermediateCertificate) -> None:
        with self._lock:
            self.intermediates[certificate.intermediate_id] = certificate

    def register_epoch(self, certificate: EpochCertificate) -> None:
        with self._lock:
            self.epochs[f"{certificate.log_id}:{certificate.epoch_id}"] = certificate

    def get_epoch(self, log_id: str, epoch_id: int) -> EpochCertificate | None:
        return self.epochs.get(f"{log_id}:{epoch_id}")

    def get_intermediate(self, intermediate_id: str) -> IntermediateCertificate | None:
        return self.intermediates.get(intermediate_id)

    def get_root(self, log_id: str) -> str | None:
        return self.pinned_roots.get(log_id)

    def get_entry(self, log_id: str, seq: int) -> StoredEntry | None:
        with self._lock:
            return self.entries.get((log_id, seq))

    def latest_entry(self, log_id: str) -> StoredEntry | None:
        with self._lock:
            records = [
                record for (stored_log, _), record in self.entries.items() if stored_log == log_id
            ]
            return max(records, key=lambda record: record.entry.body.seq, default=None)

    def insert_entry(self, record: StoredEntry) -> None:
        with self._lock:
            key = (record.entry.body.log_id, record.entry.body.seq)
            if key in self.entries:
                raise KeyError(key)
            self.entries[key] = record

    def record_conflict(
        self,
        log_id: str,
        seq: int,
        existing_hash: str,
        rejected_hash: str,
        evidence: dict[str, object],
    ) -> None:
        with self._lock:
            self.conflicts.append(
                {
                    "log_id": log_id,
                    "seq": seq,
                    "existing_hash": existing_hash,
                    "rejected_hash": rejected_hash,
                    "evidence": evidence,
                }
            )

    def read_entries(self, start_seq: int, end_seq: int) -> list[SealedEntry]:
        if start_seq < 0 or end_seq < start_seq:
            raise ValueError("invalid entry range")
        with self._lock:
            records = [
                record for (_, seq), record in self.entries.items() if start_seq <= seq <= end_seq
            ]
            return [
                record.entry for record in sorted(records, key=lambda item: item.entry.body.seq)
            ][:1000]

    def export_bundle(self, log_id: str | None = None) -> Bundle:
        if self._bundle is None:
            raise ValueError("bundle export metadata is unavailable")
        if log_id is not None and self._bundle.log_id != log_id:
            raise ValueError("bundle log identity does not match")
        entries = [
            record.entry.model_dump()
            for record in sorted(self.entries.values(), key=lambda item: item.entry.body.seq)
        ]
        return self._bundle.model_copy(update={"entries": entries})

    @property
    def pinned_keys(self) -> PinnedKeys | None:
        return self._pinned_keys

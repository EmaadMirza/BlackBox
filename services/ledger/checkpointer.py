"""Cooperative checkpoint scheduling and signer transport for the ledger."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from psycopg import Connection
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.checkpoint import verify_checkpoint, verify_cosignature
from libs.blackbox_core.encoding import decode_base64url, encode_hash
from libs.blackbox_core.merkle import root as merkle_root
from libs.blackbox_core.schemas import (
    Checkpoint,
    Cosignature,
    EpochCertificate,
    SealedEntry,
    WitnessSet,
)
from libs.blackbox_core.sealing import sealed_bytes
from libs.blackbox_core.signing import structure_hash
from libs.blackbox_core.witness_set import has_quorum
from services.ledger import merkle_store, proofs
from services.ledger.proofs import ProofError
from services.signer.clock import system_utc_now

DEFAULT_INTERVAL_SECONDS = 5.0
DEFAULT_ENTRY_INTERVAL = 100


@dataclass(frozen=True)
class SignerHead:
    log_id: str
    latest_seq: int
    latest_entry_hash: str
    epoch_id: int


@dataclass(frozen=True)
class LedgerHead:
    log_id: str
    tree_size: int
    root_hash: str
    latest_seq: int
    latest_entry_hash: str
    epoch_id: int

    @property
    def identity(self) -> tuple[object, ...]:
        return (
            self.log_id,
            self.tree_size,
            self.root_hash,
            self.latest_seq,
            self.latest_entry_hash,
            self.epoch_id,
        )


class SignerTransport(Protocol):
    def delivered_head(self, bearer_token: str) -> SignerHead: ...

    def checkpoint(self, request: Checkpoint, bearer_token: str) -> Checkpoint: ...


class SignerRejection(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message


class CheckpointSchedulerError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message


class CheckpointStateError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message


class InProcessSignerTransport:
    """Call a signer FastAPI client without a network hop."""

    def __init__(self, client: object, *, head_provider: Callable[[], SignerHead]) -> None:
        self._client = cast("object", client)
        self._head_provider = head_provider

    def delivered_head(self, bearer_token: str) -> SignerHead:
        return self._head_provider()

    def checkpoint(self, request: Checkpoint, bearer_token: str) -> Checkpoint:
        response = self._client.post(  # type: ignore[attr-defined]
            "/checkpoint",
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {bearer_token}"},
        )
        body = response.json()
        if response.status_code != 200:
            detail = body.get("error", {}) if isinstance(body, dict) else {}
            raise SignerRejection(
                response.status_code,
                str(detail.get("code", "signer_rejected")),
                "Signer rejected checkpoint request.",
            )
        try:
            return Checkpoint.model_validate(body)
        except (TypeError, ValueError) as exc:
            raise SignerRejection(
                503, "invalid_signer_response", "Signer response is invalid."
            ) from exc


class CheckpointScheduler:
    """Cooperative scheduler; callers invoke ``tick`` rather than starting a thread."""

    def __init__(
        self,
        *,
        pool: ConnectionPool,
        log_id: str,
        signer_transport: SignerTransport,
        bearer_token: str,
        clock: Callable[[], float] = time.monotonic,
        timestamp: Callable[[], str] = system_utc_now,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        entry_interval: int = DEFAULT_ENTRY_INTERVAL,
        witnesses: dict[str, object] | None = None,
        witness_set: WitnessSet | None = None,
        witness_bearer_token: str = "",
        witness_timeout: float = 2.0,
    ) -> None:
        if type(interval_seconds) not in (int, float) or interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if type(entry_interval) is not int or entry_interval <= 0:
            raise ValueError("entry_interval must be positive")
        self.pool = pool
        self.log_id = log_id
        self.signer_transport = signer_transport
        self.bearer_token = bearer_token
        self.clock = clock
        self.timestamp = timestamp
        self.interval_seconds = float(interval_seconds)
        self.entry_interval = entry_interval
        self.witnesses: dict[str, Any] = witnesses or {}
        self.witness_set = witness_set
        self.witness_bearer_token = witness_bearer_token
        self.witness_timeout = witness_timeout
        self.last_alarm: str | None = None
        self._last_attempt_at: float | None = None
        self._blocked_head: tuple[object, ...] | None = None
        self._last_error_status = 503

    def on_entry(self) -> Checkpoint | None:
        return self.tick()

    def tick(self) -> Checkpoint | None:
        return self._attempt(force=False)

    def request_now(self) -> Checkpoint:
        checkpoint = self._attempt(force=True)
        if checkpoint is not None:
            return checkpoint
        if self.last_alarm is not None:
            raise CheckpointSchedulerError(
                self._last_error_status,
                self.last_alarm,
                "Checkpoint request was not accepted.",
            )
        raise CheckpointSchedulerError(
            404, "checkpoint_unavailable", "No ledger head is available."
        )

    async def run(self) -> None:
        """Run cooperatively on an event loop; this function creates no threads."""
        while True:
            self.tick()
            await asyncio.sleep(self.interval_seconds)

    def latest(self) -> Checkpoint | None:
        with self.pool.connection() as connection:
            return _latest_checkpoint(connection, self.log_id)

    def witnessed(self) -> list[dict[str, object]]:
        with self.pool.connection() as connection:
            rows = connection.execute(
                """SELECT c.checkpoint, s.cosignature
                FROM blackbox.checkpoints c
                JOIN blackbox.cosignatures s ON s.checkpoint_hash=c.checkpoint_hash
                WHERE c.log_id=%s ORDER BY c.tree_size, s.witness_id""",
                (self.log_id,),
            ).fetchall()
        grouped: dict[str, dict[str, object]] = {}
        for raw_checkpoint, raw_cosignature in rows:
            checkpoint = Checkpoint.model_validate(raw_checkpoint)
            key = structure_hash(checkpoint)
            item = grouped.setdefault(
                key,
                {"checkpoint": checkpoint.model_dump(), "cosignatures": []},
            )
            cast(list[object], item["cosignatures"]).append(raw_cosignature)
        result = []
        for item in grouped.values():
            checkpoint = Checkpoint.model_validate(item["checkpoint"])
            cosigs = [
                Cosignature.model_validate(value)
                for value in cast(list[object], item["cosignatures"])
            ]
            if self.witness_set is not None and has_quorum(checkpoint, cosigs, self.witness_set):
                result.append(
                    {
                        "checkpoint": checkpoint.model_dump(mode="json"),
                        "cosignatures": [c.model_dump(mode="json") for c in cosigs],
                    }
                )
        return result

    def _fan_out(self, checkpoint: Checkpoint) -> int:
        if not self.witnesses or self.witness_set is None:
            return 0
        checkpoint_hash = structure_hash(checkpoint)
        collected: set[str] = set()
        for witness_id, client in self.witnesses.items():
            try:
                state_response = client.get(
                    "/v1/state",
                    params={"log_id": checkpoint.log_id},
                    headers={"Authorization": f"Bearer {self.witness_bearer_token}"},
                    timeout=self.witness_timeout,
                )
                from_size = int(state_response.json().get("tree_size") or 0)
                proof = []
                if from_size and from_size < checkpoint.tree_size:
                    proof = __import__(
                        "services.ledger.proofs", fromlist=["consistency"]
                    ).consistency(_load_proof_leaves(self.pool), from_size, checkpoint.tree_size)
                response = client.post(
                    "/v1/checkpoint",
                    json={
                        "log_id": checkpoint.log_id,
                        "checkpoint": checkpoint.model_dump(mode="json"),
                        "from_size": from_size,
                        "consistency_proof": proof,
                    },
                    headers={"Authorization": f"Bearer {self.witness_bearer_token}"},
                    timeout=self.witness_timeout,
                )
                if response.status_code != 200:
                    self._witness_alarm(witness_id, checkpoint_hash, response.json())
                    continue
                cosignature = Cosignature.model_validate(response.json())
                public = next(
                    (
                        item.public_key
                        for item in self.witness_set.witnesses
                        if item.witness_id == cosignature.witness_id
                    ),
                    None,
                )
                if (
                    public is None
                    or cosignature.checkpoint_hash != checkpoint_hash
                    or not verify_cosignature(cosignature, decode_base64url(public))
                ):
                    self._witness_alarm(witness_id, checkpoint_hash, {"code": "bad_cosignature"})
                    continue
                with self.pool.connection() as connection:
                    with connection.transaction():
                        connection.execute(
                            "INSERT INTO blackbox.cosignatures(checkpoint_hash, witness_id, cosignature) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                            (
                                checkpoint_hash,
                                cosignature.witness_id,
                                Jsonb(cosignature.model_dump(mode="json")),
                            ),
                        )
                collected.add(cosignature.witness_id)
            except Exception:
                self._witness_alarm(witness_id, checkpoint_hash, {"code": "witness_unavailable"})
        if len(collected) < self.witness_set.quorum:
            self._alarm(
                "WITNESS_QUORUM_UNAVAILABLE",
                "high",
                "Witness quorum is unavailable.",
                {
                    "checkpoint_hash": checkpoint_hash,
                    "valid_cosignatures": len(collected),
                    "quorum": self.witness_set.quorum,
                },
            )
        return len(collected)

    def _witness_alarm(
        self, witness_id: str, checkpoint_hash: str, details: dict[str, object]
    ) -> None:
        with self.pool.connection() as connection:
            with connection.transaction():
                exists = connection.execute(
                    "SELECT 1 FROM blackbox.alarms WHERE log_id=%s AND code=%s AND details->>'checkpoint_hash'=%s AND details->>'witness_id'=%s",
                    (self.log_id, "WITNESS_REFUSAL", checkpoint_hash, witness_id),
                ).fetchone()
                if exists is None:
                    connection.execute(
                        "INSERT INTO blackbox.alarms(log_id, code, severity, message, details) VALUES (%s, %s, %s, %s, %s)",
                        (
                            self.log_id,
                            "WITNESS_REFUSAL",
                            "critical",
                            "Witness refused checkpoint.",
                            Jsonb(
                                {
                                    "checkpoint_hash": checkpoint_hash,
                                    "witness_id": witness_id,
                                    **details,
                                }
                            ),
                        ),
                    )

    def _attempt(self, *, force: bool) -> Checkpoint | None:
        try:
            head = _read_head(self.pool, self.log_id)
        except (CheckpointStateError, ProofError) as exc:
            self._alarm(exc.code, "critical", exc.message, {})
            return None
        if head is None:
            return None
        if self._blocked_head == head.identity:
            return None

        latest = self.latest()
        if latest is not None and latest.tree_size == head.tree_size:
            if _checkpoint_matches_head(latest, head):
                if force:
                    self._fan_out(latest)
                return latest if force else None
            self._alarm(
                "checkpoint_root_mismatch",
                "critical",
                "Stored checkpoint disagrees with the ledger head.",
                {"tree_size": head.tree_size},
                head,
            )
            return None

        now = self.clock()
        if not force and not self._due(now, head, latest):
            return None

        try:
            signer_head = self.signer_transport.delivered_head(self.bearer_token)
        except Exception:
            self._alarm(
                "signer_unavailable",
                "high",
                "Signer head is unavailable.",
                {},
                head,
            )
            return None
        if not _head_matches(head, signer_head):
            self._alarm(
                "checkpoint_head_mismatch",
                "high",
                "Ledger head does not match signer-delivered state.",
                {"signer_latest_seq": signer_head.latest_seq},
                head,
            )
            return None

        request = Checkpoint(
            log_id=head.log_id,
            tree_size=head.tree_size,
            root_hash=head.root_hash,
            latest_seq=head.latest_seq,
            latest_entry_hash=head.latest_entry_hash,
            epoch_id=head.epoch_id,
            signer_timestamp=self.timestamp(),
        )
        self._last_attempt_at = now
        try:
            signed = self.signer_transport.checkpoint(request, self.bearer_token)
        except SignerRejection as exc:
            self._alarm(exc.code, "high", "Signer rejected checkpoint request.", {}, head)
            return None
        except Exception:
            self._alarm("signer_unavailable", "high", "Signer is unavailable.", {}, head)
            return None

        try:
            _validate_signed_checkpoint(self.pool, signed, head)
            stored = _store_checkpoint(self.pool, signed)
            self._fan_out(stored)
            return stored
        except CheckpointStateError as exc:
            self._alarm(exc.code, "critical", exc.message, {}, head)
            return None

    def _due(self, now: float, head: LedgerHead, latest: Checkpoint | None) -> bool:
        if latest is None or head.tree_size - latest.tree_size >= self.entry_interval:
            return True
        return self._last_attempt_at is None or now - self._last_attempt_at >= self.interval_seconds

    def _alarm(
        self,
        code: str,
        severity: str,
        message: str,
        details: dict[str, object],
        head: LedgerHead | None = None,
    ) -> None:
        self.last_alarm = code
        self._last_error_status = 409 if severity == "high" else 503
        if head is not None:
            self._blocked_head = head.identity
            details = {**details, "tree_size": head.tree_size, "latest_seq": head.latest_seq}
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    """INSERT INTO blackbox.alarms
                    (log_id, code, severity, message, details)
                    VALUES (%s, %s, %s, %s, %s)""",
                    (self.log_id, code, severity, message, Jsonb(details)),
                )


def _read_head(pool: ConnectionPool, log_id: str) -> LedgerHead | None:
    with pool.connection() as connection:
        rows = connection.execute(
            """SELECT log_id, seq, sealed_entry, entry_hash, epoch_id
            FROM blackbox.entries WHERE log_id=%s ORDER BY seq""",
            (log_id,),
        ).fetchall()
        if not rows:
            return None
        leaves: list[bytes] = []
        latest: tuple[int, str, int] | None = None
        for expected_seq, (stored_log, seq, raw_entry, stored_hash, epoch_id) in enumerate(rows):
            try:
                entry = SealedEntry.model_validate(raw_entry)
            except (TypeError, ValueError, KeyError) as exc:
                raise CheckpointStateError(
                    "checkpoint_entry_invalid", "Ledger entry state is invalid."
                ) from exc
            if (
                stored_log != log_id
                or seq != expected_seq
                or entry.body.seq != expected_seq
                or epoch_id != entry.body.epoch_id
            ):
                raise CheckpointStateError(
                    "checkpoint_entry_sequence_mismatch", "Ledger entry sequence is invalid."
                )
            computed_hash = entry_hash(entry.body)
            if stored_hash != computed_hash:
                raise CheckpointStateError(
                    "checkpoint_entry_hash_mismatch", "Ledger entry hash disagrees with its body."
                )
            leaves.append(sealed_bytes(entry))
            latest = (entry.body.seq, stored_hash, epoch_id)
        root_hash = encode_hash(merkle_root(leaves))
        persisted_root = merkle_store.current_root(connection, log_id)
        if persisted_root is None or encode_hash(persisted_root) != root_hash:
            raise CheckpointStateError(
                "checkpoint_root_mismatch", "Ledger Merkle root disagrees with stored state."
            )
        assert latest is not None
        return LedgerHead(log_id, len(leaves), root_hash, latest[0], latest[1], latest[2])


def _latest_checkpoint(connection: Connection, log_id: str) -> Checkpoint | None:
    row = connection.execute(
        """SELECT checkpoint FROM blackbox.checkpoints
        WHERE log_id=%s ORDER BY tree_size DESC LIMIT 1""",
        (log_id,),
    ).fetchone()
    return None if row is None else Checkpoint.model_validate(row[0])


def _load_epoch(pool: ConnectionPool, log_id: str, epoch_id: int) -> EpochCertificate:
    with pool.connection() as connection:
        row = connection.execute(
            """SELECT certificate FROM blackbox.epochs
            WHERE log_id=%s AND epoch_id=%s""",
            (log_id, epoch_id),
        ).fetchone()
    if row is None:
        raise CheckpointStateError(
            "checkpoint_epoch_unavailable", "Checkpoint epoch is unavailable."
        )
    try:
        return EpochCertificate.model_validate(row[0])
    except (TypeError, ValueError) as exc:
        raise CheckpointStateError(
            "checkpoint_epoch_invalid", "Checkpoint epoch is invalid."
        ) from exc


def _validate_signed_checkpoint(
    pool: ConnectionPool, checkpoint: Checkpoint, head: LedgerHead
) -> None:
    if (
        checkpoint.log_id != head.log_id
        or checkpoint.tree_size != head.tree_size
        or checkpoint.root_hash != head.root_hash
        or checkpoint.latest_seq != head.latest_seq
        or checkpoint.latest_entry_hash != head.latest_entry_hash
        or checkpoint.epoch_id != head.epoch_id
        or not checkpoint.signature
    ):
        raise CheckpointStateError(
            "checkpoint_mismatch", "Signed checkpoint disagrees with the ledger head."
        )
    epoch = _load_epoch(pool, head.log_id, head.epoch_id)
    if not verify_checkpoint(checkpoint, decode_base64url(epoch.epoch_public_key)):
        raise CheckpointStateError("checkpoint_signature_invalid", "Signed checkpoint is invalid.")


def _store_checkpoint(pool: ConnectionPool, checkpoint: Checkpoint) -> Checkpoint:
    checkpoint_hash = structure_hash(checkpoint)
    with pool.connection() as connection:
        with connection.transaction():
            connection.execute(
                """INSERT INTO blackbox.checkpoints
                (checkpoint_hash, log_id, tree_size, checkpoint, canonical_bytes)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (log_id, tree_size) DO NOTHING""",
                (
                    checkpoint_hash,
                    checkpoint.log_id,
                    checkpoint.tree_size,
                    Jsonb(checkpoint.model_dump(mode="json")),
                    canonicalize(checkpoint.model_dump()),
                ),
            )
            row = connection.execute(
                """SELECT checkpoint FROM blackbox.checkpoints
                WHERE log_id=%s AND tree_size=%s""",
                (checkpoint.log_id, checkpoint.tree_size),
            ).fetchone()
    if row is None:
        raise CheckpointStateError("checkpoint_storage_failed", "Checkpoint storage failed.")
    existing = Checkpoint.model_validate(row[0])
    if not _same_checkpoint_identity(existing, checkpoint):
        raise CheckpointStateError(
            "checkpoint_root_conflict", "Different checkpoints exist for the same tree size."
        )
    return existing


def _same_checkpoint_identity(left: Checkpoint, right: Checkpoint) -> bool:
    return (
        left.log_id == right.log_id
        and left.tree_size == right.tree_size
        and left.root_hash == right.root_hash
        and left.latest_seq == right.latest_seq
        and left.latest_entry_hash == right.latest_entry_hash
        and left.epoch_id == right.epoch_id
    )


def _checkpoint_matches_head(checkpoint: Checkpoint, head: LedgerHead) -> bool:
    return _same_checkpoint_identity(
        checkpoint,
        Checkpoint(
            log_id=head.log_id,
            tree_size=head.tree_size,
            root_hash=head.root_hash,
            latest_seq=head.latest_seq,
            latest_entry_hash=head.latest_entry_hash,
            epoch_id=head.epoch_id,
            signer_timestamp=checkpoint.signer_timestamp,
        ),
    )


def _head_matches(head: LedgerHead, signer: SignerHead) -> bool:
    return (
        head.log_id == signer.log_id
        and head.latest_seq == signer.latest_seq
        and head.latest_entry_hash == signer.latest_entry_hash
        and head.epoch_id == signer.epoch_id
    )


def _load_proof_leaves(pool: ConnectionPool) -> list[bytes]:
    with pool.connection() as connection:
        return proofs.load_leaves(connection)

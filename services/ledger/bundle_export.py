"""Complete-prefix evidence bundle assembly for the ledger."""

from __future__ import annotations

import os
from pathlib import Path

from psycopg_pool import ConnectionPool

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.evidence import (
    Bundle,
    CheckpointEvidence,
    ConsistencyProof,
    InclusionProof,
)
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import (
    Checkpoint,
    Cosignature,
    EpochCertificate,
    IntermediateCertificate,
    SealedEntry,
    WitnessSet,
)
from libs.blackbox_core.sealing import sealed_bytes
from services.ledger import db


class BundleExportError(Exception):
    """A client-safe failure while assembling an offline evidence bundle."""

    def __init__(self, code: str, message: str, status: int = 422) -> None:
        self.code = code
        self.message = message
        self.status = status


def build_bundle(
    pool: ConnectionPool,
    start_seq: int,
    end_seq: int,
    *,
    log_name: str,
    witness_set: WitnessSet,
    log_id: str | None = None,
) -> Bundle:
    """Build a verifier-compatible complete prefix from the append-only ledger."""
    if type(start_seq) is not int or type(end_seq) is not int:
        raise BundleExportError("invalid_bundle_range", "Bundle range must be integers.")
    if start_seq != 0 or end_seq < start_seq:
        raise BundleExportError(
            "invalid_bundle_range",
            "Stage 1 bundles must be complete prefixes beginning at sequence zero.",
        )
    if not log_name or witness_set is None:
        raise BundleExportError(
            "bundle_unavailable", "Bundle trust metadata is unavailable.", status=503
        )

    with pool.connection() as connection:
        rows = connection.execute(
            """SELECT log_id, seq, sealed_entry FROM blackbox.entries
            ORDER BY log_id, seq"""
        ).fetchall()
        if not rows:
            raise BundleExportError("bundle_unavailable", "No ledger entries are available.", 404)

        log_ids = {row[0] for row in rows}
        selected_log_id = log_id or (next(iter(log_ids)) if len(log_ids) == 1 else None)
        if selected_log_id is None or selected_log_id not in log_ids:
            raise BundleExportError(
                "bundle_unavailable", "A single ledger log is required for export.", status=503
            )
        selected_rows = [row for row in rows if row[0] == selected_log_id]
        entries = _parse_entries(selected_rows, selected_log_id)
        if end_seq >= len(entries):
            raise BundleExportError(
                "bundle_unavailable", "The requested prefix is not available.", status=422
            )
        prefix = entries[: end_seq + 1]

        checkpoint_rows = connection.execute(
            """SELECT checkpoint_hash, checkpoint FROM blackbox.checkpoints
            WHERE log_id=%s AND tree_size <= %s ORDER BY tree_size""",
            (selected_log_id, end_seq + 1),
        ).fetchall()
        checkpoints = [Checkpoint.model_validate(row[1]) for row in checkpoint_rows]
        if not any(checkpoint.tree_size == end_seq + 1 for checkpoint in checkpoints):
            raise BundleExportError(
                "bundle_unavailable",
                "The requested prefix is not covered by a stored checkpoint.",
            )

        checkpoint_evidence = []
        for checkpoint_hash, raw_checkpoint in checkpoint_rows:
            checkpoint = Checkpoint.model_validate(raw_checkpoint)
            cosig_rows = connection.execute(
                """SELECT cosignature FROM blackbox.cosignatures
                WHERE checkpoint_hash=%s ORDER BY witness_id""",
                (checkpoint_hash,),
            ).fetchall()
            checkpoint_evidence.append(
                CheckpointEvidence(
                    checkpoint=checkpoint,
                    cosignatures=[Cosignature.model_validate(row[0]) for row in cosig_rows],
                )
            )

        epoch_ids = {entry.body.epoch_certificate_id for entry in prefix}
        epoch_rows = []
        for epoch_certificate_id in epoch_ids:
            row = connection.execute(
                """SELECT certificate FROM blackbox.epochs
                WHERE log_id=%s AND epoch_certificate_id=%s""",
                (selected_log_id, epoch_certificate_id),
            ).fetchone()
            if row is None:
                raise BundleExportError(
                    "bundle_unavailable", "An entry epoch certificate is unavailable.", status=503
                )
            epoch_rows.append(EpochCertificate.model_validate(row[0]))
        epochs = sorted(epoch_rows, key=lambda certificate: certificate.epoch_id)

        intermediate_ids = {certificate.intermediate_id for certificate in epochs}
        intermediate_rows = []
        for intermediate_id in intermediate_ids:
            row = connection.execute(
                """SELECT certificate FROM blackbox.intermediates
                WHERE log_id=%s AND intermediate_id=%s""",
                (selected_log_id, intermediate_id),
            ).fetchone()
            if row is None:
                raise BundleExportError(
                    "bundle_unavailable",
                    "An epoch intermediate certificate is unavailable.",
                    status=503,
                )
            intermediate_rows.append(IntermediateCertificate.model_validate(row[0]))
        intermediates = sorted(
            intermediate_rows, key=lambda certificate: certificate.intermediate_id
        )

    tree = MerkleTree([sealed_bytes(entry) for entry in prefix])
    inclusion_proofs = [
        InclusionProof(
            seq=seq,
            tree_size=checkpoint.tree_size,
            proof=[encode_hash(item) for item in tree.inclusion_proof(seq, checkpoint.tree_size)],
        )
        for checkpoint in checkpoints
        for seq in range(checkpoint.tree_size)
    ]
    ordered_checkpoints = sorted(checkpoints, key=lambda checkpoint: checkpoint.tree_size)
    consistency_proofs = [
        ConsistencyProof(
            old_size=old.tree_size,
            new_size=new.tree_size,
            proof=[
                encode_hash(item) for item in tree.consistency_proof(old.tree_size, new.tree_size)
            ],
        )
        for old, new in zip(ordered_checkpoints, ordered_checkpoints[1:])
    ]
    return Bundle(
        format_version="4",
        log_id=selected_log_id,
        log_name=log_name,
        entries=[entry.model_dump(mode="json") for entry in prefix],
        intermediates=intermediates,
        epochs=epochs,
        witness_set=witness_set,
        checkpoints=[
            evidence
            for evidence in sorted(
                checkpoint_evidence, key=lambda evidence: evidence.checkpoint.tree_size
            )
        ],
        inclusion_proofs=inclusion_proofs,
        consistency_proofs=consistency_proofs,
    )


async def export_bundle(
    start_seq: int,
    end_seq: int,
    destination: Path,
    *,
    pool: ConnectionPool | None = None,
    log_name: str | None = None,
    witness_set: WitnessSet | None = None,
    log_id: str | None = None,
) -> Path:
    """Write a canonical JSON bundle, retaining the original scaffold API."""
    owned_pool = pool is None
    active_pool = pool or db.connect(
        os.environ.get("LEDGER_DATABASE_URL", "dbname=blackbox_ledger")
    )
    try:
        if log_name is None or witness_set is None:
            raise BundleExportError(
                "bundle_unavailable", "Bundle trust metadata is unavailable.", 503
            )
        bundle = build_bundle(
            active_pool,
            start_seq,
            end_seq,
            log_name=log_name,
            witness_set=witness_set,
            log_id=log_id,
        )
        destination.write_bytes(canonicalize(bundle.model_dump()))
        return destination
    finally:
        if owned_pool:
            active_pool.close()


def _parse_entries(rows: list[tuple[object, ...]], log_id: str) -> list[SealedEntry]:
    entries: list[SealedEntry] = []
    for expected_seq, (stored_log_id, stored_seq, raw_entry) in enumerate(rows):
        try:
            entry = SealedEntry.model_validate(raw_entry)
        except (TypeError, ValueError) as exc:
            raise BundleExportError(
                "bundle_unavailable", "Ledger entry state is invalid.", status=503
            ) from exc
        if (
            stored_log_id != log_id
            or stored_seq != expected_seq
            or entry.body.log_id != log_id
            or entry.body.seq != expected_seq
        ):
            raise BundleExportError(
                "bundle_unavailable", "Ledger entry sequence is not contiguous.", status=503
            )
        entries.append(entry)
    return entries

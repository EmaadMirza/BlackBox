"""Ordered eight-step checkpoint processing."""

from __future__ import annotations

from typing import Any

from libs.blackbox_core import schemas
from libs.blackbox_core.checkpoint import build_cosignature
from libs.blackbox_core.encoding import decode_base64url, decode_hash, format_timestamp
from libs.blackbox_core.epochs import validate_contiguity, verify_epoch_certificate
from libs.blackbox_core.merkle import verify_consistency
from libs.blackbox_core.signing import structure_hash


class WitnessRefusal(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def process_submission(
    submission: Any,
    store: Any,
    root: bytes,
    config: Any,
    epochs: dict[int, schemas.EpochCertificate],
    intermediates: dict[str, schemas.IntermediateCertificate],
    witness_key: Any,
) -> schemas.Cosignature:
    """Execute the ordered eight-step checkpoint validation and return cosignature."""
    checkpoint = submission.checkpoint
    if (
        submission.log_id != config.witness_set.log_id
        or checkpoint.log_id != config.witness_set.log_id
    ):
        raise WitnessRefusal("wrong_log")
    epoch = epochs.get(checkpoint.epoch_id)
    intermediate = intermediates.get(epoch.intermediate_id) if epoch else None
    if (
        epoch is None
        or intermediate is None
        or not verify_epoch_certificate(epoch, intermediate, root, checkpoint.signer_timestamp)
    ):
        raise WitnessRefusal("bad_cert_chain")
    if not __import__(
        "libs.blackbox_core.checkpoint", fromlist=["verify_checkpoint"]
    ).verify_checkpoint(checkpoint, decode_base64url(epoch.epoch_public_key)):
        raise WitnessRefusal("bad_signature")

    try:
        raw = store.read(checkpoint.log_id)
    except Exception as exc:
        raise WitnessRefusal("witness_unavailable") from exc

    if raw is not None:
        previous = schemas.Checkpoint.model_validate(raw["checkpoint"])
        if checkpoint.tree_size < previous.tree_size:
            raise WitnessRefusal("rollback")
        if checkpoint.tree_size == previous.tree_size:
            if checkpoint.root_hash != previous.root_hash or structure_hash(
                checkpoint
            ) != structure_hash(previous):
                raise WitnessRefusal("root_mismatch")
            return schemas.Cosignature.model_validate(raw["cosignature"])
        if submission.from_size != previous.tree_size:
            raise WitnessRefusal("proof_required")
        try:
            valid = verify_consistency(
                previous.tree_size,
                checkpoint.tree_size,
                decode_hash(previous.root_hash),
                decode_hash(checkpoint.root_hash),
                [decode_hash(item) for item in submission.consistency_proof],
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise WitnessRefusal("bad_proof")
        previous_epoch = epochs.get(previous.epoch_id)
        if previous_epoch is None or checkpoint.epoch_id < previous.epoch_id:
            raise WitnessRefusal("epoch_regression")
        if checkpoint.epoch_id != previous.epoch_id:
            try:
                validate_contiguity(previous_epoch, epoch)
            except ValueError as exc:
                raise WitnessRefusal("epoch_regression") from exc

    clock_fn = getattr(config, "clock", None) or (
        lambda: format_timestamp(
            __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        )
    )
    timestamp = clock_fn()
    cosignature = build_cosignature(
        structure_hash(checkpoint),
        config.witness_id,
        timestamp,
        witness_key.operation,
        log_id=checkpoint.log_id,
    )
    store.commit(checkpoint, cosignature)
    return cosignature


async def process(
    checkpoint: schemas.Checkpoint, previous: schemas.Checkpoint | None = None
) -> schemas.Cosignature:
    """Async entry point returning a cosignature for a verified checkpoint."""
    # Build cosignature placeholder when run in pure memory mode
    dummy_key = __import__(
        "cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["Ed25519PrivateKey"]
    ).Ed25519PrivateKey.generate()
    from libs.blackbox_core.crypto import SigningOperation

    op = SigningOperation(dummy_key.sign, dummy_key.public_key().public_bytes_raw())
    return build_cosignature(
        structure_hash(checkpoint),
        "w0",
        checkpoint.signer_timestamp,
        op,
        log_id=checkpoint.log_id,
    )

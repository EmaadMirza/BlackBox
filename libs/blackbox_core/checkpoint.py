"""Checkpoint/cosignature construction and verification (spec §8.6, §10.3)."""

from __future__ import annotations

from libs.blackbox_core.crypto import SigningOperation, sha256
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.schemas import Checkpoint, Cosignature
from libs.blackbox_core.signing import sign_structure, verify_structure


def build_checkpoint(
    log_id: str,
    tree_size: int,
    root_hash: str,
    latest_seq: int,
    epoch_id: int,
    signer_timestamp: str,
) -> Checkpoint:
    checkpoint = Checkpoint(
        log_id=log_id,
        tree_size=tree_size,
        root_hash=root_hash,
        latest_seq=latest_seq,
        epoch_id=epoch_id,
        signer_timestamp=signer_timestamp,
    )
    if latest_seq != tree_size - 1:
        raise ValueError("checkpoint size and sequence disagree")
    if tree_size == 0 and root_hash != encode_hash(sha256(b"")):
        raise ValueError("invalid empty root")
    return checkpoint


def sign_checkpoint(checkpoint: Checkpoint, signing_operation: SigningOperation) -> Checkpoint:
    build_checkpoint(**checkpoint.model_dump(exclude={"signature"}))
    return sign_structure(checkpoint, signing_operation, "checkpoint")


def verify_checkpoint(checkpoint: Checkpoint, public_key: bytes) -> bool:
    try:
        build_checkpoint(**checkpoint.model_dump(exclude={"signature"}))
    except (ValueError, TypeError):
        return False
    return verify_structure(checkpoint, public_key, "checkpoint")


def build_cosignature(
    checkpoint_hash: str,
    witness_id: str,
    witness_timestamp: str,
    signing_operation: SigningOperation,
    *,
    log_id: str,
) -> Cosignature:
    value = Cosignature(
        log_id=log_id,
        checkpoint_hash=checkpoint_hash,
        witness_id=witness_id,
        witness_timestamp=witness_timestamp,
    )
    return sign_structure(value, signing_operation, "cosignature", "witness_signature")


def verify_cosignature(cosignature: Cosignature, public_key: bytes) -> bool:
    return verify_structure(cosignature, public_key, "cosignature", "witness_signature")

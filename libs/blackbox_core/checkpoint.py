"""Checkpoint/cosignature construction and verification (spec §8.6, §10.3)."""

from __future__ import annotations

from libs.blackbox_core.crypto import SigningOperation, sha256
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.schemas import Checkpoint, Cosignature
from libs.blackbox_core.signing import sign_structure, verify_structure


class WitnessedCheckpointEvidence:
    """Authenticated witnessed checkpoint evidence for signer-side decisions."""

    def __init__(
        self,
        *,
        checkpoint: Checkpoint,
        cosignatures: list[Cosignature],
        witness_set,
        root_public_key: bytes,
        intermediate_certificate,
        epoch_certificate,
        quorum: int | None = None,
    ) -> None:
        self.checkpoint = checkpoint
        self.cosignatures = cosignatures
        self.witness_set = witness_set
        self.root_public_key = root_public_key
        self.intermediate_certificate = intermediate_certificate
        self.epoch_certificate = epoch_certificate
        self.quorum = quorum

    def covers(self, intent_seq: int, expected_log_id: str | None = None) -> bool:
        try:
            from libs.blackbox_core.encoding import decode_base64url
            from libs.blackbox_core.epochs import verify_epoch_certificate
            from libs.blackbox_core.witness_set import has_quorum, verify_witness_set

            if expected_log_id is not None and self.checkpoint.log_id != expected_log_id:
                return False
            if self.epoch_certificate.log_id != self.checkpoint.log_id:
                return False
            if self.epoch_certificate.epoch_id != self.checkpoint.epoch_id:
                return False
            if not verify_checkpoint(
                self.checkpoint, decode_base64url(self.epoch_certificate.epoch_public_key)
            ):
                return False
            if not verify_epoch_certificate(
                self.epoch_certificate,
                self.intermediate_certificate,
                self.root_public_key,
                self.checkpoint.signer_timestamp,
            ):
                return False
            if not verify_witness_set(self.witness_set, self.root_public_key):
                return False
            if self.quorum is not None and self.quorum != self.witness_set.quorum:
                return False
            return self.checkpoint.tree_size > intent_seq and has_quorum(
                self.checkpoint, self.cosignatures, self.witness_set
            )
        except (TypeError, ValueError, KeyError):
            return False


def build_checkpoint(
    log_id: str,
    tree_size: int,
    root_hash: str,
    latest_seq: int,
    epoch_id: int,
    signer_timestamp: str,
    latest_entry_hash: str = "sha256:" + "0" * 64,
) -> Checkpoint:
    checkpoint = Checkpoint(
        log_id=log_id,
        tree_size=tree_size,
        root_hash=root_hash,
        latest_seq=latest_seq,
        epoch_id=epoch_id,
        signer_timestamp=signer_timestamp,
        latest_entry_hash=latest_entry_hash,
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

"""Provider raw-body digest recomputation and attestation verification."""

from __future__ import annotations

from libs.blackbox_core import schemas
from libs.blackbox_core.attestation import verify_attestation
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash


class AttestationMismatchError(ValueError):
    pass


def verify_received_body(
    body: bytes, attestation: schemas.Attestation, public_key: bytes, now: str
) -> None:
    """Verify that the raw received body matches the attested digest and attestation is valid."""
    recomputed = encode_hash(sha256(body))
    if attestation.body_digest != recomputed:
        raise AttestationMismatchError("ATTESTATION_BODY_MISMATCH")

    if not verify_attestation(attestation, public_key, now):
        raise ValueError("invalid or expired attestation")

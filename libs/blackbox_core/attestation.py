"""Domain-separated request attestations and expiry validation."""

from __future__ import annotations

from collections.abc import Callable

from libs.blackbox_core.encoding import parse_timestamp
from libs.blackbox_core.schemas import Attestation, Intent
from libs.blackbox_core.signing import sign_structure, verify_structure


def build_attestation(
    intent: Intent, issued_at: str, expires_at: str, signing_operation: Callable[[bytes], bytes]
) -> Attestation:
    issued = parse_timestamp(issued_at)
    expires = parse_timestamp(expires_at)
    if expires <= issued:
        raise ValueError("attestation expiry must be after issuance")
    return sign_structure(
        Attestation(
            log_id=intent.log_id,
            intent_seq=intent.seq,
            idempotency_key=intent.action.idempotency_key,
            body_digest=intent.action.body_digest,
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        signing_operation,
        "attestation",
    )


def verify_attestation(attestation: Attestation, public_key: bytes, now: str) -> bool:
    try:
        current = parse_timestamp(now)
        issued = parse_timestamp(attestation.issued_at)
        expires = parse_timestamp(attestation.expires_at)
        if not issued <= current < expires:
            return False
        return verify_structure(attestation, public_key, "attestation")
    except (TypeError, ValueError):
        return False

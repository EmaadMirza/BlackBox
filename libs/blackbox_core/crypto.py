"""Ed25519 wrappers; accepts signing capabilities, never generates keys (§5.1)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from libs.blackbox_core.labels import signature_label, signature_message


class Signer(Protocol):
    def sign(self, data: bytes) -> bytes: ...


SigningOperation = Signer | Callable[[bytes], bytes]


def sign(payload: bytes, signing_operation: SigningOperation, *, domain: str, log_id: str) -> bytes:
    message = signature_message(signature_label(domain), log_id, payload)
    operation = signing_operation.sign if hasattr(signing_operation, "sign") else signing_operation
    result = operation(message)
    if not isinstance(result, bytes) or len(result) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    return result


def verify(
    public_key: bytes, signature: bytes, payload: bytes, *, domain: str, log_id: str
) -> bool:
    try:
        message = signature_message(signature_label(domain), log_id, payload)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()

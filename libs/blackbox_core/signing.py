"""Shared signed-structure envelopes; no key generation (spec §5.3)."""

from __future__ import annotations

from typing import TypeVar

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.crypto import SigningOperation, sha256, sign, verify
from libs.blackbox_core.encoding import decode_base64url, encode_base64url, encode_hash
from libs.blackbox_core.schemas import StrictModel

T = TypeVar("T", bound=StrictModel)


def unsigned_bytes(value: StrictModel, signature_field: str = "signature") -> bytes:
    data = value.model_dump()
    data.pop(signature_field, None)
    return canonicalize(data)


def sign_structure(
    value: T, operation: SigningOperation, domain: str, signature_field: str = "signature"
) -> T:
    value = type(value).model_validate(value)
    data = value.model_dump()
    data[signature_field] = encode_base64url(
        sign(
            unsigned_bytes(value, signature_field), operation, domain=domain, log_id=data["log_id"]
        )
    )
    return type(value).model_validate(data)


def verify_structure(
    value: StrictModel, public_key: bytes, domain: str, signature_field: str = "signature"
) -> bool:
    try:
        value = type(value).model_validate(value)
        data = value.model_dump()
        return verify(
            public_key,
            decode_base64url(data[signature_field]),
            unsigned_bytes(value, signature_field),
            domain=domain,
            log_id=data["log_id"],
        )
    except (ValueError, TypeError, KeyError):
        return False


def structure_hash(value: StrictModel) -> str:
    return encode_hash(sha256(canonicalize(value.model_dump())))

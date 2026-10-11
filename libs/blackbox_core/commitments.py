"""Salted SHA-256 commitments for selective offline openings (spec §8.4)."""

import hmac
import secrets

from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import decode_hash, encode_hash


def create_salt() -> bytes:
    return secrets.token_bytes(32)


def commit(value: bytes, salt: bytes) -> str:
    if len(salt) < 16:
        raise ValueError("commitment salt must contain at least 128 bits")
    return encode_hash(sha256(salt + value))


def verify_opening(commitment: str, value: bytes, salt: bytes) -> bool:
    try:
        return hmac.compare_digest(decode_hash(commitment), decode_hash(commit(value, salt)))
    except ValueError:
        return False

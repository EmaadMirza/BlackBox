"""Domain-separated sealing over entry hashes; signed bytes form Merkle leaves (§8.5)."""

from __future__ import annotations

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.crypto import SigningOperation, sign, verify
from libs.blackbox_core.encoding import decode_base64url, decode_hash, encode_base64url
from libs.blackbox_core.schemas import Entry, SealedEntry, parse_entry


def seal_entry(body: Entry, signing_operation: SigningOperation) -> SealedEntry:
    body = parse_entry(body)
    signature = sign(
        decode_hash(entry_hash(body)), signing_operation, domain="entry", log_id=body.log_id
    )
    return SealedEntry(body=body, signature=encode_base64url(signature))


def seal(candidate: Entry, epoch_key: SigningOperation) -> SealedEntry:
    return seal_entry(candidate, epoch_key)


def verify_entry(entry: SealedEntry, public_key: bytes) -> bool:
    try:
        entry = SealedEntry.model_validate(entry)
        return verify(
            public_key,
            decode_base64url(entry.signature),
            decode_hash(entry_hash(entry.body)),
            domain="entry",
            log_id=entry.body.log_id,
        )
    except (ValueError, TypeError):
        return False


def sealed_bytes(entry: SealedEntry) -> bytes:
    return canonicalize(SealedEntry.model_validate(entry).model_dump())

"""Entry hashing and first-break diagnostics (spec §8.5)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.schemas import Entry, SealedEntry, parse_entry

GENESIS_PREV_HASH = "sha256:" + "0" * 64


@dataclass(frozen=True)
class ChainBreak:
    seq: int
    reason: str
    verdict: str


def genesis_prev_hash() -> str:
    return GENESIS_PREV_HASH


def entry_hash(body: Entry) -> str:
    body = parse_entry(body)
    return encode_hash(sha256(canonicalize(body.model_dump())))


def verify_chain(entries: Sequence[SealedEntry]) -> ChainBreak | None:
    previous = GENESIS_PREV_HASH
    for expected, entry in enumerate(entries):
        seq = entry.body.seq
        if seq != expected:
            return ChainBreak(
                min(seq, expected),
                "missing sequence" if seq > expected else "reordered or duplicate sequence",
                "MISSING" if seq > expected else "TAMPERED",
            )
        if entry.body.prev_hash != previous:
            return ChainBreak(seq, "previous hash mismatch", "TAMPERED")
        previous = entry_hash(entry.body)
    return None

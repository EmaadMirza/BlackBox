"""Read-only RFC 6962 proof generation for the ledger API."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from psycopg import Connection

from libs.blackbox_core import merkle
from libs.blackbox_core.encoding import encode_hash
from libs.blackbox_core.schemas import SealedEntry
from libs.blackbox_core.sealing import sealed_bytes

MAX_PROOF_TREE_SIZE = 100
_DECIMAL = re.compile(r"[0-9]+\Z")


class ProofError(Exception):
    """A client-safe proof request or stored-state error."""

    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message


def parse_query(params: Iterable[tuple[str, str]], expected: set[str]) -> dict[str, int]:
    """Parse exactly one strict non-negative decimal value for each expected key."""
    items = list(params)
    names = {name for name, _ in items}
    if names != expected or len(items) != len(expected):
        raise ProofError(422, "invalid_query", "Invalid proof query.")
    parsed: dict[str, int] = {}
    for name, value in items:
        if not _DECIMAL.fullmatch(value):
            raise ProofError(422, "invalid_query", "Invalid proof query.")
        try:
            parsed[name] = int(value, 10)
        except ValueError as exc:
            raise ProofError(422, "invalid_query", "Invalid proof query.") from exc
    return parsed


def load_leaves(connection: Connection) -> list[bytes]:
    """Load the single contiguous log as sealed-entry leaf bytes, without writes."""
    rows = connection.execute(
        """SELECT log_id, seq, sealed_entry FROM blackbox.entries
        ORDER BY log_id, seq"""
    ).fetchall()
    if not rows:
        return []
    log_ids = {row[0] for row in rows}
    if len(log_ids) != 1:
        raise ProofError(503, "proof_unavailable", "Proof state is unavailable.")
    leaves: list[bytes] = []
    for expected_seq, (_, seq, raw_entry) in enumerate(rows):
        try:
            entry = SealedEntry.model_validate(raw_entry)
        except (TypeError, ValueError, KeyError) as exc:
            raise ProofError(503, "proof_unavailable", "Proof state is unavailable.") from exc
        if entry.body.seq != expected_seq or entry.body.seq != seq:
            raise ProofError(503, "proof_unavailable", "Proof state is unavailable.")
        leaves.append(sealed_bytes(entry))
    return leaves


def inclusion(leaves: Sequence[bytes], seq: int, tree_size: int) -> list[str]:
    """Return an encoded inclusion proof for ``seq`` in the exact tree size."""
    _validate_inclusion(seq, tree_size, len(leaves))
    return [encode_hash(item) for item in merkle.inclusion_proof(seq, tree_size, leaves)]


def consistency(leaves: Sequence[bytes], old_size: int, new_size: int) -> list[str]:
    """Return an encoded consistency proof between two exact tree sizes."""
    _validate_consistency(old_size, new_size, len(leaves))
    return [encode_hash(item) for item in merkle.consistency_proof(old_size, new_size, leaves)]


def _validate_inclusion(seq: int, tree_size: int, current_size: int) -> None:
    if (
        type(seq) is not int
        or type(tree_size) is not int
        or seq < 0
        or tree_size < 1
        or tree_size > MAX_PROOF_TREE_SIZE
        or seq >= tree_size
        or tree_size > current_size
    ):
        raise ProofError(422, "invalid_proof_range", "Invalid proof range.")


def _validate_consistency(old_size: int, new_size: int, current_size: int) -> None:
    if (
        type(old_size) is not int
        or type(new_size) is not int
        or old_size < 1
        or new_size <= old_size
        or new_size > MAX_PROOF_TREE_SIZE
        or new_size > current_size
    ):
        raise ProofError(422, "invalid_proof_range", "Invalid proof range.")

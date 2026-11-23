"""Postgres-backed RFC 6962 right-frontier persistence."""

from __future__ import annotations

from collections.abc import Sequence

from psycopg import Connection
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from libs.blackbox_core import merkle
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import (
    decode_base64url,
    decode_hash,
    encode_base64url,
    encode_hash,
)
from libs.blackbox_core.schemas import SealedEntry
from libs.blackbox_core.sealing import sealed_bytes

MERKLE_FRONTIER_MISMATCH = "merkle_frontier_mismatch"


class MerkleStateError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _frontier_json(frontier: Sequence[bytes | None]) -> list[str | None]:
    return [None if value is None else encode_base64url(value) for value in frontier]


def _frontier_bytes(values: object) -> list[bytes | None]:
    if not isinstance(values, list):
        raise MerkleStateError(MERKLE_FRONTIER_MISMATCH, "stored Merkle frontier is invalid")
    result: list[bytes | None] = []
    for value in values:
        if value is None:
            result.append(None)
        elif isinstance(value, str):
            try:
                result.append(decode_base64url(value))
            except ValueError as exc:
                raise MerkleStateError(
                    MERKLE_FRONTIER_MISMATCH, "stored Merkle frontier is invalid"
                ) from exc
        else:
            raise MerkleStateError(MERKLE_FRONTIER_MISMATCH, "stored Merkle frontier is invalid")
    return result


def _load_frontier(connection: Connection, log_id: str) -> tuple[int, list[bytes | None]]:
    row = connection.execute(
        """SELECT tree_size, frontier FROM blackbox.merkle_frontiers
        WHERE log_id=%s ORDER BY tree_size DESC LIMIT 1""",
        (log_id,),
    ).fetchone()
    if row is None:
        return 0, []
    tree_size, raw_frontier = row
    frontier = _frontier_bytes(raw_frontier)
    try:
        merkle.append(b"", frontier, tree_size)
    except ValueError as exc:
        raise MerkleStateError(
            MERKLE_FRONTIER_MISMATCH, "stored Merkle frontier shape is invalid"
        ) from exc
    return tree_size, frontier


def load_frontier(
    value: Connection | ConnectionPool, log_id: str
) -> tuple[int, list[bytes | None]]:
    """Load the latest persisted frontier, or the empty tree frontier."""
    if isinstance(value, ConnectionPool):
        with value.connection() as connection:
            return _load_frontier(connection, log_id)
    return _load_frontier(value, log_id)


def append_leaf_in_transaction(
    connection: Connection, log_id: str, leaf: bytes
) -> tuple[list[bytes | None], bytes]:
    tree_size, frontier = _load_frontier(connection, log_id)
    next_frontier, root = merkle.append(leaf, frontier, tree_size)
    connection.execute(
        """INSERT INTO blackbox.merkle_frontiers(log_id, tree_size, frontier, root_hash)
        VALUES (%s, %s, %s, %s)""",
        (log_id, tree_size + 1, Jsonb(_frontier_json(next_frontier)), encode_hash(root)),
    )
    return next_frontier, root


def append_in_transaction(connection: Connection, entry: SealedEntry) -> bytes:
    """Append one sealed-entry leaf; caller owns the surrounding transaction."""
    tree_size, _ = _load_frontier(connection, entry.body.log_id)
    if tree_size != entry.body.seq:
        raise MerkleStateError(
            MERKLE_FRONTIER_MISMATCH, "Merkle frontier and entry sequence disagree"
        )
    _, root = append_leaf_in_transaction(connection, entry.body.log_id, sealed_bytes(entry))
    return root


def current_root(value: Connection | ConnectionPool, log_id: str) -> bytes | None:
    def read(connection: Connection) -> bytes | None:
        row = connection.execute(
            """SELECT root_hash FROM blackbox.merkle_frontiers
            WHERE log_id=%s ORDER BY tree_size DESC LIMIT 1""",
            (log_id,),
        ).fetchone()
        return None if row is None else decode_hash(row[0])

    if isinstance(value, ConnectionPool):
        with value.connection() as connection:
            return read(connection)
    return read(value)


def validate_startup(pool: ConnectionPool) -> None:
    """Recompute all logs from entries; startup cost is O(total stored entries)."""
    with pool.connection() as connection:
        entry_logs = {
            row[0]
            for row in connection.execute("SELECT DISTINCT log_id FROM blackbox.entries").fetchall()
        }
        frontier_logs = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT log_id FROM blackbox.merkle_frontiers"
            ).fetchall()
        }
        for log_id in entry_logs | frontier_logs:
            try:
                leaves = [
                    sealed_bytes(SealedEntry.model_validate(row[0]))
                    for row in connection.execute(
                        "SELECT sealed_entry FROM blackbox.entries WHERE log_id=%s ORDER BY seq",
                        (log_id,),
                    ).fetchall()
                ]
                frontier: list[bytes | None] = []
                root: bytes | None = None
                tree_size = 0
                for leaf in leaves:
                    frontier, root = merkle.append(leaf, frontier, tree_size)
                    tree_size += 1
                row = connection.execute(
                    """SELECT tree_size, frontier, root_hash FROM blackbox.merkle_frontiers
                    WHERE log_id=%s ORDER BY tree_size DESC LIMIT 1""",
                    (log_id,),
                ).fetchone()
                if row is None or row[0] != tree_size or _frontier_bytes(row[1]) != frontier:
                    raise MerkleStateError(
                        MERKLE_FRONTIER_MISMATCH, "Merkle frontier disagrees with entries"
                    )
                expected_root = root if root is not None else sha256(b"")
                if decode_hash(row[2]) != expected_root:
                    raise MerkleStateError(
                        MERKLE_FRONTIER_MISMATCH, "Merkle root disagrees with entries"
                    )
            except MerkleStateError:
                raise
            except (TypeError, ValueError, KeyError) as exc:
                raise MerkleStateError(
                    MERKLE_FRONTIER_MISMATCH, "Merkle state cannot be recomputed"
                ) from exc

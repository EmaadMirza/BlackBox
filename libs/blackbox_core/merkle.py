"""RFC 6962 §2 tree, right frontier and exact-length proofs (spec §10.2)."""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

from libs.blackbox_core.crypto import sha256


def leaf_hash(leaf: bytes) -> bytes:
    return sha256(b"\x00" + leaf)


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("32-byte child hashes required")
    return sha256(b"\x01" + left + right)


def root(leaves: Sequence[bytes]) -> bytes:
    return MerkleTree(leaves).root()


class MerkleTree:
    """Immutable in-memory snapshot; caches subtree hashes for proof batches."""

    def __init__(self, leaves: Sequence[bytes]) -> None:
        self.leaves = tuple(leaves)
        # Cache is snapshot-local; it cannot retain unrelated ledger history.
        self._hash = lru_cache(maxsize=None)(self._subtree)

    def _subtree(self, start: int, size: int) -> bytes:
        if size == 0:
            return sha256(b"")
        if size == 1:
            return leaf_hash(self.leaves[start])
        k = 1 << ((size - 1).bit_length() - 1)
        return node_hash(self._hash(start, k), self._hash(start + k, size - k))

    def root(self, size: int | None = None) -> bytes:
        n = len(self.leaves) if size is None else size
        if type(n) is not int or not 0 <= n <= len(self.leaves):
            raise ValueError("invalid tree size")
        return self._hash(0, n)

    def inclusion_proof(self, m: int, n: int | None = None) -> list[bytes]:
        n = len(self.leaves) if n is None else n
        if type(m) is not int or type(n) is not int or not 0 <= m < n <= len(self.leaves):
            raise ValueError("invalid leaf index/tree size")

        def path(start: int, size: int, index: int) -> list[bytes]:
            if size == 1:
                return []
            k = 1 << ((size - 1).bit_length() - 1)
            if index < k:
                return path(start, k, index) + [self._hash(start + k, size - k)]
            return path(start + k, size - k, index - k) + [self._hash(start, k)]

        return path(0, n, m)

    def consistency_proof(self, m: int, n: int | None = None) -> list[bytes]:
        n = len(self.leaves) if n is None else n
        if type(m) is not int or type(n) is not int or not 0 <= m <= n <= len(self.leaves):
            raise ValueError("invalid tree sizes")
        if m == 0 or m == n:
            return []

        def sub(start: int, old: int, size: int, complete: bool) -> list[bytes]:
            if old == size:
                return [] if complete else [self._hash(start, size)]
            k = 1 << ((size - 1).bit_length() - 1)
            if old <= k:
                return sub(start, old, k, complete) + [self._hash(start + k, size - k)]
            return sub(start + k, old - k, size - k, False) + [self._hash(start, k)]

        return sub(0, m, n, True)


def append(
    leaf: bytes, frontier: Sequence[bytes | None], tree_size: int
) -> tuple[list[bytes | None], bytes]:
    if type(tree_size) is not int or tree_size < 0 or len(frontier) != tree_size.bit_length():
        raise ValueError("frontier shape does not match tree size")
    for level, value in enumerate(frontier):
        if bool(tree_size & (1 << level)) != (value is not None) or (
            value is not None and len(value) != 32
        ):
            raise ValueError("invalid frontier")
    result = list(frontier)
    carry = leaf_hash(leaf)
    level = 0
    size = tree_size
    while size & 1:
        carry = node_hash(result[level], carry)
        result[level] = None
        level += 1
        size >>= 1
    if level == len(result):
        result.append(carry)
    else:
        result[level] = carry
    total = None
    for h in result:
        if h is not None:
            total = h if total is None else node_hash(h, total)
    return result, total


def inclusion_proof(m: int, n: int, leaves: Sequence[bytes]) -> list[bytes]:
    return MerkleTree(leaves).inclusion_proof(m, n)


def consistency_proof(m: int, n: int, leaves: Sequence[bytes]) -> list[bytes]:
    return MerkleTree(leaves).consistency_proof(m, n)


def verify_inclusion(leaf_hash: bytes, m: int, n: int, proof: Sequence[bytes], root: bytes) -> bool:
    if (
        type(m) is not int
        or type(n) is not int
        or not 0 <= m < n
        or len(leaf_hash) != 32
        or len(root) != 32
        or any(len(p) != 32 for p in proof)
    ):
        return False
    fn = m
    sn = n - 1
    value = leaf_hash
    for sibling in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            value = node_hash(sibling, value)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            value = node_hash(value, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and value == root


def verify_consistency(
    m: int, n: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]
) -> bool:
    if (
        type(m) is not int
        or type(n) is not int
        or not 0 <= m <= n
        or len(old_root) != 32
        or len(new_root) != 32
        or any(len(p) != 32 for p in proof)
    ):
        return False
    if m == 0:
        return not proof and old_root == sha256(b"") and (n != 0 or new_root == old_root)
    if m == n:
        return not proof and old_root == new_root
    fn = m - 1
    sn = n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    nodes = list(proof)
    if fn == 0:
        fr = sr = old_root
    elif nodes:
        fr = sr = nodes.pop(0)
    else:
        return False
    for sibling in nodes:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(sibling, fr)
            sr = node_hash(sibling, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root

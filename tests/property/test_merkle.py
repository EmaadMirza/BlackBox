"""Compare Merkle roots with an independently written recursive reference."""

import hashlib

from hypothesis import given
from hypothesis import strategies as st

from libs.blackbox_core.merkle import MerkleTree, append


def reference(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return hashlib.sha256(b"\x01" + reference(leaves[:split]) + reference(leaves[split:])).digest()


@given(st.lists(st.binary(max_size=30), max_size=100))
def test_reference_and_frontier(leaves: list[bytes]) -> None:
    tree = MerkleTree(leaves)
    assert tree.root() == reference(leaves)
    frontier = []
    for i, leaf in enumerate(leaves):
        frontier, digest = append(leaf, frontier, i)
        assert digest == reference(leaves[: i + 1])

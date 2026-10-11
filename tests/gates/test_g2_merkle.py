"""G2: reference vectors, exhaustive sizes and proof corruption rejection."""

import json
import random
from pathlib import Path

import pytest

from libs.blackbox_core.merkle import (
    MerkleTree,
    leaf_hash,
    root,
    verify_consistency,
    verify_inclusion,
)


def flip(value: bytes, bit: int) -> bytes:
    data = bytearray(value)
    data[bit // 8] ^= 1 << (bit % 8)
    return bytes(data)


def test_reference_vectors() -> None:
    vector = json.loads(Path("tests/vectors/rfc6962.json").read_text())
    leaves = [bytes.fromhex(v) for v in vector["leaves"]]
    tree = MerkleTree(leaves)
    for n, expected in enumerate(vector["roots"], 1):
        assert tree.root(n).hex() == expected
    for item in vector["consistency"]:
        m, n = item["m"], item["n"]
        proof = [bytes.fromhex(v) for v in item["proof"]]
        assert tree.consistency_proof(m, n) == proof
        assert verify_consistency(m, n, tree.root(m), tree.root(n), proof)


def test_all_sizes_all_proofs() -> None:
    tree = MerkleTree([i.to_bytes(4, "big") for i in range(200)])
    for n in range(1, 201):
        for m in range(n):
            assert verify_inclusion(
                leaf_hash(tree.leaves[m]), m, n, tree.inclusion_proof(m, n), tree.root(n)
            ), (m, n)
        for m in range(1, n):
            assert verify_consistency(
                m, n, tree.root(m), tree.root(n), tree.consistency_proof(m, n)
            ), (m, n)


@pytest.mark.parametrize("n", range(1, 201))
def test_single_bit_corruption(n: int) -> None:
    tree = MerkleTree([i.to_bytes(4, "big") for i in range(n)])
    rng = random.Random(n)
    bits = list(range(256)) if n <= 64 else rng.sample(range(256), 4)
    indices = range(n) if n <= 64 else rng.sample(range(n), min(n, 4))
    for m in indices:
        leaf = leaf_hash(tree.leaves[m])
        proof = tree.inclusion_proof(m)
        digest = tree.root()
        for bit in bits:
            assert not verify_inclusion(flip(leaf, bit), m, n, proof, digest)
            assert not verify_inclusion(leaf, m, n, proof, flip(digest, bit))
            for j in range(len(proof)):
                bad = proof.copy()
                bad[j] = flip(bad[j], bit)
                assert not verify_inclusion(leaf, m, n, bad, digest)
        assert not verify_inclusion(leaf, m, n, proof + [bytes(32)], digest)
        if proof:
            assert not verify_inclusion(leaf, m, n, proof[:-1], digest)
    old_sizes = range(1, n) if n <= 64 else rng.sample(range(1, n), 4)
    for m in old_sizes:
        proof = tree.consistency_proof(m)
        old = tree.root(m)
        new = tree.root()
        for bit in bits:
            assert not verify_consistency(m, n, flip(old, bit), new, proof)
            assert not verify_consistency(m, n, old, flip(new, bit), proof)
            for j in range(len(proof)):
                bad = proof.copy()
                bad[j] = flip(bad[j], bit)
                assert not verify_consistency(m, n, old, new, bad)
        assert not verify_consistency(m, n, old, new, proof + [bytes(32)])
        assert not verify_consistency(m, n, old, new, proof[:-1])


def test_empty_equal_and_invalid_inputs() -> None:
    empty = root([])
    single = root([b"a"])
    assert verify_consistency(0, 0, empty, empty, [])
    assert verify_consistency(0, 1, empty, single, [])
    assert verify_consistency(1, 1, single, single, [])
    assert not verify_consistency(1, 0, single, empty, [])
    assert not verify_consistency(1, 1, single, single, [empty])
    assert not verify_inclusion(single, 0, 0, [], empty)

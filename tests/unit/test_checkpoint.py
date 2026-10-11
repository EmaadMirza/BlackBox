"""Checkpoint binding and root-pinned witness quorum."""

from libs.blackbox_core.checkpoint import (
    build_checkpoint,
    build_cosignature,
    sign_checkpoint,
    verify_checkpoint,
)
from libs.blackbox_core.encoding import encode_base64url, encode_hash
from libs.blackbox_core.merkle import root
from libs.blackbox_core.schemas import WitnessIdentity, WitnessSet
from libs.blackbox_core.signing import sign_structure, structure_hash
from libs.blackbox_core.witness_set import has_quorum, verify_witness_set
from tests._dev_keys import dev_key
from tests.unit.test_epochs_rules import certificates


def witness_fixture() -> tuple:
    rootkey, _, epoch, _, ec = certificates()
    keys = [dev_key(i) for i in (4, 5, 6)]
    ws = WitnessSet(
        log_id=ec.log_id,
        version=1,
        witnesses=[
            WitnessIdentity(
                witness_id=f"w{i}", public_key=encode_base64url(k.public_key().public_bytes_raw())
            )
            for i, k in enumerate(keys)
        ],
        quorum=2,
        effective_time=ec.valid_from,
    )
    return rootkey, epoch, ec, keys, sign_structure(ws, rootkey, "witness_set")


def test_checkpoint_quorum_and_replay() -> None:
    rootkey, epoch, ec, keys, ws = witness_fixture()
    cp = sign_checkpoint(
        build_checkpoint(ec.log_id, 1, encode_hash(root([b"test"])), 0, 0, ec.valid_from), epoch
    )
    assert verify_checkpoint(cp, epoch.public_key().public_bytes_raw())
    assert verify_witness_set(ws, rootkey.public_key().public_bytes_raw())
    cosigs = [
        build_cosignature(structure_hash(cp), f"w{i}", ec.valid_from, key, log_id=ec.log_id)
        for i, key in enumerate(keys)
    ]
    assert has_quorum(cp, cosigs[:2], ws)
    assert not has_quorum(cp, cosigs[:1] * 3, ws)
    assert not has_quorum(cp, [], ws)
    assert not has_quorum(cp.model_copy(update={"tree_size": 2}), cosigs, ws)
    assert not verify_checkpoint(
        cp.model_copy(update={"root_hash": "sha256:" + "a" * 64}),
        epoch.public_key().public_bytes_raw(),
    )
    duplicate = ws.model_copy(update={"witnesses": [ws.witnesses[0]] * 3})
    assert not verify_witness_set(duplicate, rootkey.public_key().public_bytes_raw())

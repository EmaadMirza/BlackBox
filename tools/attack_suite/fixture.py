"""Deterministic ten-entry workload; caller supplies ephemeral signing capabilities."""

from __future__ import annotations

from collections.abc import Sequence

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.checkpoint import build_checkpoint, build_cosignature, sign_checkpoint
from libs.blackbox_core.crypto import SigningOperation
from libs.blackbox_core.encoding import encode_base64url, encode_hash
from libs.blackbox_core.epochs import (
    build_epoch_certificate,
    build_intermediate_certificate,
    certificate_id,
)
from libs.blackbox_core.evidence import (
    Bundle,
    CheckpointEvidence,
    ConsistencyProof,
    InclusionProof,
    PinnedKeys,
)
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import WitnessIdentity, WitnessSet, parse_entry
from libs.blackbox_core.sealing import seal, sealed_bytes
from libs.blackbox_core.signing import sign_structure, structure_hash


def build_demo(keys: Sequence[tuple[SigningOperation, bytes]]) -> tuple[Bundle, PinnedKeys]:
    if len(keys) != 7:
        raise ValueError("seven independent test signing identities required")
    root, inter, epoch0, epoch1, *witnesses = keys
    log = derive_log_id(root[1], "stage1-demo")
    start = "2026-01-01T00:00:00.000Z"
    ic = build_intermediate_certificate(
        log,
        "intermediate-0",
        encode_base64url(inter[1]),
        start,
        "2026-02-01T00:00:00.000Z",
        root[0],
    )
    epochs = [
        build_epoch_certificate(
            i,
            encode_base64url(key[1]),
            f"2026-01-01T00:{i * 5:02d}:00.000Z",
            f"2026-01-01T00:{(i + 1) * 5:02d}:00.000Z",
            "intermediate-0",
            log_id=log,
            signing_operation=inter[0],
        )
        for i, key in enumerate([epoch0, epoch1])
    ]
    ws = sign_structure(
        WitnessSet(
            log_id=log,
            version=1,
            witnesses=[
                WitnessIdentity(witness_id=f"w{i}", public_key=encode_base64url(key[1]))
                for i, key in enumerate(witnesses)
            ],
            quorum=2,
            effective_time=start,
        ),
        root[0],
        "witness_set",
    )
    entries = []
    checkpoints = []
    previous = GENESIS_PREV_HASH
    for seq in range(10):
        epoch = 0 if seq < 4 else 1
        ec = epochs[epoch]
        key = [epoch0, epoch1][epoch]
        stamp = f"2026-01-01T00:{epoch * 5:02d}:{seq if epoch == 0 else seq - 4:02d}.000Z"
        if seq == 3:
            stamp = "2026-01-01T00:04:59.999Z"
        body = dict(
            format_version="4",
            log_id=log,
            epoch_id=epoch,
            seq=seq,
            signer_timestamp=stamp,
            prev_hash=previous,
            lane="agent",
            epoch_certificate_id=certificate_id(ec),
        )
        if seq in (0, 4):
            body.update(type="epoch_start", certificate=ec.model_dump())
        elif seq == 3:
            body.update(type="epoch_end")
        else:
            body.update(
                type="action",
                action_name="audit",
                reason=f"honest event {seq}",
                target_reference=f"event-{seq}",
            )
        entry = seal(parse_entry(body), key[0])
        entries.append(entry)
        previous = entry_hash(entry.body)
        if seq in (2, 9):
            tree = MerkleTree([sealed_bytes(e) for e in entries])
            cp = sign_checkpoint(
                build_checkpoint(log, seq + 1, encode_hash(tree.root()), seq, epoch, stamp), key[0]
            )
            cosigs = [
                build_cosignature(structure_hash(cp), f"w{i}", stamp, w[0], log_id=log)
                for i, w in enumerate(witnesses)
            ]
            checkpoints.append(CheckpointEvidence(checkpoint=cp, cosignatures=cosigs))
    tree = MerkleTree([sealed_bytes(e) for e in entries])
    inclusion = [
        InclusionProof(
            seq=seq,
            tree_size=c.checkpoint.tree_size,
            proof=[encode_hash(h) for h in tree.inclusion_proof(seq, c.checkpoint.tree_size)],
        )
        for c in checkpoints
        for seq in range(c.checkpoint.tree_size)
    ]
    bundle = Bundle(
        format_version="4",
        log_id=log,
        log_name="stage1-demo",
        entries=[e.model_dump() for e in entries],
        intermediates=[ic],
        epochs=epochs,
        witness_set=ws,
        checkpoints=checkpoints,
        inclusion_proofs=inclusion,
        consistency_proofs=[
            ConsistencyProof(
                old_size=3,
                new_size=10,
                proof=[encode_hash(h) for h in tree.consistency_proof(3, 10)],
            )
        ],
    )
    pins = PinnedKeys(
        log_id=log,
        log_name="stage1-demo",
        root_public_key=encode_base64url(root[1]),
        witness_public_keys={f"w{i}": encode_base64url(w[1]) for i, w in enumerate(witnesses)},
        minimum_tree_size=10,
    )
    return bundle, pins

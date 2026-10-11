"""Root-authenticated witness identity and distinct-signer quorum (spec §11.6)."""

from __future__ import annotations

from collections.abc import Sequence

from libs.blackbox_core.checkpoint import verify_cosignature
from libs.blackbox_core.encoding import decode_base64url
from libs.blackbox_core.schemas import Checkpoint, Cosignature, WitnessSet
from libs.blackbox_core.signing import structure_hash, verify_structure


def verify_witness_set(witness_set: WitnessSet, pinned_root: bytes) -> bool:
    ids = [w.witness_id for w in witness_set.witnesses]
    keys = [w.public_key for w in witness_set.witnesses]
    return (
        len(ids) == len(set(ids))
        and len(keys) == len(set(keys))
        and 1 <= witness_set.quorum <= len(ids)
        and verify_structure(witness_set, pinned_root, "witness_set")
    )


def has_quorum(
    checkpoint: Checkpoint, cosignatures: Sequence[Cosignature], witness_set: WitnessSet
) -> bool:
    """Caller MUST authenticate/pin the witness set first; count unique valid identities."""
    if (
        checkpoint.log_id != witness_set.log_id
        or checkpoint.signer_timestamp < witness_set.effective_time
    ):
        return False
    members = {w.witness_id: w.public_key for w in witness_set.witnesses}
    if len(members) != len(witness_set.witnesses) or len(set(members.values())) != len(members):
        return False
    if not 1 <= witness_set.quorum <= len(members):
        return False
    digest = structure_hash(checkpoint)
    valid = set()
    for cosig in cosignatures:
        if (
            cosig.log_id == checkpoint.log_id
            and cosig.checkpoint_hash == digest
            and cosig.witness_timestamp >= checkpoint.signer_timestamp
            and cosig.witness_id in members
            and verify_cosignature(cosig, decode_base64url(members[cosig.witness_id]))
        ):
            valid.add(cosig.witness_id)
    return len(valid) >= witness_set.quorum

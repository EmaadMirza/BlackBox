"""Versioned offline bundle contract (spec §16; docs/stage1-protocol.md)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from libs.blackbox_core.schemas import (
    Checkpoint,
    Cosignature,
    Count,
    EpochCertificate,
    Finding,
    Hash,
    IntermediateCertificate,
    PublicKey,
    Revocation,
    SealedEntry,
    StrictModel,
    WitnessSet,
)


class PinnedKeys(StrictModel):
    log_id: Hash
    log_name: str
    root_public_key: PublicKey
    witness_public_keys: dict[str, PublicKey]
    minimum_tree_size: Count = 0
    revocations: list[Revocation] = Field(default_factory=list)


class CheckpointEvidence(StrictModel):
    checkpoint: Checkpoint
    cosignatures: list[Cosignature]


class InclusionProof(StrictModel):
    seq: Count
    tree_size: Count
    proof: list[Hash]


class ConsistencyProof(StrictModel):
    old_size: Count
    new_size: Count
    proof: list[Hash]


class Opening(StrictModel):
    seq: Count
    field: Literal["action.arguments_commitment", "result_commitment"]
    value: str
    salt: str


class Bundle(StrictModel):
    format_version: Literal["4"]
    log_id: Hash
    log_name: str
    entries: list[dict[str, object]]
    intermediates: list[IntermediateCertificate]
    epochs: list[EpochCertificate]
    witness_set: WitnessSet
    checkpoints: list[CheckpointEvidence]
    inclusion_proofs: list[InclusionProof]
    consistency_proofs: list[ConsistencyProof]
    revocations: list[Revocation] = Field(default_factory=list)
    openings: list[Opening] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


def entry_dict(entry: SealedEntry) -> dict[str, object]:
    return entry.model_dump()

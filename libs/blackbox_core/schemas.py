"""Strict signed structures, spec §7–8; concrete profile in docs/stage1-protocol.md."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from libs.blackbox_core.canonical import normalize
from libs.blackbox_core.encoding import decode_base64url, decode_hash, parse_timestamp


def _hash(value: str) -> str:
    decode_hash(value)
    return value


def _time(value: str) -> str:
    parse_timestamp(value)
    return value


def _public(value: str) -> str:
    if len(decode_base64url(value)) != 32:
        raise ValueError("public key must be 32 bytes")
    return value


def _signature(value: str) -> str:
    if value and len(decode_base64url(value)) != 64:
        raise ValueError("signature must be 64 bytes")
    return value


Hash = Annotated[str, AfterValidator(_hash)]
Timestamp = Annotated[str, AfterValidator(_time)]
PublicKey = Annotated[str, AfterValidator(_public)]
Signature = Annotated[str, AfterValidator(_signature)]
Count = Annotated[int, Field(ge=0, le=2**53 - 1)]


class StrictModel(BaseModel):
    """Strict, frozen, normalized models shared by sealer and offline verifier."""

    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, revalidate_instances="always"
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: object) -> object:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="python")
        if isinstance(value, dict):
            # Nested declared models are converted before the JSON profile check.
            def plain(v: object) -> object:
                if isinstance(v, BaseModel):
                    return v.model_dump(mode="python")
                if isinstance(v, dict):
                    return {k: plain(item) for k, item in v.items()}
                if isinstance(v, list):
                    return [plain(item) for item in v]
                return v

            return normalize(plain(value))
        return value


class Principal(StrictModel):
    """Identity and delegation, §8.3."""

    client_key_id: str
    source_address: str
    human_identity: str
    agent_identity: str
    agent_version: str
    delegation_chain: list[str]


class RequestAction(StrictModel):
    """Request description, §8.3."""

    adapter: Literal["http", "mcp"]
    method: str
    path: str
    tool_name: str
    body_digest: Hash
    arguments_commitment: Hash
    idempotency_key: Hash
    payload_reference: str


class Policy(StrictModel):
    """Policy evidence, §8.3; absence of a receipt is explicit null."""

    version: str
    decision: Literal["allow", "block", "require_approval"]
    matching_rule_id: str
    severity: str
    approval_receipt_id: str | None


class UntrustedInput(StrictModel):
    """Input lineage, §8.3."""

    source: str
    content_hash: Hash
    trust_label: str


class Context(StrictModel):
    """Agent context, §8.3."""

    system_prompt_hash: Hash
    tool_definitions_hash: Hash
    model_identifier: str
    model_version: str
    untrusted_inputs: list[UntrustedInput]


class EntryBase(StrictModel):
    """Fields common to every entry, §8.2."""

    format_version: Literal["4"]
    log_id: Hash
    epoch_id: Count
    seq: Count
    signer_timestamp: Timestamp
    prev_hash: Hash
    lane: Literal["web", "agent"]
    epoch_certificate_id: Hash


class RequestEntry(EntryBase):
    """Request-bearing fields, §8.3."""

    principal: Principal
    action: RequestAction
    policy: Policy
    context: Context | None
    claimed_time: Timestamp

    @model_validator(mode="after")
    def require_agent_context(self) -> Self:
        if self.lane == "agent" and self.context is None:
            raise ValueError("agent requests require influence context")
        return self


class Intent(RequestEntry):
    """Recorded before forwarding, §8.1."""

    type: Literal["intent"]
    status: Literal["pending", "ready"]


class Outcome(RequestEntry):
    """Downstream result, §8.3."""

    type: Literal["outcome"]
    retry: bool = False
    intent_seq: Count
    upstream_status: int
    result_commitment: Hash
    provider_request_id: str
    latency: Count


class Blocked(RequestEntry):
    """Rejected request, §8.1."""

    type: Literal["blocked"]
    reason: str


class Approval(EntryBase):
    """Verified receipt entry, §8.1."""

    type: Literal["approval"]
    receipt: ApprovalReceipt


class Action(EntryBase):
    """Automated BlackBox response, §8.1."""

    type: Literal["action"]
    action_name: str
    reason: str
    target_reference: str


class EpochCertificate(StrictModel):
    """Public epoch certificate contents, §7.3."""

    epoch_id: Count
    log_id: Hash
    epoch_public_key: PublicKey
    valid_from: Timestamp
    valid_until: Timestamp
    intermediate_id: str
    signature: Signature = ""


class EpochStart(EntryBase):
    """Signer-only epoch start, §7.3."""

    type: Literal["epoch_start"]
    certificate: EpochCertificate


class EpochEnd(EntryBase):
    """Final signature of an epoch, §7.3."""

    type: Literal["epoch_end"]


class ToolDefs(EntryBase):
    """Tool snapshot marker, §8.1."""

    type: Literal["tool_defs"]
    session_id: str
    definitions_hash: Hash
    payload_reference: str


class Gap(EntryBase):
    """Queued outage interval, §10.5."""

    type: Literal["gap"]
    outage_start: Timestamp
    outage_end: Timestamp
    queued_entries: Count


class Breakglass(EntryBase):
    """Privileged protected-material access, §8.1."""

    type: Literal["breakglass"]
    principal_id: str
    reason: str
    material_reference: str


Entry = Annotated[
    Intent
    | Outcome
    | Blocked
    | Approval
    | Action
    | EpochStart
    | EpochEnd
    | ToolDefs
    | Gap
    | Breakglass,
    Field(discriminator="type"),
]


class SealedEntry(StrictModel):
    """Signed envelope, §8.5; see the Stage 1 protocol profile."""

    body: Entry
    signature: Signature = ""


class Checkpoint(StrictModel):
    """Signed checkpoint, §8.6."""

    log_id: Hash
    tree_size: Count
    root_hash: Hash
    latest_seq: Count
    epoch_id: Count
    signer_timestamp: Timestamp
    signature: Signature = ""


class Cosignature(StrictModel):
    """Witness evidence, §8.6."""

    log_id: Hash
    checkpoint_hash: Hash
    witness_id: str
    witness_timestamp: Timestamp
    witness_signature: Signature = ""


class Heartbeat(StrictModel):
    """Signer state claim, §8.6."""

    log_id: Hash
    epoch_id: Count
    latest_seq: Count
    latest_entry_hash: Hash
    queue_depth: Count
    signer_timestamp: Timestamp
    signature: Signature = ""


class Attestation(StrictModel):
    """Bound request attestation, §8.6."""

    log_id: Hash
    intent_seq: Count
    idempotency_key: Hash
    body_digest: Hash
    issued_at: Timestamp
    expires_at: Timestamp
    signature: Signature = ""


class ApprovalReceipt(StrictModel):
    """Human approval receipt, §8.6."""

    log_id: Hash
    approver_id: str
    intent_seq: Count
    arguments_commitment: Hash
    expires_at: Timestamp
    nonce: str
    signature: Signature = ""


class WitnessIdentity(StrictModel):
    """Public witness identity, §8.6."""

    witness_id: str
    public_key: PublicKey


class WitnessSet(StrictModel):
    """Root-signed witness-set document, §8.6."""

    log_id: Hash
    version: Literal[1]
    witnesses: list[WitnessIdentity]
    quorum: Annotated[int, Field(ge=1)]
    effective_time: Timestamp
    signature: Signature = ""


class Finding(StrictModel):
    """Reconciler evidence references; not a sealed entry, §8.6."""

    finding_type: Literal[
        "UNRECORDED_ACTION",
        "UNATTESTED_ACTION",
        "PHANTOM_OUTCOME",
        "ORPHAN_INTENT",
        "ARGS_MISMATCH",
        "RESULT_MISMATCH",
    ]
    ledger_seqs: list[int]
    provider_event_ids: list[str]
    detection_time: Timestamp


class IntermediateCertificate(StrictModel):
    log_id: Hash
    intermediate_id: str
    public_key: PublicKey
    valid_from: Timestamp
    valid_until: Timestamp
    signature: Signature = ""


class Revocation(StrictModel):
    log_id: Hash
    intermediate_id: str
    effective_time: Timestamp
    signature: Signature = ""


Approval.model_rebuild()
ENTRY_ADAPTER = TypeAdapter(Entry)


def parse_entry(value: object) -> Entry:
    return ENTRY_ADAPTER.validate_python(value)

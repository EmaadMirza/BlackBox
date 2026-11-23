"""Pure seal/attestation rules; no service state or networking (spec §9.3–9.4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from libs.blackbox_core.epochs import in_window
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.schemas import Checkpoint, Entry, Intent, Outcome, parse_entry


@dataclass(frozen=True)
class SignerState:
    last_seq: int
    last_hash: str
    epoch_id: int
    epoch_certificate_id: str
    valid_from: str
    valid_until: str
    now: str
    entries_this_second: int = 0
    rate_cap: int = 1000
    caller: str = "gateway"
    intents: dict[int, Intent] = field(default_factory=dict)
    outcomes: dict[int, Outcome] = field(default_factory=dict)
    log_id: str = ""


class CheckpointEvidence(Protocol):
    def covers(self, intent_seq: int) -> bool: ...


def check_seal_request(state: SignerState, candidate: Entry) -> None:
    try:
        candidate = parse_entry(candidate)
    except ValueError as exc:
        raise SignerRuleError("schema invalid") from exc
    validate_seal(
        candidate,
        state.last_seq,
        state.last_hash,
        in_window(state.now, state.valid_from, state.valid_until),
        state.entries_this_second,
        state.rate_cap,
        state.caller,
        state.intents.get(getattr(candidate, "intent_seq", -1)),
        state.outcomes.get(getattr(candidate, "intent_seq", -1)),
    )
    if (
        candidate.epoch_id != state.epoch_id
        or candidate.epoch_certificate_id != state.epoch_certificate_id
    ):
        raise SignerRuleError("wrong epoch identity")
    if candidate.signer_timestamp != state.now:
        raise SignerRuleError("signer timestamp must match trusted state time")


def validate_seal(
    candidate: Entry,
    last_seq: int,
    last_hash: str,
    epoch_valid: bool,
    entries_this_second: int,
    rate_cap: int,
    caller: str,
    intent: Intent | None,
    existing_outcome: Outcome | None,
) -> None:
    candidate = parse_entry(candidate)
    if candidate.seq != last_seq + 1:
        raise SignerRuleError("sequence must increase by one")
    if candidate.prev_hash != last_hash:
        raise SignerRuleError("previous hash mismatch")
    if not epoch_valid:
        raise SignerRuleError("expired epoch; rollover required")
    if rate_cap <= 0 or entries_this_second < 0 or entries_this_second >= rate_cap:
        raise SignerRuleError("rate cap exceeded")
    if candidate.type in ("epoch_start", "epoch_end") and caller != "signer":
        raise SignerRuleError("signer-only entry type")
    if isinstance(candidate, Outcome):
        if (
            intent is None
            or intent.seq != candidate.intent_seq
            or intent.log_id != candidate.log_id
        ):
            raise SignerRuleError("outcome must reference an existing intent")
        if candidate.action.idempotency_key != intent.action.idempotency_key:
            raise SignerRuleError("outcome idempotency mismatch")
        if existing_outcome is not None and (
            not candidate.retry
            or existing_outcome.action.idempotency_key != candidate.action.idempotency_key
        ):
            raise SignerRuleError("intent already has outcome; explicit same-key retry required")


def validate_attest(
    intent: Intent,
    requested_digest: str,
    prior_digest: str | None,
    requires_witness: bool,
    witnessed_latest_seq: int | None,
) -> None:
    if intent.action.body_digest != requested_digest or prior_digest not in (
        None,
        requested_digest,
    ):
        raise SignerRuleError("attestation digest mismatch")
    if intent.status != "ready" or intent.policy.decision == "block":
        raise SignerRuleError("intent is blocked or pending approval")
    if requires_witness and (witnessed_latest_seq is None or witnessed_latest_seq < intent.seq):
        raise SignerRuleError("intent lacks witnessed coverage")


def intent_requires_witness(intent: Intent) -> bool:
    policy = intent.policy
    severity = getattr(policy, "severity", None)
    if not isinstance(severity, str) or not severity:
        return True
    return severity.lower() == "high" or policy.decision == "require_approval"


def check_attest_request(
    intent: Intent,
    requested_body_digest: str | None,
    prior_digest: str | None,
    checkpoint_evidence: CheckpointEvidence | None,
) -> None:
    digest = intent.action.body_digest if requested_body_digest is None else requested_body_digest
    if prior_digest not in (None, digest):
        raise SignerRuleError("attestation digest mismatch")
    validate_attest(intent, digest, prior_digest, False, None)
    if intent_requires_witness(intent):
        if checkpoint_evidence is None or not checkpoint_evidence.covers(intent.seq):
            raise SignerRuleError("intent lacks witnessed coverage")


def check_checkpoint_request(
    state: SignerState, last_checkpoint: Checkpoint | None, request: Checkpoint
) -> None:
    """Validate ledger-supplied checkpoint metadata against signer-owned state."""
    if state.log_id and request.log_id != state.log_id:
        raise SignerRuleError("checkpoint log identity mismatch", code="checkpoint_log_mismatch")
    sealed_count = state.last_seq + 1
    if request.latest_seq > state.last_seq:
        raise SignerRuleError("checkpoint is ahead of signer", code="checkpoint_future")
    if request.latest_seq < state.last_seq or request.tree_size < sealed_count:
        raise SignerRuleError("checkpoint is stale", code="checkpoint_stale")
    if request.tree_size != sealed_count:
        raise SignerRuleError("checkpoint size mismatch", code="checkpoint_size_mismatch")
    if request.latest_seq != state.last_seq:
        raise SignerRuleError("checkpoint sequence mismatch", code="checkpoint_stale")
    if request.latest_entry_hash != state.last_hash:
        raise SignerRuleError("latest entry hash mismatch", code="checkpoint_latest_hash_mismatch")
    if request.epoch_id != state.epoch_id:
        raise SignerRuleError("checkpoint epoch mismatch", code="checkpoint_epoch_mismatch")
    if last_checkpoint is not None:
        if request.tree_size < last_checkpoint.tree_size:
            raise SignerRuleError("checkpoint is stale", code="checkpoint_stale")
        if (
            request.tree_size == last_checkpoint.tree_size
            and request.root_hash != last_checkpoint.root_hash
        ):
            raise SignerRuleError("checkpoint root conflicts", code="checkpoint_root_conflict")

"""Pure seal/attestation rules; no service state or networking (spec §9.3–9.4)."""

from __future__ import annotations

from dataclasses import dataclass, field

from libs.blackbox_core.epochs import in_window
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.schemas import Entry, Intent, Outcome, parse_entry


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
    if intent.status != "ready":
        raise SignerRuleError("intent is pending approval")
    if requires_witness and (witnessed_latest_seq is None or witnessed_latest_seq < intent.seq):
        raise SignerRuleError("intent lacks witnessed coverage")

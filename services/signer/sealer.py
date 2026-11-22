"""In-process signer seal operation.

This module owns the service-side orchestration around the pure signer rules.  It
does not generate or persist keys: callers provide a ``SigningOperation`` and
the operation is retained only by this signer-owned object.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from datetime import timedelta
from threading import RLock
from typing import Any

from libs.blackbox_core import sealing
from libs.blackbox_core.attestation import build_attestation
from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.checkpoint import sign_checkpoint
from libs.blackbox_core.crypto import SigningOperation
from libs.blackbox_core.encoding import decode_hash, format_timestamp, parse_timestamp
from libs.blackbox_core.epochs import in_window
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.schemas import (
    Checkpoint,
    Heartbeat,
    Intent,
    Outcome,
    SealedEntry,
    parse_entry,
)
from libs.blackbox_core.signer_rules import (
    CheckpointEvidence,
    SignerState,
    check_attest_request,
    check_seal_request,
)
from libs.blackbox_core.signing import sign_structure
from services.signer import outbox, state
from services.signer.clock import system_utc_now
from services.signer.epoch_manager import EpochManager, EpochUnavailableError, RolloverPlan
from services.signer.history import (
    HistoryIntegrityError,
    HistorySource,
    HistorySourceError,
    OutcomeConflictError,
    verify_history_record,
)
from services.signer.rate_limit import DurableRateLimiter


class SignerSealer:
    """Seal gateway entries against the signer's durable chain state.

    ``clock`` supplies a fresh trusted time for every seal, independently of
    gateway candidates. Sequence, previous hash, and epoch id are loaded from
    durable state for every operation; rate reservations are durable as well.
    ``log_id`` binds this operation to one explicitly configured log identity.

    Gateway calls intentionally use ``caller='gateway'``.  Consequently,
    ``epoch_start`` and ``epoch_end`` remain unavailable through this operation.
    """

    def __init__(
        self,
        *,
        log_id: str,
        epoch_certificate_id: str,
        valid_from: str,
        valid_until: str,
        clock: Callable[[], str] = system_utc_now,
        signing_operation: SigningOperation,
        rate_cap: int = 1000,
        epoch_id: int | None = None,
        history_source: HistorySource | None = None,
        epoch_manager: EpochManager | None = None,
        outbox_max_pending: int = outbox.MAX_PENDING,
    ) -> None:
        if epoch_id is not None and (type(epoch_id) is not int or epoch_id < 0):
            raise ValueError("epoch_id must be a non-negative integer")
        if type(rate_cap) is not int or rate_cap <= 0:
            raise ValueError("rate_cap must be a positive integer")
        if type(outbox_max_pending) is not int or outbox_max_pending <= 0:
            raise ValueError("outbox_max_pending must be a positive integer")

        # Validate runtime metadata at construction, before any candidate can
        # reach the signing operation.  These are the same encodings used by
        # the core schemas and epoch-window rules.
        decode_hash(log_id)
        decode_hash(epoch_certificate_id)
        parse_timestamp(valid_from)
        parse_timestamp(valid_until)

        self._log_id = log_id
        self._epoch_id = epoch_id
        self._epoch_certificate_id = epoch_certificate_id
        self._valid_from = valid_from
        self._valid_until = valid_until
        self._clock = clock
        self._rate_cap = rate_cap
        self._outbox_max_pending = outbox_max_pending
        self._signing_operation = signing_operation
        self._rate_limiter = DurableRateLimiter()
        self._history_source = history_source
        self._epoch_manager = epoch_manager
        self._last_rollover_entries: tuple[SealedEntry, ...] = ()
        self._attested_digests: dict[int, str] = {}
        self._sealed_intents: dict[int, str] = {}
        self._lock = RLock()
        self._heartbeat_interval = 5
        self._last_heartbeat_at = None
        self._delivery_alarm: str | None = None

    def seal_with_rollover(self, candidate: object) -> tuple[tuple[SealedEntry, ...], SealedEntry]:
        sealed = self.seal(candidate)
        return self._last_rollover_entries, sealed

    @property
    def health_reason(self) -> str | None:
        if self._delivery_alarm is not None:
            return self._delivery_alarm
        if self._epoch_manager is not None and self._epoch_manager.degraded:
            return "new_epoch_required"
        pending = len(state.load_outbox(self._log_id).entries)
        if pending >= self._outbox_max_pending:
            return "outbox_full"
        if pending * 2 >= self._outbox_max_pending:
            return "outbox_high"
        return None

    def set_delivery_alarm(self, reason: str) -> None:
        with self._lock:
            self._delivery_alarm = reason

    def reset_delivery_alarm(self) -> None:
        with self._lock:
            self._delivery_alarm = None

    def seal(self, candidate: object) -> SealedEntry:
        with self._lock:
            return self._seal_unlocked(candidate)

    def pending_outbox(self, limit: int | None = None) -> tuple[SealedEntry, ...]:
        with self._lock:
            if limit is not None and (type(limit) is not int or limit < 0):
                raise ValueError("outbox limit must be a non-negative integer")
            entries = state.load_outbox(self._log_id).entries
            return entries if limit is None else entries[:limit]

    def acknowledge_outbox(self, seq: int, entry_hash_value: str) -> outbox.OutboxSnapshot:
        with self._lock:
            return state.acknowledge_outbox(self._log_id, seq, entry_hash_value)

    def _persist_with_outbox(
        self,
        last_seq: int,
        last_hash: str,
        epoch_id: int,
        log_id: str,
        outcome_index: Mapping[int, str] | None = None,
        epoch_metadata: Mapping[str, Any] | None = None,
        last_checkpoint: Any = None,
        *,
        outbox_append: tuple[SealedEntry, ...],
        reserved: bool = False,
    ) -> None:
        parameters = inspect.signature(state.persist_state).parameters
        accepts_outbox = "outbox_append" in parameters or any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
        )
        if not accepts_outbox:
            # Preserve compatibility with test-only legacy persistence callbacks.
            legacy_args: list[object] = [last_seq, last_hash, epoch_id, log_id]
            positional = [
                parameter
                for parameter in parameters.values()
                if parameter.kind
                in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            ]
            optional_values = (outcome_index, epoch_metadata, last_checkpoint)
            legacy_args.extend(optional_values[: max(0, len(positional) - 4)])
            state.persist_state(*legacy_args)  # type: ignore[arg-type]
            return
        state.persist_state(
            last_seq,
            last_hash,
            epoch_id,
            log_id,
            outcome_index,
            epoch_metadata,
            last_checkpoint,
            outbox_append=outbox_append,
            reserved=reserved,
            outbox_max_pending=self._outbox_max_pending,
        )

    def _seal_unlocked(self, candidate: object) -> SealedEntry:
        """Validate, sign, durably advance, and return one gateway entry.

        Validate before reserving quota and signing. A signing or persistence
        error retains its quota reservation and returns no sealed result; the
        atomic chain state API retains its existing persistence semantics.
        """

        from services.signer import quarantine

        if quarantine.is_quarantined():
            reason = quarantine.get_quarantine_reason() or "quarantined"
            raise quarantine.QuarantineActiveError(reason)

        now = self._clock()
        parse_timestamp(now)
        if self._epoch_manager is None and state.epoch_metadata_exists():
            raise EpochUnavailableError("new epoch required")
        last_seq, last_hash, durable_epoch_id = state.load_state(self._log_id)
        outcome_index = state.load_outcome_index(self._log_id)
        self._last_rollover_entries = ()
        if self._epoch_manager is not None:
            if self._epoch_manager.degraded:
                raise EpochUnavailableError("new epoch required")
            if self._epoch_manager.due(now):
                plan = self._prepare_rollover(now, last_seq, last_hash, outcome_index)
                self._epoch_manager.commit_rollover(plan)
                self._last_rollover_entries = (plan.end, plan.start)
                try:
                    from services.signer import journal

                    journal.append_issuance(journal.record_from_sealed(plan.end, now))
                    journal.append_issuance(journal.record_from_sealed(plan.start, now))
                except Exception:
                    pass
                last_seq = plan.start.body.seq
                last_hash = entry_hash(plan.start.body)
                durable_epoch_id = plan.start.body.epoch_id
                outcome_index = state.load_outcome_index(self._log_id)
            epoch_certificate_id = self._epoch_manager.certificate_id
            signing_operation = self._epoch_manager.signing_operation
        else:
            epoch_certificate_id = self._epoch_certificate_id
            signing_operation = self._signing_operation
        valid_from = (
            self._epoch_manager.certificate.valid_from
            if self._epoch_manager is not None
            else self._valid_from
        )
        valid_until = (
            self._epoch_manager.certificate.valid_until
            if self._epoch_manager is not None
            else self._valid_until
        )
        try:
            parsed_candidate = parse_entry(candidate)
        except (TypeError, ValueError) as exc:
            raise SignerRuleError("schema invalid") from exc
        if parsed_candidate.log_id != self._log_id:
            raise SignerRuleError("wrong log identity")
        if (
            self._epoch_manager is None
            and self._epoch_id is not None
            and durable_epoch_id != self._epoch_id
        ):
            raise SignerRuleError("wrong epoch identity")

        intents: dict[int, Intent] = {}
        outcomes: dict[int, Outcome] = {}
        if isinstance(parsed_candidate, Outcome):
            if self._history_source is None:
                raise HistorySourceError("history source is unavailable")
            try:
                intent_record = self._history_source.get_intent(
                    self._log_id, parsed_candidate.intent_seq
                )
                intent_entry = verify_history_record(
                    intent_record, self._log_id, target_seq=parsed_candidate.intent_seq
                )
                if not isinstance(intent_entry.body, Intent):
                    raise HistoryIntegrityError("history target is not an intent")
                if intent_entry.body.seq != parsed_candidate.intent_seq:
                    raise HistoryIntegrityError("history intent sequence disagrees")
                if (
                    intent_entry.body.action.idempotency_key
                    != parsed_candidate.action.idempotency_key
                ):
                    raise HistoryIntegrityError("history idempotency disagreement")
                intents[parsed_candidate.intent_seq] = intent_entry.body
                previous_hash = outcome_index.get(parsed_candidate.intent_seq)
                if previous_hash is not None:
                    if not parsed_candidate.retry:
                        raise OutcomeConflictError("intent already has a sealed outcome")
                    prior_record = self._history_source.get_outcome(
                        self._log_id, parsed_candidate.intent_seq, previous_hash
                    )
                    prior_entry = verify_history_record(
                        prior_record,
                        self._log_id,
                        target_seq=prior_record.target_seq,
                    )
                    if (
                        not isinstance(prior_entry.body, Outcome)
                        or entry_hash(prior_entry.body) != previous_hash
                        or prior_entry.body.intent_seq != parsed_candidate.intent_seq
                    ):
                        raise HistoryIntegrityError("indexed outcome evidence disagrees")
                    outcomes[parsed_candidate.intent_seq] = prior_entry.body
            except (HistorySourceError, HistoryIntegrityError, OutcomeConflictError) as exc:
                if isinstance(exc, HistoryIntegrityError):
                    self.set_delivery_alarm(exc.alarm_code)
                raise
            except Exception as exc:
                raise HistorySourceError("history source failed closed") from exc

        signer_state = SignerState(
            last_seq=last_seq,
            last_hash=last_hash,
            epoch_id=durable_epoch_id,
            epoch_certificate_id=epoch_certificate_id,
            valid_from=valid_from,
            valid_until=valid_until,
            now=now,
            entries_this_second=0,
            rate_cap=self._rate_cap,
            caller="gateway",
            intents=intents,
            outcomes=outcomes,
            log_id=self._log_id,
        )
        check_seal_request(signer_state, parsed_candidate)

        # Preliminary pure rules do not spend quota on invalid requests. The
        # durable reservation is committed immediately before the signing path
        # and is never refunded, even if signing or chain persistence fails.
        self._rate_limiter.reserve(now, self._rate_cap)
        sealed = sealing.seal(parsed_candidate, signing_operation)
        sealed_body_hash = entry_hash(sealed.body)

        # The state write is deliberately the final operation.  The existing
        # state implementation performs an atomic replacement, so a failed
        # write cannot produce a successful return.
        if isinstance(sealed.body, Outcome):
            outcome_index[sealed.body.intent_seq] = sealed_body_hash
            self._persist_with_outbox(
                sealed.body.seq,
                sealed_body_hash,
                sealed.body.epoch_id,
                self._log_id,
                outcome_index,
                outbox_append=(sealed,),
            )
        else:
            self._persist_with_outbox(
                sealed.body.seq,
                sealed_body_hash,
                sealed.body.epoch_id,
                self._log_id,
                outbox_append=(sealed,),
            )
        if isinstance(sealed.body, Intent):
            self._sealed_intents[sealed.body.seq] = sealed_body_hash
        try:
            from services.signer import journal

            journal.append_issuance(journal.record_from_sealed(sealed, now))
        except Exception:
            pass
        return sealed

    def attest(
        self,
        intent_seq: int,
        requested_body_digest: str | None = None,
        checkpoint_evidence: CheckpointEvidence | None = None,
    ):
        from services.signer import quarantine

        if quarantine.is_quarantined():
            reason = quarantine.get_quarantine_reason() or "quarantined"
            raise quarantine.QuarantineActiveError(reason)
        if type(intent_seq) is not int or intent_seq < 0 or self._history_source is None:
            raise SignerRuleError("intent unavailable")
        try:
            record = self._history_source.get_intent(self._log_id, intent_seq)
            intent_entry = verify_history_record(record, self._log_id, target_seq=intent_seq)
        except (HistorySourceError, HistoryIntegrityError) as exc:
            raise SignerRuleError("intent unavailable") from exc
        if not isinstance(intent_entry.body, Intent):
            raise SignerRuleError("intent unavailable")
        recorded_hash = self._sealed_intents.get(intent_seq)
        if recorded_hash is None or recorded_hash != entry_hash(intent_entry.body):
            raise SignerRuleError("intent was not sealed by this signer")
        prior_digest = self._attested_digests.get(intent_seq)
        check_attest_request(
            intent_entry.body, requested_body_digest, prior_digest, checkpoint_evidence
        )
        now = self._clock()
        issued = parse_timestamp(now)
        expires = format_timestamp(issued + timedelta(seconds=30))
        if self._epoch_manager is not None:
            if self._epoch_manager.degraded:
                raise EpochUnavailableError("attestation key unavailable")
            operation = self._epoch_manager.signing_operation
        else:
            operation = self._signing_operation
        if operation is None:
            raise EpochUnavailableError("attestation key unavailable")
        attestation = build_attestation(intent_entry.body, now, expires, operation)
        self._attested_digests[intent_seq] = intent_entry.body.action.body_digest
        return attestation

    def checkpoint(self, request: object) -> Checkpoint:
        try:
            requested = Checkpoint.model_validate(request)
        except (TypeError, ValueError) as exc:
            raise SignerRuleError(
                "checkpoint schema invalid", code="checkpoint_invalid_request"
            ) from exc
        last_seq, last_hash, epoch_id = state.load_state(self._log_id)
        previous = state.load_last_checkpoint(self._log_id)
        if previous is not None and (
            requested.log_id == previous.log_id
            and requested.tree_size == previous.tree_size
            and requested.root_hash == previous.root_hash
            and requested.latest_seq == previous.latest_seq
            and requested.latest_entry_hash == previous.latest_entry_hash
            and requested.epoch_id == previous.epoch_id
        ):
            return previous
        now = self._clock()
        if requested.signer_timestamp != now:
            requested = requested.model_copy(update={"signer_timestamp": now})
        signer_state = SignerState(
            last_seq=last_seq,
            last_hash=last_hash,
            epoch_id=epoch_id,
            epoch_certificate_id=self._epoch_certificate_id,
            valid_from=self._valid_from,
            valid_until=self._valid_until,
            now=now,
            log_id=self._log_id,
        )
        from libs.blackbox_core.signer_rules import check_checkpoint_request

        check_checkpoint_request(signer_state, previous, requested)
        operation = (
            self._epoch_manager.signing_operation
            if self._epoch_manager is not None
            else self._signing_operation
        )
        if operation is None:
            raise EpochUnavailableError("checkpoint key unavailable")
        signed = sign_checkpoint(requested, operation)
        state.persist_state(
            last_seq,
            last_hash,
            epoch_id,
            self._log_id,
            last_checkpoint=signed,
        )
        return signed

    def heartbeat(self) -> Heartbeat:
        last_seq, last_hash, epoch_id = state.load_state(self._log_id)
        now = self._clock()
        valid_from = self._valid_from
        if self._epoch_manager:
            valid_from = self._epoch_manager.certificate.valid_from
        valid_until = (
            self._epoch_manager.certificate.valid_until
            if self._epoch_manager
            else self._valid_until
        )
        if not in_window(now, valid_from, valid_until):
            raise EpochUnavailableError("heartbeat epoch unavailable")
        operation = (
            self._epoch_manager.signing_operation
            if self._epoch_manager
            else self._signing_operation
        )
        if operation is None:
            raise EpochUnavailableError("heartbeat key unavailable")
        return sign_structure(
            Heartbeat(
                log_id=self._log_id,
                epoch_id=epoch_id,
                latest_seq=max(last_seq, 0),
                latest_entry_hash=last_hash,
                queue_depth=len(state.load_outbox(self._log_id).entries),
                signer_timestamp=now,
            ),
            operation,
            "heartbeat",
        )

    def tick(self) -> tuple[tuple[SealedEntry, ...], Heartbeat | None]:
        """Serialize idle rollover and periodic heartbeat emission with sealing."""
        with self._lock:
            now = self._clock()
            rollover: tuple[SealedEntry, ...] = ()
            if self._epoch_manager is not None:
                if self._epoch_manager.degraded:
                    return (), None
                last_seq, last_hash, _ = state.load_state(self._log_id)
                if self._epoch_manager.due(now):
                    plan = self._prepare_rollover(
                        now, last_seq, last_hash, state.load_outcome_index(self._log_id)
                    )
                    self._epoch_manager.commit_rollover(plan)
                    rollover = (plan.end, plan.start)
            current = parse_timestamp(now)
            if self._last_heartbeat_at is None:
                self._last_heartbeat_at = current
                return rollover, None
            if current - self._last_heartbeat_at < timedelta(seconds=self._heartbeat_interval):
                return rollover, None
            heartbeat = self.heartbeat()
            self._last_heartbeat_at = current
            return rollover, heartbeat

    def _prepare_rollover(
        self,
        now: str,
        last_seq: int,
        last_hash: str,
        outcome_index: dict[int, str],
    ) -> RolloverPlan:
        assert self._epoch_manager is not None
        try:
            plan = self._epoch_manager.prepare_rollover(
                last_seq, last_hash, self._epoch_manager.last_timestamp
            )
            self._persist_with_outbox(
                plan.start.body.seq,
                entry_hash(plan.start.body),
                plan.start.body.epoch_id,
                self._log_id,
                outcome_index,
                self._epoch_manager.metadata_for(plan.new_runtime),
                outbox_append=(plan.end, plan.start),
                reserved=True,
            )
            return plan
        except BaseException:
            self._epoch_manager.fail_closed()
            raise


# A short compatibility name for callers that refer to the object simply as a
# signer sealer; both names identify the same service-owned implementation.
Sealer = SignerSealer

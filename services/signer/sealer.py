"""In-process signer seal operation.

This module owns the service-side orchestration around the pure signer rules.  It
does not generate or persist keys: callers provide a ``SigningOperation`` and
the operation is retained only by this signer-owned object.
"""

from __future__ import annotations

from collections.abc import Callable

from libs.blackbox_core import sealing
from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.crypto import SigningOperation
from libs.blackbox_core.encoding import decode_hash, parse_timestamp
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.schemas import SealedEntry, parse_entry
from libs.blackbox_core.signer_rules import SignerState, check_seal_request
from services.signer import state
from services.signer.clock import system_utc_now
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
    ) -> None:
        if epoch_id is not None and (type(epoch_id) is not int or epoch_id < 0):
            raise ValueError("epoch_id must be a non-negative integer")
        if type(rate_cap) is not int or rate_cap <= 0:
            raise ValueError("rate_cap must be a positive integer")

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
        self._signing_operation = signing_operation
        self._rate_limiter = DurableRateLimiter()

    def seal(self, candidate: object) -> SealedEntry:
        """Validate, sign, durably advance, and return one gateway entry.

        Validate before reserving quota and signing. A signing or persistence
        error retains its quota reservation and returns no sealed result; the
        atomic chain state API retains its existing persistence semantics.
        """

        now = self._clock()
        parse_timestamp(now)
        last_seq, last_hash, durable_epoch_id = state.load_state(self._log_id)
        try:
            parsed_candidate = parse_entry(candidate)
        except (TypeError, ValueError) as exc:
            raise SignerRuleError("schema invalid") from exc
        if parsed_candidate.log_id != self._log_id:
            raise SignerRuleError("wrong log identity")
        if self._epoch_id is not None and durable_epoch_id != self._epoch_id:
            raise SignerRuleError("wrong epoch identity")

        signer_state = SignerState(
            last_seq=last_seq,
            last_hash=last_hash,
            epoch_id=durable_epoch_id,
            epoch_certificate_id=self._epoch_certificate_id,
            valid_from=self._valid_from,
            valid_until=self._valid_until,
            now=now,
            entries_this_second=0,
            rate_cap=self._rate_cap,
            caller="gateway",
        )
        check_seal_request(signer_state, parsed_candidate)

        # Preliminary pure rules do not spend quota on invalid requests. The
        # durable reservation is committed immediately before the signing path
        # and is never refunded, even if signing or chain persistence fails.
        self._rate_limiter.reserve(now, self._rate_cap)
        sealed = sealing.seal(parsed_candidate, self._signing_operation)
        sealed_body_hash = entry_hash(sealed.body)

        # The state write is deliberately the final operation.  The existing
        # state implementation performs an atomic replacement, so a failed
        # write cannot produce a successful return.
        state.persist_state(sealed.body.seq, sealed_body_hash, sealed.body.epoch_id, self._log_id)
        return sealed


# A short compatibility name for callers that refer to the object simply as a
# signer sealer; both names identify the same service-owned implementation.
Sealer = SignerSealer

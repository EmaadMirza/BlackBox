"""Cooperative, at-least-once delivery of signer outbox entries."""

from __future__ import annotations

import os
import random
import time
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Protocol

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.schemas import SealedEntry

LEDGER_EQUIVOCATION = "ledger_equivocation"
LEDGER_OUT_OF_ORDER = "ledger_out_of_order"
LEDGER_REJECTED = "ledger_rejected"
BAD_ACK = "delivery_bad_ack"
LEDGER_AUTH_UNAVAILABLE = "ledger_auth_unavailable"
DELIVERY_STATUS_INVALID = "delivery_status_invalid"
_ALARM_CODES = frozenset(
    {
        LEDGER_EQUIVOCATION,
        LEDGER_OUT_OF_ORDER,
        LEDGER_REJECTED,
        BAD_ACK,
        LEDGER_AUTH_UNAVAILABLE,
        DELIVERY_STATUS_INVALID,
    }
)


class LedgerTransport(Protocol):
    """Minimal synchronous ledger append transport used by the worker."""

    def append(self, entry: SealedEntry, bearer_token: str) -> object: ...


@dataclass(frozen=True)
class LedgerResponse:
    status_code: int
    entry_hash: str | None
    code: str | None = None


_lock_guard = Lock()
_signer_locks: weakref.WeakKeyDictionary[object, Lock] = weakref.WeakKeyDictionary()
_fallback_locks: dict[int, Lock] = {}


def _lock_for(signer: object) -> Lock:
    with _lock_guard:
        try:
            lock = _signer_locks.get(signer)
            if lock is None:
                lock = Lock()
                _signer_locks[signer] = lock
            return lock
        except TypeError:
            key = id(signer)
            return _fallback_locks.setdefault(key, Lock())


def _response(value: object) -> LedgerResponse:
    if isinstance(value, LedgerResponse):
        return value
    if isinstance(value, Mapping):
        status = value.get("status_code", value.get("status"))
        return LedgerResponse(
            int(status),
            value.get("entry_hash"),
            value.get("code"),
        )
    try:
        status = getattr(value, "status_code")
    except AttributeError as exc:
        raise ValueError("ledger response status is missing") from exc
    return LedgerResponse(
        int(status), getattr(value, "entry_hash", None), getattr(value, "code", None)
    )


class DeliveryWorker:
    """One cooperative delivery attempt at a time; never sleeps internally."""

    def __init__(
        self,
        signer,
        transport: LedgerTransport,
        *,
        bearer_token: str | None = None,
        clock=time.monotonic,
        random_seed: int | None = None,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter_ratio: float = 0.25,
    ) -> None:
        if base_delay <= 0 or max_delay < base_delay or jitter_ratio < 0:
            raise ValueError("invalid delivery backoff configuration")
        self.signer = signer
        self.transport = transport
        self._token = (
            bearer_token if bearer_token is not None else os.environ.get("LEDGER_AUTH_TOKEN")
        )
        self._clock = clock
        self._random = random.Random(random_seed)
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._jitter_ratio = jitter_ratio
        self._attempts = 0
        self.next_attempt_at = 0.0
        signer_alarm = getattr(signer, "health_reason", None)
        self.alarm_code: str | None = signer_alarm if signer_alarm in _ALARM_CODES else None
        self._lock = _lock_for(signer)

    @classmethod
    def signer_lock(cls, signer: object) -> Lock:
        """Expose the shared lock for deterministic single-flight tests."""

        return _lock_for(signer)

    @property
    def token_configured(self) -> bool:
        return bool(self._token)

    @property
    def health_reason(self) -> str | None:
        return self.alarm_code

    def tick_once(self) -> bool:
        return self.run_once()

    def run_once(self) -> bool:
        if not self._lock.acquire(blocking=False):
            return False
        try:
            now = float(self._clock())
            if self.alarm_code is not None or now < self.next_attempt_at:
                return False
            if not self._token:
                self._alarm(LEDGER_AUTH_UNAVAILABLE)
                return False
            pending = self.signer.pending_outbox(limit=1)
            if not pending:
                self._attempts = 0
                self.next_attempt_at = 0.0
                return False
            entry = pending[0]
            local_hash = entry_hash(entry.body)
            try:
                result = _response(self.transport.append(entry, self._token))
            except (TimeoutError, OSError, ConnectionError):
                self._retry(now)
                return False
            except Exception:
                self._retry(now)
                return False

            if 200 <= result.status_code < 300:
                if result.entry_hash != local_hash:
                    self._alarm(BAD_ACK)
                    return False
                try:
                    self.signer.acknowledge_outbox(entry.body.seq, local_hash)
                except (TimeoutError, OSError, ConnectionError):
                    self._retry(now)
                    return False
                self._attempts = 0
                self.next_attempt_at = 0.0
                return True
            if result.status_code == 409 and result.code == "equivocation":
                self._alarm(LEDGER_EQUIVOCATION)
                return False
            if result.status_code == 409 and result.code == "out_of_order":
                self._alarm(LEDGER_OUT_OF_ORDER)
                return False
            if 400 <= result.status_code < 500:
                self._alarm(LEDGER_REJECTED)
                return False
            if 500 <= result.status_code < 600:
                self._retry(now)
                return False
            self._alarm(DELIVERY_STATUS_INVALID)
            return False
        finally:
            self._lock.release()

    def reset_alarm(self) -> None:
        """Clear a delivery alarm only through an explicit operator action."""

        self.alarm_code = None
        self._attempts = 0
        self.next_attempt_at = 0.0
        reset = getattr(self.signer, "reset_delivery_alarm", None)
        if reset is not None:
            reset()

    def _alarm(self, code: str) -> None:
        self.alarm_code = code
        set_alarm = getattr(self.signer, "set_delivery_alarm", None)
        if set_alarm is not None:
            set_alarm(code)

    def _retry(self, now: float) -> None:
        self._attempts += 1
        delay = min(self._max_delay, self._base_delay * (2 ** (self._attempts - 1)))
        jitter = self._random.uniform(0.0, min(delay * self._jitter_ratio, self._max_delay - delay))
        self.next_attempt_at = now + delay + jitter

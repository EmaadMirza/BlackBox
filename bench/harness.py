"""Shared in-process benchmark harness and context.

Does NOT import Locust or gevent, so it can be safely imported by pytest
without triggering gevent monkey patching.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core import schemas
from libs.blackbox_core.attestation import build_attestation
from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.epochs import (
    build_epoch_certificate,
    build_intermediate_certificate,
    certificate_id,
)
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.schemas import parse_entry
from libs.blackbox_core.sealing import seal
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.ledger.store import InMemoryLedgerStore, StoredEntry
from services.payload_store.main import PayloadStore
from services.provider_mock.main import ProviderMock
from services.signer.clock import system_utc_now
from tests._dev_keys import dev_key


class ThreadSafeBenchSigner:
    """Thread-safe signer maintaining strict sequential hash-chain ordering."""

    def __init__(
        self,
        key: Ed25519PrivateKey,
        public_key: bytes,
        ledger_store: InMemoryLedgerStore,
        log_id: str,
        cert_id: str,
    ) -> None:
        self.key = key
        self.public_key = public_key
        self.ledger = ledger_store
        self.log_id = log_id
        self.cert_id = cert_id
        self.seq = 0
        self.prev = GENESIS_PREV_HASH
        self.lock = threading.Lock()

    def seal(self, candidate: schemas.Entry) -> schemas.SealedEntry:
        with self.lock:
            now = system_utc_now()
            body = candidate.model_copy(
                update={
                    "seq": self.seq,
                    "prev_hash": self.prev,
                    "signer_timestamp": now,
                    "log_id": self.log_id,
                    "epoch_id": 0,
                    "epoch_certificate_id": self.cert_id,
                }
            )
            self.seq += 1
            sealed = seal(body, self.key)
            self.prev = entry_hash(sealed.body)
            self.ledger.insert_entry(StoredEntry(sealed, self.prev))
            return sealed

    def attest(self, intent: schemas.Intent) -> dict[str, Any]:
        now = system_utc_now()
        exp = "2026-12-31T23:59:59.000Z"
        att = build_attestation(intent, now, exp, self.key)
        return att.model_dump(mode="json")


class BenchmarkContext:
    """Encapsulates the BlackBox stack for load testing and measurements."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
        self.root, self.inter, self.epoch0, self.epoch1, *self.witnesses = self.keys
        self.log_id = derive_log_id(self.root[1], "bench-log")

        self.ic = build_intermediate_certificate(
            self.log_id,
            "intermediate-0",
            encode_base64url(self.inter[1]),
            "2026-01-01T00:00:00.000Z",
            "2027-01-01T00:00:00.000Z",
            self.root[0],
        )
        self.ec = build_epoch_certificate(
            0,
            encode_base64url(self.epoch0[1]),
            "2026-01-01T00:00:00.000Z",
            "2027-01-01T00:00:00.000Z",
            "intermediate-0",
            log_id=self.log_id,
            signing_operation=self.inter[0],
        )
        self.cert_id = certificate_id(self.ec)

        self.ledger = InMemoryLedgerStore()
        self.signer = ThreadSafeBenchSigner(
            self.epoch0[0], self.epoch0[1], self.ledger, self.log_id, self.cert_id
        )
        self.provider = ProviderMock(signer_public_key=self.epoch0[1])

        rules_path = Path("services/gateway/policy/rules.yaml")
        self.policy = PolicyEngine(load_rules(rules_path))
        self.payload_store = PayloadStore(tmp_path / "payload_store")

        self.pipeline = GatewayPipeline(
            signer=self.signer,
            provider=self.provider,
            payload_store=self.payload_store,
            policy=self.policy,
            agent_tokens={"agent-1": "token-1"},
            clock=system_utc_now,
        )
        self._action_counter = 0
        self._counter_lock = threading.Lock()

        # Seal genesis epoch_start entry at seq 0
        genesis_start = parse_entry(
            dict(
                format_version="4",
                log_id=self.log_id,
                epoch_id=0,
                seq=0,
                signer_timestamp=system_utc_now(),
                prev_hash=GENESIS_PREV_HASH,
                lane="agent",
                epoch_certificate_id=self.cert_id,
                type="epoch_start",
                certificate=self.ec.model_dump(),
            )
        )
        self.signer.seal(genesis_start)

    def next_action_id(self) -> str:
        with self._counter_lock:
            self._action_counter += 1
            idx = self._action_counter
        return f"sha256:{idx:064x}"

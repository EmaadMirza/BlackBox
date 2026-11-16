"""Provider-owned append-only event log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash

GENESIS_HASH = "sha256:" + "0" * 64


class ProviderEventLog:
    def __init__(self, state_dir: Path | None = None) -> None:
        self.state_dir = state_dir
        if self.state_dir is not None:
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.log_file = self.state_dir / "events.jsonl"
        else:
            self.log_file = None
        self._events: list[dict[str, Any]] = []
        self._prev_hash = GENESIS_HASH

    def append(
        self,
        *,
        intent_seq: int | None,
        idempotency_key: str,
        received_digest: str,
        action: str,
        provider_request_id: str,
        timestamp: str,
        attested: bool = True,
        status: int = 200,
        result_commitment: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "request_id": provider_request_id,
            "intent_seq": intent_seq,
            "idempotency_key": idempotency_key,
            "body_digest": received_digest,
            "action": action,
            "timestamp": timestamp,
            "attested": attested,
            "status": status,
            "result_commitment": result_commitment,
            "prev_hash": self._prev_hash,
        }
        event_bytes = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        current_hash = encode_hash(sha256(event_bytes))
        event["event_hash"] = current_hash
        self._prev_hash = current_hash

        self._events.append(event)
        if self.log_file is not None:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
                f.flush()
        return event

    def feed(self, after_id: str | None = None) -> list[dict[str, Any]]:
        if not after_id:
            return list(self._events)
        result = []
        found = False
        for ev in self._events:
            if found:
                result.append(ev)
            elif ev.get("request_id") == after_id:
                found = True
        return result


_default = ProviderEventLog(Path("provider-events"))


async def append_event(
    intent_seq: int | None,
    idempotency_key: str,
    received_digest: str,
    action: str,
    provider_request_id: str,
    timestamp: str,
) -> str:
    ev = _default.append(
        intent_seq=intent_seq,
        idempotency_key=idempotency_key,
        received_digest=received_digest,
        action=action,
        provider_request_id=provider_request_id,
        timestamp=timestamp,
    )
    return ev["request_id"]


async def feed(after_id: str | None) -> list[dict[str, str]]:
    return _default.feed(after_id)

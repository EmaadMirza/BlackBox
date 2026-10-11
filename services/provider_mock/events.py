"""Provider-owned append-only event log Scaffold only; no runtime behavior."""

from __future__ import annotations

# TODO(spec §14.4): implement and validate before enabling this module.


async def append_event(
    intent_seq: int | None,
    idempotency_key: str,
    received_digest: str,
    action: str,
    provider_request_id: str,
    timestamp: str,
) -> str:
    raise NotImplementedError("not built")


async def feed(after_id: str | None) -> list[dict[str, str]]:
    raise NotImplementedError("not built")

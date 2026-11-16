"""Intent, idempotency and provider-event joins."""

from __future__ import annotations

from typing import Any

from libs.blackbox_core import schemas


def join(
    entries: list[schemas.SealedEntry],
    events: list[dict[str, Any]],
    now: str,
    grace_seconds: int = 30,
) -> list[tuple[schemas.SealedEntry | None, dict[str, Any] | None]]:
    """Join ledger entries and provider events by intent_seq, request_id, or idempotency_key."""
    pairs: list[tuple[schemas.SealedEntry | None, dict[str, Any] | None]] = []
    matched_events: set[int] = set()
    matched_entries: set[int] = set()

    # Index events
    for idx_entry, entry in enumerate(entries):
        body = entry.body
        intent_seq = (
            getattr(body, "seq", None)
            if body.type in ("intent", "action")
            else getattr(body, "intent_seq", None)
        )
        idempotency_key = getattr(getattr(body, "action", None), "idempotency_key", None)
        provider_request_id = getattr(body, "provider_request_id", None)

        found_event_idx = None
        for idx_ev, ev in enumerate(events):
            if idx_ev in matched_events:
                continue
            ev_intent_seq = ev.get("intent_seq")
            ev_idemp = ev.get("idempotency_key")
            ev_req_id = ev.get("request_id")

            if (
                (
                    intent_seq is not None
                    and ev_intent_seq is not None
                    and intent_seq == ev_intent_seq
                )
                or (idempotency_key and ev_idemp and idempotency_key == ev_idemp)
                or (provider_request_id and ev_req_id and provider_request_id == ev_req_id)
            ):
                found_event_idx = idx_ev
                break

        if found_event_idx is not None:
            pairs.append((entry, events[found_event_idx]))
            matched_events.add(found_event_idx)
            matched_entries.add(idx_entry)

    # Remaining entries with no event
    for idx_entry, entry in enumerate(entries):
        if idx_entry not in matched_entries:
            pairs.append((entry, None))

    # Remaining events with no entry
    for idx_ev, ev in enumerate(events):
        if idx_ev not in matched_events:
            pairs.append((None, ev))

    return pairs

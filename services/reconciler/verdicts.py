"""Six findings classifications for BlackBox reconciliation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from libs.blackbox_core import schemas
from services.reconciler.join import join


def _parse_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _is_past_grace(event_ts: str, now_ts: str, grace_seconds: int) -> bool:
    t_ev = _parse_ts(event_ts)
    t_now = _parse_ts(now_ts)
    return (t_now - t_ev) >= grace_seconds


def classify(
    entries: list[schemas.SealedEntry],
    events: list[dict[str, Any]],
    now: str,
    grace_seconds: int = 30,
) -> list[schemas.Finding]:
    """Classify disagreements between ledger entries and provider event feed."""
    findings: list[schemas.Finding] = []

    # Map outcomes and blocked by intent_seq
    outcomes_by_intent: dict[int, schemas.SealedEntry] = {}
    blocked_by_intent: dict[int, schemas.SealedEntry] = {}
    for e in entries:
        if e.body.type == "outcome":
            outcomes_by_intent[e.body.intent_seq] = e
        elif e.body.type == "blocked":
            intent_seq = getattr(e.body, "seq", None)
            if intent_seq is not None:
                blocked_by_intent[intent_seq] = e

    pairs = join(entries, events, now, grace_seconds)

    for entry, ev in pairs:
        # Case A: Provider event without ledger entry
        if entry is None and ev is not None:
            req_id = str(ev.get("request_id") or "")
            if ev.get("attested") is False or ev.get("unattested") is True:
                findings.append(
                    schemas.Finding(
                        finding_type="UNATTESTED_ACTION",
                        ledger_seqs=[],
                        provider_event_ids=[req_id] if req_id else [],
                        detection_time=now,
                    )
                )
            else:
                findings.append(
                    schemas.Finding(
                        finding_type="UNRECORDED_ACTION",
                        ledger_seqs=[],
                        provider_event_ids=[req_id] if req_id else [],
                        detection_time=now,
                    )
                )

        # Case B: Both entry and event exist
        elif entry is not None and ev is not None:
            req_id = str(ev.get("request_id") or "")
            body = entry.body

            # Check for unattested flag on event
            if ev.get("attested") is False or ev.get("unattested") is True:
                findings.append(
                    schemas.Finding(
                        finding_type="UNATTESTED_ACTION",
                        ledger_seqs=[body.seq],
                        provider_event_ids=[req_id] if req_id else [],
                        detection_time=now,
                    )
                )

            # Check args mismatch on intent
            if body.type == "intent" and hasattr(body, "action"):
                ev_digest = ev.get("body_digest")
                if ev_digest and ev_digest != body.action.body_digest:
                    findings.append(
                        schemas.Finding(
                            finding_type="ARGS_MISMATCH",
                            ledger_seqs=[body.seq],
                            provider_event_ids=[req_id] if req_id else [],
                            detection_time=now,
                        )
                    )

            # Check result mismatch on outcome
            if body.type == "outcome":
                ev_res = ev.get("result_commitment")
                if ev_res and ev_res != body.result_commitment:
                    findings.append(
                        schemas.Finding(
                            finding_type="RESULT_MISMATCH",
                            ledger_seqs=[body.seq],
                            provider_event_ids=[req_id] if req_id else [],
                            detection_time=now,
                        )
                    )

        # Case C: Ledger entry without event
        elif entry is not None and ev is None:
            body = entry.body
            if body.type == "outcome":
                if _is_past_grace(body.signer_timestamp, now, grace_seconds):
                    findings.append(
                        schemas.Finding(
                            finding_type="PHANTOM_OUTCOME",
                            ledger_seqs=[body.seq],
                            provider_event_ids=[],
                            detection_time=now,
                        )
                    )
            elif body.type == "intent":
                # Only orphan if no outcome and no blocked entry exists for this intent
                if body.seq not in outcomes_by_intent and body.seq not in blocked_by_intent:
                    if _is_past_grace(body.signer_timestamp, now, grace_seconds):
                        findings.append(
                            schemas.Finding(
                                finding_type="ORPHAN_INTENT",
                                ledger_seqs=[body.seq],
                                provider_event_ids=[],
                                detection_time=now,
                            )
                        )

    return findings

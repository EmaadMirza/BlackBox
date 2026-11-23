"""Reproducible property coverage for signer epoch interleavings."""

from __future__ import annotations

from datetime import timedelta

from hypothesis import given, settings
from hypothesis.strategies import integers, lists

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.encoding import decode_base64url, format_timestamp, parse_timestamp
from libs.blackbox_core.epochs import certificate_id, validate_contiguity
from libs.blackbox_core.schemas import Action
from libs.blackbox_core.sealing import seal, verify_entry
from tests.unit.test_signer_epoch_rollover import manager


@settings(max_examples=32, derandomize=True, database=None, deadline=None)
@given(steps=lists(integers(min_value=0, max_value=400), min_size=1, max_size=12))
def test_seal_clock_rollover_interleavings_preserve_verified_history(steps: list[int]) -> None:
    now = parse_timestamp("2026-01-01T00:00:00.000Z")
    state = manager(clock=lambda: format_timestamp(now))
    entries = []
    seq = 0
    previous_hash = "sha256:" + "0" * 64
    previous_timestamp = format_timestamp(now)

    for index, advance in enumerate(steps):
        now += timedelta(seconds=advance)
        if state.due(format_timestamp(now)):
            plan = state.prepare_rollover(seq, previous_hash, previous_timestamp)
            validate_contiguity(plan.old_runtime.certificate, plan.new_runtime.certificate)
            old_public_key = decode_base64url(plan.old_runtime.certificate.epoch_public_key)
            new_public_key = decode_base64url(plan.new_runtime.certificate.epoch_public_key)
            for lifecycle, public_key in ((plan.end, old_public_key), (plan.start, new_public_key)):
                assert lifecycle.body.seq == seq + 1
                assert lifecycle.body.prev_hash == previous_hash
                assert verify_entry(lifecycle, public_key)
                entries.append(lifecycle)
                seq = lifecycle.body.seq
                previous_hash = entry_hash(lifecycle.body)
                previous_timestamp = lifecycle.body.signer_timestamp
            state.commit_rollover(plan)

        body = Action(
            type="action",
            format_version="4",
            log_id=state.log_id,
            epoch_id=state.certificate.epoch_id,
            seq=seq + 1,
            signer_timestamp=format_timestamp(now),
            prev_hash=previous_hash,
            lane="agent",
            epoch_certificate_id=certificate_id(state.certificate),
            action_name=f"seal-{index}",
            reason="property test",
            target_reference="target",
        )
        sealed = seal(body, state.signing_operation)
        assert parse_timestamp(body.signer_timestamp) <= parse_timestamp(
            state.certificate.valid_until
        )
        entries.append(sealed)
        seq = body.seq
        previous_hash = entry_hash(body)
        previous_timestamp = body.signer_timestamp

    assert [entry.body.seq for entry in entries] == list(range(1, len(entries) + 1))
    assert len({entry.body.seq for entry in entries}) == len(entries)
    for previous, current in zip(entries, entries[1:]):
        assert current.body.prev_hash == entry_hash(previous.body)

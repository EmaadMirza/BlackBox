"""S5 multi-epoch and cross-epoch outcome tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.encoding import parse_timestamp
from libs.blackbox_core.epochs import validate_contiguity
from libs.blackbox_core.evidence import Bundle
from libs.blackbox_core.schemas import EpochEnd, EpochStart
from tests.unit.test_signer_epoch_rollover import manager
from tests.unit.test_verifier import demo
from tools.verifier.verify import verify_evidence


def test_three_rollovers_have_contiguous_epochs_and_windows() -> None:
    epoch_manager = manager()
    previous_hash = "sha256:" + "a" * 64
    previous_timestamp = "2026-01-01T00:04:00.000Z"
    seq = 4
    for _ in range(3):
        plan = epoch_manager.prepare_rollover(seq, previous_hash, previous_timestamp)
        assert isinstance(plan.end.body, EpochEnd)
        assert isinstance(plan.start.body, EpochStart)
        assert plan.start.body.epoch_id == plan.end.body.epoch_id + 1
        assert plan.new_runtime.certificate.valid_from == plan.old_runtime.certificate.valid_until
        assert parse_timestamp(plan.end.body.signer_timestamp) <= parse_timestamp(
            plan.start.body.signer_timestamp
        )
        epoch_manager.commit_rollover(plan)
        seq += 2
        previous_hash = entry_hash(plan.start.body)
        previous_timestamp = plan.start.body.signer_timestamp


def test_idle_gap_produces_one_long_window() -> None:
    epoch_manager = manager(clock=lambda: "2026-01-01T01:06:00.000Z")
    plan = epoch_manager.prepare_rollover(4, "sha256:" + "a" * 64, "2026-01-01T00:04:00.000Z")

    assert plan.new_runtime.certificate.valid_from == plan.old_runtime.certificate.valid_until
    assert parse_timestamp(plan.new_runtime.certificate.valid_until) - parse_timestamp(
        plan.new_runtime.certificate.valid_from
    ) == timedelta(seconds=3960)


def test_invalid_epoch_certificate_inputs_are_rejected() -> None:
    epoch_manager = manager()
    certificate = epoch_manager.certificate.model_copy(
        update={"epoch_id": epoch_manager.certificate.epoch_id + 2}
    )

    with pytest.raises(ValueError):
        validate_contiguity(epoch_manager.certificate, certificate)


@pytest.mark.parametrize(
    "mutation", ["wrong_intermediate", "skipped_epoch", "window_gap", "timestamp"]
)
def test_verifier_rejects_invalid_epoch_metadata(mutation: str) -> None:
    bundle, pins = demo()
    data = bundle.model_dump()
    if mutation == "wrong_intermediate":
        data["epochs"][1]["intermediate_id"] = "unknown"
    elif mutation == "skipped_epoch":
        data["epochs"][1]["epoch_id"] = 3
    elif mutation == "window_gap":
        data["epochs"][1]["valid_from"] = "2026-01-01T00:06:00.000Z"
    else:
        data["entries"][5]["body"]["signer_timestamp"] = "2026-01-01T00:30:00.000Z"
    report = verify_evidence(Bundle.model_validate(data), pins)
    assert report.verdict in ("TAMPERED", "MISSING")

"""Task R epoch rollover tests."""

from __future__ import annotations

import pytest

from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.encoding import decode_base64url, encode_base64url, parse_timestamp
from libs.blackbox_core.epochs import build_epoch_certificate, build_intermediate_certificate
from libs.blackbox_core.sealing import verify_entry
from services.signer.epoch_manager import EpochManager, EpochRuntime, InMemoryIntermediateSigner
from tests._dev_keys import dev_key

LOG_ID = "sha256:" + "1" * 64
START = "2026-01-01T00:00:00.000Z"
END = "2026-01-01T00:05:00.000Z"


def manager(clock=lambda: "2026-01-01T00:06:00.000Z") -> EpochManager:
    root = dev_key(1)
    intermediate = dev_key(2)
    epoch = dev_key(3)
    cert = build_intermediate_certificate(
        LOG_ID,
        "intermediate-0",
        encode_base64url(intermediate.public_key().public_bytes_raw()),
        START,
        "2026-02-01T00:00:00.000Z",
        root,
    )
    return EpochManager(
        log_id=LOG_ID,
        intermediate_signer=InMemoryIntermediateSigner(
            cert, intermediate, root.public_key().public_bytes_raw()
        ),
        runtime=EpochRuntime(
            certificate=build_epoch_certificate(
                0,
                encode_base64url(epoch.public_key().public_bytes_raw()),
                START,
                END,
                "intermediate-0",
                log_id=LOG_ID,
                signing_operation=intermediate,
            ),
            signing_operation=epoch,
        ),
        clock=clock,
    )


def test_rollover_uses_contiguous_window_and_old_key_end() -> None:
    operation = manager()
    plan = operation.prepare_rollover(4, "sha256:" + "a" * 64, START)

    assert plan.end.body.type == "epoch_end"
    assert plan.start.body.type == "epoch_start"
    assert plan.end.body.seq == 5
    assert plan.start.body.seq == 6
    assert plan.start.body.prev_hash == entry_hash(plan.end.body)
    assert plan.end.body.signer_timestamp <= END
    assert plan.start.body.signer_timestamp == "2026-01-01T00:06:00.000Z"
    assert plan.start.body.epoch_id == 1
    assert parse_timestamp(plan.end.body.signer_timestamp) <= parse_timestamp(
        plan.start.body.signer_timestamp
    )
    assert verify_entry(plan.end, decode_base64url(operation.runtime.certificate.epoch_public_key))


def test_old_key_is_unusable_after_commit() -> None:
    operation = manager()
    operation.prepare_rollover(4, "sha256:" + "a" * 64, START)
    operation.destroy_current_key()

    with pytest.raises(RuntimeError, match="destroyed"):
        operation.signing_operation.sign(b"must fail")

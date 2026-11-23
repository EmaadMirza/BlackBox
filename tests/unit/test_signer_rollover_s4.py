"""S4 signer-level rollover and post-rollover durability tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.chain import entry_hash
from services.signer import state
from services.signer.main import create_app
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.unit.test_epochs_rules import request_pair
from tests.unit.test_signer_epoch_persistence import metadata
from tests.unit.test_signer_epoch_rollover import manager

LOG_ID = "sha256:" + "1" * 64


def test_keyless_restart_after_rollover_metadata_requires_new_epoch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(
        6,
        "sha256:" + "a" * 64,
        1,
        LOG_ID,
        {},
        {
            "format_version": "1",
            "log_id": LOG_ID,
            "epoch_id": 1,
            **metadata(),
        },
    )

    sealer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id="sha256:" + "2" * 64,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2026-01-01T00:10:00.000Z",
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=dev_key(4),
    )
    with pytest.raises(Exception, match="new epoch"):
        sealer.seal(object())


def test_signer_level_old_key_guard_after_rollover() -> None:
    epoch_manager = manager()
    plan = epoch_manager.prepare_rollover(4, "sha256:" + "a" * 64, "2026-01-01T00:04:00.000Z")
    epoch_manager.commit_rollover(plan)
    epoch_manager.destroy_current_key()

    with pytest.raises(RuntimeError, match="destroyed"):
        epoch_manager.signing_operation.sign(b"old-key-attempt")


def test_rollover_plan_has_no_expired_or_reused_sequence() -> None:
    epoch_manager = manager()
    plan = epoch_manager.prepare_rollover(4, "sha256:" + "a" * 64, "2026-01-01T00:04:00.000Z")

    assert plan.end.body.seq == 5
    assert plan.start.body.seq == 6
    assert plan.end.body.epoch_id == 0
    assert plan.start.body.epoch_id == 1
    assert plan.end.body.signer_timestamp < plan.old_runtime.certificate.valid_until
    assert plan.start.body.signer_timestamp >= plan.new_runtime.certificate.valid_from


def test_s4_health_and_normal_response_shape_remain_stable() -> None:
    response = TestClient(create_app()).get("/health")
    assert response.json() == {"status": "ok"}


def test_outcome_index_and_state_helpers_remain_available_after_rollover(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    previous = "sha256:" + "a" * 64
    state.persist_state(6, previous, 1, LOG_ID, {0: previous})

    assert state.load_state(LOG_ID) == (6, previous, 1)
    assert state.load_outcome_index(LOG_ID) == {0: previous}


def test_sealer_rolls_before_request_and_returns_ordered_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(0, "sha256:" + "a" * 64, 0, LOG_ID, {})
    epoch_manager = manager()
    _, request, _ = request_pair()
    commits: list[int] = []
    original_persist = state.persist_state

    def persist(*args, **kwargs):
        commits.append(args[0])
        return original_persist(*args, **kwargs)

    monkeypatch.setattr(state, "persist_state", persist)
    from services.signer import sealer as sealer_module

    original_prepare = epoch_manager.prepare_rollover
    prepared = {}

    def prepare(*args, **kwargs):
        plan = original_prepare(*args, **kwargs)
        prepared["plan"] = plan
        return plan

    monkeypatch.setattr(epoch_manager, "prepare_rollover", prepare)

    def parse_dynamic(value: object):
        if value != "dynamic-request":
            return sealer_module.parse_entry(value)
        start_hash = entry_hash(prepared["plan"].start.body)
        return request.model_copy(
            update={
                "seq": 3,
                "prev_hash": start_hash,
                "log_id": LOG_ID,
                "epoch_id": 1,
                "epoch_certificate_id": epoch_manager.certificate_id,
                "signer_timestamp": "2026-01-01T00:06:00.000Z",
            }
        )

    monkeypatch.setattr(sealer_module, "parse_entry", parse_dynamic)
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_certificate_id=epoch_manager.certificate_id,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2026-01-01T00:05:00.000Z",
        clock=lambda: "2026-01-01T00:06:00.000Z",
        signing_operation=dev_key(5),
        epoch_manager=epoch_manager,
    )

    rollover_entries, sealed = signer.seal_with_rollover("dynamic-request")
    assert [entry.body.seq for entry in rollover_entries] == [1, 2]
    assert sealed.body.seq == 3
    assert commits == [2, 3]

"""L2a-3 sealer, delivery queue, heartbeat, and migration coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.schemas import Heartbeat, parse_entry
from libs.blackbox_core.sealing import seal
from services.signer import outbox, state
from services.signer.main import create_app
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action
from tests.unit.test_signer_epoch_rollover import manager

LOG_ID = "sha256:" + "1" * 64
CERTIFICATE_ID = "sha256:" + "2" * 64
NOW = "2026-01-01T00:01:00.000Z"
VALID_FROM = "2026-01-01T00:00:00.000Z"
VALID_UNTIL = "2026-01-01T00:05:00.000Z"


def candidate(seq: int = 0, prev_hash: str = GENESIS_PREV_HASH) -> dict[str, object]:
    value = action()
    value.update(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        seq=seq,
        prev_hash=prev_hash,
        signer_timestamp=NOW,
    )
    return value


def make_sealer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    epoch_manager=None,
    max_pending: int = 1000,
    clock=lambda: NOW,
) -> SignerSealer:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    return SignerSealer(
        log_id=LOG_ID,
        epoch_id=0 if epoch_manager is None else None,
        epoch_certificate_id=CERTIFICATE_ID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        clock=clock,
        signing_operation=dev_key(),
        epoch_manager=epoch_manager,
        outbox_max_pending=max_pending,
    )


def test_seal_commit_releases_entry_only_after_outbox_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = make_sealer(monkeypatch, tmp_path)
    original = state.persist_state
    calls: list[tuple[object, ...]] = []

    def persist(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(state, "persist_state", persist)
    sealed = signer.seal(candidate())

    assert sealed.body.seq == 0
    assert calls
    assert state.load_outbox(LOG_ID).entries == (sealed,)


def test_pending_and_acknowledge_outbox_are_serialized(tmp_path: Path, monkeypatch) -> None:
    signer = make_sealer(monkeypatch, tmp_path)
    sealed = signer.seal(candidate())
    entry_hash_value = entry_hash(sealed.body)

    assert signer.pending_outbox() == (sealed,)
    assert signer.pending_outbox(0) == ()
    assert signer.acknowledge_outbox(sealed.body.seq, entry_hash_value).entries == ()
    assert signer.pending_outbox() == ()


def test_lost_http_response_survives_restart_in_outbox(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = make_sealer(monkeypatch, tmp_path)
    sealed = first.seal(candidate())
    restarted = make_sealer(monkeypatch, tmp_path)

    assert restarted.pending_outbox() == (sealed,)


def test_outbox_full_refuses_normal_seal_and_health_degrades(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = make_sealer(monkeypatch, tmp_path, max_pending=1)
    sealed = signer.seal(candidate())

    with pytest.raises(outbox.OutboxError) as exc:
        signer.seal(candidate(1, entry_hash(sealed.body)))
    assert exc.value.code == "outbox_full"
    assert signer.health_reason == "outbox_full"


def test_high_water_health_warning_at_half_capacity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = make_sealer(monkeypatch, tmp_path, max_pending=2)
    signer.seal(candidate())

    assert signer.health_reason == "outbox_high"
    assert signer.pending_outbox()


def test_http_maps_outbox_full_to_stable_503(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = make_sealer(monkeypatch, tmp_path, max_pending=1)
    first = signer.seal(candidate())
    app = create_app(sealer=signer)
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "test-token")
    client = TestClient(app)
    second = candidate(1, entry_hash(first.body))

    response = client.post("/seal", json=second, headers={"Authorization": "Bearer test-token"})

    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "outbox_full", "message": "Signer outbox is full."}
    }


def test_tick_rollover_is_queued_as_reserved_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(4, "sha256:" + "a" * 64, 0, LOG_ID)
    epochs = manager()
    signer = make_sealer(
        monkeypatch,
        tmp_path,
        epoch_manager=epochs,
        max_pending=1,
        clock=lambda: "2026-01-01T00:06:00.000Z",
    )

    rollover, heartbeat = signer.tick()

    assert [entry.body.type for entry in rollover] == ["epoch_end", "epoch_start"]
    assert heartbeat is None
    assert [entry.body.type for entry in signer.pending_outbox()] == ["epoch_end", "epoch_start"]


def test_reserved_rollover_can_use_headroom_when_normal_queue_is_full(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    state.persist_state(4, "sha256:" + "a" * 64, 0, LOG_ID)
    epochs = manager()
    signer = make_sealer(
        monkeypatch,
        tmp_path,
        epoch_manager=epochs,
        max_pending=1,
        clock=lambda: "2026-01-01T00:06:00.000Z",
    )
    normal = seal(parse_entry(candidate(5, "sha256:" + "a" * 64)), dev_key())
    state.persist_state(
        5,
        entry_hash(normal.body),
        0,
        LOG_ID,
        outbox_append=(normal,),
    )

    rollover, _ = signer.tick()

    assert len(rollover) == 2
    assert [entry.body.type for entry in signer.pending_outbox()] == [
        "action",
        "epoch_end",
        "epoch_start",
    ]


def test_heartbeat_reports_pending_outbox_depth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    signer = make_sealer(monkeypatch, tmp_path)
    sealed = signer.seal(candidate())
    heartbeat = signer.heartbeat()

    assert heartbeat.queue_depth == 1
    assert Heartbeat.model_validate(heartbeat)
    assert sealed.body.seq == heartbeat.latest_seq


def test_migration_requires_matching_initialized_ledger_head(tmp_path: Path) -> None:
    from tools.migrate_outbox import MigrationError, migrate_outbox

    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "last_seq": 7,
                "last_hash": "sha256:" + "a" * 64,
                "epoch_id": 0,
                "log_id": LOG_ID,
            }
        ),
        encoding="utf-8",
    )
    path.with_name(".state.json.initialized").touch(mode=0o600)

    with pytest.raises(MigrationError) as mismatch:
        migrate_outbox(path, LOG_ID, 6, "sha256:" + "a" * 64)
    assert mismatch.value.code == "ledger_head_mismatch"
    with pytest.raises(MigrationError) as wrong_log:
        migrate_outbox(path, "sha256:" + "f" * 64, 7, "sha256:" + "a" * 64)
    assert wrong_log.value.code == "log_mismatch"

    result = migrate_outbox(path, LOG_ID, 7, "sha256:" + "a" * 64)
    assert result.is_file()
    state_outbox = json.loads(result.read_text(encoding="utf-8"))
    assert state_outbox["entries"] == []


def test_migration_refuses_missing_state_uninitialized_outbox_and_marker(tmp_path: Path) -> None:
    from tools.migrate_outbox import MigrationError, migrate_outbox

    path = tmp_path / "state.json"
    with pytest.raises(MigrationError) as missing:
        migrate_outbox(path, LOG_ID, 0, "sha256:" + "a" * 64)
    assert missing.value.code == "state_missing"

    path.write_text("{}", encoding="utf-8")
    with pytest.raises(MigrationError) as uninitialized:
        migrate_outbox(path, LOG_ID, 0, "sha256:" + "a" * 64)
    assert uninitialized.value.code == "not_initialized"

    path.with_name(".state.json.initialized").touch(mode=0o600)
    path.with_name("state.json.outbox.json").write_text("{}", encoding="utf-8")
    with pytest.raises(MigrationError) as existing:
        migrate_outbox(path, LOG_ID, 0, "sha256:" + "a" * 64)
    assert existing.value.code == "outbox_exists"

    path.with_name("state.json.outbox.json").unlink()
    path.with_name(".state.json.commit").touch(mode=0o600)
    with pytest.raises(MigrationError) as marked:
        migrate_outbox(path, LOG_ID, 0, "sha256:" + "a" * 64)
    assert marked.value.code == "uncertain_commit"

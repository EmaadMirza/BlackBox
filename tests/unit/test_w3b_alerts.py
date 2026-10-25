"""W3b checkpoint stall and alert collector tests."""

from pathlib import Path

from fastapi.testclient import TestClient

from libs.blackbox_core.schemas import Checkpoint, Heartbeat
from services.alerting.collector import AlarmCollector, create_app
from services.witness.heartbeat_monitor import checkpoint_stall


def test_alert_collector_dedupes_and_requires_auth(tmp_path: Path):
    collector = AlarmCollector(tmp_path / "alarms.jsonl")
    collector.collect("WITNESS_REFUSAL", "w0", "cp", "critical", "2026-01-01T00:00:00.000Z")
    collector.collect("WITNESS_REFUSAL", "w0", "cp", "critical", "2026-01-01T00:00:01.000Z")
    with TestClient(create_app(collector=collector, bearer_token="token")) as client:
        assert client.get("/alarms").status_code == 401
        response = client.get("/alarms", headers={"Authorization": "Bearer token"})
    assert len(response.json()) == 1


def test_healthy_collector_has_no_alarms(tmp_path: Path):
    collector = AlarmCollector(tmp_path / "alarms.jsonl")
    with TestClient(create_app(collector=collector)) as client:
        assert client.get("/alarms").json() == []


def test_checkpoint_stall_fires_after_window_and_not_during_healthy_progress():
    heartbeat = Heartbeat(
        log_id="sha256:" + "a" * 64,
        epoch_id=0,
        latest_seq=9,
        latest_entry_hash="sha256:" + "b" * 64,
        queue_depth=0,
        signer_timestamp="2026-01-01T00:00:01.000Z",
    )
    checkpoint = Checkpoint(
        log_id=heartbeat.log_id,
        tree_size=10,
        root_hash="sha256:" + "c" * 64,
        latest_seq=9,
        latest_entry_hash="sha256:" + "d" * 64,
        epoch_id=0,
        signer_timestamp="2026-01-01T00:00:00.000Z",
    )
    assert checkpoint_stall(
        heartbeat, checkpoint, "2026-01-01T00:00:20.000Z", unverified_window=15
    ) == ["CHECKPOINT_STALL"]
    assert (
        checkpoint_stall(heartbeat, checkpoint, "2026-01-01T00:00:03.000Z", unverified_window=2)
        == []
    )

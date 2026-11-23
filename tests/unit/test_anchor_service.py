"""Unit tests for Stage 6 Public Transparency & External Anchoring (services/anchor)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from fastapi.testclient import TestClient

from libs.blackbox_core import schemas
from libs.blackbox_core.encoding import encode_base64url
from services.alerting.collector import AlarmCollector
from services.anchor.git_backend import GitAnchorBackend
from services.anchor.main import create_app, health, publish
from services.anchor.ots_backend import OpenTimestampsAdapter
from services.anchor.worker import AnchorWorker


def _make_checkpoint(
    tree_size: int = 10,
    root_hash: str = "sha256:" + "a" * 64,
) -> schemas.Checkpoint:
    return schemas.Checkpoint(
        log_id="sha256:" + "0" * 64,
        tree_size=tree_size,
        root_hash=root_hash,
        latest_seq=max(0, tree_size - 1),
        epoch_id=0,
        signer_timestamp="2026-01-01T00:00:00.000Z",
        latest_entry_hash="sha256:" + "0" * 64,
        signature=encode_base64url(b"\x00" * 64),
    )


def _make_cosignatures(checkpoint_hash: str, count: int = 2) -> list[schemas.Cosignature]:
    return [
        schemas.Cosignature(
            log_id="sha256:" + "0" * 64,
            checkpoint_hash=checkpoint_hash,
            witness_id=f"witness-{i + 1}",
            witness_timestamp="2026-01-01T00:00:00.000Z",
            witness_signature=encode_base64url((i + 1).to_bytes(64, "big")),
        )
        for i in range(count)
    ]


def test_git_anchor_backend(tmp_path: Path) -> None:
    """GitAnchorBackend appends witnessed checkpoints and records commits."""
    repo = tmp_path / "anchor_repo"
    backend = GitAnchorBackend(repo)

    cp = _make_checkpoint(tree_size=15, root_hash="sha256:" + "1" * 64)
    cosigs = _make_cosignatures(cp.root_hash, count=2)
    record = backend.append_checkpoint(cp, cosignatures=cosigs)

    assert record["tree_size"] == 15
    assert record["root_hash"] == "sha256:" + "1" * 64
    assert len(record["cosignatures"]) == 2
    assert "git_commit" in record

    anchors = backend.get_anchors()
    assert len(anchors) == 1
    assert anchors[0]["tree_size"] == 15

    found = backend.get_anchor_for_tree_size(15)
    assert found is not None
    assert found["root_hash"] == "sha256:" + "1" * 64
    assert backend.get_anchor_for_tree_size(99) is None


def test_opentimestamps_adapter() -> None:
    """OpenTimestampsAdapter creates and verifies Bitcoin testnet commitments."""
    ots = OpenTimestampsAdapter(testnet=True)
    cp = _make_checkpoint(tree_size=20, root_hash="sha256:" + "2" * 64)

    receipt = ots.anchor_checkpoint(cp)
    assert receipt["adapter"] == "opentimestamps"
    assert receipt["tree_size"] == 20
    assert receipt["chain"] == "bitcoin_testnet"
    assert "ots_proof_base64" in receipt
    assert "block_height" in receipt

    # Verify commitment matches honest checkpoint
    assert ots.verify_commitment(cp, receipt) is True

    # Tampered checkpoint must fail verification
    tampered_cp = _make_checkpoint(tree_size=20, root_hash="sha256:" + "3" * 64)
    assert ots.verify_commitment(tampered_cp, receipt) is False


def test_anchor_worker_poll_and_publish(tmp_path: Path) -> None:
    """AnchorWorker polls witnessed checkpoints and skips unwitnessed ones."""
    worker = AnchorWorker(
        repo_path=tmp_path / "worker_repo",
        min_quorum=2,
        max_stall_seconds=300,
    )

    async def _test() -> None:
        # 1. Unwitnessed checkpoint (only 1 cosignature, quorum requires 2)
        cp1 = _make_checkpoint(tree_size=5)
        cosigs1 = _make_cosignatures(cp1.root_hash, count=1)
        res1 = await worker.poll_once(checkpoint=cp1, cosignatures=cosigs1)
        assert res1 is None
        assert worker.last_anchored_tree_size == 0

        # 2. Witnessed checkpoint (2 cosignatures)
        cp2 = _make_checkpoint(tree_size=10)
        cosigs2 = _make_cosignatures(cp2.root_hash, count=2)
        res2 = await worker.poll_once(checkpoint=cp2, cosignatures=cosigs2)
        assert res2 is not None
        assert res2["status"] == "published"
        assert res2["tree_size"] == 10
        assert worker.last_anchored_tree_size == 10

        # 3. Same tree size polled again reports up_to_date
        res3 = await worker.poll_once(checkpoint=cp2, cosignatures=cosigs2)
        assert res3 == {"status": "up_to_date", "tree_size": 10}

    asyncio.run(_test())


def test_anchor_mismatch_alarm_telemetry(tmp_path: Path) -> None:
    """Contradicting root hash for an already anchored tree size triggers ANCHOR_MISMATCH."""
    collector = AlarmCollector(tmp_path / "alarms.log")
    worker = AnchorWorker(
        repo_path=tmp_path / "mismatch_repo",
        alarm_collector=collector,
    )

    cp_honest = _make_checkpoint(tree_size=25, root_hash="sha256:" + "4" * 64)
    worker.publish_checkpoint(cp_honest)

    # An attacker attempts to anchor a conflicting root hash for tree_size=25
    cp_forked = _make_checkpoint(tree_size=25, root_hash="sha256:" + "5" * 64)

    async def _test() -> None:
        res = await worker.poll_once(checkpoint=cp_forked)
        assert res is not None
        assert res["status"] == "mismatch"
        assert res["error"] == "ANCHOR_MISMATCH"

        # Check alarm raised
        alarms = [a for a in worker.alarms if a["type"] == "ANCHOR_MISMATCH"]
        assert len(alarms) >= 1
        assert alarms[0]["severity"] == "high"

        # Check collector received alarm
        collected = collector.records()
        assert any(r["type"] == "ANCHOR_MISMATCH" for r in collected)

    asyncio.run(_test())


def test_anchor_stall_alarm_telemetry(tmp_path: Path) -> None:
    """When time since last anchor exceeds max_stall_seconds, ANCHOR_STALL is emitted."""
    collector = AlarmCollector(tmp_path / "alarms.log")
    worker = AnchorWorker(
        repo_path=tmp_path / "stall_repo",
        alarm_collector=collector,
        max_stall_seconds=60,
    )

    # Set last anchored time to 120 seconds in past
    worker.last_anchored_time = time.time() - 120

    async def _test() -> None:
        await worker.poll_once(checkpoint=None)

        stall_alarms = [a for a in worker.alarms if a["type"] == "ANCHOR_STALL"]
        assert len(stall_alarms) >= 1
        assert stall_alarms[0]["severity"] == "low"

        collected = collector.records()
        assert any(r["type"] == "ANCHOR_STALL" for r in collected)

    asyncio.run(_test())


def test_anchor_fastapi_service_endpoints(tmp_path: Path) -> None:
    """Test Anchor FastAPI HTTP application routes."""
    worker = AnchorWorker(repo_path=tmp_path / "http_repo")
    app = create_app(worker=worker)

    with TestClient(app) as client:
        # 1. Health
        h_res = client.get("/health")
        assert h_res.status_code == 200
        assert h_res.json()["service"] == "anchor"

        # 2. Publish on-demand
        cp = _make_checkpoint(tree_size=30, root_hash="sha256:" + "6" * 64)
        pub_res = client.post("/v1/anchors/publish", json=cp.model_dump())
        assert pub_res.status_code == 200
        assert pub_res.json()["status"] == "published"
        assert pub_res.json()["tree_size"] == 30

        # 3. List anchors
        list_res = client.get("/v1/anchors")
        assert list_res.status_code == 200
        assert len(list_res.json()) == 1
        assert list_res.json()[0]["tree_size"] == 30

        # 4. Verify anchor
        v_res = client.post("/v1/anchors/verify", json=cp.model_dump())
        assert v_res.status_code == 200
        assert v_res.json()["verdict"] == "VERIFIED"

        # 5. Verify mismatch
        bad_cp = _make_checkpoint(tree_size=30, root_hash="sha256:" + "9" * 64)
        bad_v = client.post("/v1/anchors/verify", json=bad_cp.model_dump())
        assert bad_v.status_code == 200
        assert bad_v.json()["verdict"] == "MISMATCH"

        # 6. Alarms endpoint
        alarms_res = client.get("/v1/anchors/alarms")
        assert alarms_res.status_code == 200
        assert any(a["type"] == "ANCHOR_MISMATCH" for a in alarms_res.json())


def test_anchor_module_helpers() -> None:
    """Verify module-level health(), publish(), and verify() functions."""

    async def _test() -> None:
        h = await health()
        assert h["service"] == "anchor"

        cp = _make_checkpoint(tree_size=50)
        res = await publish(cp)
        assert res["status"] == "published"
        assert res["tree_size"] == 50

        # Verify
        from services.anchor.main import verify

        v = await verify(cp)
        assert v["verdict"] == "VERIFIED"

    asyncio.run(_test())


def test_anchor_stall_unwitnessed_quorum_loss(tmp_path: Path) -> None:
    """When checkpoints arrive but witness quorum is lost for > max_stall, ANCHOR_STALL is emitted."""
    collector = AlarmCollector(tmp_path / "stall_quorum.log")
    worker = AnchorWorker(
        repo_path=tmp_path / "quorum_stall_repo",
        alarm_collector=collector,
        max_stall_seconds=60,
        min_quorum=2,
    )
    worker.last_anchored_time = time.time() - 120

    async def _test() -> None:
        cp = _make_checkpoint(tree_size=100)
        # Only 1 cosignature provided (less than min_quorum=2)
        cosigs = _make_cosignatures(cp.root_hash, count=1)
        res = await worker.poll_once(checkpoint=cp, cosignatures=cosigs)
        assert res is None

        stall_alarms = [a for a in worker.alarms if a["type"] == "ANCHOR_STALL"]
        assert len(stall_alarms) >= 1
        assert "insufficient_witness_quorum" in stall_alarms[0]["evidence_reference"]

        collected = collector.records()
        assert any(r["type"] == "ANCHOR_STALL" for r in collected)

    asyncio.run(_test())


def test_anchor_worker_verify_checkpoint_mismatch(tmp_path: Path) -> None:
    """Direct verify_checkpoint method detects ANCHOR_MISMATCH contradiction."""
    collector = AlarmCollector(tmp_path / "mismatch_verify.log")
    worker = AnchorWorker(
        repo_path=tmp_path / "verify_repo",
        alarm_collector=collector,
    )

    honest_cp = _make_checkpoint(tree_size=75, root_hash="sha256:" + "7" * 64)
    worker.publish_checkpoint(honest_cp)

    # Contradicting checkpoint
    bad_cp = _make_checkpoint(tree_size=75, root_hash="sha256:" + "8" * 64)
    res = worker.verify_checkpoint(bad_cp)

    assert res["verdict"] == "MISMATCH"
    assert res["published_root"] == "sha256:" + "7" * 64
    assert res["checkpoint_root"] == "sha256:" + "8" * 64

    # Verify alarm emitted with severity high
    assert any(a["type"] == "ANCHOR_MISMATCH" and a["severity"] == "high" for a in worker.alarms)
    assert any(r["type"] == "ANCHOR_MISMATCH" for r in collector.records())


def test_anchor_alerting_http_dispatch(tmp_path: Path) -> None:
    """Test HTTP alarm dispatch to alerting service /alarms endpoint."""
    from services.alerting.collector import create_app as create_alerting_app

    alert_collector = AlarmCollector(tmp_path / "http_alarms.log")
    alert_app = create_alerting_app(collector=alert_collector)

    # Use in-process test client for alerting service
    with TestClient(alert_app) as client:
        # Verify POST /alarms
        post_res = client.post(
            "/alarms",
            json={
                "type": "ANCHOR_STALL",
                "source": "anchor-service",
                "evidence_reference": "test_evidence",
                "severity": "low",
                "time": "2026-01-01T00:00:00.000Z",
            },
        )
        assert post_res.status_code == 200
        assert post_res.json()["status"] == "recorded"

        # Verify alarm recorded
        records = alert_collector.records()
        assert len(records) == 1
        assert records[0]["type"] == "ANCHOR_STALL"

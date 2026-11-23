"""Unit tests for BlackBox Operator CLI commands (export-bundle, status, reconcile-report)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize
from services.reconciler.findings_store import FindingsStore
from tools.bundle_export import export_bundle
from tools.reconcile_report import generate_reconcile_report
from tools.status import inspect_signer_dir


def test_status_offline_inspection(tmp_path: Path) -> None:
    # 1. Uninitialized dir
    res_uninit = inspect_signer_dir(tmp_path / "empty")
    assert res_uninit["status"] == "uninitialized"

    # 2. Initialized state dir
    signer_dir = tmp_path / "signer"
    signer_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "log_id": "sha256:" + "0" * 64,
        "seq": 42,
        "epoch_id": 3,
        "latest_entry_hash": "sha256:" + "a" * 64,
        "signer_timestamp": "2026-01-01T00:00:00.000Z",
    }
    (signer_dir / "state.json").write_bytes(canonicalize(state))

    res_ok = inspect_signer_dir(signer_dir)
    assert res_ok["status"] == "ok"
    assert res_ok["seq"] == 42
    assert res_ok["epoch_id"] == 3
    assert res_ok["quarantined"] is False

    # 3. Quarantined state dir
    (signer_dir / "state.json.quarantine.json").write_text(
        json.dumps(
            {"reason": "manual operator isolation", "quarantined_at": "2026-01-01T00:01:00Z"}
        )
    )
    res_quarantine = inspect_signer_dir(signer_dir)
    assert res_quarantine["status"] == "quarantined"
    assert res_quarantine["quarantined"] is True
    assert res_quarantine["quarantine_reason"] == "manual operator isolation"


def test_export_bundle_cli(tmp_path: Path, monkeypatch) -> None:
    fake_bundle = {
        "log_id": "sha256:" + "0" * 64,
        "entries": [],
        "checkpoints": [],
        "inclusion_proofs": [],
        "epochs": [],
        "intermediates": [],
        "witness_set": {"quorum": 2, "witnesses": []},
    }

    class FakeResponse:
        def __init__(self, status_code: int, json_data: dict) -> None:
            self.status_code = status_code
            self._json = json_data
            self.text = json.dumps(json_data)

        def json(self) -> dict:
            return self._json

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args) -> None:
            pass

        def get(self, path: str, params: dict | None = None) -> FakeResponse:
            if path == "/checkpoint/latest":
                return FakeResponse(200, {"latest_seq": 5})
            if path == "/bundle":
                return FakeResponse(200, fake_bundle)
            return FakeResponse(404, {})

    monkeypatch.setattr("httpx.Client", FakeClient)

    out_file = tmp_path / "bundle.json"
    res = export_bundle(start_seq=0, end_seq=5, output=out_file, ledger_url="http://fake-ledger")
    assert res["log_id"] == fake_bundle["log_id"]
    assert out_file.exists()
    saved = json.loads(out_file.read_text())
    assert saved["log_id"] == fake_bundle["log_id"]


def test_reconcile_report(tmp_path: Path) -> None:
    store_file = tmp_path / "findings.json"
    store = FindingsStore(store_file)

    finding1 = schemas.Finding(
        finding_type="UNRECORDED_ACTION",
        ledger_seqs=[10],
        provider_event_ids=["prov-1"],
        detection_time="2026-01-01T00:00:00.000Z",
    )
    finding2 = schemas.Finding(
        finding_type="UNATTESTED_ACTION",
        ledger_seqs=[],
        provider_event_ids=["prov-2"],
        detection_time="2026-01-01T00:00:05.000Z",
    )
    store.append(finding1)
    store.append(finding2)

    out_file = tmp_path / "report.json"
    report = generate_reconcile_report(store_path=store_file, output=out_file)

    assert report["total_findings"] == 2
    assert report["by_type"]["UNRECORDED_ACTION"] == 1
    assert report["by_type"]["UNATTESTED_ACTION"] == 1
    assert out_file.exists()


def test_cli_subprocesses(tmp_path: Path) -> None:
    # 1. status CLI command
    signer_dir = tmp_path / "signer_cli"
    signer_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "log_id": "sha256:" + "0" * 64,
        "seq": 100,
        "epoch_id": 5,
        "latest_entry_hash": "sha256:" + "b" * 64,
        "signer_timestamp": "2026-01-01T00:00:00.000Z",
    }
    (signer_dir / "state.json").write_bytes(canonicalize(state))

    status_out = tmp_path / "status.json"
    cmd_status = [
        sys.executable,
        "-m",
        "tools.cli",
        "status",
        "--signer-state-dir",
        str(signer_dir),
        "--output",
        str(status_out),
    ]
    res_status = subprocess.run(cmd_status, capture_output=True, text=True, check=True)
    assert res_status.returncode == 0
    assert status_out.exists()
    status_data = json.loads(status_out.read_text())
    assert status_data["signer_offline"]["seq"] == 100

    # 2. reconcile-report CLI command
    findings_file = tmp_path / "cli_findings.json"
    store = FindingsStore(findings_file)
    store.append(
        schemas.Finding(
            finding_type="ARGS_MISMATCH",
            ledger_seqs=[5],
            provider_event_ids=["prov-3"],
            detection_time="2026-01-01T00:00:00.000Z",
        )
    )
    reconcile_out = tmp_path / "reconcile_report.json"
    cmd_rec = [
        sys.executable,
        "-m",
        "tools.cli",
        "reconcile-report",
        "--store",
        str(findings_file),
        "--output",
        str(reconcile_out),
    ]
    res_rec = subprocess.run(cmd_rec, capture_output=True, text=True, check=True)
    assert res_rec.returncode == 0
    assert reconcile_out.exists()
    rec_data = json.loads(reconcile_out.read_text())
    assert rec_data["total_findings"] == 1
    assert rec_data["by_type"]["ARGS_MISMATCH"] == 1

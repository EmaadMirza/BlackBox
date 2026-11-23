"""Unit test for Attack Suite CLI engine."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.attack_suite import run_all


def test_attack_suite_direct_run(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    result = run_all(output=report_file)

    assert result["verdict"] == "PASSED"
    assert result["summary"]["total_scenarios"] == 10
    assert result["summary"]["passed"] == 10
    assert result["summary"]["failed"] == 0

    assert report_file.exists()
    saved = json.loads(report_file.read_text())
    assert saved["verdict"] == "PASSED"
    assert len(saved["scenarios"]) == 10


def test_attack_suite_directory_output(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifacts"
    result = run_all(output=out_dir)

    assert result["verdict"] == "PASSED"
    report_file = out_dir / "report.json"
    assert report_file.exists()


def test_attack_suite_cli_subprocess(tmp_path: Path) -> None:
    out_file = tmp_path / "cli_report.json"
    cmd = [sys.executable, "-m", "tools.cli", "attack-suite", "--output", str(out_file)]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)

    assert res.returncode == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["verdict"] == "PASSED"
    assert data["summary"]["passed"] == 10

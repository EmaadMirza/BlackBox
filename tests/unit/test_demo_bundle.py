"""Development demo CLI and read-only Makefile verification integration."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from libs.blackbox_core.evidence import Bundle, PinnedKeys
from tools.verifier.verify import verify_bundle

PROJECT = Path(__file__).resolve().parents[2]
FILENAMES = ("bundle.json", "pinned-keys.json")


def generate(output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tools.demo_bundle", "--output", str(output)],
        cwd=PROJECT,
        capture_output=True,
        text=True,
    )


def assert_generated(output: Path) -> None:
    result = generate(output)
    assert result.returncode == 0, result.stdout + result.stderr


def test_cli_generates_public_ten_entry_verified_bundle(tmp_path: Path) -> None:
    assert_generated(tmp_path)
    assert {path.name for path in tmp_path.iterdir()} == set(FILENAMES)
    bundle = Bundle.model_validate_json((tmp_path / FILENAMES[0]).read_bytes())
    pins = PinnedKeys.model_validate_json((tmp_path / FILENAMES[1]).read_bytes())
    assert len(bundle.entries) == 10
    assert pins.log_id == bundle.log_id
    report = verify_bundle(tmp_path / FILENAMES[0], tmp_path / FILENAMES[1])
    assert report.verdict == "VERIFIED", report.to_dict()
    assert len(report.entries) == 10
    assert all(entry.verdict == "VERIFIED" for entry in report.entries)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.cli",
            "verify",
            str(tmp_path / FILENAMES[0]),
            "--pinned-keys",
            str(tmp_path / FILENAMES[1]),
        ],
        cwd=PROJECT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["verdict"] == "VERIFIED"


@pytest.mark.parametrize("existing", [(FILENAMES[0],), (FILENAMES[1],), FILENAMES])
def test_refuses_existing_or_partial_pair_without_changes(
    tmp_path: Path, existing: tuple[str, ...]
) -> None:
    for name in existing:
        (tmp_path / name).write_bytes(b"existing data must remain untouched\n")
    before = {name: (tmp_path / name).stat() for name in existing}
    result = generate(tmp_path)
    assert result.returncode == 2
    assert "refus" in result.stderr.lower()
    assert {path.name for path in tmp_path.iterdir()} == set(existing)
    for name in existing:
        assert (tmp_path / name).read_bytes() == b"existing data must remain untouched\n"
        assert (tmp_path / name).stat().st_mtime_ns == before[name].st_mtime_ns


def test_requires_existing_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "missing"
    result = generate(output)
    assert result.returncode == 2
    assert "directory" in result.stderr.lower()
    assert not output.exists()


def test_workload_and_timestamps_repeat_but_ephemeral_keys_do_not(tmp_path: Path) -> None:
    bundles = []
    pins = []
    for name in ("first", "second"):
        output = tmp_path / name
        output.mkdir()
        assert_generated(output)
        bundles.append(json.loads((output / FILENAMES[0]).read_text()))
        pins.append(json.loads((output / FILENAMES[1]).read_text()))
    workload_fields = (
        "seq",
        "epoch_id",
        "type",
        "signer_timestamp",
        "lane",
        "action_name",
        "reason",
        "target_reference",
    )
    workloads = [
        [{field: entry["body"].get(field) for field in workload_fields} for entry in b["entries"]]
        for b in bundles
    ]
    assert workloads[0] == workloads[1]
    assert [entry["seq"] for entry in workloads[0]] == list(range(10))
    assert pins[0]["root_public_key"] != pins[1]["root_public_key"]
    assert pins[0]["witness_public_keys"] != pins[1]["witness_public_keys"]
    assert bundles[0]["log_id"] != bundles[1]["log_id"]


def test_no_private_keys_persisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.hazmat.primitives import serialization

    from libs.blackbox_core.encoding import encode_base64url
    from tools import demo_bundle
    from tools.ceremony import generate_dev_keys

    keys = generate_dev_keys()
    monkeypatch.setattr(demo_bundle, "generate_dev_keys", lambda: keys)
    monkeypatch.setattr(sys, "argv", ["demo_bundle", "--output", str(tmp_path)])
    demo_bundle.main()
    assert {path.name for path in tmp_path.iterdir()} == set(FILENAMES)
    data = b"\n".join((tmp_path / name).read_bytes() for name in FILENAMES)
    assert b"PRIVATE KEY" not in data
    assert b"private_key" not in data
    for key, _ in keys:
        private = key.private_bytes_raw()
        assert encode_base64url(private).encode() not in data
        assert private.hex().encode() not in data
        assert (
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            not in data
        )


def test_make_demo_and_custom_verify_are_read_only(tmp_path: Path) -> None:
    output = tmp_path / "demo output"
    output.mkdir()
    result = subprocess.run(
        ["make", "demo-bundle", f"PYTHON={sys.executable}", f"DEMO_OUTPUT={output}"],
        cwd=PROJECT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    before = {name: (output / name).read_bytes() for name in FILENAMES}
    verify_command = [
        "make",
        "verify",
        f"BLACKBOX={sys.executable} -m tools.cli",
        f"BUNDLE={output / FILENAMES[0]}",
        f"PINNED_KEYS={output / FILENAMES[1]}",
    ]
    result = subprocess.run(verify_command, cwd=PROJECT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"verdict": "VERIFIED"' in result.stdout
    assert {name: (output / name).read_bytes() for name in FILENAMES} == before
    (output / FILENAMES[0]).unlink()
    result = subprocess.run(verify_command, cwd=PROJECT, capture_output=True, text=True)
    assert result.returncode != 0
    assert not (output / FILENAMES[0]).exists()
    assert (output / FILENAMES[1]).read_bytes() == before[FILENAMES[1]]


def test_make_defaults_use_artifacts_and_verify_has_no_generation() -> None:
    result = subprocess.run(
        ["make", "-n", "verify", "demo-bundle"], cwd=PROJECT, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 2
    assert 'verify "artifacts/bundle.json" --pinned-keys "artifacts/pinned-keys.json"' in lines[0]
    assert '-m tools.demo_bundle --output "artifacts"' in lines[1]

"""Tests for Shamir's Secret Sharing and air-gapped root key ceremony (§7.2)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.shamir import ShamirShare, combine_shares, split_secret
from tools.ceremony import main as ceremony_main
from tools.ceremony import prepare_air_gapped_ceremony, recover_root_from_shards


def test_shamir_split_and_combine_basic() -> None:
    secret = os.urandom(32)
    shares = split_secret(secret, threshold=3, total_shares=5)
    assert len(shares) == 5

    # Any 3 shares reconstruct the exact secret
    assert combine_shares(shares[:3]) == secret
    assert combine_shares([shares[0], shares[2], shares[4]]) == secret
    assert combine_shares(shares[2:5]) == secret

    # 4 or 5 shares also reconstruct the secret
    assert combine_shares(shares[:4]) == secret
    assert combine_shares(shares) == secret


def test_shamir_threshold_insufficient_shares() -> None:
    secret = os.urandom(32)
    shares = split_secret(secret, threshold=3, total_shares=5)

    # 2 shares (< 3) should raise ValueError
    with pytest.raises(ValueError, match="Insufficient shares"):
        combine_shares(shares[:2], threshold=3)


def test_shamir_various_thresholds() -> None:
    secret = os.urandom(32)

    # 1-of-1
    s1 = split_secret(secret, 1, 1)
    assert combine_shares(s1) == secret

    # 2-of-3
    s2 = split_secret(secret, 2, 3)
    assert combine_shares([s2[0], s2[1]]) == secret
    assert combine_shares([s2[1], s2[2]]) == secret

    # 4-of-7
    s4 = split_secret(secret, 4, 7)
    assert combine_shares([s4[0], s4[2], s4[4], s4[6]]) == secret


def test_shamir_invalid_inputs() -> None:
    secret = os.urandom(32)

    # Invalid secret length
    with pytest.raises(ValueError, match="Secret must be exactly 32 bytes"):
        split_secret(b"short", 3, 5)

    # Threshold < 1
    with pytest.raises(ValueError, match="Threshold must be at least 1"):
        split_secret(secret, 0, 5)

    # Total shares < threshold
    with pytest.raises(ValueError, match="Total shares.*must be >= threshold"):
        split_secret(secret, 5, 3)

    # Zero shares passed to combine
    with pytest.raises(ValueError, match="Cannot reconstruct secret from zero shares"):
        combine_shares([])


def test_shamir_share_serialization() -> None:
    share = ShamirShare(index=2, value=12345678901234567890, threshold=3, total_shares=5)

    # String format
    s_str = share.to_string()
    reconstructed = ShamirShare.from_string(s_str)
    assert reconstructed == share

    # Dict format
    d = share.to_dict()
    reconstructed_dict = ShamirShare.from_dict(d)
    assert reconstructed_dict == share


def test_air_gapped_ceremony_artifacts(tmp_path: Path) -> None:
    out_dir = tmp_path / "ceremony"
    prepare_air_gapped_ceremony(
        log_name="test-log",
        destination=out_dir,
        threshold=3,
        total_shares=5,
        witness_count=3,
    )

    # 1. Root private key MUST NOT exist on disk
    assert not (out_dir / "root.dev-private.pem").exists()

    # 2. Shards 1 through 5 must exist with restricted permissions
    for i in range(1, 6):
        shard_path = out_dir / f"shard-{i}.json"
        assert shard_path.exists()
        # Verify file permissions are 0o600 (-rw-------)
        mode = shard_path.stat().st_mode & 0o777
        assert mode == 0o600

    # 3. Standard identity and signed credentials exist
    assert (out_dir / "identity.json").exists()
    assert (out_dir / "intermediate.json").exists()
    assert (out_dir / "intermediate.dev-private.pem").exists()
    assert (out_dir / "witness-set.json").exists()
    assert (out_dir / "root-manifest.json").exists()

    # 4. Manifest contents
    manifest = __import__("json").loads((out_dir / "root-manifest.json").read_text())
    assert manifest["log_name"] == "test-log"
    assert manifest["threshold"] == 3
    assert manifest["total_shares"] == 5
    assert "root_public_key_sha256" in manifest


def test_air_gapped_recovery(tmp_path: Path) -> None:
    out_dir = tmp_path / "ceremony"
    prepare_air_gapped_ceremony(
        log_name="test-log",
        destination=out_dir,
        threshold=3,
        total_shares=5,
    )

    shards = [out_dir / f"shard-{i}.json" for i in (1, 3, 5)]
    recovered_pem_path = tmp_path / "recovered_root.pem"

    recovered_key = recover_root_from_shards(
        shard_paths=shards,
        identity_or_manifest_path=out_dir / "identity.json",
        output_path=recovered_pem_path,
    )

    assert isinstance(recovered_key, Ed25519PrivateKey)
    assert recovered_pem_path.exists()

    # Verify public key matches identity
    identity = __import__("json").loads((out_dir / "identity.json").read_text())
    assert (
        encode_base64url(recovered_key.public_key().public_bytes_raw())
        == identity["root_public_key"]
    )


def test_air_gapped_recovery_insufficient_or_corrupted(tmp_path: Path) -> None:
    out_dir = tmp_path / "ceremony"
    prepare_air_gapped_ceremony(
        log_name="test-log",
        destination=out_dir,
        threshold=3,
        total_shares=5,
    )

    # Only 2 shards provided (threshold is 3)
    shards_2 = [out_dir / "shard-1.json", out_dir / "shard-2.json"]
    with pytest.raises(ValueError, match="Insufficient shares"):
        recover_root_from_shards(shards_2, out_dir / "identity.json")

    # Corrupted shard
    corrupt_shard = tmp_path / "corrupt_shard.json"
    corrupt_data = __import__("json").loads((out_dir / "shard-1.json").read_text())
    corrupt_data["value"] = f"{(int(corrupt_data['value'], 16) ^ 0xFF):064x}"
    corrupt_shard.write_text(__import__("json").dumps(corrupt_data))

    with pytest.raises(ValueError, match="Reconstructed root key public mismatch"):
        recover_root_from_shards(
            [corrupt_shard, out_dir / "shard-2.json", out_dir / "shard-3.json"],
            out_dir / "identity.json",
        )


def test_ceremony_cli_air_gapped_and_recovery(tmp_path: Path) -> None:
    out_dir = tmp_path / "cli_ceremony"

    # Run air-gapped via CLI
    with patch(
        "sys.argv",
        [
            "ceremony.py",
            "air-gapped",
            "--log-name",
            "cli-test",
            "--output",
            str(out_dir),
            "--threshold",
            "2",
            "--shares",
            "3",
        ],
    ):
        ceremony_main()

    assert (out_dir / "shard-1.json").exists()
    assert (out_dir / "shard-2.json").exists()
    assert (out_dir / "shard-3.json").exists()
    assert not (out_dir / "root.dev-private.pem").exists()

    # Run recover-root via CLI
    rec_out = tmp_path / "cli_recovered.pem"
    with patch(
        "sys.argv",
        [
            "ceremony.py",
            "recover-root",
            "--identity",
            str(out_dir / "identity.json"),
            "--shards",
            str(out_dir / "shard-1.json"),
            str(out_dir / "shard-2.json"),
            "--output",
            str(rec_out),
        ],
    ):
        ceremony_main()

    assert rec_out.exists()

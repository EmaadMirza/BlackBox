"""Air-gapped and development key ceremony tooling (§7.2, Shamir SSS root shards)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.encoding import encode_base64url, format_timestamp
from libs.blackbox_core.epochs import build_intermediate_certificate
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.schemas import WitnessIdentity, WitnessSet
from libs.blackbox_core.shamir import ShamirShare, combine_shares, split_secret
from libs.blackbox_core.signing import sign_structure
from services.signer.custody import (
    HardwareKeyCustodyMock,
    KeyCustodyProvider,
    create_custody_provider,
    zeroize_buffer,
)


def generate_dev_keys(count: int = 7) -> list[tuple[Ed25519PrivateKey, bytes]]:
    """Only this file and tests/_dev_keys.py generate Stage 1 signing keys."""
    result = []
    for _ in range(count):
        key = Ed25519PrivateKey.generate()
        result.append((key, key.public_key().public_bytes_raw()))
    return result


def prepare_ceremony(log_name: str, destination: Path) -> Path:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    root, inter, *witnesses = generate_dev_keys(5)
    log = derive_log_id(root[1], log_name)
    now = datetime.now(timezone.utc)
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    cert = build_intermediate_certificate(
        log,
        "intermediate-0",
        encode_base64url(inter[1]),
        format_timestamp(now),
        format_timestamp(now + timedelta(days=30)),
        root[0],
    )
    for name, key in [("root", root[0]), ("intermediate", inter[0])]:
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(
            destination / f"{name}.dev-private.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    (destination / "intermediate.json").write_bytes(canonicalize(cert.model_dump()))
    (destination / "identity.json").write_bytes(
        canonicalize(
            {"log_id": log, "log_name": log_name, "root_public_key": encode_base64url(root[1])}
        )
    )
    witness_set = sign_structure(
        WitnessSet(
            log_id=log,
            version=1,
            witnesses=[
                WitnessIdentity(witness_id=f"w{i}", public_key=encode_base64url(public_key))
                for i, (_, public_key) in enumerate(witnesses)
            ],
            quorum=2,
            effective_time=format_timestamp(now),
        ),
        root[0],
        "witness_set",
    )
    (destination / "witness-set.json").write_bytes(canonicalize(witness_set.model_dump()))
    for i, (key, _) in enumerate(witnesses):
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(
            destination / f"w{i}.dev-private.pem",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    return destination


def prepare_air_gapped_ceremony(
    log_name: str,
    destination: Path,
    *,
    threshold: int = 3,
    total_shares: int = 5,
    witness_count: int = 3,
    intermediate_valid_days: int = 30,
) -> Path:
    """Execute an air-gapped root key ceremony with K-of-N Shamir's Secret Sharing shards.

    In an air-gapped ceremony:
    1. The root private key is generated ephemeral in memory and split into N Shamir shares.
    2. Shards are written to individual shard files with restricted permissions (0o600).
    3. Intermediate and witness credentials are signed by the root key.
    4. Memory buffers holding the root private seed are explicitly zeroized.
    5. No root private key PEM file is ever written to disk.
    """
    if threshold < 1 or total_shares < threshold:
        raise ValueError(f"Invalid threshold {threshold} or total shares {total_shares}")
    if witness_count < 1:
        raise ValueError("Witness count must be positive")

    destination.mkdir(mode=0o700, parents=True, exist_ok=False)

    # 1. Ephemeral root key generation
    root_seed = bytearray(os.urandom(32))
    root_priv = Ed25519PrivateKey.from_private_bytes(bytes(root_seed))
    root_pub_bytes = root_priv.public_key().public_bytes_raw()
    root_pub_b64 = encode_base64url(root_pub_bytes)
    log_id = derive_log_id(root_pub_bytes, log_name)

    # 2. Split root private seed into Shamir shares
    shares = split_secret(bytes(root_seed), threshold, total_shares)

    # 3. Write individual shard files
    for share in shares:
        shard_data = {
            "format_version": "1",
            "log_id": log_id,
            "root_public_key": root_pub_b64,
            **share.to_dict(),
        }
        shard_path = destination / f"shard-{share.index}.json"
        fd = os.open(shard_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonicalize(shard_data))

    # 4. Generate operational intermediate key
    inter_priv = Ed25519PrivateKey.generate()
    inter_pub_bytes = inter_priv.public_key().public_bytes_raw()
    inter_pub_b64 = encode_base64url(inter_pub_bytes)

    now = datetime.now(timezone.utc)
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    intermediate_cert = build_intermediate_certificate(
        log_id,
        "intermediate-0",
        inter_pub_b64,
        format_timestamp(now),
        format_timestamp(now + timedelta(days=intermediate_valid_days)),
        root_priv,
    )

    inter_pem = inter_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    inter_fd = os.open(
        destination / "intermediate.dev-private.pem",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(inter_fd, "wb") as stream:
        stream.write(inter_pem)

    (destination / "intermediate.json").write_bytes(canonicalize(intermediate_cert.model_dump()))

    # 5. Generate witness keys & signed witness set
    witness_keys = [Ed25519PrivateKey.generate() for _ in range(witness_count)]
    quorum = min(2, witness_count)
    witness_set = sign_structure(
        WitnessSet(
            log_id=log_id,
            version=1,
            witnesses=[
                WitnessIdentity(
                    witness_id=f"w{i}",
                    public_key=encode_base64url(key.public_key().public_bytes_raw()),
                )
                for i, key in enumerate(witness_keys)
            ],
            quorum=quorum,
            effective_time=format_timestamp(now),
        ),
        root_priv,
        "witness_set",
    )
    (destination / "witness-set.json").write_bytes(canonicalize(witness_set.model_dump()))

    for i, key in enumerate(witness_keys):
        pem_data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(
            destination / f"w{i}.dev-private.pem",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(pem_data)

        raw_path = destination / f"w{i}.private.raw"
        raw_fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(raw_fd, "wb") as stream:
            stream.write(key.private_bytes_raw())

    # 6. Write identity.json
    identity_data = {
        "log_id": log_id,
        "log_name": log_name,
        "root_public_key": root_pub_b64,
    }
    (destination / "identity.json").write_bytes(canonicalize(identity_data))

    # 7. Write root-manifest.json
    manifest_data = {
        "format_version": "1",
        "log_id": log_id,
        "log_name": log_name,
        "root_public_key": root_pub_b64,
        "root_public_key_sha256": encode_base64url(hashlib.sha256(root_pub_bytes).digest()),
        "threshold": threshold,
        "total_shares": total_shares,
        "ceremony_timestamp": format_timestamp(now),
        "intermediate_id": "intermediate-0",
        "witness_set_version": 1,
    }
    (destination / "root-manifest.json").write_bytes(canonicalize(manifest_data))

    # 8. Memory zeroization: actively overwrite root key memory buffer
    zeroize_buffer(root_seed)
    del root_seed
    del root_priv

    return destination


def recover_root_from_shards(
    shard_paths: list[Path],
    identity_or_manifest_path: Path,
    output_path: Path | None = None,
) -> Ed25519PrivateKey:
    """Reconstruct the root Ed25519 private key from K Shamir shares and verify against identity."""
    if not shard_paths:
        raise ValueError("No shard paths provided for recovery")

    shares: list[ShamirShare] = []
    expected_log_id: str | None = None

    for p in shard_paths:
        data = json.loads(p.read_text(encoding="utf-8"))
        share = ShamirShare.from_dict(data)
        shares.append(share)
        if expected_log_id is None:
            expected_log_id = data.get("log_id")
        elif expected_log_id != data.get("log_id"):
            raise ValueError(f"Shard {p} belongs to different log_id")

    # Read identity or manifest
    id_data = json.loads(identity_or_manifest_path.read_text(encoding="utf-8"))
    pinned_root_pub = id_data.get("root_public_key")
    if not pinned_root_pub:
        raise ValueError("Identity file missing root_public_key")

    # Reconstruct raw 32-byte secret seed
    recovered_seed = bytearray(combine_shares(shares))
    try:
        recovered_key = Ed25519PrivateKey.from_private_bytes(bytes(recovered_seed))
        recovered_pub_b64 = encode_base64url(recovered_key.public_key().public_bytes_raw())

        if recovered_pub_b64 != pinned_root_pub:
            raise ValueError(
                f"Reconstructed root key public mismatch: got {recovered_pub_b64}, expected {pinned_root_pub}. "
                "Shares may be invalid, insufficient, or corrupted."
            )

        if output_path is not None:
            pem = recovered_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(pem)

        return recovered_key
    finally:
        zeroize_buffer(recovered_seed)


def prepare_witness_set(
    root_private_path: Path, identity_path: Path, destination: Path, count: int = 3
) -> Path:
    """Additively create development witness raw-key files and a root-signed set."""
    if type(count) is not int or count < 1:
        raise ValueError("witness count must be positive")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = serialization.load_pem_private_key(root_private_path.read_bytes(), password=None)
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    keys = generate_dev_keys(count)
    witness_set = sign_structure(
        WitnessSet(
            log_id=identity["log_id"],
            version=1,
            witnesses=[
                WitnessIdentity(witness_id=f"w{i}", public_key=encode_base64url(public))
                for i, (_, public) in enumerate(keys)
            ],
            quorum=min(2, count),
            effective_time=format_timestamp(datetime.now(timezone.utc).replace(microsecond=0)),
        ),
        root,
        "witness_set",
    )
    (destination / "witness-set.json").write_bytes(canonicalize(witness_set.model_dump()))
    for i, (key, _) in enumerate(keys):
        path = destination / f"w{i}.private.raw"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key.private_bytes_raw())
    return destination


def prepare_hsm_ceremony(
    log_name: str,
    destination: Path,
    *,
    root_provider: KeyCustodyProvider | None = None,
    root_provider_type: str = "mock",
    root_provider_kwargs: dict[str, Any] | None = None,
    intermediate_provider: KeyCustodyProvider | None = None,
    intermediate_provider_type: str = "mock",
    intermediate_provider_kwargs: dict[str, Any] | None = None,
    witness_count: int = 3,
    intermediate_valid_days: int = 30,
) -> Path:
    """Execute a ceremony using hardware security modules or cloud KMS providers (§7.1).

    In an HSM / KMS ceremony:
    1. The root key resides inside an HSM / Cloud KMS (PKCS#11, AWS KMS, GCP KMS, Vault).
    2. Software never handles root private key material on disk.
    3. The intermediate key may also reside in an HSM / Cloud KMS or be generated locally.
    4. Root signs intermediate-0 and the initial witness set via the custody provider.
    5. An hsm-manifest.json and intermediate-custody.json are written to describe provider linkage.
    """
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)

    if root_provider is None:
        root_provider = create_custody_provider(root_provider_type, **(root_provider_kwargs or {}))

    root_pub_bytes = root_provider.get_public_key()
    root_pub_b64 = encode_base64url(root_pub_bytes)
    log_id = derive_log_id(root_pub_bytes, log_name)

    now = datetime.now(timezone.utc)
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)

    # Intermediate key setup
    if intermediate_provider is None:
        if intermediate_provider_type == "dev":
            inter_priv = Ed25519PrivateKey.generate()
            inter_pub_bytes = inter_priv.public_key().public_bytes_raw()
            inter_provider = None
        else:
            inter_provider = create_custody_provider(
                intermediate_provider_type, **(intermediate_provider_kwargs or {})
            )
            inter_pub_bytes = inter_provider.get_public_key()
            inter_priv = None
    else:
        inter_provider = intermediate_provider
        inter_pub_bytes = inter_provider.get_public_key()
        inter_priv = None

    inter_pub_b64 = encode_base64url(inter_pub_bytes)

    # Root signs the intermediate certificate using the HSM/KMS root provider
    intermediate_cert = build_intermediate_certificate(
        log_id,
        "intermediate-0",
        inter_pub_b64,
        format_timestamp(now),
        format_timestamp(now + timedelta(days=intermediate_valid_days)),
        root_provider,
    )
    (destination / "intermediate.json").write_bytes(canonicalize(intermediate_cert.model_dump()))

    if inter_priv is not None:
        inter_pem = inter_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        inter_fd = os.open(
            destination / "intermediate.dev-private.pem",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(inter_fd, "wb") as stream:
            stream.write(inter_pem)
    else:
        inter_kwargs = dict(intermediate_provider_kwargs or {})
        if (
            isinstance(inter_provider, HardwareKeyCustodyMock)
            and "key_seed_or_raw" not in inter_kwargs
        ):
            inter_kwargs["key_seed_or_raw"] = encode_base64url(bytes(inter_provider._key_buffer))
        custody_data = {
            "format_version": "1",
            "log_id": log_id,
            "provider_type": intermediate_provider_type,
            "intermediate_id": "intermediate-0",
            "public_key": inter_pub_b64,
            "provider_kwargs": inter_kwargs,
        }
        (destination / "intermediate-custody.json").write_bytes(canonicalize(custody_data))

    # Witnesses & Root-signed witness set
    witness_keys = [Ed25519PrivateKey.generate() for _ in range(witness_count)]
    quorum = min(2, witness_count)
    witness_set = sign_structure(
        WitnessSet(
            log_id=log_id,
            version=1,
            witnesses=[
                WitnessIdentity(
                    witness_id=f"w{i}",
                    public_key=encode_base64url(key.public_key().public_bytes_raw()),
                )
                for i, key in enumerate(witness_keys)
            ],
            quorum=quorum,
            effective_time=format_timestamp(now),
        ),
        root_provider,
        "witness_set",
    )
    (destination / "witness-set.json").write_bytes(canonicalize(witness_set.model_dump()))

    for i, key in enumerate(witness_keys):
        pem_data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(
            destination / f"w{i}.dev-private.pem",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(pem_data)

        raw_path = destination / f"w{i}.private.raw"
        raw_fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(raw_fd, "wb") as stream:
            stream.write(key.private_bytes_raw())

    # Write identity.json
    identity_data = {
        "log_id": log_id,
        "log_name": log_name,
        "root_public_key": root_pub_b64,
        "root_custody_type": root_provider_type,
    }
    (destination / "identity.json").write_bytes(canonicalize(identity_data))

    # Write hsm-manifest.json
    manifest_data = {
        "format_version": "1",
        "log_id": log_id,
        "log_name": log_name,
        "root_public_key": root_pub_b64,
        "root_provider_type": root_provider_type,
        "root_provider_kwargs": root_provider_kwargs or {},
        "intermediate_provider_type": intermediate_provider_type,
        "intermediate_provider_kwargs": intermediate_provider_kwargs or {},
        "ceremony_timestamp": format_timestamp(now),
        "intermediate_id": "intermediate-0",
        "witness_set_version": 1,
    }
    (destination / "hsm-manifest.json").write_bytes(canonicalize(manifest_data))

    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Key ceremony tooling (§7.1, §7.2, Shamir SSS & HSM/KMS)"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    # Legacy dev ceremony
    legacy = commands.add_parser("prepare")
    legacy.add_argument("--log-name", required=True)
    legacy.add_argument("--output", type=Path, required=True)

    # Air-gapped ceremony with Shamir shards
    air = commands.add_parser("air-gapped")
    air.add_argument("--log-name", default="blackbox")
    air.add_argument("--output", type=Path, required=True)
    air.add_argument("--threshold", type=int, default=3)
    air.add_argument("--shares", type=int, default=5)
    air.add_argument("--witness-count", type=int, default=3)
    air.add_argument("--intermediate-days", type=int, default=30)

    # HSM / Cloud KMS Ceremony
    hsm = commands.add_parser("hsm-ceremony")
    hsm.add_argument("--log-name", default="blackbox")
    hsm.add_argument("--output", type=Path, required=True)
    hsm.add_argument(
        "--root-provider",
        default="mock",
        choices=["mock", "pkcs11", "aws_kms", "gcp_kms", "vault", "file"],
    )
    hsm.add_argument(
        "--inter-provider",
        default="mock",
        choices=["mock", "pkcs11", "aws_kms", "gcp_kms", "vault", "file", "dev"],
    )
    hsm.add_argument("--witness-count", type=int, default=3)
    hsm.add_argument("--intermediate-days", type=int, default=30)

    # Root key recovery from shards
    rec = commands.add_parser("recover-root")
    rec.add_argument("--identity", type=Path, required=True)
    rec.add_argument("--shards", type=Path, nargs="+", required=True)
    rec.add_argument("--output", type=Path, default=None)

    # Witness set generation
    witness = commands.add_parser("witness-set")
    witness.add_argument("--root-private", type=Path, required=True)
    witness.add_argument("--identity", type=Path, required=True)
    witness.add_argument("--output", type=Path, required=True)
    witness.add_argument("--count", type=int, default=3)

    args = parser.parse_args()
    if args.command == "prepare":
        print(prepare_ceremony(args.log_name, args.output))
    elif args.command == "air-gapped":
        print(
            prepare_air_gapped_ceremony(
                args.log_name,
                args.output,
                threshold=args.threshold,
                total_shares=args.shares,
                witness_count=args.witness_count,
                intermediate_valid_days=args.intermediate_days,
            )
        )
    elif args.command == "hsm-ceremony":
        print(
            prepare_hsm_ceremony(
                args.log_name,
                args.output,
                root_provider_type=args.root_provider,
                intermediate_provider_type=args.inter_provider,
                witness_count=args.witness_count,
                intermediate_valid_days=args.intermediate_days,
            )
        )
    elif args.command == "recover-root":
        recovered = recover_root_from_shards(args.shards, args.identity, args.output)
        pub_b64 = encode_base64url(recovered.public_key().public_bytes_raw())
        print(f"Successfully recovered root key. Public key: {pub_b64}")
    else:
        print(prepare_witness_set(args.root_private, args.identity, args.output, args.count))


if __name__ == "__main__":
    main()

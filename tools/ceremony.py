"""Explicit DEVELOPMENT key ceremony; never use these files as production custody (§7.2)."""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.encoding import encode_base64url, format_timestamp
from libs.blackbox_core.epochs import build_intermediate_certificate
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.schemas import WitnessIdentity, WitnessSet
from libs.blackbox_core.signing import sign_structure


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


def prepare_witness_set(
    root_private_path: Path, identity_path: Path, destination: Path, count: int = 3
) -> Path:
    """Additively create development witness raw-key files and a root-signed set."""
    if type(count) is not int or count < 1:
        raise ValueError("witness count must be positive")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = serialization.load_pem_private_key(root_private_path.read_bytes(), password=None)
    identity = __import__("json").loads(identity_path.read_text(encoding="utf-8"))
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Development-only key ceremony; not production custody"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    legacy = commands.add_parser("prepare")
    legacy.add_argument("--log-name", required=True)
    legacy.add_argument("--output", type=Path, required=True)
    witness = commands.add_parser("witness-set")
    witness.add_argument("--root-private", type=Path, required=True)
    witness.add_argument("--identity", type=Path, required=True)
    witness.add_argument("--output", type=Path, required=True)
    witness.add_argument("--count", type=int, default=3)
    args = parser.parse_args()
    if args.command == "prepare":
        print(prepare_ceremony(args.log_name, args.output))
    else:
        print(prepare_witness_set(args.root_private, args.identity, args.output, args.count))


if __name__ == "__main__":
    main()

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


def generate_dev_keys(count: int = 7) -> list[tuple[Ed25519PrivateKey, bytes]]:
    """Only this file and tests/_dev_keys.py generate Stage 1 signing keys."""
    result = []
    for _ in range(count):
        key = Ed25519PrivateKey.generate()
        result.append((key, key.public_key().public_bytes_raw()))
    return result


def prepare_ceremony(log_name: str, destination: Path) -> Path:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    root, inter = generate_dev_keys(2)
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
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Throwaway development root/intermediate ceremony; not production custody"
    )
    parser.add_argument("--log-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(prepare_ceremony(args.log_name, args.output))


if __name__ == "__main__":
    main()

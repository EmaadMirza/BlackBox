"""Tests for hardware key custody providers, mock HSM boundaries, and memory zeroization (§7.2)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from libs.blackbox_core.encoding import encode_base64url, format_timestamp
from libs.blackbox_core.epochs import build_intermediate_certificate
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.schemas import EpochCertificate
from services.signer.custody import HardwareKeyCustodyMock, LocalFileKeyCustody, zeroize_buffer
from services.signer.epoch_manager import EpochManager, EpochRuntime, HSMIntermediateSigner


def test_zeroize_buffer() -> None:
    buf = bytearray(b"super_secret_key_material_123456")
    assert any(b != 0 for b in buf)
    zeroize_buffer(buf)
    assert all(b == 0 for b in buf)


def test_hardware_custody_mock_lifecycle() -> None:
    raw_seed = os.urandom(32)
    hsm = HardwareKeyCustodyMock(raw_seed, handle_id="slot-0-key-1")

    # 1. Public key extraction
    pub_bytes = hsm.get_public_key()
    assert len(pub_bytes) == 32
    assert (
        pub_bytes == Ed25519PrivateKey.from_private_bytes(raw_seed).public_key().public_bytes_raw()
    )

    # 2. Signing operations inside the mock enclave
    message = b"transaction-payload-to-sign"
    sig = hsm.sign(message)
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, message)

    # 3. Memory zeroization and destruction
    assert not hsm.is_destroyed()
    hsm.zeroize()
    assert hsm.is_destroyed()

    # 4. Enforce fail-closed upon zeroization
    with pytest.raises(RuntimeError, match="HSM key handle invalidated / zeroized"):
        hsm.sign(message)


def test_local_file_key_custody(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw()
    key_file = tmp_path / "test.raw"
    key_file.write_bytes(raw)

    custody = LocalFileKeyCustody(key_file)
    assert custody.get_public_key() == priv.public_key().public_bytes_raw()

    sig = custody.sign(b"test-data")
    assert len(sig) == 64
    priv.public_key().verify(sig, b"test-data")

    custody.destroy_key()
    assert custody.is_destroyed()
    with pytest.raises(RuntimeError, match="zeroized"):
        custody.sign(b"test-data")


def test_hsm_intermediate_signer(tmp_path: Path) -> None:
    root_priv = Ed25519PrivateKey.generate()
    root_pub_bytes = root_priv.public_key().public_bytes_raw()
    log_id = derive_log_id(root_pub_bytes, "test-log")

    # Intermediate key lives strictly inside the mock HSM
    hsm = HardwareKeyCustodyMock()
    inter_pub_b64 = encode_base64url(hsm.get_public_key())

    now = datetime.now(timezone.utc).replace(microsecond=0)
    cert = build_intermediate_certificate(
        log_id,
        "intermediate-0",
        inter_pub_b64,
        format_timestamp(now),
        format_timestamp(now + timedelta(days=30)),
        root_priv,
    )

    signer = HSMIntermediateSigner(cert, hsm, root_pub_bytes)

    # Issue an epoch certificate signed by intermediate via HSM
    epoch_key = Ed25519PrivateKey.generate()
    candidate = EpochCertificate(
        log_id=log_id,
        epoch_id=1,
        epoch_public_key=encode_base64url(epoch_key.public_key().public_bytes_raw()),
        valid_from=format_timestamp(now),
        valid_until=format_timestamp(now + timedelta(minutes=5)),
        intermediate_id="intermediate-0",
    )

    signed_cert = signer.sign_epoch_certificate(candidate)
    assert signed_cert.signature is not None
    assert signer.verify_epoch_certificate(signed_cert)

    # Zeroize intermediate custody
    signer.destroy_key()
    assert hsm.is_destroyed()

    # Further signing attempts fail
    with pytest.raises(RuntimeError):
        signer.sign_epoch_certificate(candidate)


def test_epoch_manager_with_hsm_custody(tmp_path: Path) -> None:
    root_priv = Ed25519PrivateKey.generate()
    root_pub_bytes = root_priv.public_key().public_bytes_raw()
    log_id = derive_log_id(root_pub_bytes, "test-log")

    hsm = HardwareKeyCustodyMock()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    inter_cert = build_intermediate_certificate(
        log_id,
        "intermediate-0",
        encode_base64url(hsm.get_public_key()),
        format_timestamp(now),
        format_timestamp(now + timedelta(days=30)),
        root_priv,
    )
    intermediate_signer = HSMIntermediateSigner(inter_cert, hsm, root_pub_bytes)

    # Initial epoch runtime with HardwareKeyCustodyMock for the epoch key
    epoch_hsm = HardwareKeyCustodyMock()
    initial_cert = EpochCertificate(
        log_id=log_id,
        epoch_id=1,
        epoch_public_key=encode_base64url(epoch_hsm.get_public_key()),
        valid_from=format_timestamp(now),
        valid_until=format_timestamp(now + timedelta(minutes=5)),
        intermediate_id="intermediate-0",
    )
    signed_initial_cert = intermediate_signer.sign_epoch_certificate(initial_cert)
    initial_runtime = EpochRuntime(signed_initial_cert, epoch_hsm)

    manager = EpochManager(
        log_id=log_id,
        intermediate_signer=intermediate_signer,
        runtime=initial_runtime,
        clock=lambda: format_timestamp(now),
    )

    # Verify initial manager state
    assert manager.certificate.epoch_id == 1
    assert not epoch_hsm.is_destroyed()

    # Destroy current key -> triggers zeroization on the custody provider
    manager.destroy_current_key()
    assert epoch_hsm.is_destroyed()

    # Signing with destroyed manager raises RuntimeError
    with pytest.raises(RuntimeError, match="destroyed"):
        manager.signing_operation.sign(b"data")

"""Tests for Stage 7: KMS/HSM Cryptographic Provider Interface & Memory Protection (§7.1, §7.2).

Validates:
- PKCS#11 (Cryptoki) HSM provider
- AWS KMS asymmetric signing (ED25519_RAW)
- Google Cloud KMS asymmetric signing (EC_SIGN_ED25519)
- HashiCorp Vault Transit engine (ed25519)
- Factory provider instantiation
- ZeroizableEpochKey memory buffer zeroization & fail-closed enforcement
- Ephemeral epoch key zeroization upon rollover in EpochManager
- HSM-backed root & intermediate ceremony execution
"""

from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from libs.blackbox_core.encoding import encode_base64url, format_timestamp
from libs.blackbox_core.epochs import build_intermediate_certificate
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.schemas import EpochCertificate
from services.signer.custody import (
    AWSKMSCustodyProvider,
    GoogleCloudKMSCustodyProvider,
    HardwareKeyCustodyMock,
    HashiCorpVaultCustodyProvider,
    LocalFileKeyCustody,
    PKCS11CustodyProvider,
    ZeroizableEpochKey,
    create_custody_provider,
)
from services.signer.epoch_manager import (
    EpochManager,
    EpochRuntime,
    HSMIntermediateSigner,
    load_intermediate_signer,
)
from tools.ceremony import prepare_hsm_ceremony


def test_zeroizable_epoch_key_lifecycle() -> None:
    raw_seed = os.urandom(32)
    key = ZeroizableEpochKey(raw_seed)

    # 1. Public key extraction
    pub_bytes = key.get_public_key()
    assert len(pub_bytes) == 32
    assert pub_bytes == key.public_key().public_bytes_raw()
    assert (
        pub_bytes == Ed25519PrivateKey.from_private_bytes(raw_seed).public_key().public_bytes_raw()
    )

    # 2. Signing data
    message = b"blackbox-epoch-payload"
    sig = key.sign(message)
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, message)

    # 3. Buffer active zeroization
    assert not key.is_destroyed()
    key.zeroize()
    assert key.is_destroyed()
    assert all(b == 0 for b in key._buffer)

    # 4. Enforce fail-closed upon zeroization
    with pytest.raises(RuntimeError, match="destroyed / zeroized"):
        key.sign(message)


def test_zeroizable_epoch_key_context_manager() -> None:
    with ZeroizableEpochKey.generate() as key:
        pub = key.get_public_key()
        sig = key.sign(b"test")
        assert len(sig) == 64
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, b"test")
        assert not key.is_destroyed()

    assert key.is_destroyed()
    with pytest.raises(RuntimeError):
        key.sign(b"test")


def test_pkcs11_custody_provider_with_client_mock() -> None:
    native_priv = Ed25519PrivateKey.generate()
    native_pub_bytes = native_priv.public_key().public_bytes_raw()

    mock_session = MagicMock()
    mock_session.get_public_key.return_value = native_pub_bytes
    mock_session.sign.side_effect = lambda label, data, mechanism: native_priv.sign(data)

    provider = PKCS11CustodyProvider(
        module_path="/opt/hsm/lib/libcryptoki.so",
        token_label="BlackBoxToken",
        key_label="intermediate-key",
        user_pin="123456",
        session_client=mock_session,
    )

    assert provider.provider_type == "pkcs11"
    assert provider.get_public_key() == native_pub_bytes

    data = b"audit-log-entry-digest"
    sig = provider.sign(data)
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(native_pub_bytes).verify(sig, data)

    provider.zeroize()
    assert provider.is_destroyed()
    mock_session.close.assert_called_once()

    with pytest.raises(RuntimeError, match="PKCS#11 session closed"):
        provider.sign(data)


def test_aws_kms_custody_provider_with_client_mock() -> None:
    native_priv = Ed25519PrivateKey.generate()
    native_pub_bytes = native_priv.public_key().public_bytes_raw()
    # Build standard DER SPKI for Ed25519 (44 bytes: 12-byte header + 32-byte key)
    spki_der = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00" + native_pub_bytes

    mock_client = MagicMock()
    mock_client.get_public_key.return_value = {"PublicKey": spki_der}
    mock_client.sign.side_effect = lambda KeyId, Message, MessageType, SigningAlgorithm: {
        "Signature": native_priv.sign(Message)
    }

    provider = AWSKMSCustodyProvider(
        key_id="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        region_name="us-east-1",
        client=mock_client,
    )

    assert provider.provider_type == "aws_kms"
    assert provider.get_public_key() == native_pub_bytes

    payload = b"aws-kms-attestation-bytes"
    sig = provider.sign(payload)
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(native_pub_bytes).verify(sig, payload)

    provider.zeroize()
    assert provider.is_destroyed()
    with pytest.raises(RuntimeError, match="AWS KMS provider session invalidated"):
        provider.sign(payload)


def test_gcp_kms_custody_provider_with_client_mock() -> None:
    native_priv = Ed25519PrivateKey.generate()
    native_pub_bytes = native_priv.public_key().public_bytes_raw()

    mock_client = MagicMock()
    mock_client.get_public_key.return_value = {"data": native_pub_bytes}
    mock_client.asymmetric_sign.side_effect = lambda request: {
        "signature": native_priv.sign(request["data"])
    }

    key_name = "projects/my-project/locations/global/keyRings/blackbox/cryptoKeys/signer/cryptoKeyVersions/1"
    provider = GoogleCloudKMSCustodyProvider(
        key_version_name=key_name,
        client=mock_client,
    )

    assert provider.provider_type == "gcp_kms"
    assert provider.get_public_key() == native_pub_bytes

    payload = b"gcp-kms-checkpoint-bytes"
    sig = provider.sign(payload)
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(native_pub_bytes).verify(sig, payload)

    provider.zeroize()
    assert provider.is_destroyed()
    with pytest.raises(RuntimeError, match="Google Cloud KMS provider session invalidated"):
        provider.sign(payload)


def test_vault_transit_custody_provider_with_http_mock() -> None:
    native_priv = Ed25519PrivateKey.generate()
    native_pub_bytes = native_priv.public_key().public_bytes_raw()

    def mock_http_post(
        endpoint: str, headers: dict[str, str], payload: dict[str, str]
    ) -> dict[str, object]:
        assert headers.get("X-Vault-Token") == "s.my-vault-token"
        raw_input = base64.b64decode(payload["input"])
        sig = native_priv.sign(raw_input)
        return {"data": {"signature": f"vault:v1:{base64.b64encode(sig).decode('ascii')}"}}

    provider = HashiCorpVaultCustodyProvider(
        key_name="blackbox-signer",
        vault_addr="https://vault.internal:8200",
        token="s.my-vault-token",
        http_post_fn=mock_http_post,
        public_key_bytes=native_pub_bytes,
    )

    assert provider.provider_type == "vault"
    assert provider.get_public_key() == native_pub_bytes

    payload = b"vault-transit-entry"
    sig = provider.sign(payload)
    assert len(sig) == 64
    Ed25519PublicKey.from_public_bytes(native_pub_bytes).verify(sig, payload)

    provider.zeroize()
    assert provider.is_destroyed()
    with pytest.raises(RuntimeError, match="HashiCorp Vault session invalidated"):
        provider.sign(payload)


def test_create_custody_provider_factory(tmp_path: Path) -> None:
    mock_prov = create_custody_provider("mock", handle_id="custom-hsm")
    assert isinstance(mock_prov, HardwareKeyCustodyMock)
    assert mock_prov.handle_id == "custom-hsm"

    file_key = tmp_path / "test.raw"
    file_key.write_bytes(os.urandom(32))
    file_prov = create_custody_provider("file", key_path=file_key)
    assert isinstance(file_prov, LocalFileKeyCustody)

    pkcs11_prov = create_custody_provider("pkcs11", key_label="hsm-test")
    assert isinstance(pkcs11_prov, PKCS11CustodyProvider)

    aws_prov = create_custody_provider("aws_kms", key_id="arn:aws:kms:test")
    assert isinstance(aws_prov, AWSKMSCustodyProvider)

    gcp_prov = create_custody_provider("gcp_kms", key_version_name="projects/test")
    assert isinstance(gcp_prov, GoogleCloudKMSCustodyProvider)

    vault_prov = create_custody_provider("vault", key_name="test-key")
    assert isinstance(vault_prov, HashiCorpVaultCustodyProvider)

    epoch_prov = create_custody_provider("epoch")
    assert isinstance(epoch_prov, ZeroizableEpochKey)

    with pytest.raises(ValueError, match="Unknown key custody provider"):
        create_custody_provider("invalid-provider-type")


def test_epoch_rollover_zeroizes_expired_key() -> None:
    """Verify that commit_rollover actively zeroizes the expired epoch private key (§7.2)."""
    root_priv = Ed25519PrivateKey.generate()
    root_pub_bytes = root_priv.public_key().public_bytes_raw()
    log_id = derive_log_id(root_pub_bytes, "test-log")

    inter_hsm = HardwareKeyCustodyMock()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    inter_cert = build_intermediate_certificate(
        log_id,
        "intermediate-0",
        encode_base64url(inter_hsm.get_public_key()),
        format_timestamp(now),
        format_timestamp(now + timedelta(days=30)),
        root_priv,
    )
    inter_signer = HSMIntermediateSigner(inter_cert, inter_hsm, root_pub_bytes)

    # Initial epoch runtime with ZeroizableEpochKey
    initial_epoch_key = ZeroizableEpochKey.generate()
    initial_cert = EpochCertificate(
        log_id=log_id,
        epoch_id=1,
        epoch_public_key=encode_base64url(initial_epoch_key.get_public_key()),
        valid_from=format_timestamp(now),
        valid_until=format_timestamp(now + timedelta(seconds=60)),
        intermediate_id="intermediate-0",
    )
    signed_initial_cert = inter_signer.sign_epoch_certificate(initial_cert)
    initial_runtime = EpochRuntime(signed_initial_cert, initial_epoch_key)

    current_time = now
    manager = EpochManager(
        log_id=log_id,
        intermediate_signer=inter_signer,
        runtime=initial_runtime,
        clock=lambda: format_timestamp(current_time),
        epoch_duration=60,
    )

    # Initial state: key is active and operational
    assert not initial_epoch_key.is_destroyed()
    sig1 = manager.signing_operation.sign(b"data1")
    assert len(sig1) == 64

    # Advance time and prepare rollover
    current_time = now + timedelta(seconds=61)
    plan = manager.prepare_rollover(10, "sha256:" + "a" * 64, format_timestamp(now))
    assert plan.old_runtime.signing_operation is initial_epoch_key
    assert not initial_epoch_key.is_destroyed()

    # Commit rollover
    manager.commit_rollover(plan)

    # CRITICAL §7.2 REQUIREMENT: Expired epoch key must be destroyed and zeroized
    assert initial_epoch_key.is_destroyed()
    assert all(b == 0 for b in initial_epoch_key._buffer)

    # Any subsequent use of expired key fails closed
    with pytest.raises(RuntimeError, match="destroyed / zeroized"):
        initial_epoch_key.sign(b"forbidden")

    # New runtime is active and can sign
    assert manager.runtime.certificate.epoch_id == 2
    sig2 = manager.signing_operation.sign(b"data2")
    assert len(sig2) == 64


def test_begin_new_epoch_zeroizes_predecessor_key() -> None:
    """Verify that begin_new_epoch zeroizes the previous key."""
    root_priv = Ed25519PrivateKey.generate()
    root_pub_bytes = root_priv.public_key().public_bytes_raw()
    log_id = derive_log_id(root_pub_bytes, "test-log")

    inter_hsm = HardwareKeyCustodyMock()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    inter_cert = build_intermediate_certificate(
        log_id,
        "intermediate-0",
        encode_base64url(inter_hsm.get_public_key()),
        format_timestamp(now),
        format_timestamp(now + timedelta(days=30)),
        root_priv,
    )
    inter_signer = HSMIntermediateSigner(inter_cert, inter_hsm, root_pub_bytes)

    initial_key = ZeroizableEpochKey.generate()
    initial_cert = EpochCertificate(
        log_id=log_id,
        epoch_id=1,
        epoch_public_key=encode_base64url(initial_key.get_public_key()),
        valid_from=format_timestamp(now),
        valid_until=format_timestamp(now + timedelta(seconds=60)),
        intermediate_id="intermediate-0",
    )
    initial_runtime = EpochRuntime(inter_signer.sign_epoch_certificate(initial_cert), initial_key)

    manager = EpochManager(
        log_id=log_id,
        intermediate_signer=inter_signer,
        runtime=initial_runtime,
        clock=lambda: format_timestamp(now + timedelta(seconds=65)),
        epoch_duration=60,
    )

    assert not initial_key.is_destroyed()
    new_runtime = manager.begin_new_epoch(reason="test-rekey")

    # Predecessor key zeroized
    assert initial_key.is_destroyed()
    with pytest.raises(RuntimeError):
        initial_key.sign(b"data")

    # New runtime operational
    assert new_runtime.certificate.epoch_id == 2
    assert not new_runtime.signing_operation.is_destroyed()


def test_prepare_hsm_ceremony_end_to_end(tmp_path: Path) -> None:
    """Verify that prepare_hsm_ceremony executes without software root keys on disk (§7.1)."""
    dest = tmp_path / "hsm_ceremony_out"

    root_hsm = HardwareKeyCustodyMock(handle_id="root-hsm-slot-0")
    inter_hsm = HardwareKeyCustodyMock(handle_id="inter-hsm-slot-1")

    res = prepare_hsm_ceremony(
        "blackbox-prod",
        dest,
        root_provider=root_hsm,
        intermediate_provider=inter_hsm,
        intermediate_provider_type="mock",
        witness_count=3,
        intermediate_valid_days=30,
    )

    assert res == dest
    # Verify no root private key exists on disk
    assert not (dest / "root.dev-private.pem").exists()
    assert not (dest / "root.private.raw").exists()

    # Identity and manifests exist
    assert (dest / "identity.json").exists()
    assert (dest / "intermediate.json").exists()
    assert (dest / "intermediate-custody.json").exists()
    assert (dest / "witness-set.json").exists()
    assert (dest / "hsm-manifest.json").exists()

    # Verify intermediate certificate is cryptographically valid against root public key
    import json

    from libs.blackbox_core.schemas import IntermediateCertificate

    inter_data = json.loads((dest / "intermediate.json").read_text(encoding="utf-8"))
    inter_cert = IntermediateCertificate.model_validate(inter_data)
    assert inter_cert.public_key == encode_base64url(inter_hsm.get_public_key())
    assert inter_cert.signature is not None

    # Intermediate certificate signature verification against root public key using domain separation
    root_pub = root_hsm.get_public_key()
    from libs.blackbox_core.signing import verify_structure

    assert verify_structure(inter_cert, root_pub, "intermediate_cert")

    # Verify witness set signature as well
    from libs.blackbox_core.schemas import WitnessSet

    witness_data = json.loads((dest / "witness-set.json").read_text(encoding="utf-8"))
    witness_set = WitnessSet.model_validate(witness_data)
    assert verify_structure(witness_set, root_pub, "witness_set")


def test_load_intermediate_signer_from_hsm_directory(tmp_path: Path) -> None:
    dest = tmp_path / "ceremony_dir"
    root_hsm = HardwareKeyCustodyMock()
    inter_hsm = HardwareKeyCustodyMock()

    prepare_hsm_ceremony(
        "blackbox-test",
        dest,
        root_provider=root_hsm,
        intermediate_provider=inter_hsm,
        intermediate_provider_type="mock",
    )

    root_pub = root_hsm.get_public_key()
    signer = load_intermediate_signer(dest, root_pub)
    assert isinstance(signer, HSMIntermediateSigner)
    assert signer.certificate.intermediate_id == "intermediate-0"

    # Sign an epoch certificate using loaded signer
    from libs.blackbox_core.encoding import parse_timestamp

    start_time = parse_timestamp(signer.certificate.valid_from)
    epoch_key = ZeroizableEpochKey.generate()
    candidate = EpochCertificate(
        log_id=signer.certificate.log_id,
        epoch_id=1,
        epoch_public_key=encode_base64url(epoch_key.get_public_key()),
        valid_from=signer.certificate.valid_from,
        valid_until=format_timestamp(start_time + timedelta(minutes=5)),
        intermediate_id="intermediate-0",
    )
    signed = signer.sign_epoch_certificate(candidate)
    assert signer.verify_epoch_certificate(signed)

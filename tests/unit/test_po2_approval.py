"""PO2 approval receipts and durable verification tests."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core.receipts import build_receipt, verify_receipt
from services.approval.registry import ApproverRegistry
from services.approval.verify import ApprovalVerificationError, ApprovalVerifier
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def test_receipt_signs_and_verifies_offline():
    key = Ed25519PrivateKey.generate()
    receipt = build_receipt(
        "approver",
        3,
        "sha256:" + "b" * 64,
        "2026-01-01T00:10:00.000Z",
        "nonce",
        key,
        log_id="sha256:" + "a" * 64,
    )
    assert verify_receipt(receipt, key.public_key().public_bytes_raw())


def test_approval_rejects_self_expired_altered_reused_and_unregistered(tmp_path: Path):
    approver = Ed25519PrivateKey.generate()
    registry = ApproverRegistry(tmp_path / "registry.json")
    registry.register("approver", approver.public_key().public_bytes_raw())
    verifier = ApprovalVerifier(
        registry, tmp_path / "nonces.json", clock=lambda: "2026-01-01T00:00:00.000Z"
    )
    receipt = build_receipt(
        "approver",
        3,
        "sha256:" + "b" * 64,
        "2026-01-01T00:10:00.000Z",
        "nonce",
        approver,
        log_id="sha256:" + "a" * 64,
    )
    assert verifier.verify(receipt, "requester", "sha256:" + "b" * 64) is None
    with pytest.raises(ApprovalVerificationError, match="self"):
        verifier.verify(receipt, "approver", receipt.arguments_commitment)
    altered = receipt.model_copy(update={"arguments_commitment": "sha256:" + "c" * 64})
    with pytest.raises(ApprovalVerificationError, match="arguments"):
        verifier.verify(altered, "requester", "sha256:" + "b" * 64)
    with pytest.raises(ApprovalVerificationError, match="nonce"):
        verifier.verify(receipt, "requester", receipt.arguments_commitment)


def test_nonce_reuse_survives_restart(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    registry = ApproverRegistry(tmp_path / "registry.json")
    registry.register("a", key.public_key().public_bytes_raw())
    receipt = build_receipt(
        "a",
        1,
        "sha256:" + "b" * 64,
        "2026-01-01T00:10:00.000Z",
        "n",
        key,
        log_id="sha256:" + "a" * 64,
    )
    ApprovalVerifier(
        registry, tmp_path / "nonces.json", clock=lambda: "2026-01-01T00:00:00.000Z"
    ).verify(receipt, "r", receipt.arguments_commitment)
    with pytest.raises(ApprovalVerificationError, match="nonce"):
        ApprovalVerifier(
            registry, tmp_path / "nonces.json", clock=lambda: "2026-01-01T00:00:00.000Z"
        ).verify(receipt, "r", receipt.arguments_commitment)


def test_bundle_can_carry_approval_receipt_and_pinned_key(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    identities = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(identities)
    receipt = build_receipt(
        "approver",
        1,
        "sha256:" + "b" * 64,
        "2026-01-01T00:10:00.000Z",
        "n",
        key,
        log_id=bundle.log_id,
    )
    updated_pins = pins.model_copy(
        update={
            "approver_public_keys": {
                "approver": __import__("base64")
                .urlsafe_b64encode(key.public_key().public_bytes_raw())
                .decode()
                .rstrip("=")
            }
        }
    )
    updated_bundle = bundle.model_copy(update={"approvals": [receipt]})
    assert updated_bundle.approvals[0] == receipt
    assert updated_pins.approver_public_keys["approver"]
    assert verify_evidence(updated_bundle, updated_pins).verdict == "VERIFIED"

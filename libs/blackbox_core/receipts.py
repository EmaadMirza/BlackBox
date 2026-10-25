"""Approval receipt construction and offline signature verification."""

from __future__ import annotations

from collections.abc import Callable

from libs.blackbox_core.schemas import ApprovalReceipt
from libs.blackbox_core.signing import sign_structure, verify_structure

# TODO(spec §13.5): implement and validate before enabling this module.


def build_receipt(
    approver_id: str,
    intent_seq: int,
    arguments_commitment: str,
    expires_at: str,
    nonce: str,
    signing_operation: Callable[[bytes], bytes],
    *,
    log_id: str,
) -> ApprovalReceipt:
    receipt = ApprovalReceipt(
        log_id=log_id,
        approver_id=approver_id,
        intent_seq=intent_seq,
        arguments_commitment=arguments_commitment,
        expires_at=expires_at,
        nonce=nonce,
    )
    return sign_structure(receipt, signing_operation, "approval_receipt")


def verify_receipt(receipt: ApprovalReceipt, public_key: bytes) -> bool:
    return verify_structure(receipt, public_key, "approval_receipt")

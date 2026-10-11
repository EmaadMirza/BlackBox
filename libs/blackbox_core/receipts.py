"""Approval receipt construction and signature checks Scaffold only; no runtime behavior."""

from __future__ import annotations

from collections.abc import Callable

from libs.blackbox_core.schemas import ApprovalReceipt

# TODO(spec §13.5): implement and validate before enabling this module.


def build_receipt(
    approver_id: str,
    intent_seq: int,
    arguments_commitment: str,
    expires_at: str,
    nonce: str,
    signing_operation: Callable[[bytes], bytes],
) -> ApprovalReceipt:
    raise NotImplementedError("not built")


def verify_receipt(receipt: ApprovalReceipt, public_key: bytes) -> bool:
    raise NotImplementedError("not built")

"""Approval receipt verification and durable nonce consumption."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from libs.blackbox_core import schemas
from libs.blackbox_core.receipts import verify_receipt
from services.approval.registry import ApproverRegistry

# TODO(spec §13.5): implement and validate before enabling this module.


class ApprovalVerificationError(ValueError):
    pass


class ApprovalVerifier:
    def __init__(
        self, registry: ApproverRegistry, nonce_path: Path, *, clock: Callable[[], str]
    ) -> None:
        self.registry, self.nonce_path, self.clock = registry, nonce_path, clock

    def verify(
        self, receipt: schemas.ApprovalReceipt, requester_id: str, arguments_commitment: str
    ) -> None:
        if receipt.approver_id == requester_id:
            raise ApprovalVerificationError("self approval")
        if receipt.expires_at <= self.clock():
            raise ApprovalVerificationError("receipt expired")
        if receipt.arguments_commitment != arguments_commitment:
            raise ApprovalVerificationError("arguments commitment mismatch")
        try:
            public_key = self.registry.get(receipt.approver_id)
        except KeyError as exc:
            raise ApprovalVerificationError("approver is not registered") from exc
        if not verify_receipt(receipt, public_key):
            raise ApprovalVerificationError("receipt signature invalid")
        used = set(json.loads(self.nonce_path.read_text()) if self.nonce_path.exists() else [])
        if receipt.nonce in used:
            raise ApprovalVerificationError("nonce already used")
        used.add(receipt.nonce)
        self.nonce_path.write_text(json.dumps(sorted(used)))
        self.nonce_path.chmod(0o600)


async def verify(
    receipt: schemas.ApprovalReceipt, requester_id: str, intent: schemas.Intent, now: str
) -> None:
    raise NotImplementedError("use ApprovalVerifier with a durable registry and nonce store")

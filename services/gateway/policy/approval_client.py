"""Approval request and receipt client Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.5): implement and validate before enabling this module.


async def request(intent: schemas.Intent) -> schemas.ApprovalReceipt:
    raise NotImplementedError("not built")

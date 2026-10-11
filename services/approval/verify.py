"""Not-self, expiry, nonce and argument binding Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.5): implement and validate before enabling this module.


async def verify(
    receipt: schemas.ApprovalReceipt, requester_id: str, intent: schemas.Intent, now: str
) -> None:
    raise NotImplementedError("not built")

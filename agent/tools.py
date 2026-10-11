"""Agent tools call gateway only and hold no provider credentials Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.4): implement and validate before enabling this module.


async def refund(amount_minor: int, account_id: str, logical_call_id: str) -> bytes:
    raise NotImplementedError("not built")


async def read_invoice(invoice_id: str) -> bytes:
    raise NotImplementedError("not built")


def refund_request(
    amount_minor: int, account_id: str, logical_call_id: str
) -> schemas.RequestAction:
    raise NotImplementedError("not built")

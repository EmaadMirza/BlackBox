"""Approval request and receipt client (spec §13.5)."""

from __future__ import annotations

import os

import httpx

from libs.blackbox_core import schemas


async def request(
    intent: schemas.Intent,
    *,
    approval_url: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> schemas.ApprovalReceipt:
    """Request approval for a pending intent from Approval service."""
    url = (approval_url or os.environ.get("APPROVAL_URL", "http://approval:8000")).rstrip("/")
    payload = {
        "intent_seq": intent.seq,
        "arguments_commitment": intent.action.arguments_commitment,
    }
    if client is not None:
        res = await client.post(f"{url}/v1/approvals", json=payload)
        res.raise_for_status()
        return schemas.ApprovalReceipt.model_validate(res.json())

    async with httpx.AsyncClient(timeout=5.0) as http_client:
        res = await http_client.post(f"{url}/v1/approvals", json=payload)
        res.raise_for_status()
        return schemas.ApprovalReceipt.model_validate(res.json())

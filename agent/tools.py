"""Agent tools calling BlackBox Gateway with no provider credentials (spec §13.4)."""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import httpx

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "read_invoice",
        "description": "Read invoice status and metadata from downstream billing system.",
        "input_schema": {
            "type": "object",
            "properties": {
                "invoice_id": {"type": "string", "description": "Unique invoice identifier"},
            },
            "required": ["invoice_id"],
        },
    },
    {
        "name": "refund",
        "description": "Issue customer payment refund through billing provider.",
        "input_schema": {
            "type": "object",
            "properties": {
                "amount_minor": {
                    "type": "integer",
                    "description": "Refund amount in minor currency units (cents)",
                },
                "account_id": {"type": "string", "description": "Target account ID"},
            },
            "required": ["amount_minor", "account_id"],
        },
    },
]


def get_tool_definitions() -> list[dict[str, Any]]:
    """Return standard tool definitions for this agent runtime."""
    return list(TOOL_DEFINITIONS)


def compute_tool_definitions_hash(tools: list[dict[str, Any]] | None = None) -> str:
    """Compute RFC-8785 canonical SHA-256 hash of tool definitions."""
    tool_list = tools if tools is not None else TOOL_DEFINITIONS
    canon = canonicalize(tool_list)
    return encode_hash(sha256(canon))


def _ensure_hash(val: str | bytes) -> str:
    """Ensure a string or bytes is a canonical Hash (sha256:hex)."""
    if isinstance(val, str) and val.startswith("sha256:") and len(val) == 71:
        return val
    raw = val.encode("utf-8") if isinstance(val, str) else val
    return encode_hash(sha256(raw))


def refund_request(
    amount_minor: int, account_id: str, logical_call_id: str
) -> schemas.RequestAction:
    """Construct a canonical RequestAction for a refund."""
    body_dict = {"amount_minor": amount_minor, "account_id": account_id}
    body_bytes = canonicalize(body_dict)
    body_digest = encode_hash(sha256(body_bytes))
    return schemas.RequestAction(
        adapter="http",
        method="POST",
        path="/refund",
        tool_name="refund",
        body_digest=body_digest,
        arguments_commitment=body_digest,
        idempotency_key=_ensure_hash(logical_call_id),
        payload_reference=f"payload:{logical_call_id}",
        amount_minor=amount_minor,
    )


async def _dispatch_to_gateway(
    tool_name: str,
    payload_body: dict[str, Any],
    idempotency_key: str,
    *,
    gateway_url: str | None = None,
    client: Any = None,
    agent_id: str = "agent-1",
    delegation_token: str = "token-1",
    context: schemas.Context | None = None,
    session_id: str | None = None,
    approval_receipt: schemas.ApprovalReceipt | None = None,
) -> bytes:
    """Internal helper to dispatch action through Gateway HTTP service or in-process pipeline."""
    idem_hash = _ensure_hash(idempotency_key)
    aid = os.environ.get("AGENT_ID", agent_id)
    tok = os.environ.get("DELEGATION_TOKEN", delegation_token)

    # 1. In-process pipeline dispatch
    if client is not None and hasattr(client, "execute"):
        body_bytes = canonicalize(payload_body)
        res = client.execute(
            agent_id=aid,
            delegation_token=tok,
            tool_name=tool_name,
            body=body_bytes,
            idempotency_key=idem_hash,
            context=context,
            approval_receipt=approval_receipt,
            session_id=session_id,
        )
        return json.dumps(res, default=str).encode("utf-8")

    # 2. HTTP Gateway dispatch
    url = (gateway_url or os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000")).rstrip("/")
    headers = {
        "Authorization": f"Bearer {tok}",
        "Content-Type": "application/json",
    }
    action_data: dict[str, Any] = {
        "agent_id": aid,
        "tool_name": tool_name,
        "body": payload_body,
        "idempotency_key": idem_hash,
        "delegation_token": tok,
        "session_id": session_id,
    }
    if context is not None:
        action_data["context"] = context.model_dump()
    if approval_receipt is not None:
        action_data["approval_receipt"] = approval_receipt.model_dump()

    if client is not None and isinstance(client, httpx.AsyncClient):
        res = await client.post(f"{url}/v1/actions", json=action_data, headers=headers)
        return res.content

    async with httpx.AsyncClient(timeout=10.0) as http_client:
        res = await http_client.post(f"{url}/v1/actions", json=action_data, headers=headers)
        return res.content


async def refund(
    amount_minor: int,
    account_id: str,
    logical_call_id: str,
    *,
    gateway_url: str | None = None,
    client: Any = None,
    agent_id: str = "agent-1",
    delegation_token: str = "token-1",
    context: schemas.Context | None = None,
    session_id: str | None = None,
    approval_receipt: schemas.ApprovalReceipt | None = None,
) -> bytes:
    """Execute refund tool through Gateway."""
    payload_body = {"amount_minor": amount_minor, "account_id": account_id}
    return await _dispatch_to_gateway(
        "refund",
        payload_body,
        logical_call_id,
        gateway_url=gateway_url,
        client=client,
        agent_id=agent_id,
        delegation_token=delegation_token,
        context=context,
        session_id=session_id,
        approval_receipt=approval_receipt,
    )


async def read_invoice(
    invoice_id: str,
    *,
    logical_call_id: str | None = None,
    gateway_url: str | None = None,
    client: Any = None,
    agent_id: str = "agent-1",
    delegation_token: str = "token-1",
    context: schemas.Context | None = None,
    session_id: str | None = None,
) -> bytes:
    """Execute read_invoice tool through Gateway."""
    call_id = logical_call_id or f"idem-{uuid.uuid4().hex[:16]}"
    payload_body = {"invoice_id": invoice_id}
    return await _dispatch_to_gateway(
        "read_invoice",
        payload_body,
        call_id,
        gateway_url=gateway_url,
        client=client,
        agent_id=agent_id,
        delegation_token=delegation_token,
        context=context,
        session_id=session_id,
    )

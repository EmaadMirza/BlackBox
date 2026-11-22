"""Reference Tool-calling Agent Loop with Session & Lineage Tracking (spec §13.4)."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from agent.tools import (
    compute_tool_definitions_hash,
    get_tool_definitions,
    read_invoice,
    refund,
)
from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash
from services.gateway.context import build_context


async def run(
    model_identifier: str,
    invoice_path: Path,
    *,
    gateway_url: str | None = None,
    session_id: str | None = None,
    pipeline: Any = None,
    client: Any = None,
    agent_id: str = "agent-1",
    delegation_token: str = "token-1",
    tools: list[dict[str, Any]] | None = None,
    system_prompt: str = "You are a customer service invoice processing agent.",
) -> dict[str, Any]:
    """Execute reference agent loop over an invoice document."""
    invoice_path = Path(invoice_path)
    if not invoice_path.exists():
        raise FileNotFoundError(f"Invoice not found: {invoice_path}")

    # 1. Establish session identity
    sid = session_id or f"sess-{uuid.uuid4().hex[:12]}"
    aid = os.environ.get("AGENT_ID", agent_id)
    tok = os.environ.get("DELEGATION_TOKEN", delegation_token)

    # 2. Compute canonical tool definition hash for session
    active_tools = tools if tools is not None else get_tool_definitions()
    tools_canon_bytes = canonicalize(active_tools)
    tool_defs_hash = compute_tool_definitions_hash(active_tools)

    # 3. Register session tool definitions on initial session setup
    if pipeline is not None and getattr(pipeline, "tooldefs_registry", None) is not None:
        reg = pipeline.tooldefs_registry
        if sid not in getattr(reg, "_sessions", {}):
            reg.register(sid, tools_canon_bytes)

    # 4. Ingest and hash untrusted input document
    invoice_bytes = invoice_path.read_bytes()
    invoice_text = invoice_bytes.decode("utf-8", errors="replace")
    invoice_hash = encode_hash(sha256(invoice_bytes))

    untrusted_input = schemas.UntrustedInput(
        source=str(invoice_path.name),
        content_hash=invoice_hash,
        trust_label="untrusted",
    )

    # 5. Construct full context with lineage
    context = build_context(
        system_prompt=system_prompt,
        tool_definitions=tools_canon_bytes,
        model_identifier=model_identifier,
        model_version="1.0",
        inputs=[untrusted_input],
    )

    # 6. Parse task and invoke tools via Gateway
    action_taken: str = "none"
    res_bytes: bytes = b""

    # Check for adversarial injection vs honest read task
    lower_text = invoice_text.lower()
    if "refund" in lower_text:
        action_taken = "refund"
        # Parse amount (e.g. "900000" or extract digits) and account
        amount_match = re.search(r"refund\s+(\d+)", lower_text)
        amount_minor = int(amount_match.group(1)) if amount_match else 900000

        account_match = re.search(r"to\s+([\w\-]+)", lower_text)
        account_id = account_match.group(1) if account_match else "attacker-test-account"

        call_id = f"refund-{uuid.uuid4().hex[:12]}"
        res_bytes = await refund(
            amount_minor=amount_minor,
            account_id=account_id,
            logical_call_id=call_id,
            gateway_url=gateway_url,
            client=pipeline or client,
            agent_id=aid,
            delegation_token=tok,
            context=context,
            session_id=sid,
        )
    else:
        action_taken = "read_invoice"
        # Extract invoice ID (e.g., INV-001)
        inv_match = re.search(r"(INV-[\w\-]+)", invoice_text)
        invoice_id = inv_match.group(1) if inv_match else "INV-001"

        res_bytes = await read_invoice(
            invoice_id=invoice_id,
            gateway_url=gateway_url,
            client=pipeline or client,
            agent_id=aid,
            delegation_token=tok,
            context=context,
            session_id=sid,
        )

    # 7. Parse response
    parsed: dict[str, Any] = {}
    if res_bytes:
        try:
            parsed = json.loads(res_bytes.decode("utf-8"))
        except Exception:
            parsed = {"raw": res_bytes.decode("utf-8", errors="replace")}

    status = "ok"
    if (
        parsed.get("status") in ("denied", "blocked")
        or "error" in parsed
        or parsed.get("decision") in ("denied", "block")
    ):
        status = parsed.get("status", "denied")

    return {
        "status": status,
        "session_id": sid,
        "model_identifier": model_identifier,
        "invoice_path": str(invoice_path),
        "invoice_hash": invoice_hash,
        "tool_definitions_hash": tool_defs_hash,
        "action_taken": action_taken,
        "raw_response": res_bytes,
        "response": parsed,
    }

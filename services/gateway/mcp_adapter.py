"""Stage 5 Model Context Protocol (MCP) Adapter (spec §13.4, §22).

Implements an MCP-compliant JSON-RPC 2.0 proxy server allowing AI agent frameworks
(Claude Code, Cursor, LangChain, AutoGen) to interact with tools while BlackBox
transparently seals intents, checks tool definition hashes, and seals outcomes.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from agent.tools import (
    compute_tool_definitions_hash,
    get_tool_definitions,
)
from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash
from services.gateway.context import build_context
from services.gateway.pipeline import GatewayPipeline

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {
    "name": "blackbox-gateway-mcp",
    "version": "1.0.0",
}


def _ensure_hash(val: str | bytes) -> str:
    """Ensure a string or bytes is a canonical Hash (sha256:hex)."""
    if isinstance(val, str) and val.startswith("sha256:") and len(val) == 71:
        return val
    raw = val.encode("utf-8") if isinstance(val, str) else val
    return encode_hash(sha256(raw))


class MCPAdapter:
    """Standard Model Context Protocol (MCP) Server Adapter."""

    def __init__(
        self,
        *,
        pipeline: GatewayPipeline | None = None,
        tools: list[dict[str, Any]] | None = None,
        default_agent_id: str = "agent-mcp",
        default_token: str = "token-mcp",
    ) -> None:
        self.pipeline = pipeline
        self.tools = tools if tools is not None else get_tool_definitions()
        self.default_agent_id = default_agent_id
        self.default_token = default_token
        self._tool_defs_hash = compute_tool_definitions_hash(self.tools)

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return MCP-formatted tool schemas."""
        mcp_tools = []
        for t in self.tools:
            mcp_tools.append(
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "inputSchema": t.get("input_schema", {"type": "object", "properties": {}}),
                }
            )
        return mcp_tools

    async def handle_jsonrpc(
        self,
        request_data: dict[str, Any] | str,
        *,
        agent_id: str | None = None,
        delegation_token: str | None = None,
    ) -> dict[str, Any]:
        """Handle incoming MCP JSON-RPC 2.0 request."""
        if isinstance(request_data, str):
            try:
                msg = json.loads(request_data)
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
        else:
            msg = request_data

        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        if not method:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: missing method"},
            }

        # 1. MCP Lifecycle: initialize
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO,
                },
            }

        # 2. MCP Lifecycle: notifications/initialized
        if method == "notifications/initialized":
            # Notification does not return a result
            return {}

        # 3. MCP Ping
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        # 4. MCP Discovery: tools/list
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.get_tool_definitions()},
            }

        # 5. MCP Execution: tools/call
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            meta = params.get("_meta", {})

            if not tool_name:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: 'name' is required"},
                }

            result_data = await self.execute_tool(
                name=tool_name,
                arguments=arguments,
                meta=meta,
                agent_id=agent_id or meta.get("agent_id", self.default_agent_id),
                delegation_token=delegation_token
                or meta.get("delegation_token", self.default_token),
            )

            is_error = result_data.get("status") in ("blocked", "error", "denied")
            text_output = result_data.get("output", "")
            if not text_output:
                if is_error:
                    reason = result_data.get("evidence", {}).get("reason") or result_data.get(
                        "error", "blocked"
                    )
                    text_output = f"Tool execution blocked: {reason}"
                else:
                    text_output = json.dumps(result_data, default=str)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": text_output}],
                    "isError": is_error,
                    "_blackbox": {
                        "intent_seq": result_data.get("intent_seq"),
                        "outcome_seq": result_data.get("outcome_seq"),
                        "status": result_data.get("status"),
                    },
                },
            }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    async def execute_tool(
        name: str,
        arguments: dict[str, Any] | bytes | str,
        *,
        meta: dict[str, Any] | None = None,
        agent_id: str | None = None,
        delegation_token: str | None = None,
        context: schemas.Context | None = None,
    ) -> dict[str, Any]:
        """Execute a tool through BlackBox Gateway pipeline."""
        pass  # Replaced below with self implementation


class MCPAdapter(MCPAdapter):  # type: ignore[no-redef]
    async def execute_tool(  # type: ignore[misc]
        self,
        name: str,
        arguments: dict[str, Any] | bytes | str,
        *,
        meta: dict[str, Any] | None = None,
        agent_id: str | None = None,
        delegation_token: str | None = None,
        context: schemas.Context | None = None,
    ) -> dict[str, Any]:
        meta_dict = meta or {}
        aid = agent_id or meta_dict.get("agent_id", self.default_agent_id)
        tok = delegation_token or meta_dict.get("delegation_token", self.default_token)
        sid = meta_dict.get("session_id", f"mcp-sess-{uuid.uuid4().hex[:12]}")

        # Parse body bytes
        if isinstance(arguments, bytes):
            body_bytes = arguments
            try:
                parsed_args = json.loads(arguments)
            except Exception:
                parsed_args = {}
        elif isinstance(arguments, str):
            body_bytes = arguments.encode("utf-8")
            try:
                parsed_args = json.loads(arguments)
            except Exception:
                parsed_args = {}
        elif isinstance(arguments, dict):
            parsed_args = arguments
            body_bytes = canonicalize(arguments)
        else:
            parsed_args = {}
            body_bytes = b"{}"

        # Build context if not supplied
        active_context = context
        if active_context is None:
            active_context = build_context(
                system_prompt="MCP Tool Runner",
                tool_definitions=canonicalize(self.tools),
                model_identifier=meta_dict.get("model_identifier", "mcp-agent"),
                model_version="1.0",
                inputs=[],
            )

        call_id = meta_dict.get("call_id", f"mcp-{uuid.uuid4().hex[:16]}")
        idem_key = _ensure_hash(call_id)

        # In-process pipeline execution
        if self.pipeline is not None:
            # Register tools in tooldefs registry if active on initial setup
            if getattr(self.pipeline, "tooldefs_registry", None) is not None:
                reg = self.pipeline.tooldefs_registry
                if sid not in getattr(reg, "_sessions", {}):
                    reg.register(sid, canonicalize(self.tools))

            res = self.pipeline.execute(
                agent_id=aid,
                delegation_token=tok,
                tool_name=name,
                body=body_bytes,
                idempotency_key=idem_key,
                context=active_context,
                session_id=sid,
            )
            out: dict[str, Any] = dict(res)

            # Resolve result from payload_store
            res_ref = out.get("evidence", {}).get("result_reference")
            if res_ref and hasattr(self.pipeline, "payload_store"):
                try:
                    res_bytes, _, _ = self.pipeline.payload_store.read(res_ref)
                    out["output"] = res_bytes.decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif "result" in out and isinstance(out["result"], bytes):
                out["output"] = out["result"].decode("utf-8", errors="replace")
            return out

        # Fallback to Gateway HTTP API
        import httpx

        url = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
        headers = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
        req_payload = {
            "agent_id": aid,
            "tool_name": name,
            "body": parsed_args,
            "idempotency_key": idem_key,
            "delegation_token": tok,
            "session_id": sid,
            "context": active_context.model_dump(),
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{url}/v1/actions", json=req_payload, headers=headers)
            try:
                res_json = resp.json()
            except Exception:
                res_json = {"raw": resp.text}
            res_json["status_code"] = resp.status_code
            if resp.status_code >= 400:
                res_json["status"] = "blocked"
            return res_json


# Global default adapter instance
_default_adapter = MCPAdapter()


async def call_tool(
    name: str,
    arguments: bytes | dict[str, Any] | str,
    *,
    adapter: MCPAdapter | None = None,
    pipeline: GatewayPipeline | None = None,
    session_id: str | None = None,
) -> bytes:
    """Stage 5 MCP tool invocation helper."""
    active_adapter = adapter or (
        _default_adapter if pipeline is None else MCPAdapter(pipeline=pipeline)
    )
    meta = {"session_id": session_id} if session_id else {}
    result = await active_adapter.execute_tool(name, arguments, meta=meta)
    return json.dumps(result, default=str).encode("utf-8")

"""Credential removal and scoped credential injection (spec §13.4)."""

from __future__ import annotations

import os

DISALLOWED_AGENT_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
    "set-cookie",
}


async def broker_headers(
    agent_headers: dict[str, str],
    tool_name: str,
    *,
    brokered_tokens: dict[str, str] | None = None,
) -> dict[str, str]:
    """Strip agent credentials and inject narrowly scoped brokered credentials."""
    sanitized = {
        k: v for k, v in agent_headers.items() if k.lower() not in DISALLOWED_AGENT_HEADERS
    }
    tokens = brokered_tokens or {}
    token = tokens.get(tool_name) or os.environ.get(
        f"BROKER_TOKEN_{tool_name.upper()}", "brokered-service-token"
    )
    sanitized["Authorization"] = f"Bearer {token}"
    return sanitized

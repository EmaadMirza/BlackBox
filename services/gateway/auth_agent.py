"""Agent identity and delegation authentication (spec §13.4)."""

from __future__ import annotations

from libs.blackbox_core import schemas


async def authenticate(
    agent_id: str,
    delegation_token: str,
    agent_tokens: dict[str, str] | None = None,
) -> schemas.Principal:
    """Authenticate an agent call and produce a verified Principal."""
    if agent_tokens is not None:
        expected = agent_tokens.get(agent_id)
        if expected is None or expected != delegation_token:
            raise PermissionError("agent authentication failed")

    return schemas.Principal(
        client_key_id=agent_id,
        source_address="gateway",
        human_identity=agent_id,
        agent_identity=agent_id,
        agent_version="1",
        delegation_chain=[delegation_token],
    )

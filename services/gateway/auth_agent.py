"""Agent identity and delegation authentication Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.4): implement and validate before enabling this module.


async def authenticate(agent_id: str, delegation_token: str) -> schemas.Principal:
    raise NotImplementedError("not built")

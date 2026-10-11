"""Session tool-definition change detection Scaffold only; no runtime behavior."""

from __future__ import annotations

# TODO(spec §13.4): implement and validate before enabling this module.


async def record_tool_definitions(session_id: str, definitions: bytes) -> str:
    raise NotImplementedError("not built")


def changed(previous_hash: str, current_hash: str) -> bool:
    raise NotImplementedError("not built")

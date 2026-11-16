"""Session tool-definition tracking and change detection."""

from __future__ import annotations

from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash


class ToolDefsRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, str] = {}
        self._alarms: list[dict[str, str]] = []

    def register(self, session_id: str, definitions_bytes: bytes) -> str:
        current_hash = encode_hash(sha256(definitions_bytes))
        prev = self._sessions.get(session_id)
        if prev is not None and prev != current_hash:
            self._alarms.append(
                {
                    "alarm_type": "TOOL_DEF_CHANGE",
                    "session_id": session_id,
                    "previous_hash": prev,
                    "new_hash": current_hash,
                }
            )
        self._sessions[session_id] = current_hash
        return current_hash

    def is_changed(self, session_id: str, current_hash: str) -> bool:
        prev = self._sessions.get(session_id)
        if prev is not None and prev != current_hash:
            return True
        return False

    def get_alarms(self) -> list[dict[str, str]]:
        return list(self._alarms)


def changed(previous_hash: str, current_hash: str) -> bool:
    return previous_hash != current_hash


async def record_tool_definitions(session_id: str, definitions: bytes) -> str:
    return encode_hash(sha256(definitions))

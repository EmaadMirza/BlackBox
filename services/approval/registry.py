"""Durable registry of approver public keys."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any


class ApproverRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def register(self, approver_id: str, public_key: bytes, valid_until: str | None = None) -> None:
        values = self._read()
        encoded = base64.urlsafe_b64encode(public_key).decode().rstrip("=")
        if valid_until is not None:
            values[approver_id] = {"public_key": encoded, "valid_until": valid_until}
        else:
            values[approver_id] = encoded
        self.path.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")))
        self.path.chmod(0o600)

    def get_entry(self, approver_id: str) -> tuple[bytes, str | None]:
        values = self._read()
        entry = values.get(approver_id)
        if entry is None:
            raise KeyError("approver is not registered")
        if isinstance(entry, dict):
            encoded = entry["public_key"]
            valid_until = entry.get("valid_until")
        else:
            encoded = entry
            valid_until = None
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        return raw, valid_until

    def get(self, approver_id: str) -> bytes:
        raw, _ = self.get_entry(approver_id)
        return raw


_default = ApproverRegistry(Path("approval-registry.json"))


def get_public_key(approver_id: str) -> bytes:
    return _default.get(approver_id)


def register(approver_id: str, public_key: bytes, valid_until: str | None = None) -> None:
    _default.register(approver_id, public_key, valid_until)

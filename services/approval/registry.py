"""Durable registry of approver public keys."""

from __future__ import annotations

import base64
import json
from pathlib import Path

# TODO(spec §13.5): implement and validate before enabling this module.


class ApproverRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _read(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def register(self, approver_id: str, public_key: bytes) -> None:
        values = self._read()
        values[approver_id] = base64.urlsafe_b64encode(public_key).decode().rstrip("=")
        self.path.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")))
        self.path.chmod(0o600)

    def get(self, approver_id: str) -> bytes:
        values = self._read()
        encoded = values.get(approver_id)
        if encoded is None:
            raise KeyError("approver is not registered")
        return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


_default = ApproverRegistry(Path("approval-registry.json"))


def get_public_key(approver_id: str) -> bytes:
    return _default.get(approver_id)


def register(approver_id: str, public_key: bytes) -> None:
    _default.register(approver_id, public_key)

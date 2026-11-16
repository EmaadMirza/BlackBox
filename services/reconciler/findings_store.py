"""Findings persistence and query store."""

from __future__ import annotations

import json
from pathlib import Path

from libs.blackbox_core import schemas


class FindingsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        if self.path is not None:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._in_memory: list[schemas.Finding] = []

    def append(self, finding: schemas.Finding) -> None:
        self._in_memory.append(finding)
        if self.path is not None:
            existing = self.list_findings()
            existing.append(finding)
            self.path.write_text(
                json.dumps(
                    [f.model_dump() for f in existing], sort_keys=True, separators=(",", ":")
                )
            )
            self.path.chmod(0o600)

    def list_findings(self) -> list[schemas.Finding]:
        if self.path is not None and self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                return [schemas.Finding.model_validate(item) for item in raw]
            except Exception:
                return list(self._in_memory)
        return list(self._in_memory)


_default = FindingsStore(Path("findings-store.json"))


async def append(finding: schemas.Finding) -> None:
    _default.append(finding)


async def list_findings() -> list[schemas.Finding]:
    return _default.list_findings()

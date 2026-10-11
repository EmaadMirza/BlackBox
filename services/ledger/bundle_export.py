"""Evidence bundle export Scaffold only; no runtime behavior."""

from __future__ import annotations

from pathlib import Path

# TODO(spec §16.2): implement and validate before enabling this module.


async def export_bundle(start_seq: int, end_seq: int, destination: Path) -> Path:
    raise NotImplementedError("not built")

"""Plain-log attack control (spec §23)."""

from __future__ import annotations

from pathlib import Path


def append(path: Path, record: bytes) -> None:
    """Append unauthenticated line to plain file log (evaluation control)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "ab") as f:
        f.write(record + b"\n")

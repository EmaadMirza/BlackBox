"""Finding persistence Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §15.4): implement and validate before enabling this module.


async def append(finding: schemas.Finding) -> None:
    raise NotImplementedError("not built")


async def list_findings() -> list[schemas.Finding]:
    raise NotImplementedError("not built")

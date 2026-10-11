"""Nine-step request pipeline Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.2): implement and validate before enabling this module.


async def execute(
    action: schemas.RequestAction, principal: schemas.Principal, context: schemas.Context | None
) -> bytes:
    raise NotImplementedError("not built")

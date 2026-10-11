"""Ledger proof endpoints Scaffold only; no runtime behavior."""

from __future__ import annotations

# TODO(spec §10.4): implement and validate before enabling this module.


async def inclusion(seq: int, tree_size: int) -> list[str]:
    raise NotImplementedError("not built")


async def consistency(old_size: int, new_size: int) -> list[str]:
    raise NotImplementedError("not built")

"""Witness peer exchange and split-view detection Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §11.5): implement and validate before enabling this module.


async def exchange(peer_urls: list[str]) -> list[schemas.Checkpoint]:
    raise NotImplementedError("not built")


def detect_split_view(checkpoints: list[schemas.Checkpoint]) -> bool:
    raise NotImplementedError("not built")

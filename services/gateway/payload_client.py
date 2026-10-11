"""Payload and salt storage client Scaffold only; no runtime behavior."""

from __future__ import annotations

# TODO(spec §8.4): implement and validate before enabling this module.


async def store(value: bytes, salt: bytes) -> str:
    raise NotImplementedError("not built")


async def retrieve(reference: str) -> tuple[bytes, bytes]:
    raise NotImplementedError("not built")

"""Web HMAC and nonce authentication Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.3): implement and validate before enabling this module.


async def authenticate(
    method: str, path: str, body: bytes, headers: dict[str, str]
) -> schemas.Principal:
    raise NotImplementedError("not built")

"""Registered approver public keys Scaffold only; no runtime behavior."""

from __future__ import annotations

# TODO(spec §13.5): implement and validate before enabling this module.


def get_public_key(approver_id: str) -> bytes:
    raise NotImplementedError("not built")


def register(approver_id: str, public_key: bytes) -> None:
    raise NotImplementedError("not built")

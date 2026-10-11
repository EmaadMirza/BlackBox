"""Provider must recompute digest of exact received body Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §14.2): implement and validate before enabling this module.


def verify_received_body(
    body: bytes, attestation: schemas.Attestation, public_key: bytes, now: str
) -> None:
    raise NotImplementedError("not built")

"""Attestation binding and verification interfaces Scaffold only; no runtime behavior."""

from __future__ import annotations

from collections.abc import Callable

from libs.blackbox_core.schemas import Attestation, Intent

# TODO(spec §14.1): implement and validate before enabling this module.


def build_attestation(
    intent: Intent, issued_at: str, expires_at: str, signing_operation: Callable[[bytes], bytes]
) -> Attestation:
    raise NotImplementedError("not built")


def verify_attestation(attestation: Attestation, public_key: bytes, now: str) -> bool:
    raise NotImplementedError("not built")

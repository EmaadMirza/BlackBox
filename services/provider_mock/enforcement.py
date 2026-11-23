"""Attestation enforcement switch."""

from __future__ import annotations


def require_attestation(enabled: bool, valid_attestation: bool) -> None:
    if enabled and not valid_attestation:
        raise PermissionError("unattested action rejected under enforcement mode")

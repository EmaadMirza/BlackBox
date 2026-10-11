"""Signer-owned key lifecycle; no keys generated in scaffold Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §7.3): implement and validate before enabling this module.


def generate_epoch(epoch_id: int) -> schemas.EpochCertificate:
    raise NotImplementedError("not built")


def rollover(current_epoch: int) -> schemas.EpochCertificate:
    raise NotImplementedError("not built")


def destroy_epoch_key(epoch_id: int) -> None:
    raise NotImplementedError("not built")

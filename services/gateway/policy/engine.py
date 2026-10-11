"""Declarative policy evaluation Scaffold only; no runtime behavior."""

from __future__ import annotations

from pathlib import Path

from libs.blackbox_core import schemas

# TODO(spec §13.5): implement and validate before enabling this module.


def load_rules(path: Path) -> dict[str, object]:
    raise NotImplementedError("not built")


def evaluate(
    action: schemas.RequestAction, principal: schemas.Principal, rules: dict[str, object]
) -> schemas.Policy:
    raise NotImplementedError("not built")
